//! Spec A emergency entry and one legacy DLOAD programmer upload, REPLAY ONLY.
//! WPInternals 2.9.2 LumiaUnlockBootloaderViewModel.PerformSoftBrick/SendLoader
//! and QualcommDownload.cs, Rene Lergner, MIT. No OS/device handles or write grant.
use crate::spec_a_journal::{Checkpoint, Kind, Phase, Step};
use serde::Serialize;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use wpi_image::{ffu::FfuMetadata, spec_a, ImageError};
use wpi_protocol::{
    flash,
    identity::PublicId,
    preflight::{self, RootKeyHash},
    qualcomm::{dload, v1},
    replay::{FramedReplayTransport, ReplayTransport},
    MessageTransport,
};
use wpi_types::{Operation, OperationEvent, OperationState};

const DEADLINE_MS: u32 = 30_000;
pub(crate) const ENTRY_CHUNK: usize = 0x20000;
fn invalid(message: &str) -> ImageError {
    ImageError::Invalid(message.into())
}
fn hash(bytes: &[u8]) -> wpi_image::Result<String> {
    wpi_image::stream::sha256(&mut Cursor::new(bytes))
}
fn matches_hash(actual: &str, expected: &str) -> bool {
    expected.len() == 64
        && expected.bytes().all(|b| b.is_ascii_hexdigit())
        && actual.eq_ignore_ascii_case(expected)
}

/// Header bytes captured from the same pass as the complete pinned digest.
/// Not serializable; a report cannot be imported to construct one.
pub struct EntryPlan {
    header: Vec<u8>,
    platform: String,
    sha256: String,
    total_size: u64,
}
impl EntryPlan {
    /// Reconstruct bounded reference metadata using the retained hash table and
    /// verified copies of each payload chunk. No later file header is trusted.
    pub fn reference<R: Read + Seek>(
        &self,
        source: &mut R,
    ) -> wpi_image::Result<crate::spec_a_preflight::Reference> {
        let mut pinned =
            crate::spec_a_source::Source::new(source, &self.header, self.total_size, true)?;
        let mut reference = crate::spec_a_preflight::Reference::read(&mut pinned)?;
        reference.mark_full_integrity_checked(&self.sha256);
        Ok(reference)
    }
    pub(crate) fn source(&self) -> (&str, &str) {
        (&self.sha256, &self.platform)
    }
    pub fn read<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
        source: &mut R,
        expected_sha256: &str,
        mut progress: F,
    ) -> wpi_image::Result<Self> {
        if !progress(0, 0) {
            return Err(ImageError::Cancelled);
        }
        let initial = FfuMetadata::open(source)?;
        if initial.total_size > 16 * 1024 * 1024 * 1024 {
            return Err(invalid("Entry source exceeds 16 GiB"));
        }
        struct Prefix {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl Write for Prefix {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let n = b.len().min(self.limit - self.bytes.len());
                self.bytes.extend_from_slice(&b[..n]);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut header = Prefix {
            bytes: Vec::new(),
            limit: initial.header_size as usize,
        };
        let total = initial.total_size + initial.total_size - initial.security_size;
        source.seek(SeekFrom::Start(0))?;
        let sha256 =
            wpi_image::stream::copy_hashed(source, &mut header, initial.total_size, |done, _| {
                progress(done, total)
            })?;
        if !matches_hash(&sha256, expected_sha256) {
            return Err(invalid("Entry source digest differs from selected FFU"));
        }
        let ffu = FfuMetadata::read_headers(&mut Cursor::new(&header.bytes), initial.total_size)?;
        if ffu.header_size as usize != header.bytes.len()
            || ffu.chunk_size as usize != ENTRY_CHUNK
            || !(ffu.total_size - ffu.security_size).is_multiple_of(u64::from(ffu.chunk_size))
        {
            return Err(invalid("Entry requires the pinned 128 KiB FFU profile"));
        }
        let mappings: Vec<_> = ffu
            .mappings
            .iter()
            .filter(|m| m.payload_chunk == 0)
            .collect();
        if mappings.len() != 2
            || ![0, 2].iter().all(|access| {
                mappings
                    .iter()
                    .filter(|m| m.disk_access == *access && m.disk_chunk == 0 && m.chunk_count == 1)
                    .count()
                    == 1
            })
        {
            return Err(invalid(
                "Entry first chunk must map once to each disk boundary only",
            ));
        }
        let mut pinned =
            crate::spec_a_source::Source::new(source, &header.bytes, initial.total_size, false)?;
        ffu.verify_hashes(&mut pinned, |done, _| {
            progress(initial.total_size + done * u64::from(ffu.chunk_size), total)
        })?;
        let mut checked =
            crate::spec_a_source::Source::new(source, &header.bytes, initial.total_size, true)?;
        ffu.gpt(&mut checked)?;
        checked.seek(SeekFrom::Start(ffu.header_size))?;
        let mut first = vec![0; ENTRY_CHUNK];
        checked.read_exact(&mut first)?;
        if first.iter().any(|b| *b != 0) {
            return Err(invalid(
                "Entry source first payload chunk is not zero filled",
            ));
        }
        if !progress(total, total) {
            return Err(ImageError::Cancelled);
        }
        Ok(Self {
            header: header.bytes,
            platform: ffu.platform_id,
            sha256,
            total_size: initial.total_size,
        })
    }
}

pub struct Loader {
    bytes: Vec<u8>,
    root: RootKeyHash,
    input_sha256: String,
    decoded_sha256: String,
}
impl Loader {
    pub(crate) fn matches_root(&self, root: &RootKeyHash) -> bool {
        self.root == *root
    }
    pub(crate) fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }
    pub(crate) fn fingerprints(&self) -> (&str, &str) {
        (&self.input_sha256, &self.decoded_sha256)
    }
    /// Pin exactly one local import. Internal certificate equality and the V1
    /// marker are format/family evidence, not authentication or device acceptance.
    pub fn prepare(
        input: &[u8],
        expected_sha256: &str,
        expected_root: &RootKeyHash,
    ) -> wpi_image::Result<Self> {
        if input.is_empty() || input.len() > spec_a::MAX_LOADER_FILE {
            return Err(invalid("Loader import exceeds bounds"));
        }
        let input_sha256 = hash(input)?;
        if !matches_hash(&input_sha256, expected_sha256) {
            return Err(invalid("Loader input digest mismatch"));
        }
        let bytes = spec_a::decode_loader(input)?;
        let image = spec_a::parse(&bytes, 0)?;
        let mut root_bytes = [0; 32];
        for (byte, pair) in root_bytes
            .iter_mut()
            .zip(image.root_certificate_sha256.as_bytes().as_chunks::<2>().0)
        {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        let root =
            RootKeyHash::parse(&root_bytes).map_err(|_| invalid("Loader root is invalid"))?;
        let marker: Vec<_> = "QHSUSB_ARMPRG"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        if root != *expected_root
            || !bytes[image.image_offset..image.image_offset + image.code_size]
                .windows(marker.len())
                .any(|b| b == marker)
        {
            return Err(invalid("Loader root fingerprint or V1 marker mismatch"));
        }
        let decoded_sha256 = hash(&bytes)?;
        Ok(Self {
            bytes,
            root,
            input_sha256,
            decoded_sha256,
        })
    }
}

/// Local unauthenticated correlation values. Never serialized or printed.
pub struct Binding {
    pub public_id: PublicId,
    pub physical_port: String,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Download,
    Programmer,
}
#[derive(Clone)]
pub enum Observation {
    Disconnected,
    Connected {
        endpoint: Endpoint,
        physical_port: String,
        candidates: u8,
    },
}
#[derive(Clone)]
pub struct TimedObservation {
    pub elapsed_ms: u32,
    pub observation: Observation,
}
pub struct Scenario {
    pub source_port: String,
    pub source_candidates: u8,
    pub flash: ReplayTransport,
    pub download: FramedReplayTransport,
    pub programmer: FramedReplayTransport,
    pub download_arrivals: Vec<TimedObservation>,
    pub programmer_arrivals: Vec<TimedObservation>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub source_ffu_sha256: String,
    pub loader_input_sha256: String,
    pub loader_decoded_sha256: String,
    pub acknowledged_ram_bytes: u64,
    pub programmer_hello_acknowledged: bool,
    pub physical_port_correlated: bool,
    pub root_fingerprint_matched: bool,
    pub device_identity_authenticated: bool,
    pub data_preservation_validated: bool,
    pub replay_only: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Emergency replay preflight: {0}")]
    Preflight(String),
    #[error("Emergency replay cancelled before entry submission")]
    Cancelled,
    #[error("Emergency replay interrupted during {phase}; inspect state: {detail}")]
    RecoveryRequired {
        phase: &'static str,
        acknowledged_ram_bytes: u64,
        storage_submission_attempted: bool,
        loader_start_attempted: bool,
        detail: String,
    },
}

/// This entire workflow accepts only concrete replay objects. Emergency entry
/// changes simulated disk boundaries; upload ACKs do not establish an unlock.
pub fn run<F: FnMut(&OperationEvent) -> bool>(
    plan: &EntryPlan,
    loader: &Loader,
    binding: &Binding,
    scenario: &mut Scenario,
    event: F,
) -> Result<Report, Error> {
    run_checkpointed(plan, loader, binding, scenario, event, |_| Ok(()))
}

pub(crate) fn run_checkpointed<
    F: FnMut(&OperationEvent) -> bool,
    J: FnMut(Checkpoint) -> std::io::Result<()>,
>(
    plan: &EntryPlan,
    loader: &Loader,
    binding: &Binding,
    scenario: &mut Scenario,
    event: F,
    checkpoint: J,
) -> Result<Report, Error> {
    let mut runner = Runner {
        event,
        checkpoint,
        current: Checkpoint::new(Phase::EntryUpload, Kind::Ready, Step::SourcePreflight),
        sequence: 0,
        done: 0,
        total: loader.bytes.len() as u64,
        storage: false,
        started_loader: false,
    };
    if binding.physical_port.is_empty()
        || binding.physical_port.len() > 256
        || !binding.physical_port.bytes().all(|b| b.is_ascii_graphic())
        || scenario.source_candidates != 1
        || scenario.source_port != binding.physical_port
    {
        return Err(runner.fail(
            "source binding",
            "ambiguous or changed physical port".into(),
        ));
    }
    let mut cancelled = false;
    let capture = preflight::capture_bound(
        &mut scenario.flash,
        &loader.root,
        &plan.platform,
        false,
        &binding.public_id,
        |stage| {
            let proceed = runner.notify(OperationState::Running, stage);
            cancelled |= !proceed;
            proceed
        },
    );
    let capture = match capture {
        Ok(c) => c.into_observation(),
        Err(_) if cancelled => return Err(runner.cancel("source preflight")),
        Err(error) => return Err(runner.fail("source preflight", error.to_string())),
    };
    if capture.info.protocol_major != 1
        || capture.info.protocol_mask.is_none_or(|m| m & 1 == 0)
        || capture.application_security.is_none()
    {
        return Err(runner.fail(
            "source preflight",
            "missing Spec A/FFU-v1/security evidence".into(),
        ));
    }
    runner.record(Checkpoint::new(
        Phase::EntryUpload,
        Kind::PhaseComplete,
        Step::SourcePreflight,
    ))?;
    let header = flash::ffu_header_v1(&plan.header)
        .map_err(|e| runner.fail("header encoding", e.to_string()))?;
    let response = runner.request(&mut scenario.flash, "FFU header", &header, true, false)?;
    flash::check_status(&response, b"NOKXFS")
        .map_err(|e| runner.fail("FFU header", e.to_string()))?;
    runner.ack()?;
    let zero = flash::ffu_payload_v1(&vec![0; ENTRY_CHUNK], 0)
        .map_err(|e| runner.fail("entry encoding", e.to_string()))?;
    let response = runner.request(
        &mut scenario.flash,
        "boundary zero chunk",
        &zero,
        true,
        false,
    )?;
    flash::check_status(&response, b"NOKXFS")
        .map_err(|e| runner.fail("boundary zero chunk", e.to_string()))?;
    runner.ack()?;
    if !runner.notify(OperationState::Running, "Replay entry reboot") {
        return Err(runner.cancel("entry reboot"));
    }
    runner.record(Checkpoint::new(
        Phase::EntryUpload,
        Kind::Intent,
        Step::EntryReboot,
    ))?;
    scenario
        .flash
        .send(b"NOKR")
        .map_err(|e| runner.fail("entry reboot", e.to_string()))?;
    runner.record(Checkpoint::new(
        Phase::EntryUpload,
        Kind::Submitted,
        Step::EntryReboot,
    ))?;
    runner.arrival(
        &scenario.download_arrivals,
        Endpoint::Download,
        &binding.physical_port,
    )?;
    let response = runner.request(
        &mut scenario.download,
        "DLOAD alive",
        &dload::alive().unwrap(),
        false,
        false,
    )?;
    dload::check_ack(&response).map_err(|e| runner.fail("DLOAD alive", e.to_string()))?;
    runner.ack()?;
    let response = runner.request(
        &mut scenario.download,
        "DLOAD root",
        &dload::root_key().unwrap(),
        false,
        false,
    )?;
    let root =
        dload::parse_root(&response).map_err(|e| runner.fail("DLOAD root", e.to_string()))?;
    if root != loader.root {
        return Err(runner.fail("DLOAD root", "root fingerprint changed across modes".into()));
    }
    runner.ack()?;
    for (index, chunk) in loader.bytes.chunks(dload::MAX_MEMORY_BYTES).enumerate() {
        let address = dload::LOADER_ADDRESS + (index * dload::MAX_MEMORY_BYTES) as u32;
        let request = dload::memory(address, chunk)
            .map_err(|e| runner.fail("RAM encoding", e.to_string()))?;
        let response =
            runner.request(&mut scenario.download, "RAM upload", &request, false, false)?;
        dload::check_ack(&response).map_err(|e| runner.fail("RAM upload", e.to_string()))?;
        runner.done += chunk.len() as u64;
        runner.ack()?;
    }
    let response = runner.request(
        &mut scenario.download,
        "loader start",
        &dload::start(dload::LOADER_ADDRESS).unwrap(),
        false,
        true,
    )?;
    dload::check_ack(&response).map_err(|e| runner.fail("loader start", e.to_string()))?;
    runner.ack()?;
    runner.arrival(
        &scenario.programmer_arrivals,
        Endpoint::Programmer,
        &binding.physical_port,
    )?;
    let response = runner.request(
        &mut scenario.programmer,
        "programmer hello",
        &v1::hello(),
        false,
        false,
    )?;
    v1::check_ack(&response, v1::Ack::Hello)
        .map_err(|e| runner.fail("programmer hello", e.to_string()))?;
    runner.ack()?;
    runner.notify(
        OperationState::Completed,
        "Replay programmer handshake complete; no phone was contacted or unlocked",
    );
    Ok(Report {
        source_ffu_sha256: plan.sha256.clone(),
        loader_input_sha256: loader.input_sha256.clone(),
        loader_decoded_sha256: loader.decoded_sha256.clone(),
        acknowledged_ram_bytes: runner.done,
        programmer_hello_acknowledged: true,
        physical_port_correlated: true,
        root_fingerprint_matched: true,
        device_identity_authenticated: false,
        data_preservation_validated: false,
        replay_only: true,
        phone_contacted: false,
        phone_writes_enabled: false,
    })
}

struct Runner<F, J> {
    event: F,
    checkpoint: J,
    current: Checkpoint,
    sequence: u64,
    done: u64,
    total: u64,
    storage: bool,
    started_loader: bool,
}
impl<F: FnMut(&OperationEvent) -> bool, J: FnMut(Checkpoint) -> std::io::Result<()>> Runner<F, J> {
    fn record(&mut self, checkpoint: Checkpoint) -> Result<(), Error> {
        self.current = checkpoint;
        (self.checkpoint)(checkpoint).map_err(|e| self.fail("journal", e.to_string()))
    }
    fn ack(&mut self) -> Result<(), Error> {
        self.record(Checkpoint {
            kind: Kind::Acknowledged,
            ..self.current
        })
    }
    fn notify(&mut self, state: OperationState, message: &str) -> bool {
        self.sequence += 1;
        (self.event)(&OperationEvent {
            sequence: self.sequence,
            operation: Operation::UnlockBootloader,
            state,
            completed_bytes: self.done,
            total_bytes: self.total,
            message: message.into(),
        })
    }
    fn fail(&mut self, phase: &'static str, detail: String) -> Error {
        self.notify(
            if self.storage {
                OperationState::RecoveryRequired
            } else {
                OperationState::Failed
            },
            &format!("Replay {phase}: {detail}"),
        );
        if self.storage {
            Error::RecoveryRequired {
                phase,
                acknowledged_ram_bytes: self.done,
                storage_submission_attempted: true,
                loader_start_attempted: self.started_loader,
                detail,
            }
        } else {
            Error::Preflight(detail)
        }
    }
    fn cancel(&mut self, phase: &'static str) -> Error {
        if self.storage {
            self.fail(phase, "cancelled before the next command".into())
        } else {
            self.notify(
                OperationState::Cancelled,
                "Replay cancelled before entry submission",
            );
            Error::Cancelled
        }
    }
    fn request<T: MessageTransport>(
        &mut self,
        transport: &mut T,
        phase: &'static str,
        request: &[u8],
        storage: bool,
        start: bool,
    ) -> Result<Vec<u8>, Error> {
        if !self.notify(OperationState::Running, phase) {
            return Err(self.cancel(phase));
        }
        let mut checkpoint =
            Checkpoint::new(Phase::EntryUpload, Kind::Intent, Step::emergency(phase));
        match checkpoint.step {
            Step::FfuHeader => checkpoint.bytes = (request.len() - 32) as u64,
            Step::BoundaryZero => checkpoint.bytes = ENTRY_CHUNK as u64,
            Step::RamUpload => {
                // Decode our bounded, freshly generated request to bind journal
                // metadata to its actual byte address/length, not an event label.
                let payload = wpi_protocol::qualcomm::decode_hdlc(request)
                    .map_err(|e| self.fail("journal metadata", e.to_string()))?;
                checkpoint.address = Some(u32::from_be_bytes(payload[1..5].try_into().unwrap()));
                checkpoint.bytes = u16::from_be_bytes(payload[5..7].try_into().unwrap()) as u64;
            }
            Step::LoaderStart => checkpoint.address = Some(dload::LOADER_ADDRESS),
            _ => {}
        }
        self.record(checkpoint)?;
        self.storage |= storage;
        self.started_loader |= start;
        transport
            .exchange(request, if storage { 65536 } else { v1::MAX_REPLY_FRAME })
            .map_err(|e| self.fail(phase, e.to_string()))
    }
    fn arrival(
        &mut self,
        observations: &[TimedObservation],
        expected: Endpoint,
        port: &str,
    ) -> Result<(), Error> {
        let step = if expected == Endpoint::Download {
            Step::DownloadArrival
        } else {
            Step::ProgrammerArrival
        };
        self.record(Checkpoint::new(
            Phase::EntryUpload,
            Kind::AwaitingArrival,
            step,
        ))?;
        if observations.is_empty() || observations.len() > 64 {
            return Err(self.fail(
                "reconnection",
                "missing or oversized observation timeline".into(),
            ));
        }
        let mut disconnected = false;
        let mut last = 0;
        for (index, observation) in observations.iter().enumerate() {
            if !self.notify(OperationState::AwaitingReconnect, "Replay mode arrival") {
                return Err(self.cancel("reconnection"));
            }
            if observation.elapsed_ms < last || observation.elapsed_ms > DEADLINE_MS {
                return Err(self.fail("reconnection", "nonmonotonic or expired arrival".into()));
            }
            last = observation.elapsed_ms;
            match &observation.observation {
                Observation::Disconnected => disconnected = true,
                Observation::Connected {
                    endpoint,
                    physical_port,
                    candidates,
                } => {
                    if !disconnected
                        || *endpoint != expected
                        || physical_port != port
                        || *candidates != 1
                        || index + 1 != observations.len()
                    {
                        return Err(self.fail("reconnection", "missing disconnect, wrong/ambiguous endpoint, changed port or surplus arrival".into()));
                    }
                    self.record(Checkpoint::new(
                        Phase::EntryUpload,
                        Kind::ArrivalMatched,
                        step,
                    ))?;
                    return Ok(());
                }
            }
        }
        Err(self.fail("reconnection", "endpoint did not arrive".into()))
    }
}
