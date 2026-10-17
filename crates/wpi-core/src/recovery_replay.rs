//! Stock-flash streaming workflow restricted to a concrete replay transport.
//! No native/serial/WebUSB transport can be passed to this API. A validated hardware
//! executor and authenticated recovery policy are required before exposing real writes.
use crate::recovery_journal::{Entry, Kind};
use std::io::{Read, Seek, SeekFrom};
use wpi_image::{ffu::FfuMetadata, ImageError};
use wpi_protocol::{flash, replay::ReplayTransport, MessageTransport, ProtocolError};
use wpi_types::{DeviceMode, Operation, OperationEvent, OperationState};

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("Image preflight: {0}")]
    Image(#[from] ImageError),
    #[error("Protocol: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Recovery preflight: {0}")]
    Preflight(String),
    #[error("Replay cancelled before changing simulated device state")]
    Cancelled,
    #[error("Replay journal failed before header submission: {0}")]
    Journal(String),
    #[error("Replay interrupted after a header was sent; inspect state before recovery: {0}")]
    RecoveryRequired(String),
}

pub fn run<R: Read + Seek, F: FnMut(&OperationEvent) -> bool>(
    reader: &mut R,
    transport: &mut ReplayTransport,
    event: F,
) -> Result<(), RecoveryError> {
    run_journaled(reader, transport, event, |_| Ok(()))
}

/// Only a concrete replay transport is accepted. The sink must durably save each
/// entry before returning Ok. No native writer, journal import or resume API exists.
pub fn run_journaled<
    R: Read + Seek,
    F: FnMut(&OperationEvent) -> bool,
    J: FnMut(&Entry) -> std::io::Result<()>,
>(
    reader: &mut R,
    transport: &mut ReplayTransport,
    mut event: F,
    sink: J,
) -> Result<(), RecoveryError> {
    let ffu = FfuMetadata::open(reader)?;
    ffu.gpt(reader)?;
    ffu.verify_hashes(reader, |_, _| true)?;
    let info = flash::read_info(transport)?;
    if info.mode != DeviceMode::Flash {
        return Err(RecoveryError::Preflight("device is not in FlashApp".into()));
    }
    if info.platform_id.as_deref() != Some(ffu.platform_id.as_str()) {
        return Err(RecoveryError::Preflight(
            "exact platform ID does not match the FFU".into(),
        ));
    }
    let mask = info.protocol_mask.ok_or_else(|| {
        RecoveryError::Preflight("device did not advertise its FFU protocol mask".into())
    })?;
    if mask & 5 == 0 {
        return Err(RecoveryError::Preflight(
            "no supported synchronous FFU protocol".into(),
        ));
    }
    let v2 = mask & 4 != 0;
    let buffer_size = if v2 {
        let size = info
            .write_buffer_size
            .ok_or_else(|| RecoveryError::Preflight("missing device write buffer size".into()))?;
        if size < ffu.chunk_size || size > 4 * 1024 * 1024 || size % ffu.chunk_size != 0 {
            return Err(RecoveryError::Preflight(
                "invalid device write buffer geometry".into(),
            ));
        }
        size as usize
    } else {
        ffu.chunk_size as usize
    };
    reader.seek(SeekFrom::Start(0)).map_err(ImageError::from)?;
    let image_sha256 = wpi_image::stream::sha256(reader)?;
    let mut journal = Journal {
        sink,
        entry: Entry {
            schema: 1,
            sequence: 0,
            kind: Kind::Ready,
            image_sha256,
            image_bytes: ffu.total_size,
            total_payload_bytes: ffu.payload_size,
            acknowledged_payload_bytes: 0,
            payload_offset: 0,
            payload_bytes: 0,
            header_acknowledged: false,
            state_inspection_required: false,
            fresh_device_checks_required: true,
            automatic_resume_allowed: false,
            replay_only: true,
            phone_writes_enabled: false,
        },
        submitted: false,
    };
    journal.save(Kind::Ready, 0, 0, 0)?;
    let mut sequence = 1;
    let mut notify = |state, done, message: &str| {
        let response = event(&OperationEvent {
            sequence,
            operation: Operation::StockFlash,
            state,
            completed_bytes: done,
            total_bytes: ffu.payload_size,
            message: message.into(),
        });
        sequence += 1;
        response
    };
    if !notify(
        OperationState::Running,
        0,
        "Replay preflight passed; no physical device is contacted",
    ) {
        journal.save(Kind::Cancelled, 0, 0, 0)?;
        return Err(RecoveryError::Cancelled);
    }
    reader.seek(SeekFrom::Start(0)).map_err(ImageError::from)?;
    let mut header = vec![0; ffu.header_size as usize];
    reader.read_exact(&mut header).map_err(ImageError::from)?;
    let request = flash::ffu_header_v1(&header)?;
    journal.save(Kind::HeaderIntent, 0, 0, 0)?;
    journal.submitted = true;
    // An uncertain acknowledgement can mean the device accepted the header. Never retry it.
    let response = transport
        .exchange(&request, 65536)
        .and_then(|r| flash::check_status(&r, b"NOKXFS"));
    if let Err(error) = response {
        journal.save(Kind::RecoveryRequired, 0, 0, 0)?;
        notify(OperationState::RecoveryRequired, 0, &error.to_string());
        return Err(RecoveryError::RecoveryRequired(error.to_string()));
    }
    journal.entry.header_acknowledged = true;
    journal.save(Kind::HeaderAcknowledged, 0, 0, 0)?;
    let mut buffer = vec![0; buffer_size];
    let mut done = 0u64;
    while done < ffu.payload_size {
        if !notify(OperationState::Running, done, "Replay payload boundary") {
            journal.save(Kind::RecoveryRequired, done, done, 0)?;
            notify(
                OperationState::RecoveryRequired,
                done,
                "Replay cancelled after header acceptance",
            );
            return Err(RecoveryError::RecoveryRequired(
                "cancelled after header acceptance".into(),
            ));
        }
        let n = (ffu.payload_size - done).min(buffer.len() as u64) as usize;
        if let Err(error) = reader.read_exact(&mut buffer[..n]) {
            journal.save(Kind::RecoveryRequired, done, done, 0)?;
            notify(OperationState::RecoveryRequired, done, &error.to_string());
            return Err(RecoveryError::RecoveryRequired(error.to_string()));
        }
        let percentage = ((done + n as u64) * 100 / ffu.payload_size) as u8;
        let request = if v2 {
            flash::ffu_payload_v2(&buffer[..n], percentage)?
        } else {
            flash::ffu_payload_v1(&buffer[..n], percentage)?
        };
        journal.save(Kind::PayloadIntent, done, done, n as u64)?;
        if let Err(error) = transport
            .exchange(&request, 65536)
            .and_then(|r| flash::check_status(&r, b"NOKXFS"))
        {
            journal.save(Kind::RecoveryRequired, done, done, n as u64)?;
            notify(OperationState::RecoveryRequired, done, &error.to_string());
            return Err(RecoveryError::RecoveryRequired(error.to_string()));
        }
        let offset = done;
        done += n as u64;
        journal.save(Kind::PayloadAcknowledged, done, offset, n as u64)?;
    }
    journal.save(Kind::Completed, done, done, 0)?;
    notify(
        OperationState::Completed,
        done,
        "Stock flash replay complete; no physical device was contacted",
    );
    Ok(())
}

struct Journal<J> {
    sink: J,
    entry: Entry,
    submitted: bool,
}
impl<J: FnMut(&Entry) -> std::io::Result<()>> Journal<J> {
    fn save(
        &mut self,
        kind: Kind,
        acknowledged: u64,
        offset: u64,
        length: u64,
    ) -> Result<(), RecoveryError> {
        self.entry.sequence += 1;
        self.entry.kind = kind;
        self.entry.acknowledged_payload_bytes = acknowledged;
        self.entry.payload_offset = offset;
        self.entry.payload_bytes = length;
        self.entry.state_inspection_required = self.submitted || kind == Kind::HeaderIntent;
        (self.sink)(&self.entry).map_err(|e| {
            if self.submitted {
                RecoveryError::RecoveryRequired(format!("journal save failed: {e}"))
            } else {
                RecoveryError::Journal(e.to_string())
            }
        })
    }
}
