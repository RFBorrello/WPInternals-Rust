//! Separate, explicitly selected recovery experiment for an already exposed
//! RM-875 DLOAD endpoint. No journal import, entry command or unlock continuation.
//! GPT length follows WPInternals 2.9.2 TestCode.RecoverBadGPT (Rene Lergner, MIT).
use super::*;

pub const CONFIRMATION: &str = "RM875-RESTORE-CAPTURED-PRIMARY-GPT-FROM-DLOAD";
const PRIMARY_BYTES: usize = 34 * 512;
const RESTORED_BYTES: usize = PRIMARY_BYTES - 1;
const WRITE_STAGE: &str = "Restore captured primary GPT";

struct Step {
    stage: &'static str,
    bytes: Vec<u8>,
    storage: bool,
}
/// Process-local exact packet allowlist. Counters advance before an uncertain
/// submission; neither imported records nor a failed command can reset them.
pub(super) struct Guard {
    steps: Vec<Step>,
    next: usize,
}
impl Guard {
    fn new(primary: &[u8], loader: &[u8]) -> Result<Self, String> {
        if primary.len() != PRIMARY_BYTES
            || primary.last() != Some(&0)
            || loader.is_empty()
            || loader.len() > wpi_image::spec_a::MAX_LOADER_FILE
        {
            return Err("Recovery requires a full captured primary with a zero omitted final byte and a bounded pinned loader".into());
        }
        let mut steps = Vec::new();
        for (index, bytes) in loader.chunks(dload::MAX_MEMORY_BYTES).enumerate() {
            let offset = u32::try_from(index * dload::MAX_MEMORY_BYTES).map_err(text)?;
            let address = dload::LOADER_ADDRESS
                .checked_add(offset)
                .ok_or("Loader address overflow")?;
            steps.push(Step {
                stage: "DLOAD RAM upload",
                bytes: dload::memory(address, bytes).map_err(text)?,
                storage: false,
            });
        }
        steps.push(Step {
            stage: "Start one pinned loader",
            bytes: dload::start(dload::LOADER_ADDRESS).map_err(text)?,
            storage: false,
        });
        for (stage, bytes) in [
            ("Programmer hello", v1::hello()),
            ("Programmer security mode", v1::SECURITY_MODE_ZERO.to_vec()),
            (
                "Programmer open boot partition",
                v1::OPEN_BOOT_PARTITION.to_vec(),
            ),
        ] {
            steps.push(Step {
                stage,
                bytes,
                storage: false,
            });
        }
        for (address, bytes) in writes(primary)? {
            steps.push(Step {
                stage: WRITE_STAGE,
                bytes: v1::write(address, bytes).map_err(text)?,
                storage: true,
            });
        }
        for (stage, bytes) in [
            ("Programmer close", v1::CLOSE_PARTITION),
            ("Programmer reboot", v1::REBOOT),
        ] {
            steps.push(Step {
                stage,
                bytes: bytes.to_vec(),
                storage: false,
            });
        }
        Ok(Self { steps, next: 0 })
    }
    pub(super) fn admit(&mut self, stage: &str, bytes: &[u8], storage: bool) -> Result<(), String> {
        let expected = self
            .steps
            .get(self.next)
            .ok_or("Entry-recovery command sequence already finished")?;
        if stage != expected.stage || bytes != expected.bytes || storage != expected.storage {
            return Err("Entry-recovery boundary refuses unplanned bytes, addresses, stages or extra commands".into());
        }
        self.next += 1;
        Ok(())
    }
    fn complete(&self) -> bool {
        self.next == self.steps.len()
    }
}
fn writes(primary: &[u8]) -> Result<Vec<(u32, &[u8])>, String> {
    if primary.len() != PRIMARY_BYTES || primary.last() != Some(&0) {
        return Err("Invalid captured primary length or omitted-byte assumption".into());
    }
    // Upstream writes MBR separately and GPT at 0x200 for 0x41ff bytes.
    // Its loader rejects the last byte at the GPT partition boundary. That byte
    // must already be zero after entry; only subsequent readback can verify it.
    let mut result = vec![(0, &primary[..512])];
    result.extend(
        primary[512..RESTORED_BYTES]
            .chunks(v1::MAX_WRITE_BYTES)
            .enumerate()
            .map(|(index, bytes)| ((512 + index * v1::MAX_WRITE_BYTES) as u32, bytes)),
    );
    Ok(result)
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && value.bytes().any(|b| b != b'0')
}
fn validate_plan(plan: &Plan<'_>) -> Result<(), String> {
    if plan.capacity() != 61_071_360 {
        return Err(
            "This recovery experiment is limited to the recorded 32 GB RM-875 layout".into(),
        );
    }
    entry_recovery::Capsule::build(
        plan.prepared.boot().original_primary(),
        plan.capacity(),
        &plan.prepared.artifacts().saved_primary_sha256,
    )
    .map_err(text)?;
    Guard::new(
        plan.prepared.boot().original_primary(),
        plan.prepared.loader().decoded_bytes(),
    )?;
    Ok(())
}

#[derive(Serialize)]
pub struct Preview {
    pub recovery_only: bool,
    pub preview_only: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
    pub source_ffu_sha256: String,
    pub captured_primary_sha256: String,
    pub loader_input_sha256: String,
    pub restored_bytes: usize,
    pub write_requests: usize,
    pub omitted_final_primary_byte_offset: usize,
    pub omitted_byte_must_already_be_zero: bool,
    pub secondary_gpt_restored: bool,
    pub unlock_attempted: bool,
    pub data_preservation_validated: bool,
    pub automatic_resume_allowed: bool,
    pub limitations: Vec<&'static str>,
}
pub fn preview(plan: &Plan<'_>) -> Result<Preview, String> {
    validate_plan(plan)?;
    Ok(Preview {
        recovery_only: true, preview_only: true, phone_contacted: false, phone_writes_enabled: false,
        source_ffu_sha256: plan.prepared.artifacts().source_ffu_sha256.clone(),
        captured_primary_sha256: plan.prepared.artifacts().saved_primary_sha256.clone(),
        loader_input_sha256: plan.prepared.artifacts().loader_input_sha256.clone(),
        restored_bytes: RESTORED_BYTES, write_requests: writes(plan.prepared.boot().original_primary())?.len(),
        omitted_final_primary_byte_offset: RESTORED_BYTES, omitted_byte_must_already_be_zero: true,
        secondary_gpt_restored: false, unlock_attempted: false, data_preservation_validated: false,
        automatic_resume_allowed: false,
        limitations: vec![
            "This starts a new explicitly approved recovery on a selected current DLOAD endpoint; it never resumes the stopped unlock or repeats entry.",
            "Fresh physical-port and DLOAD/reference-root checks precede one pinned RAM loader. The root is a family fingerprint, not authenticated Lumia model identity.",
            "Only captured MBR/primary GPT bytes 0..17406 are written. The final byte at 17407 is omitted for the known loader boundary quirk and must be zero already; BootManager double-read verifies all 17408 bytes afterward.",
            "The backup GPT, front padding, boot partitions and any Data-tail damage are not restored. This is not a complete rollback or full-data recovery.",
            "After the planned programmer reboot, the exact BootManager read window and original Normal serial/model/product/firmware must validate. Missing it stops without a retry or extra restart.",
            "Loader acceptance, programmer writes and physical recovery remain unvalidated and may leave the phone unbootable. No fallback loader, erase, full FFU flash, raw disk, boot-partition patch or automatic reset is permitted.",
        ],
    })
}

#[derive(Serialize)]
pub struct Report {
    pub recovery_only: bool,
    pub primary_gpt_readback_verified: bool,
    pub original_normal_profile_and_serial_verified: bool,
    pub primary_payload_bytes_submitted: usize,
    pub secondary_gpt_restored: bool,
    pub unlock_attempted: bool,
    pub storage_may_have_changed: bool,
    pub data_preservation_validated: bool,
    pub hardware_validated: bool,
    pub automatic_resume_allowed: bool,
    pub journal_records: u64,
}
/// Hash a Windows hub/connection index selector, never log the raw identifiers.
pub(super) fn port_digest(port: &PhysicalPort) -> Result<String, String> {
    #[cfg(windows)]
    {
        let PhysicalPort::Windows { hub, number } = port;
        let hub = hub.to_str().ok_or("Unsupported hub identifier encoding")?;
        Ok(hash(
            format!("{}\n{number}", hub.to_ascii_uppercase()).as_bytes(),
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = port;
        Err("Windows physical-port binding is required".into())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run<F: FnMut(&str)>(
    id: &str,
    plan: &Plan<'_>,
    confirmation: &str,
    expected_port: &str,
    expected_normal_serial: &str,
    journal: &Path,
    cancelled: &AtomicBool,
    mut progress: F,
) -> Result<Report, String> {
    if confirmation != CONFIRMATION || !digest(expected_port) || !digest(expected_normal_serial) {
        return Err("Exact recovery confirmation and valid expected port/Normal serial digests required; no device was opened".into());
    }
    if !cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        return Err("This recovery experiment supports Windows ARM64 only".into());
    }
    validate_plan(plan)?;
    validate_outputs([journal])?;
    boundary(cancelled)?;
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let selected = device_binding::selected(id)?;
    super::super::emergency_probe::admit(&selected)?;
    if selected.descriptor.product_id != 0x9008 {
        return Err("Select only the already exposed 9008 DLOAD target".into());
    }
    let port = selected.port.as_ref().ok_or("Missing physical port")?;
    if !port_digest(port)?.eq_ignore_ascii_case(expected_port) {
        return Err("Selected physical port does not match the reviewed target".into());
    }
    // Descriptor admission and current WinUSB status are checked before even
    // the read-only root query. This API never installs or changes a driver.
    #[cfg(windows)]
    {
        let info = nusb::list_devices()
            .wait()
            .map_err(text)?
            .find(|d| format!("{:?}", d.id()) == selected.descriptor.id)
            .ok_or("Selected emergency endpoint disappeared")?;
        if Snapshot::of(&info) != selected {
            return Err("Selected emergency descriptors changed".into());
        }
        let binding = readiness::selected_binding(
            info.instance_id()
                .to_str()
                .ok_or("Unsupported instance encoding")?,
        )?
        .ok_or("Selected emergency binding metadata is missing")?;
        if binding.binding_target != readiness::BindingTarget::WholeDevice
            || !binding.usable_binding()
        {
            return Err("Recovery requires the exact healthy whole-device WinUSB binding; no protocol query sent".into());
        }
        super::super::emergency_probe::check_setup_descriptors(&selected)?;
    }
    let mut sink = Journal::create(journal, plan_binding(plan))?;
    sink.storage = true; // Prior entry has already made storage state uncertain.
    sink.restore_guard = Some(Guard::new(
        plan.prepared.boot().original_primary(),
        plan.prepared.loader().decoded_bytes(),
    )?);
    sink.append(
        "prepared",
        "New primary-GPT recovery; prior entry changed storage; not an imported unlock resume",
        None,
    )?;
    let result = execute(
        plan,
        &selected,
        port,
        expected_normal_serial,
        &mut sink,
        cancelled,
        &mut progress,
    );
    if let Err(error) = &result {
        let _ = sink.append("recovery_required", error, None);
        progress("Recovery stopped. Preserve the journal and inspect state; no retry, alternate loader, extra reboot or rollback was sent.");
    }
    result
}

fn execute<F: FnMut(&str)>(
    plan: &Plan<'_>,
    selected: &Snapshot,
    port: &PhysicalPort,
    expected_serial: &str,
    sink: &mut Journal,
    cancelled: &AtomicBool,
    progress: &mut F,
) -> Result<Report, String> {
    progress("Recovery: freshly verify DLOAD root, upload/start one pinned RAM loader and validate the programmer");
    let (programmer, mut io) = load_programmer(
        plan,
        selected,
        port,
        sink,
        cancelled,
        progress,
        EmergencyAccess::ExistingBinding,
    )?;
    progress(
        "Recovery: write only the captured MBR and primary GPT, omitting the loader boundary byte",
    );
    let mut exchange = |request: &[u8]| {
        boundary(cancelled)?;
        validate(&programmer)?;
        io.exchange_framed(request, v1::MAX_REPLY_FRAME, None)
            .map_err(text)
    };
    for (address, bytes) in writes(plan.prepared.boot().original_primary())? {
        let request = v1::write(address, bytes).map_err(text)?;
        command(sink, cancelled, WRITE_STAGE, &request, true, || {
            v1::check_ack(&exchange(&request)?, v1::Ack::Write(address)).map_err(text)
        })?;
    }
    command(
        sink,
        cancelled,
        "Programmer close",
        v1::CLOSE_PARTITION,
        false,
        || v1::check_ack(&exchange(v1::CLOSE_PARTITION)?, v1::Ack::Close).map_err(text),
    )?;
    let mut watch = Watch::new()?;
    command(
        sink,
        cancelled,
        "Programmer reboot",
        v1::REBOOT,
        false,
        || v1::check_ack(&exchange(v1::REBOOT)?, v1::Ack::Reboot).map_err(text),
    )?;
    drop(io);
    let mut primary_verified = false;
    let mut normal_verified = false;
    watch.wait(&programmer, port, DeviceMode::Normal, cancelled, |next, application| {
        if next.descriptor.mode == DeviceMode::Normal {
            let serial = next.descriptor.serial.as_deref().filter(|s| !s.trim().is_empty()).ok_or("Returning Normal USB serial is missing")?;
            if !hash(serial.as_bytes()).eq_ignore_ascii_case(expected_serial) { return Err("Returning Normal serial differs; no further command sent".into()); }
            let application = application.ok_or("Missing Normal arrival handle")?;
            super::super::spec_a_session::capture_normal_on(next, plan.prepared, application.channel, cancelled, |_| {})?;
            normal_verified = true;
        } else if let Some(application) = application.filter(|a| a.info.as_ref().is_some_and(|i| i.mode == DeviceMode::BootManager)) {
            if primary_verified { return Err("Second BootManager cannot repeat recovery readback".into()); }
            let capture = wpi_core::boot_gpt::read(application.channel, plan.capacity() as u32, |_| !cancelled.load(Ordering::Acquire)).map_err(text)?;
            if capture.bytes() != plan.prepared.boot().original_primary() { return Err("Recovered primary readback differs from captured original".into()); }
            primary_verified = true;
            sink.append("verified", "Recovered primary double-read matches all captured bytes; Normal verification pending", None)?;
        }
        Ok(true)
    })?;
    boundary(cancelled)?;
    if !primary_verified
        || !normal_verified
        || !sink.restore_guard.as_ref().is_some_and(Guard::complete)
    {
        return Err(
            "Recovery readback/Normal verification incomplete; no additional restart sent".into(),
        );
    }
    sink.append("completed", "Primary GPT readback and original Normal profile/serial verified; backup GPT not restored; no unlock attempted", None)?;
    Ok(Report {
        recovery_only: true,
        primary_gpt_readback_verified: true,
        original_normal_profile_and_serial_verified: true,
        primary_payload_bytes_submitted: RESTORED_BYTES,
        secondary_gpt_restored: false,
        unlock_attempted: false,
        storage_may_have_changed: true,
        data_preservation_validated: false,
        hardware_validated: false,
        automatic_resume_allowed: false,
        journal_records: sink.sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn primary() -> Vec<u8> {
        let mut b = (0..PRIMARY_BYTES)
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        b[RESTORED_BYTES] = 0;
        b
    }
    #[test]
    fn recovery_spans_only_mbr_and_primary_with_the_upstream_boundary_quirk() {
        let primary = primary();
        let spans = writes(&primary).unwrap();
        assert_eq!(spans.len(), 18);
        assert_eq!(spans[0], (0, &primary[..512]));
        let mut restored = vec![0; PRIMARY_BYTES];
        let mut end = 0;
        for (address, bytes) in spans {
            assert_eq!(address as usize, end);
            assert!(bytes.len() <= 1024);
            restored[end..end + bytes.len()].copy_from_slice(bytes);
            end += bytes.len();
        }
        assert_eq!(end, RESTORED_BYTES);
        assert_eq!(restored, primary);
        for length in [0, 512, PRIMARY_BYTES - 1, PRIMARY_BYTES + 1] {
            assert!(writes(&vec![0; length]).is_err());
        }
        let mut bad = primary;
        bad[RESTORED_BYTES] = 1;
        assert!(writes(&bad).is_err());
    }
    #[test]
    fn exact_guard_refuses_entry_unlock_altered_payloads_addresses_storage_flags_and_retries() {
        let primary = primary();
        let guard = Guard::new(&primary, &[7; 1025]).unwrap();
        for at in 0..guard.steps.len() {
            for mutation in 0..4 {
                let mut attempt = Guard::new(&primary, &[7; 1025]).unwrap();
                for step in &guard.steps[..at] {
                    attempt
                        .admit(step.stage, &step.bytes, step.storage)
                        .unwrap();
                }
                let step = &guard.steps[at];
                let mut bytes = step.bytes.clone();
                if mutation == 0 {
                    bytes[0] ^= 1;
                }
                if mutation == 1 {
                    bytes.push(0);
                }
                let stage = if mutation == 2 {
                    "Entry FFU header (backup GPT may be cleared)"
                } else {
                    step.stage
                };
                let storage = if mutation == 3 {
                    !step.storage
                } else {
                    step.storage
                };
                assert!(attempt.admit(stage, &bytes, storage).is_err());
                assert_eq!(attempt.next, at);
            }
        }
        let mut attempt = Guard::new(&primary, &[7; 1025]).unwrap();
        for step in &guard.steps {
            attempt
                .admit(step.stage, &step.bytes, step.storage)
                .unwrap();
            assert!(attempt
                .admit(step.stage, &step.bytes, step.storage)
                .is_err());
        }
        assert!(attempt.complete());
        for bytes in [b"NOKR".as_slice(), b"NOKM", b"NOKS", b"NOKXFS"] {
            assert!(attempt.admit("extra", bytes, false).is_err());
        }
    }
    #[test]
    fn source_shapes_and_selector_digests_fail_closed() {
        assert!(Guard::new(&primary(), &[]).is_err());
        for bad in ["", "0", &"0".repeat(64), &"x".repeat(64), &"a".repeat(65)] {
            assert!(!digest(bad));
        }
        assert!(digest(&"a".repeat(64)));
        #[cfg(windows)]
        {
            let a = PhysicalPort::Windows {
                hub: "test-hub".into(),
                number: 2,
            };
            let b = PhysicalPort::Windows {
                hub: "TEST-HUB".into(),
                number: 2,
            };
            let c = PhysicalPort::Windows {
                hub: "TEST-HUB".into(),
                number: 3,
            };
            assert_eq!(port_digest(&a).unwrap(), port_digest(&b).unwrap());
            assert_ne!(port_digest(&a).unwrap(), port_digest(&c).unwrap());
        }
    }
    #[test]
    fn recovery_guard_and_durable_journal_stop_at_every_save_fault() {
        let primary = primary();
        let steps = Guard::new(&primary, &[7; 1025]).unwrap().steps;
        for fail_at in 1..=steps.len() as u64 * 2 {
            let dir = tempfile::tempdir().unwrap();
            let binding = Binding {
                source_ffu_sha256: "a".repeat(64),
                package_sha256: "b".repeat(64),
                saved_primary_sha256: "c".repeat(64),
                boot_primary_sha256: "d".repeat(64),
                nv_primary_sha256: "e".repeat(64),
                loader_input_sha256: "f".repeat(64),
                loader_decoded_sha256: "1".repeat(64),
                donor_sha256: "2".repeat(64),
                capacity_sectors: 61_071_360,
            };
            let mut sink = Journal::create(&dir.path().join("recovery.jsonl"), binding).unwrap();
            sink.restore_guard = Some(Guard::new(&primary, &[7; 1025]).unwrap());
            sink.fail_at = Some(fail_at);
            let sent = std::cell::Cell::new(0u64);
            let mut stopped = false;
            for step in &steps {
                if command(
                    &mut sink,
                    &AtomicBool::new(false),
                    step.stage,
                    &step.bytes,
                    step.storage,
                    || {
                        sent.set(sent.get() + 1);
                        Ok(())
                    },
                )
                .is_err()
                {
                    stopped = true;
                    break;
                }
            }
            assert!(stopped);
            assert_eq!(sent.get(), fail_at / 2);
            assert!(sink.retired);
        }
    }
}
