//! Experimental native Spec A controller. No browser or production capability
//! is enabled by this module. Source: pinned WPInternals 2.9.2, Rene Lergner, MIT.
//! A failed command never triggers a retry, fallback loader, rollback or reset.
use super::{
    device_binding::{self, Snapshot},
    mode_test::PhysicalPort,
    open_selected, usb_session, UsbMessages, PHONE_ACCESS,
};
use futures_core::Stream;
use nusb::hotplug::HotplugEvent;
#[cfg(windows)]
use nusb::MaybeFuture;
use serde::{Deserialize, Serialize};
mod driver_setup;
pub mod journal;
pub mod readiness;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use wpi_core::spec_a_session::{FlashSession, NormalSession, Prepared};
use wpi_image::spec_a::{entry_recovery, entry_snapshot, finish_plan};
use wpi_protocol::{
    flash, mode, preflight,
    qualcomm::{dload, v1},
    MessageTransport,
};
use wpi_types::{BootloaderFamily, DeviceMode};

pub const CONFIRMATION: &str = "RM875-EXPERIMENTAL-UNLOCK-WITHOUT-FULL-BACKUP";
pub const SETUP_CONFIRMATION: &str =
    "RM875-EXPERIMENTAL-ENTRY-BEFORE-DRIVER-SETUP-WITHOUT-FULL-BACKUP";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyAccess {
    #[default]
    ExistingBinding,
    ManualSetup,
}
impl EmergencyAccess {
    pub fn confirmation(self) -> &'static str {
        match self {
            Self::ExistingBinding => CONFIRMATION,
            Self::ManualSetup => SETUP_CONFIRMATION,
        }
    }
    fn admit(self, host: &readiness::Readiness) -> Result<(), String> {
        if !host.supported_experiment_host
            || !host.administrator_ready
            || (self == Self::ExistingBinding && !host.prerequisites_met)
        {
            return Err("Native unlock access prerequisites are missing; run native-unlock-readiness. No phone command was sent.".into());
        }
        Ok(())
    }
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn text<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Immutable local composition. Neither a report nor a completed replay admits
/// hardware execution. The native entry point also rechecks the physical phone.
pub struct Plan<'a> {
    prepared: &'a Prepared,
    finish: &'a finish_plan::Plan,
    donor: &'a [u8],
    secondary: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct Preview {
    pub preview_only: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
    pub profile: &'static str,
    pub source_ffu_sha256: String,
    pub package_sha256: String,
    pub donor_sha256: String,
    pub programmer_bytes: u64,
    pub first_pass_bytes: u64,
    pub secondary_gpt_bytes: usize,
    pub secondary_gpt_start_sector: u64,
    pub requires_native_windows_arm64: bool,
    pub requires_administrator: bool,
    pub emergency_access: EmergencyAccess,
    pub manual_setup_timeout_seconds_per_endpoint: Option<u64>,
    pub requires_offline_read_only_storage: bool,
    pub installed_flashapp_binary_verified: bool,
    pub installed_originals_captured: bool,
    pub data_preservation_validated: bool,
    pub hardware_validated: bool,
    pub automatic_resume_allowed: bool,
    pub actions: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}
impl<'a> Plan<'a> {
    pub fn new(
        prepared: &'a Prepared,
        finish: &'a finish_plan::Plan,
        donor: &'a [u8],
    ) -> Result<Self, String> {
        let a = prepared.artifacts();
        let f = finish.report();
        if a.source_ffu_sha256 != wpi_image::spec_a::entry_code::SOURCE_FFU
            || a.source_ffu_sha256 != f.source_ffu_sha256
            || a.package_sha256 != f.package_sha256
            || a.saved_primary_sha256 != f.saved_primary_sha256
            || a.candidate_primary_sha256 != f.expected_boot_primary_sha256
            || hash(finish.primary()) != f.nv_primary_sha256
        {
            return Err("Native finish, boot and entry plans must share the exact reviewed source and layout".into());
        }
        if donor.len() > 4 * 1024 * 1024
            || wpi_image::spec_a::efiesp::assess(Some(donor), None)
                .map_err(text)?
                .status
                != "original_supported"
        {
            return Err("A catalog-verified original supported donor boot file is required before any phone access".into());
        }
        let capacity = prepared.boot().report().layout.recorded_capacity_sectors;
        let secondary =
            entry_recovery::secondary_from_primary(finish.primary(), capacity).map_err(text)?;
        entry_snapshot::Plan::after_nv(finish.primary(), capacity, &f.nv_primary_sha256)
            .map_err(text)?;
        Ok(Self {
            prepared,
            finish,
            donor,
            secondary,
        })
    }
    fn capacity(&self) -> u64 {
        self.prepared
            .boot()
            .report()
            .layout
            .recorded_capacity_sectors
    }
    pub fn preview(&self) -> Preview {
        self.preview_with_access(EmergencyAccess::ExistingBinding)
    }
    pub fn preview_with_access(&self, access: EmergencyAccess) -> Preview {
        Preview {
            preview_only: true, phone_contacted: false, phone_writes_enabled: false,
            profile: "Lumia 1020 / RM-875 / 059T909 / 3051.50009.1451.1003 / experimental",
            source_ffu_sha256: self.prepared.artifacts().source_ffu_sha256.clone(),
            package_sha256: self.prepared.artifacts().package_sha256.clone(), donor_sha256: hash(self.donor),
            programmer_bytes: self.prepared.boot().report().total_transfer_bytes,
            first_pass_bytes: self.finish.nv_regions().iter().chain(self.finish.efiesp_regions())
                .map(|r| r.bytes().len() as u64).sum(),
            secondary_gpt_bytes: self.secondary.len(), secondary_gpt_start_sector: self.capacity() - 33,
            requires_native_windows_arm64: true, requires_administrator: true,
            emergency_access: access,
            manual_setup_timeout_seconds_per_endpoint: (access == EmergencyAccess::ManualSetup).then_some(driver_setup::TIMEOUT_SECONDS),
            requires_offline_read_only_storage: true, installed_flashapp_binary_verified: false,
            installed_originals_captured: false, data_preservation_validated: false,
            hardware_validated: false, automatic_resume_allowed: false,
            actions: vec![
                "Correlate Normal and Flash identities; read the installed primary GPT twice during return through BootManager; verify returning Normal.",
                "Re-enter Flash once and recheck identity, root fingerprint, capacity and protocol before emergency entry.",
                "Send one pinned FFU header and zero chunk, reboot, verify DLOAD root, upload one pinned programmer to RAM and start it.",
                "Write the ten immutable programmer regions, close and reboot; correlate the returning Flash identity and candidate GPT.",
                "Write the NV and first EFIESP pass, then reconstruct the reciprocal secondary GPT cleared by entry.",
                "Enter mass storage; require the same physical USB port, exact PnP ancestry, capacity, offline/read-only state and exclusive disk access.",
                "Save and reread a targeted current-state snapshot; prepare the second EFIESP pass from that installed capture.",
                "Request a manual restart; capture returning BootManager and select Flash with NOKS; recheck identity and GPT.",
                "Write the second EFIESP pass; capture mass storage again and require exact EFIESP readback.",
                "Request a manual restart; verify Flash identity, GPT and unlocked security evidence; reboot and verify the original Normal identity.",
            ],
            limitations: vec![
                "This experiment may leave the phone in emergency or recovery mode. No automatic retry or rollback is performed.",
                "The installed FlashApp binary and entry footprint have not been physically verified. A targeted snapshot after entry is not a pre-unlock or full userdata backup.",
                "No reset, full stock flash, MainOS patch, filesystem mounting or Data-partition write is planned. This does not guarantee data preservation.",
                "Qualcomm USB WinUSB binding, loader acceptance, NOKF acknowledgements and engineering-SBL3 storage behavior require hardware validation.",
                "Mass-storage disks must already be offline and read-only. This controller never changes host disk attributes or assigns drive letters.",
                "Optional upstream MainOS patching is not implemented; failure to boot ends in recovery-required state.",
                "Manual setup mode, if selected, permits storage-changing emergency entry before a historical binding exists. It waits for manual WinUSB setup on the observed 9008 endpoint, then continues after descriptor and protocol checks. No driver is installed automatically.",
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub source_ffu_sha256: String,
    pub package_sha256: String,
    pub saved_primary_sha256: String,
    pub boot_primary_sha256: String,
    pub nv_primary_sha256: String,
    pub loader_input_sha256: String,
    pub loader_decoded_sha256: String,
    pub donor_sha256: String,
    pub capacity_sectors: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u32,
    pub sequence: u64,
    pub kind: String,
    pub stage: String,
    pub request_sha256: Option<String>,
    pub request_bytes: usize,
    pub storage_start_bytes: Option<u64>,
    pub storage_payload_bytes: usize,
    pub binding_sha256: String,
    pub prepared_binding: Option<Binding>,
    pub storage_may_have_changed: bool,
    pub automatic_resume_allowed: bool,
}
struct Journal {
    file: File,
    sequence: u64,
    retired: bool,
    storage: bool,
    binding: Binding,
    binding_hash: String,
    #[cfg(test)]
    fail_at: Option<u64>,
}
impl Journal {
    fn create(path: &Path, binding: Binding) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(text)?;
        if !file.metadata().map_err(text)?.is_file() {
            return Err("Journal must be a new regular file".into());
        }
        file.sync_all().map_err(text)?;
        let binding_hash = hash(&serde_json::to_vec(&binding).map_err(text)?);
        Ok(Self {
            file,
            sequence: 0,
            retired: false,
            storage: false,
            binding,
            binding_hash,
            #[cfg(test)]
            fail_at: None,
        })
    }
    fn append(
        &mut self,
        kind: &'static str,
        stage: &str,
        bytes: Option<&[u8]>,
    ) -> Result<(), String> {
        if self.retired {
            return Err("Native journal retired after save failure".into());
        }
        let result = (|| {
            self.sequence += 1;
            #[cfg(test)]
            if self.fail_at == Some(self.sequence) {
                return Err("Injected journal save failure".into());
            }
            let (address, length) = bytes.map_or((None, 0), storage_range);
            let point = Record {
                schema: 1,
                sequence: self.sequence,
                kind: kind.into(),
                stage: stage.into(),
                request_sha256: bytes.map(hash),
                request_bytes: bytes.map_or(0, <[u8]>::len),
                storage_start_bytes: address,
                storage_payload_bytes: length,
                binding_sha256: self.binding_hash.clone(),
                prepared_binding: (kind == "prepared").then(|| self.binding.clone()),
                storage_may_have_changed: self.storage,
                automatic_resume_allowed: false,
            };
            let mut line = serde_json::to_vec(&point).map_err(text)?;
            if line.len() > 8192 {
                return Err("Native journal record exceeds bound".into());
            }
            line.push(b'\n');
            self.file.write_all(&line).map_err(text)?;
            self.file.flush().map_err(text)?;
            self.file.sync_all().map_err(text)
        })();
        self.retired |= result.is_err();
        result
    }
}
fn storage_range(bytes: &[u8]) -> (Option<u64>, usize) {
    if bytes.starts_with(b"NOKF") && bytes.len() >= 64 {
        (
            Some(u64::from(u32::from_be_bytes(bytes[11..15].try_into().unwrap())) * 512),
            bytes.len() - 64,
        )
    } else if bytes.first() == Some(&7) && bytes.len() >= 5 {
        (
            Some(u64::from(u32::from_le_bytes(
                bytes[1..5].try_into().unwrap(),
            ))),
            bytes.len() - 5,
        )
    } else {
        (None, 0)
    }
}

/// Actual outcome of this invocation only. It does not certify another phone,
/// firmware, host or browser, or turn a targeted capture into a userdata backup.
#[derive(Debug, Serialize)]
pub struct Report {
    pub native_controller_completed: bool,
    pub return_to_windows_verified: bool,
    pub second_pass_readback_verified: bool,
    pub unlocked_security_observed: bool,
    pub storage_may_have_changed: bool,
    pub data_preservation_validated: bool,
    pub hardware_validated: bool,
    pub automatic_resume_allowed: bool,
    pub journal_records: u64,
}

/// Execution is an explicit experimental action, distinct from preview and the
/// browser capability matrix. The confirmation acknowledges the missing original
/// backup and installed-binary evidence; callers must present `preview()` first.
/// A fresh journal and both fresh snapshot files are required. No resume API.
#[allow(clippy::too_many_arguments)]
pub fn run<F: FnMut(&str)>(
    id: &str,
    plan: &Plan<'_>,
    confirmation: &str,
    emergency_access: EmergencyAccess,
    journal: &Path,
    first_snapshot: &Path,
    final_snapshot: &Path,
    cancelled: &AtomicBool,
    mut progress: F,
) -> Result<Report, String> {
    if confirmation != emergency_access.confirmation() {
        return Err("Explicit experimental unlock confirmation is required".into());
    }
    if !cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        return Err("This initial native unlock experiment supports Windows ARM64 only".into());
    }
    wpi_storage::raw_access_prerequisite().map_err(text)?;
    emergency_access.admit(&readiness::inspect()?)?;
    validate_outputs([journal, first_snapshot, final_snapshot])?;
    // Test local output permissions before a USB interface or mode is touched.
    for output in [first_snapshot, final_snapshot] {
        let parent = output_parent(output)?;
        let probe = tempfile::NamedTempFile::new_in(parent).map_err(text)?;
        probe.as_file().sync_all().map_err(text)?;
    }
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let artifacts = plan.prepared.artifacts();
    let binding = Binding {
        source_ffu_sha256: artifacts.source_ffu_sha256.clone(),
        package_sha256: artifacts.package_sha256.clone(),
        saved_primary_sha256: artifacts.saved_primary_sha256.clone(),
        boot_primary_sha256: artifacts.candidate_primary_sha256.clone(),
        nv_primary_sha256: plan.finish.report().nv_primary_sha256.clone(),
        loader_input_sha256: artifacts.loader_input_sha256.clone(),
        loader_decoded_sha256: artifacts.loader_decoded_sha256.clone(),
        donor_sha256: hash(plan.donor),
        capacity_sectors: plan.capacity(),
    };
    let mut sink = Journal::create(journal, binding)?;
    sink.append(
        "prepared",
        "Experimental native plan; evidence flags remain unverified",
        None,
    )?;
    if emergency_access == EmergencyAccess::ManualSetup {
        sink.append(
            "manual_setup_selected",
            "Explicit first-time setup policy; entry before driver availability was acknowledged",
            None,
        )?;
    }
    let result = execute(
        id,
        plan,
        emergency_access,
        &mut sink,
        first_snapshot,
        final_snapshot,
        cancelled,
        &mut progress,
    );
    if let Err(error) = &result {
        let _ = sink.append("recovery_required", error, None);
        progress("Stopped. Inspect the phone and journal before any further command; no automatic recovery or retry was sent.");
    }
    result.map_err(|e| format!("{e}. Storage may have changed: {}. Inspect device state; no retry, reset, or rollback was sent.", sink.storage))
}
fn validate_outputs(paths: [&Path; 3]) -> Result<(), String> {
    let mut selected = HashSet::new();
    for path in paths {
        let parent = output_parent(path)?;
        let name = path.file_name().ok_or("Output must name a new file")?;
        let absolute = parent.canonicalize().map_err(text)?.join(name);
        // Windows filenames are normally case-insensitive. Reject collisions
        // conservatively on every host, including case-sensitive directories.
        let key = absolute.to_string_lossy().to_lowercase();
        if path.exists() || !selected.insert(key) {
            return Err("Journal and snapshot outputs must be three distinct NEW files".into());
        }
    }
    Ok(())
}
fn output_parent(path: &Path) -> Result<&Path, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err("Output parent is missing".into());
    }
    Ok(parent)
}

struct Channel {
    selected: Snapshot,
    transport: UsbMessages,
}
impl Channel {
    fn open(selected: &Snapshot) -> Result<Self, String> {
        validate(selected)?;
        let (_, transport) = open_selected(&selected.descriptor.id)?;
        validate(selected)?;
        Ok(Self {
            selected: selected.clone(),
            transport,
        })
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        validate(&self.selected)?;
        self.transport.send_once(bytes).map_err(text)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        validate(&self.selected)?;
        self.transport
            .session
            .exchange_flash(bytes, 65536, None)
            .map_err(text)
    }
}
impl MessageTransport for Channel {
    fn exchange(&mut self, bytes: &[u8], maximum: usize) -> wpi_protocol::Result<Vec<u8>> {
        validate(&self.selected).map_err(wpi_protocol::ProtocolError::Transport)?;
        self.transport.exchange(bytes, maximum)
    }
}
fn validate(selected: &Snapshot) -> Result<(), String> {
    let current = device_binding::scan()?;
    if current.iter().filter(|s| s.port == selected.port).count() != 1
        || current
            .iter()
            .filter(|s| s.descriptor.id == selected.descriptor.id)
            .count()
            != 1
        || !current.contains(selected)
    {
        return Err("USB identity or physical port changed or became ambiguous".into());
    }
    Ok(())
}
fn boundary(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        Err("Cancelled at a safe boundary; no next command sent".into())
    } else {
        Ok(())
    }
}

// The watch is armed BEFORE each mode command so rapid disconnects between
// inventory polls are retained. Each newly observed interface is queried once.
struct Watch {
    watch: nusb::hotplug::HotplugWatch,
    tracker: ArrivalTracker,
}
#[derive(Default)]
struct ArrivalTracker {
    removed: HashSet<String>,
    generation: HashMap<String, u64>,
    examined: HashSet<(String, u64)>,
    gone: bool,
}
impl ArrivalTracker {
    fn event(&mut self, id: String, removed: bool) -> Result<(), String> {
        if !self.generation.contains_key(&id) && self.generation.len() >= 256 {
            return Err("USB event inventory exceeds the session bound".into());
        }
        if removed {
            self.removed.insert(id.clone());
        }
        let generation = self.generation.entry(id).or_default();
        *generation = generation
            .checked_add(1)
            .ok_or("Hotplug generation overflow")?;
        Ok(())
    }
    fn observe(
        &mut self,
        all: &[Snapshot],
        source: &Snapshot,
        port: &PhysicalPort,
    ) -> Result<Option<Snapshot>, String> {
        self.gone |= self.removed.contains(&source.descriptor.id)
            || !all.iter().any(|s| s.descriptor.id == source.descriptor.id);
        let selected: Vec<_> = all
            .iter()
            .filter(|s| s.port.as_ref() == Some(port))
            .collect();
        if selected.len() > 1 {
            return Err("Ambiguous interfaces on the bound physical port".into());
        }
        if let [next] = selected.as_slice() {
            let generation = self
                .generation
                .get(&next.descriptor.id)
                .copied()
                .unwrap_or(0);
            if self.gone
                && self
                    .examined
                    .insert((next.descriptor.id.clone(), generation))
            {
                if next.descriptor.mode == DeviceMode::Unknown {
                    return Err("Unexpected device on the bound USB port".into());
                }
                return Ok(Some((*next).clone()));
            }
        }
        Ok(None)
    }
}
impl Watch {
    fn new() -> Result<Self, String> {
        Ok(Self {
            watch: nusb::watch_devices().map_err(text)?,
            tracker: ArrivalTracker::default(),
        })
    }
    fn drain(&mut self) -> Result<(), String> {
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..256 {
            match Pin::new(&mut self.watch).poll_next(&mut cx) {
                Poll::Ready(Some(HotplugEvent::Disconnected(id))) => {
                    self.tracker.event(format!("{id:?}"), true)?;
                }
                Poll::Ready(Some(HotplugEvent::Connected(info))) => {
                    self.tracker.event(format!("{:?}", info.id()), false)?;
                }
                Poll::Pending => return Ok(()),
                Poll::Ready(None) => return Err("Native hotplug observer ended".into()),
            }
        }
        Err("USB hotplug event flood".into())
    }
    fn wait<F: FnMut(&Snapshot, Option<&flash::FlashInfo>) -> Result<bool, String>>(
        &mut self,
        source: &Snapshot,
        port: &PhysicalPort,
        expected: DeviceMode,
        cancelled: &AtomicBool,
        mut inspect: F,
    ) -> Result<Snapshot, String> {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            boundary(cancelled)?;
            self.drain()?;
            let all = device_binding::scan()?;
            if let Some(next) = self.tracker.observe(&all, source, port)? {
                let info = if next.descriptor.mode == DeviceMode::Flash {
                    let mut channel = Channel::open(&next)?;
                    let (info, _) = preflight::parse_application(
                        &channel.exchange(b"NOKV", 65536).map_err(text)?,
                    )
                    .map_err(text)?;
                    Some(info)
                } else {
                    None
                };
                let actual = info.as_ref().map_or(next.descriptor.mode, |i| i.mode);
                let accepted = inspect(&next, info.as_ref())?;
                if Instant::now() >= deadline {
                    return Err("USB observation finished after its deadline".into());
                }
                if actual == expected && accepted {
                    return Ok(next);
                }
                if actual != DeviceMode::BootManager {
                    return Err("Unexpected arrival mode; no fallback command sent".into());
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err("Timed out awaiting the bound phone; no mode request was repeated".into())
    }
}

fn command<F: FnMut() -> Result<(), String>>(
    sink: &mut Journal,
    cancelled: &AtomicBool,
    stage: &str,
    request: &[u8],
    storage: bool,
    mut submit: F,
) -> Result<(), String> {
    boundary(cancelled)?;
    // A durable intent is already uncertain after a crash, even if OUT has not
    // begun. Advance the conservative flag BEFORE synchronizing the intent.
    sink.storage |= storage;
    sink.append("intent", stage, Some(request))?;
    boundary(cancelled)?;
    submit()?;
    sink.append("acknowledged_or_submitted", stage, Some(request))
}
fn switch(
    sink: &mut Journal,
    cancelled: &AtomicBool,
    source: &Snapshot,
    port: &PhysicalPort,
    target: DeviceMode,
    request: &[u8],
) -> Result<Snapshot, String> {
    let mut watch = Watch::new()?;
    let mut channel = Channel::open(source)?;
    command(
        sink,
        cancelled,
        "Mode request submitted once",
        request,
        false,
        || channel.send(request),
    )?;
    drop(channel);
    watch.wait(source, port, target, cancelled, |_, _| Ok(true))
}
fn check_flash(
    proof: &FlashSession<'_>,
    current: &Snapshot,
    expected_primary: Option<&[u8]>,
    capacity: u64,
    cancelled: &AtomicBool,
) -> Result<preflight::Observation, String> {
    let mut channel = Channel::open(current)?;
    let observation =
        proof.capture_current(&mut channel, false, |_| !cancelled.load(Ordering::Acquire))?;
    if observation.info.emmc_sectors.map(u64::from) != Some(capacity) {
        return Err("Flash capacity changed".into());
    }
    if let Some(primary) = expected_primary {
        // This is a distinct experimental post-programmer path. Do not loosen
        // the read-only preflight's conservative SS/opaque-tail GPT policy.
        if observation.security.platform_secure_boot {
            return Err("Flash remains locked; no GPT query or finish write permitted".into());
        }
        boundary(cancelled)?;
        let first =
            preflight::parse_primary_gpt(&channel.exchange(b"NOKT", 8 + 17408).map_err(text)?)
                .map_err(text)?;
        if first != primary {
            return Err("Fresh Flash primary differs from the expected active stage".into());
        }
        boundary(cancelled)?;
        let second =
            preflight::parse_primary_gpt(&channel.exchange(b"NOKT", 8 + 17408).map_err(text)?)
                .map_err(text)?;
        if second != primary {
            return Err("Flash GPT changed between reads".into());
        }
        let bookend =
            proof.capture_current(&mut channel, false, |_| !cancelled.load(Ordering::Acquire))?;
        if observation.security != bookend.security {
            return Err("Flash security evidence changed across GPT reads".into());
        }
    }
    Ok(observation)
}
fn enter_flash<'a>(
    normal: &Snapshot,
    baseline: NormalSession<'a>,
    port: &PhysicalPort,
    sink: &mut Journal,
    cancelled: &AtomicBool,
) -> Result<(Snapshot, FlashSession<'a>), String> {
    let request = mode::command(
        DeviceMode::Normal,
        DeviceMode::Flash,
        BootloaderFamily::SpecA,
        None,
    )
    .map_err(text)?
    .request;
    let next = switch(sink, cancelled, normal, port, DeviceMode::Flash, &request)?;
    let mut channel = Channel::open(&next)?;
    let proof = baseline.into_flash(&mut channel, |_| !cancelled.load(Ordering::Acquire))?;
    Ok((next, proof))
}

#[allow(clippy::too_many_arguments)]
fn execute<F: FnMut(&str)>(
    id: &str,
    plan: &Plan<'_>,
    emergency_access: EmergencyAccess,
    sink: &mut Journal,
    first_snapshot: &Path,
    final_snapshot: &Path,
    cancelled: &AtomicBool,
    progress: &mut F,
) -> Result<Report, String> {
    boundary(cancelled)?;
    progress("Read fresh Normal identity before the installed GPT capture cycle");
    let original = device_binding::selected(id)?;
    let port = original.port.clone().ok_or("Missing physical port")?;
    let (normal, _) =
        super::spec_a_session::capture_normal_bound(id, plan.prepared, cancelled, |_| {})?;
    let (first_flash, proof) = enter_flash(&original, normal, &port, sink, cancelled)?;
    // Capture a FRESH installed primary in the known transient BootManager
    // window and correlate the returning Normal ID before trusting the bytes.
    progress("Read installed GPT twice during the returning BootManager stage");
    let mut watch = Watch::new()?;
    let mut channel = Channel::open(&first_flash)?;
    command(
        sink,
        cancelled,
        "Return for fresh BootManager GPT",
        b"NOKR",
        false,
        || channel.send(b"NOKR"),
    )?;
    drop(channel);
    let mut captured = None;
    let returning = watch.wait(
        &first_flash,
        &port,
        DeviceMode::Normal,
        cancelled,
        |next, info| {
            if info.is_some_and(|i| i.mode == DeviceMode::BootManager) {
                if captured.is_some() {
                    return Err("Second BootManager cannot replace the first capture".into());
                }
                let mut channel = Channel::open(next)?;
                captured = Some(
                    wpi_core::boot_gpt::read(&mut channel, plan.capacity() as u32, |_| {
                        !cancelled.load(Ordering::Acquire)
                    })
                    .map_err(text)?,
                );
            }
            Ok(true)
        },
    )?;
    let (returned, _) = super::spec_a_session::capture_normal_bound(
        &returning.descriptor.id,
        plan.prepared,
        cancelled,
        |_| {},
    )?;
    let returned = proof.verify_return_for_continuation(returned)?;
    if captured.as_ref().map(|c| c.bytes()) != Some(plan.prepared.boot().original_primary()) {
        return Err(
            "Fresh installed GPT is absent or differs from the prepared layout; entry was not sent"
                .into(),
        );
    }
    sink.append(
        "verified",
        "Fresh installed GPT and original Normal identity match",
        None,
    )?;
    let (flash, proof) = enter_flash(&returning, returned, &port, sink, cancelled)?;
    check_flash(&proof, &flash, None, plan.capacity(), cancelled)?;
    progress("Entering emergency mode with the pinned header and zero chunk");
    let flash = emergency(
        plan,
        &flash,
        &port,
        sink,
        cancelled,
        progress,
        emergency_access,
    )?;
    check_flash(
        &proof,
        &flash,
        Some(plan.prepared.boot().candidate_primary()),
        plan.capacity(),
        cancelled,
    )?;
    progress("Write the first NV/EFIESP pass and reciprocal secondary GPT");
    write_regions(plan.finish.nv_regions(), &flash, sink, cancelled)?;
    write_regions(plan.finish.efiesp_regions(), &flash, sink, cancelled)?;
    write_sectors(
        (plan.capacity() - 33) as u32,
        &plan.secondary,
        &flash,
        sink,
        cancelled,
    )?;
    check_flash(
        &proof,
        &flash,
        Some(plan.finish.primary()),
        plan.capacity(),
        cancelled,
    )?;
    let storage = switch(
        sink,
        cancelled,
        &flash,
        &port,
        DeviceMode::MassStorage,
        b"NOKM",
    )?;
    progress("Capture USB-bound phone storage. It must already be offline/read-only; no host disk attributes are changed.");
    let first = capture(plan, &storage, first_snapshot, cancelled)?;
    let mut snapshot = wpi_core::artifacts::open_artifact(first_snapshot).map_err(text)?;
    let installed_efiesp =
        entry_snapshot::read_efiesp(&mut snapshot, &first.archive_sha256).map_err(text)?;
    let second = plan
        .finish
        .prepare_second_pass(
            plan.finish.primary(),
            &installed_efiesp,
            &hash(&installed_efiesp),
            plan.donor,
            |_, _| !cancelled.load(Ordering::Acquire),
        )
        .map_err(text)?;
    // Compute the exact expected final installed image before submitting a second
    // pass. Full image readback below, rather than ACKs, proves these bytes.
    let mut expected = installed_efiesp;
    overlay(&mut expected, plan.finish.primary(), second.regions())?;
    sink.append(
        "verified",
        "First USB-bound snapshot reread and second-pass image prepared",
        None,
    )?;
    let flash = manual_return(&storage, &port, sink, cancelled, progress)?;
    check_flash(
        &proof,
        &flash,
        Some(plan.finish.primary()),
        plan.capacity(),
        cancelled,
    )?;
    progress("Write the second EFIESP pass composed from the installed capture");
    write_regions(second.regions(), &flash, sink, cancelled)?;
    let storage = switch(
        sink,
        cancelled,
        &flash,
        &port,
        DeviceMode::MassStorage,
        b"NOKM",
    )?;
    let final_capture = capture(plan, &storage, final_snapshot, cancelled)?;
    let mut snapshot = wpi_core::artifacts::open_artifact(final_snapshot).map_err(text)?;
    if entry_snapshot::read_efiesp(&mut snapshot, &final_capture.archive_sha256).map_err(text)?
        != expected
    {
        return Err(
            "Final installed EFIESP readback differs; no return/reset command was sent".into(),
        );
    }
    sink.append(
        "verified",
        "Entire final installed EFIESP matches expected second-pass bytes",
        None,
    )?;
    let flash = manual_return(&storage, &port, sink, cancelled, progress)?;
    let observation = check_flash(
        &proof,
        &flash,
        Some(plan.finish.primary()),
        plan.capacity(),
        cancelled,
    )?;
    if observation.security.platform_secure_boot || observation.security.uefi_secure_boot {
        return Err(
            "Expected unlocked security evidence is absent; no success claim or automatic recovery"
                .into(),
        );
    }
    let normal = switch(sink, cancelled, &flash, &port, DeviceMode::Normal, b"NOKR")?;
    let (returned, _) = super::spec_a_session::capture_normal_bound(
        &normal.descriptor.id,
        plan.prepared,
        cancelled,
        |_| {},
    )?;
    proof.verify_return_session(returned)?;
    sink.append(
        "completed",
        "Second-pass readback, security observation and original Normal identity verified",
        None,
    )?;
    Ok(Report {
        native_controller_completed: true,
        return_to_windows_verified: true,
        second_pass_readback_verified: true,
        unlocked_security_observed: true,
        storage_may_have_changed: sink.storage,
        data_preservation_validated: false,
        hardware_validated: false,
        automatic_resume_allowed: false,
        journal_records: sink.sequence,
    })
}

#[allow(clippy::too_many_arguments)]
fn emergency<F: FnMut(&str)>(
    plan: &Plan<'_>,
    source: &Snapshot,
    port: &PhysicalPort,
    sink: &mut Journal,
    cancelled: &AtomicBool,
    progress: &mut F,
    emergency_access: EmergencyAccess,
) -> Result<Snapshot, String> {
    let mut channel = Channel::open(source)?;
    let header = flash::ffu_header_v1(plan.prepared.entry().header_bytes()).map_err(text)?;
    command(
        sink,
        cancelled,
        "Entry FFU header (backup GPT may be cleared)",
        &header,
        true,
        || flash::check_status(&channel.write(&header)?, b"NOKXFS").map_err(text),
    )?;
    let zero = flash::ffu_payload_v1(&vec![0; 128 * 1024], 0).map_err(text)?;
    command(sink, cancelled, "Entry zero payload", &zero, true, || {
        flash::check_status(&channel.write(&zero)?, b"NOKXFS").map_err(text)
    })?;
    let mut watch = Watch::new()?;
    command(sink, cancelled, "Entry reboot", b"NOKR", false, || {
        channel.send(b"NOKR")
    })?;
    drop(channel);
    let download = watch.wait(source, port, DeviceMode::Emergency, cancelled, |_, _| {
        Ok(true)
    })?;
    if emergency_access == EmergencyAccess::ManualSetup {
        driver_setup::wait(&download, sink, cancelled, progress)?;
    }
    let mut io = super::emergency_probe::open_bound(&download)?;
    let framed = |io: &mut usb_session::Session<usb_session::NativeIo>,
                  selected: &Snapshot,
                  bytes: &[u8]| {
        boundary(cancelled)?;
        validate(selected)?;
        io.exchange_framed(bytes, v1::MAX_REPLY_FRAME, None)
            .map_err(text)
    };
    progress("Verify the emergency root before uploading exactly one loader");
    let alive = framed(&mut io, &download, &dload::alive().map_err(text)?)?;
    dload::check_ack(&alive).map_err(text)?;
    let root = framed(&mut io, &download, &dload::root_key().map_err(text)?)?;
    if dload::parse_root(&root).map_err(text)? != *plan.prepared.reference().root() {
        return Err("Emergency root fingerprint differs; no loader was uploaded".into());
    }
    for (index, bytes) in plan
        .prepared
        .loader()
        .decoded_bytes()
        .chunks(dload::MAX_MEMORY_BYTES)
        .enumerate()
    {
        let address = dload::LOADER_ADDRESS + (index * dload::MAX_MEMORY_BYTES) as u32;
        let request = dload::memory(address, bytes).map_err(text)?;
        command(sink, cancelled, "DLOAD RAM upload", &request, false, || {
            dload::check_ack(&framed(&mut io, &download, &request)?).map_err(text)
        })?;
    }
    let mut watch = Watch::new()?;
    let start = dload::start(dload::LOADER_ADDRESS).map_err(text)?;
    command(
        sink,
        cancelled,
        "Start one pinned loader",
        &start,
        false,
        || dload::check_ack(&framed(&mut io, &download, &start)?).map_err(text),
    )?;
    drop(io);
    let programmer = watch.wait(&download, port, DeviceMode::Emergency, cancelled, |_, _| {
        Ok(true)
    })?;
    if emergency_access == EmergencyAccess::ManualSetup {
        driver_setup::wait(&programmer, sink, cancelled, progress)?;
    }
    let mut io = super::emergency_probe::open_bound(&programmer)?;
    progress("Send immutable programmer regions; stop on any invalid or missing acknowledgement");
    for (stage, request, ack) in [
        ("Programmer hello", v1::hello(), v1::Ack::Hello),
        (
            "Programmer security mode",
            v1::SECURITY_MODE_ZERO.to_vec(),
            v1::Ack::SecurityMode,
        ),
        (
            "Programmer open boot partition",
            v1::OPEN_BOOT_PARTITION.to_vec(),
            v1::Ack::Open,
        ),
    ] {
        command(sink, cancelled, stage, &request, false, || {
            v1::check_ack(&framed(&mut io, &programmer, &request)?, ack).map_err(text)
        })?;
    }
    for region in plan.prepared.boot().regions() {
        for (index, bytes) in region.bytes().chunks(v1::MAX_WRITE_BYTES).enumerate() {
            let address = region.start_bytes() + (index * v1::MAX_WRITE_BYTES) as u32;
            let request = v1::write(address, bytes).map_err(text)?;
            command(
                sink,
                cancelled,
                "Programmer boot write",
                &request,
                true,
                || {
                    v1::check_ack(
                        &framed(&mut io, &programmer, &request)?,
                        v1::Ack::Write(address),
                    )
                    .map_err(text)
                },
            )?;
        }
    }
    command(
        sink,
        cancelled,
        "Programmer close",
        v1::CLOSE_PARTITION,
        false,
        || {
            v1::check_ack(
                &framed(&mut io, &programmer, v1::CLOSE_PARTITION)?,
                v1::Ack::Close,
            )
            .map_err(text)
        },
    )?;
    let mut watch = Watch::new()?;
    command(
        sink,
        cancelled,
        "Programmer reboot",
        v1::REBOOT,
        false,
        || v1::check_ack(&framed(&mut io, &programmer, v1::REBOOT)?, v1::Ack::Reboot).map_err(text),
    )?;
    drop(io);
    wait_flash(&mut watch, &programmer, port, sink, cancelled)
}

fn wait_flash(
    watch: &mut Watch,
    source: &Snapshot,
    port: &PhysicalPort,
    sink: &mut Journal,
    cancelled: &AtomicBool,
) -> Result<Snapshot, String> {
    let mut selected_boot = false;
    watch.wait(source, port, DeviceMode::Flash, cancelled, |next, info| {
        if let Some(info) = info.filter(|i| i.mode == DeviceMode::BootManager) {
            wpi_core::boot_gpt::validate_info(info).map_err(text)?;
            if selected_boot {
                return Err("A second BootManager cannot trigger another NOKS".into());
            }
            selected_boot = true;
            let mut channel = Channel::open(next)?;
            command(
                sink,
                cancelled,
                "Select Flash from returning BootManager",
                b"NOKS",
                false,
                || channel.send(b"NOKS"),
            )?;
        }
        Ok(true)
    })
}
fn manual_return<F: FnMut(&str)>(
    storage: &Snapshot,
    port: &PhysicalPort,
    sink: &mut Journal,
    cancelled: &AtomicBool,
    progress: &mut F,
) -> Result<Snapshot, String> {
    // No speculative serial reboot: old/new mass-storage commands differ and
    // serial parent mapping is not interchangeable with USB WinUSB ownership.
    let mut watch = Watch::new()?;
    sink.append(
        "awaiting_manual_restart",
        "All disk handles closed; Volume Down + Power restart required",
        None,
    )?;
    progress("Snapshot verified and disk handles closed. Hold Volume Down + Power until vibration now; leave USB connected. Waiting up to 120 seconds.");
    wait_flash(&mut watch, storage, port, sink, cancelled)
}
fn write_regions(
    regions: &[finish_plan::Region],
    selected: &Snapshot,
    sink: &mut Journal,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    for region in regions {
        write_sectors(
            region.start_sector(),
            region.bytes(),
            selected,
            sink,
            cancelled,
        )?;
    }
    Ok(())
}
fn write_sectors(
    start: u32,
    bytes: &[u8],
    selected: &Snapshot,
    sink: &mut Journal,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    let mut channel = Channel::open(selected)?;
    for (index, chunk) in bytes.chunks(2 * 1024 * 1024).enumerate() {
        let sector = u32::try_from(u64::from(start) + index as u64 * 4096).map_err(text)?;
        let request = flash::sectors_v1(sector, chunk, 0).map_err(text)?;
        command(
            sink,
            cancelled,
            "Flash sector write",
            &request,
            true,
            || flash::sectors_v1_status(&channel.write(&request)?).map_err(text),
        )?;
    }
    Ok(())
}
fn capture(
    plan: &Plan<'_>,
    storage: &Snapshot,
    output: &Path,
    cancelled: &AtomicBool,
) -> Result<entry_snapshot::Report, String> {
    boundary(cancelled)?;
    validate(storage)?;
    #[cfg(windows)]
    {
        let infos: Vec<_> = nusb::list_devices()
            .wait()
            .map_err(text)?
            .filter(|i| format!("{:?}", i.id()) == storage.descriptor.id)
            .collect();
        let [info] = infos.as_slice() else {
            return Err("Mass-storage USB instance is absent or ambiguous".into());
        };
        if Snapshot::of(info) != *storage {
            return Err("Mass-storage USB instance changed".into());
        }
        let instance = info
            .instance_id()
            .to_str()
            .ok_or("Unsupported USB instance encoding")?;
        let report = wpi_storage::capture_spec_a_bound(
            instance,
            plan.capacity(),
            plan.finish.primary(),
            true,
            output,
            |_, _, _| !cancelled.load(Ordering::Acquire),
        )
        .map_err(text)?;
        validate(storage)?;
        Ok(report)
    }
    #[cfg(not(windows))]
    {
        let _ = (plan, output);
        Err("Windows USB ancestry binding is required".into())
    }
}
fn overlay(
    efiesp: &mut [u8],
    primary: &[u8],
    regions: &[finish_plan::Region],
) -> Result<(), String> {
    let gpt = wpi_image::gpt::Gpt::from_parts(&primary[512..1024], &primary[1024..], None)
        .map_err(text)?;
    let partition = gpt.partition("EFIESP").map_err(text)?;
    if efiesp.len() as u64 != partition.byte_range().map_err(text)?.1 {
        return Err("Captured EFIESP size changed".into());
    }
    for region in regions {
        let offset = u64::from(region.start_sector())
            .checked_sub(partition.first_sector)
            .and_then(|v| v.checked_mul(512))
            .ok_or("EFIESP overlay address underflow")?;
        let end = offset
            .checked_add(region.bytes().len() as u64)
            .ok_or("EFIESP overlay overflow")?;
        let target = efiesp
            .get_mut(offset as usize..end as usize)
            .ok_or("EFIESP overlay exceeds partition")?;
        target.copy_from_slice(region.bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, sync::atomic::AtomicBool};
    #[test]
    fn manual_setup_changes_only_historical_binding_admission_and_confirmation() {
        let mut host = readiness::Readiness {
            supported_experiment_host: true,
            administrator_ready: true,
            known_emergency_endpoint_count: 0,
            known_winusb_bindings: 0,
            usable_winusb_bindings: 0,
            present_emergency_endpoint_count: 0,
            endpoints: vec![],
            prerequisites_met: false,
            phone_contacted: false,
            driver_changes_sent: false,
            hardware_validated: false,
            messages: vec![],
        };
        assert_eq!(EmergencyAccess::default(), EmergencyAccess::ExistingBinding);
        assert!(EmergencyAccess::ExistingBinding.admit(&host).is_err());
        assert!(EmergencyAccess::ManualSetup.admit(&host).is_ok());
        assert_ne!(EmergencyAccess::ManualSetup.confirmation(), CONFIRMATION);
        host.administrator_ready = false;
        assert!(EmergencyAccess::ManualSetup.admit(&host).is_err());
        host.administrator_ready = true;
        host.supported_experiment_host = false;
        assert!(EmergencyAccess::ManualSetup.admit(&host).is_err());
    }
    pub(super) fn binding() -> Binding {
        Binding {
            source_ffu_sha256: hash(b"ffu"),
            package_sha256: hash(b"zip"),
            saved_primary_sha256: hash(b"old"),
            boot_primary_sha256: hash(b"boot"),
            nv_primary_sha256: hash(b"nv"),
            loader_input_sha256: hash(b"hex"),
            loader_decoded_sha256: hash(b"loader"),
            donor_sha256: hash(b"donor"),
            capacity_sectors: 10000,
        }
    }
    #[test]
    fn journal_orders_intent_before_submission_and_validated_ack_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stage.jsonl");
        let mut journal = Journal::create(&path, binding()).unwrap();
        journal.append("prepared", "Inputs pinned", None).unwrap();
        let packet = flash::sectors_v1(120, &[7; 512], 0).unwrap();
        command(
            &mut journal,
            &AtomicBool::new(false),
            "sector write",
            &packet,
            true,
            || {
                let text = std::fs::read_to_string(&path).unwrap();
                let records: Vec<serde_json::Value> = text
                    .lines()
                    .map(|s| serde_json::from_str(s).unwrap())
                    .collect();
                assert_eq!(records.len(), 2);
                assert_eq!(records[1]["kind"], "intent");
                assert_eq!(records[1]["storage_start_bytes"], 120 * 512);
                assert_eq!(records[1]["storage_payload_bytes"], 512);
                assert_eq!(records[1]["storage_may_have_changed"], true);
                Ok(())
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["kind"], "acknowledged_or_submitted");
        assert_eq!(records[1]["request_sha256"], records[2]["request_sha256"]);
        assert_eq!(records[0]["binding_sha256"], records[2]["binding_sha256"]);
        assert!(records[0]["prepared_binding"].is_object());
        assert!(records[2]["prepared_binding"].is_null());
        assert!(!text.contains("PRIVATE-ID"));
        assert!(Journal::create(&path, binding()).is_err());
    }
    #[test]
    fn every_intent_ack_fault_and_cancellation_stops_before_followup_submission() {
        for fail_at in 1..=8 {
            let dir = tempfile::tempdir().unwrap();
            let mut journal = Journal::create(&dir.path().join("fault.jsonl"), binding()).unwrap();
            journal.fail_at = Some(fail_at);
            let submitted = Cell::new(0);
            let result: Result<(), String> = (|| {
                for _ in 0..4 {
                    command(
                        &mut journal,
                        &AtomicBool::new(false),
                        "write",
                        b"packet",
                        true,
                        || {
                            submitted.set(submitted.get() + 1);
                            Ok(())
                        },
                    )?;
                }
                Ok(())
            })();
            assert!(result.is_err());
            assert_eq!(submitted.get(), fail_at / 2);
            assert!(journal.retired);
            assert!(command(
                &mut journal,
                &AtomicBool::new(false),
                "sentinel",
                b"x",
                true,
                || panic!("Retired journal must stop before transport")
            )
            .is_err());
        }
        for fail_command in 0..4 {
            for reason in [
                "timeout",
                "partial OUT",
                "disconnect",
                "wrong ACK",
                "short ACK",
            ] {
                let dir = tempfile::tempdir().unwrap();
                let mut journal =
                    Journal::create(&dir.path().join("fault.jsonl"), binding()).unwrap();
                let mut submitted = 0;
                let result: Result<(), String> = (|| {
                    for index in 0..4 {
                        command(
                            &mut journal,
                            &AtomicBool::new(false),
                            "write",
                            b"packet",
                            true,
                            || {
                                submitted += 1;
                                if index == fail_command {
                                    Err(reason.into())
                                } else {
                                    Ok(())
                                }
                            },
                        )?;
                    }
                    Ok(())
                })();
                assert!(result.is_err());
                assert_eq!(submitted, fail_command + 1);
                assert!(journal.storage);
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create(&dir.path().join("cancel.jsonl"), binding()).unwrap();
        let cancelled = AtomicBool::new(true);
        assert!(
            command(&mut journal, &cancelled, "cancel", b"x", true, || panic!(
                "Cancelled command cannot reach transport"
            ))
            .is_err()
        );
        assert_eq!(journal.sequence, 0);
        assert!(!journal.storage);
    }
    #[test]
    fn cancellation_after_ack_never_submits_the_next_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create(&dir.path().join("cancel.jsonl"), binding()).unwrap();
        let cancelled = AtomicBool::new(false);
        command(&mut journal, &cancelled, "write", b"x", true, || {
            cancelled.store(true, Ordering::Release);
            Ok(())
        })
        .unwrap();
        assert!(
            command(&mut journal, &cancelled, "sentinel", b"y", true, || panic!(
                "No next command"
            ))
            .is_err()
        );
        assert_eq!(journal.sequence, 2);
    }
    #[test]
    fn aliased_existing_and_case_colliding_output_paths_fail_before_usb() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.zip");
        let b = dir.path().join("b.zip");
        let c = dir.path().join("c.jsonl");
        validate_outputs([&a, &b, &c]).unwrap();
        let alias = dir.path().join(".").join("a.zip");
        assert!(validate_outputs([&a, &alias, &c]).is_err());
        let upper = dir.path().join("A.ZIP");
        assert!(validate_outputs([&a, &upper, &c]).is_err());
        std::fs::write(&a, b"preserve me").unwrap();
        assert!(validate_outputs([&a, &b, &c]).is_err());
        assert_eq!(std::fs::read(&a).unwrap(), b"preserve me");
    }
    #[test]
    fn byte_address_journal_distinguishes_v1_programmer_and_sector_protocol() {
        assert_eq!(
            storage_range(&v1::write(12345, &[1; 10]).unwrap()),
            (Some(12345), 10)
        );
        assert_eq!(
            storage_range(&flash::sectors_v1(12345, &[1; 512], 0).unwrap()),
            (Some(12345 * 512), 512)
        );
        assert_eq!(storage_range(b"NOKR"), (None, 0));
    }
    fn endpoint(id: &str, mode: DeviceMode) -> Snapshot {
        let port = {
            #[cfg(windows)]
            {
                PhysicalPort::Windows {
                    hub: "SYNTHETIC-HUB".into(),
                    number: 1,
                }
            }
            #[cfg(not(windows))]
            {
                PhysicalPort::Native {
                    bus: "SYNTHETIC-BUS".into(),
                    chain: vec![1],
                }
            }
        };
        Snapshot {
            port: Some(port),
            descriptor: wpi_types::DeviceIdentity {
                id: id.into(),
                vendor_id: 0x0421,
                product_id: 0x066e,
                manufacturer: None,
                product: None,
                serial: None,
                model: None,
                variant: None,
                firmware: None,
                platform_id: None,
                family: BootloaderFamily::SpecA,
                mode,
                interfaces: vec![],
            },
        }
    }
    #[test]
    fn observer_requires_removal_and_does_not_requery_retired_interfaces_on_unrelated_events() {
        let source = endpoint("normal", DeviceMode::Normal);
        let boot = endpoint("boot", DeviceMode::Flash);
        let port = source.port.as_ref().unwrap();
        let mut tracker = ArrivalTracker::default();
        assert!(tracker
            .observe(std::slice::from_ref(&source), &source, port)
            .unwrap()
            .is_none());
        assert!(tracker.observe(&[], &source, port).unwrap().is_none());
        assert!(tracker
            .observe(std::slice::from_ref(&boot), &source, port)
            .unwrap()
            .is_some());
        tracker.event("unrelated keyboard".into(), true).unwrap();
        tracker.event("unrelated keyboard".into(), false).unwrap();
        assert!(tracker
            .observe(std::slice::from_ref(&boot), &source, port)
            .unwrap()
            .is_none());
        // Windows can reuse the same ID after an actual disconnect/reconnect.
        tracker.event("boot".into(), true).unwrap();
        tracker.event("boot".into(), false).unwrap();
        assert!(tracker
            .observe(std::slice::from_ref(&boot), &source, port)
            .unwrap()
            .is_some());
        assert!(tracker
            .observe(std::slice::from_ref(&boot), &source, port)
            .unwrap()
            .is_none());
    }
    #[test]
    fn observer_rejects_unknown_and_ambiguous_same_port_devices_and_bounds_hotplug_floods() {
        let source = endpoint("normal", DeviceMode::Normal);
        let port = source.port.as_ref().unwrap();
        for candidates in [
            vec![endpoint("unexpected", DeviceMode::Unknown)],
            vec![
                endpoint("a", DeviceMode::Flash),
                endpoint("b", DeviceMode::Flash),
            ],
        ] {
            assert!(ArrivalTracker::default()
                .observe(&candidates, &source, port)
                .is_err());
        }
        let mut tracker = ArrivalTracker::default();
        for i in 0..256 {
            tracker.event(format!("id-{i}"), true).unwrap();
        }
        assert!(tracker.event("overflow".into(), true).is_err());
    }
}
