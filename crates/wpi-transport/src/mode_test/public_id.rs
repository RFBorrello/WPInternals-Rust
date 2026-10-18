//! Separate CLI-only public-ID validation experiment; the original serial-only test stays blocked.
use super::*;
use wpi_protocol::{identity as public_identity, MessageTransport};

pub const CONFIRMATION: &str = "RM875-PUBLIC-ID-ROUNDTRIP";
pub const EXPERIMENT: &str = "rm875_public_id_normal_flash_normal";
const FLASH_PLATFORM: &str = "Nokia.MSM8960.P5217.3.2.1";
const NORMAL_RECONNECT_LIMIT: Duration = Duration::from_secs(90);
// Hotplug is a hint: Windows arrivals can precede descriptor availability.
// Rediscovery must not repeat protocol queries to a retired boot interface.
const REDISCOVERY_INTERVAL: Duration = Duration::from_secs(2);
pub const PREFLIGHT_CONFIRMATION: &str = "RM875-READONLY-PREFLIGHT-ROUNDTRIP";
pub const PREFLIGHT_EXPERIMENT: &str = "rm875_normal_flash_preflight_normal";
pub const GPT_CONFIRMATION: &str = "RM875-BOOT-GPT-READ-ROUNDTRIP";
pub const GPT_EXPERIMENT: &str = "rm875_flash_preflight_boot_primary_gpt_normal";
pub const PREPARED_CONFIRMATION: &str = "RM875-PREPARED-READONLY-ROUNDTRIP";
pub const PREPARED_EXPERIMENT: &str = "rm875_prepared_normal_flash_normal";

#[derive(Debug, Serialize)]
pub struct Preview {
    pub experiment: &'static str,
    pub device: DeviceIdentity,
    pub eligible_for_experiment: bool,
    pub blockers: Vec<String>,
    pub public_id_available: bool,
    pub public_id_bytes_exported: bool,
    pub physical_port_binding_available: bool,
    pub hotplug_watch_available: bool,
    pub actions: Vec<&'static str>,
    pub confirmation_phrase: &'static str,
    pub flash_firmware_query_included: bool,
    pub flash_reconnect_timeout_seconds: u64,
    pub normal_reconnect_timeout_seconds: u64,
    pub production_mode_switching_available: bool,
    pub recovery_authorized: bool,
}
#[derive(Clone)]
struct Snapshot {
    probe: ProbeResult,
    public_id: public_identity::PublicId,
}
enum Observation {
    Identity(Snapshot),
    Boot(ProbeResult),
}
#[derive(Debug, Serialize)]
pub struct Summary {
    pub result: &'static str,
    pub mode_commands_attempted: u8,
    pub normal_reconnection: ReconnectReport,
    pub public_id_matched_in_both_modes: bool,
    pub identity_authenticated: bool,
    pub recovery_authorized: bool,
    pub spec_a_preflight_completed: bool,
    pub primary_gpt: Option<wpi_core::boot_gpt::Report>,
    pub prepared_session: Option<wpi_core::spec_a_session::Report>,
}
#[derive(Debug, Serialize)]
pub struct PreflightPreview {
    pub mode_test: Preview,
    pub reference: wpi_core::spec_a_preflight::ReferenceSummary,
    pub gpt_query_included: bool,
    pub phone_writes_enabled: bool,
}
#[derive(Debug, Serialize)]
pub struct SecurityDiagnostic {
    pub info: wpi_protocol::flash::FlashInfo,
    pub security_blocks: Vec<wpi_protocol::preflight::SecurityBlockDiagnostic>,
    pub response_length: usize,
    pub mode_changes_sent: bool,
    pub phone_writes_enabled: bool,
}
/// One fixed, read-only NOKV query on an already exposed reviewed FlashApp.
/// This never resumes a stopped experiment or sends its pending return command.
pub fn security_diagnostic(id: &str) -> Result<SecurityDiagnostic, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let selected = enumerate()?
        .into_iter()
        .find(|d| d.id == id)
        .ok_or("Selected phone disconnected")?;
    if selected.mode != DeviceMode::Flash {
        return Err(
            "Diagnostic requires an already exposed Flash interface; no mode change is sent".into(),
        );
    }
    let (mut device, mut transport) = open_selected(id)?;
    transport.deadline = Some(Instant::now() + Duration::from_secs(20));
    let response = transport
        .exchange(b"NOKV", 65536)
        .map_err(|e| e.to_string())?;
    let info = wpi_protocol::flash::parse_info(&response).map_err(|e| e.to_string())?;
    device.mode = info.mode;
    device.platform_id = info.platform_id.clone();
    validate_flash(&ProbeResult {
        device,
        info: Some(info.clone()),
        normal: None,
        firmware: None,
    })?;
    Ok(SecurityDiagnostic {
        info,
        security_blocks: wpi_protocol::preflight::security_block_diagnostics(&response)
            .map_err(|e| e.to_string())?,
        response_length: response.len(),
        mode_changes_sent: false,
        phone_writes_enabled: false,
    })
}

fn read_snapshot<T: MessageTransport>(
    device: DeviceIdentity,
    transport: &mut T,
) -> Result<Snapshot, String> {
    match read_observation(device, transport, false)? {
        Observation::Identity(snapshot) => Ok(snapshot),
        Observation::Boot(_) => {
            Err("An unverified boot observation cannot permit a command".into())
        }
    }
}
fn read_observation<T: MessageTransport>(
    device: DeviceIdentity,
    transport: &mut T,
    allow_boot: bool,
) -> Result<Observation, String> {
    let (probe, public_id) = match device.mode {
        DeviceMode::Normal => {
            let normal = wpi_protocol::normal::read_info(transport)
                .map_err(|e| format!("Normal information probe failed: {e}"))?;
            let mut device = device;
            wpi_core::profiles::apply_variant(
                &mut device,
                normal
                    .manufacturer_model
                    .split('_')
                    .next()
                    .unwrap_or_default(),
            );
            device.firmware = Some(normal.firmware.clone());
            let public_id = public_identity::read_normal(transport, 4)
                .map_err(|e| format!("Normal public-ID query failed: {e}"))?;
            (
                ProbeResult {
                    firmware: device.firmware.clone(),
                    device,
                    info: None,
                    normal: Some(normal),
                },
                public_id,
            )
        }
        DeviceMode::Flash => {
            let info = wpi_protocol::flash::read_info(transport)
                .map_err(|e| format!("NOKV information query failed: {e}"))?;
            let mut device = device;
            device.mode = info.mode;
            device.platform_id = info.platform_id.clone();
            let probe = ProbeResult {
                device,
                info: Some(info),
                normal: None,
                firmware: None,
            };
            if allow_boot
                && probe.device.vendor_id == 0x0421
                && probe.device.product_id == 0x066e
                && probe.device.mode == DeviceMode::BootManager
                && probe
                    .info
                    .as_ref()
                    .is_some_and(|i| matches!(i.protocol_major, 1 | 2))
            {
                // Only after NOKR: observation cannot permit a terminal query, reset or context switch.
                return Ok(Observation::Boot(probe));
            }
            validate_flash(&probe)?; // No terminal query to an unexpected application/profile.
            let response = transport
                .exchange(&public_identity::flash_request(), 65536)
                .map_err(|e| format!("Terminal identity transfer failed: {e}"))?;
            let public_id = public_identity::parse_flash(&response).map_err(|e| {
                // Never expose arbitrary leading payload bytes as a supposed signature.
                let signature = ["NOKXFT", "NOKXFR", "NOKU", "NOKV", "NOKX"]
                    .into_iter().find(|s| response.starts_with(s.as_bytes())).unwrap_or("unrecognized");
                format!("Terminal identity query failed: {e}; response_length={}; signature={signature}",response.len())
            })?;
            (probe, public_id)
        }
        _ => {
            return Err(
                "Only Normal and the reviewed FlashApp are accepted; no context switch is sent"
                    .into(),
            )
        }
    };
    Ok(Observation::Identity(Snapshot { probe, public_id }))
}
fn validate_flash(probe: &ProbeResult) -> Result<(), String> {
    let d = &probe.device;
    let info = probe.info.as_ref().ok_or("FlashApp information missing")?;
    if d.mode != DeviceMode::Flash
        || d.vendor_id != 0x0421
        || d.product_id != 0x066e
        || info.mode != DeviceMode::Flash
        || (info.protocol_major, info.protocol_minor) != (1, 18)
        || (info.version_major, info.version_minor) != (2, 2)
        || d.platform_id.as_deref() != Some(FLASH_PLATFORM)
        || info.platform_id.as_deref() != Some(FLASH_PLATFORM)
    {
        return Err(format!("Unexpected FlashApp, USB identity, protocol/version or full platform; observed_mode={:?}, protocol={}.{}, application={}.{}, platform_matches={}; no terminal query or mode command is permitted",info.mode,info.protocol_major,info.protocol_minor,info.version_major,info.version_minor,d.platform_id.as_deref()==Some(FLASH_PLATFORM) && info.platform_id.as_deref()==Some(FLASH_PLATFORM)));
    }
    Ok(())
}
fn descriptor_allowed(d: &DeviceIdentity, serial: &str, port_matches: bool) -> Result<(), String> {
    if !port_matches {
        return Err(
            "Physical USB port is missing or different; no query or mode command is permitted"
                .into(),
        );
    }
    let observed = d.serial.as_deref().filter(|s| !s.trim().is_empty());
    match d.mode {
        DeviceMode::Normal if observed == Some(serial) && d.vendor_id == 0x0421 && d.product_id == 0x0661 => Ok(()),
        DeviceMode::Flash if d.vendor_id == 0x0421 && d.product_id == 0x066e && observed.is_none_or(|s| s == serial) => Ok(()),
        _ => Err("Returning USB mode/IDs or available serial contradict the baseline; no query or mode command is permitted".into()),
    }
}
fn validate(snapshot: &Snapshot, baseline: &Snapshot, mode: DeviceMode) -> Result<(), String> {
    let d = &snapshot.probe.device;
    if snapshot.public_id != baseline.public_id {
        return Err(
            "Public ID contradicts the selected phone; no mode command is permitted".into(),
        );
    }
    descriptor_allowed(
        d,
        baseline
            .probe
            .device
            .serial
            .as_deref()
            .ok_or("Baseline USB serial missing")?,
        true,
    )?;
    if d.mode != mode {
        return Err("Unexpected freshly observed application mode".into());
    }
    if mode == DeviceMode::Normal {
        if wpi_core::reconnect::compare(&baseline.probe.device, d, mode).status
            != ReconnectStatus::Correlated
        {
            return Err(
                "Fresh Normal identity, firmware or USB serial contradicts the baseline".into(),
            );
        }
        if !admission(d, true).is_empty() {
            return Err("Fresh Normal admission profile changed".into());
        }
    } else {
        validate_flash(&snapshot.probe)?;
        // Never discard a contradiction if a future adapter supplies these fields.
        let comparison = wpi_core::reconnect::compare(&baseline.probe.device, d, mode);
        if comparison.status == ReconnectStatus::Mismatch {
            return Err("Fresh Flash identity contradicts available baseline fields".into());
        }
    }
    Ok(())
}

pub fn preview(id: &str) -> Result<Preview, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let devices = enumerate()?;
    let selected = devices
        .iter()
        .find(|d| d.id == id)
        .ok_or("Selected phone is disconnected")?;
    if selected.mode != DeviceMode::Normal {
        return Err("Preview requires Normal mode".into());
    }
    let port = port_available(id)?;
    let (device, mut transport) = open_selected(id)?;
    transport.deadline = Some(Instant::now() + Duration::from_secs(20));
    let baseline = read_snapshot(device, &mut transport)?;
    let mut blockers = admission(
        &baseline.probe.device,
        cfg!(all(target_os = "windows", target_arch = "aarch64")),
    );
    if devices.len() != 1 {
        blockers.push("Connect only the selected Lumia".into());
    }
    if !port {
        blockers.push("Physical USB port binding unavailable".into());
    }
    let hotplug = nusb::watch_devices().is_ok();
    if !hotplug {
        blockers.push("Native hotplug watch unavailable".into());
    }
    Ok(Preview {
        experiment: EXPERIMENT,
        device: redact(baseline.probe.device),
        eligible_for_experiment: blockers.is_empty(),
        blockers,
        public_id_available: true,
        public_id_bytes_exported: false,
        physical_port_binding_available: port,
        hotplug_watch_available: hotplug,
        actions: vec![
            "Fresh Normal model/firmware/serial/public-ID admission",
            "Send SetDeviceMode(Flash, HwReset) once",
            "Require removal, one arrival on the same physical port and matching public ID",
            "Require exact FlashApp 2.2 / protocol 1.18 / Nokia.MSM8960.P5217.3.2.1",
            "Re-read identity on the command handle before NOKR once",
            "Require fresh Normal serial, model, firmware and public-ID equality",
        ],
        confirmation_phrase: CONFIRMATION,
        flash_firmware_query_included: false,
        flash_reconnect_timeout_seconds: RECONNECT_LIMIT.as_secs(),
        normal_reconnect_timeout_seconds: NORMAL_RECONNECT_LIMIT.as_secs(),
        production_mode_switching_available: false,
        recovery_authorized: false,
    })
}

/// Same admission as the mode test, with a distinct reviewed action list and
/// confirmation. No physical mode command is sent by this preview.
pub fn preflight_preview(
    id: &str,
    reference: &wpi_core::spec_a_preflight::Reference,
) -> Result<PreflightPreview, String> {
    check_reference_platform(reference)?;
    let mut mode = preview(id)?;
    mode.experiment = PREFLIGHT_EXPERIMENT;
    mode.confirmation_phrase = PREFLIGHT_CONFIRMATION;
    mode.actions.insert(4, "On a freshly bound handle compare Normal/Flash public IDs, RRKH and SS; no GPT/FVER/context requests");
    Ok(PreflightPreview {
        mode_test: mode,
        reference: reference.summary().clone(),
        gpt_query_included: false,
        phone_writes_enabled: false,
    })
}
pub fn gpt_preview(
    id: &str,
    reference: &wpi_core::spec_a_preflight::Reference,
    output: &std::path::Path,
) -> Result<PreflightPreview, String> {
    wpi_core::boot_gpt::check_destination(output).map_err(|e| e.to_string())?;
    let mut preview = preflight_preview(id, reference)?;
    preview.mode_test.experiment = GPT_EXPERIMENT;
    preview.mode_test.confirmation_phrase = GPT_CONFIRMATION;
    preview.mode_test.actions.insert(6,"During return boot, require BootMgr 1.16 / protocol 1.1; read primary GPT twice without changing its boot timer");
    preview.mode_test.actions.push("After the original Normal identity returns, atomically preserve the verified primary GPT to a NEW local file");
    preview.gpt_query_included = true;
    Ok(preview)
}
pub fn run_gpt<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    reference: &wpi_core::spec_a_preflight::Reference,
    output: &std::path::Path,
    confirmation: &str,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    check_reference_platform(reference)?;
    wpi_core::boot_gpt::check_destination(output).map_err(|e| e.to_string())?;
    run_session_with_gpt(
        id,
        confirmation,
        Some(reference),
        Some(output),
        cancelled,
        emit,
    )
}
fn check_reference_platform(
    reference: &wpi_core::spec_a_preflight::Reference,
) -> Result<(), String> {
    let platform = reference.platform();
    if FLASH_PLATFORM != platform
        && !FLASH_PLATFORM
            .strip_prefix(platform)
            .is_some_and(|s| s.starts_with('.'))
    {
        return Err(
            "Source reference platform is outside the reviewed RM-875 Flash profile".into(),
        );
    }
    Ok(())
}
pub fn run_preflight<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    reference: &wpi_core::spec_a_preflight::Reference,
    confirmation: &str,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    check_reference_platform(reference)?;
    run_session(id, confirmation, Some(reference), cancelled, emit)
}
pub fn run<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    confirmation: &str,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    run_session(id, confirmation, None, cancelled, emit)
}
fn run_session<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    confirmation: &str,
    reference: Option<&wpi_core::spec_a_preflight::Reference>,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    run_session_with_gpt(id, confirmation, reference, None, cancelled, emit)
}
fn run_session_with_gpt<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    confirmation: &str,
    reference: Option<&wpi_core::spec_a_preflight::Reference>,
    gpt_output: Option<&std::path::Path>,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    run_session_inputs(
        id,
        confirmation,
        reference,
        gpt_output,
        None,
        cancelled,
        emit,
    )
}
pub fn run_prepared<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    prepared: &wpi_core::spec_a_session::Prepared,
    confirmation: &str,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    run_session_inputs(
        id,
        confirmation,
        Some(prepared.reference()),
        None,
        Some(prepared),
        cancelled,
        emit,
    )
}
#[allow(clippy::too_many_arguments)]
fn run_session_inputs<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    confirmation: &str,
    reference: Option<&wpi_core::spec_a_preflight::Reference>,
    gpt_output: Option<&std::path::Path>,
    prepared: Option<&wpi_core::spec_a_session::Prepared>,
    cancelled: &AtomicBool,
    mut emit: F,
) -> Result<Summary, String> {
    if confirmation
        != if prepared.is_some() {
            PREPARED_CONFIRMATION
        } else if gpt_output.is_some() {
            GPT_CONFIRMATION
        } else if reference.is_some() {
            PREFLIGHT_CONFIRMATION
        } else {
            CONFIRMATION
        }
    {
        return Err("Exact public-ID experiment confirmation required".into());
    }
    if !cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        return Err("Public-ID mode experiment is limited to Windows ARM64".into());
    }
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let watch = nusb::watch_devices().map_err(|_| "Cannot arm native USB hotplug watch")?;
    let devices: Vec<_> = nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .filter(|d| wpi_core::classify_usb(d.vendor_id(), d.product_id()).is_some())
        .collect();
    if devices.len() != 1 {
        return Err("Connect exactly one recognized Lumia".into());
    }
    let selected = devices
        .first()
        .filter(|d| format!("{:?}", d.id()) == id)
        .ok_or("Selected phone changed")?;
    if wpi_core::classify_usb(selected.vendor_id(), selected.product_id())
        != Some(DeviceMode::Normal)
    {
        return Err("Execution must start with the selected phone in Normal mode".into());
    }
    let serial = selected
        .serial_number()
        .filter(|s| !s.trim().is_empty())
        .ok_or("Baseline USB serial missing")?
        .to_owned();
    let port = physical_port(selected).ok_or("Physical USB port missing")?;
    let mut driver = PublicDriver {
        native: NativeDriver {
            watch,
            removed: HashSet::new(),
            change_generation: 0,
            serial,
            port,
        },
        observed_generation: 0,
        reference,
        gpt: gpt_output.map(|output| GptPlan {
            output,
            candidate: None,
        }),
        flash_sectors: None,
        prepared,
        prepared_normal: None,
        prepared_flash: None,
    };
    let descriptor = identity(selected, DeviceMode::Normal);
    let baseline = match driver
        .probe(&descriptor, Instant::now() + Duration::from_secs(20), false)
        .map_err(|e| e.message())?
    {
        Observation::Identity(s) => s,
        Observation::Boot(_) => return Err("Normal baseline identity is required".into()),
    };
    if let Some(prepared) = prepared {
        let (normal, _) =
            crate::spec_a_session::capture_normal_bound(id, prepared, cancelled, |_| {})?;
        if !emit(&ModeTestEvent::PreparedSession {
            report: Box::new(normal.report()),
        }) {
            return Err("Prepared session journal failed before mode entry".into());
        }
        driver.prepared_normal = Some(normal);
    }
    round_trip_inner(&mut driver, baseline, reference.is_some(), cancelled, emit)
}

trait IdentityDriver {
    fn finish_prepared(
        &mut self,
        _normal: &Snapshot,
        _cancelled: &AtomicBool,
    ) -> Result<Option<wpi_core::spec_a_session::Report>, String> {
        Ok(None)
    }
    fn boot_gpt(
        &mut self,
        _probe: &ProbeResult,
        _baseline: &Snapshot,
        _cancelled: &AtomicBool,
    ) -> Result<Option<wpi_core::boot_gpt::Report>, String> {
        Ok(None)
    }
    fn finish_gpt(
        &mut self,
        _normal: &Snapshot,
        _baseline: &Snapshot,
        _cancelled: &AtomicBool,
    ) -> Result<Option<wpi_core::boot_gpt::Report>, String> {
        Ok(None)
    }
    fn preflight(
        &mut self,
        _current: &Snapshot,
        _baseline: &Snapshot,
        _cancelled: &AtomicBool,
    ) -> Result<wpi_core::spec_a_preflight::Report, String> {
        Err("This driver has no read-only preflight implementation".into())
    }
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String>;
    fn arm(&mut self, id: &str) -> Result<(), String>;
    fn removed(&mut self, id: &str) -> Result<bool, String>;
    fn changed(&mut self) -> Result<bool, String>;
    fn probe(
        &mut self,
        d: &DeviceIdentity,
        deadline: Instant,
        allow_boot: bool,
    ) -> Result<Observation, DriverError>;
    fn send(
        &mut self,
        current: &Snapshot,
        baseline: &Snapshot,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Sent, String>;
    fn now(&self) -> Instant;
    fn pause(&mut self);
}
struct PublicDriver<'a> {
    native: NativeDriver,
    observed_generation: u64,
    reference: Option<&'a wpi_core::spec_a_preflight::Reference>,
    gpt: Option<GptPlan<'a>>,
    flash_sectors: Option<u32>,
    prepared: Option<&'a wpi_core::spec_a_session::Prepared>,
    prepared_normal: Option<wpi_core::spec_a_session::NormalSession<'a>>,
    prepared_flash: Option<wpi_core::spec_a_session::FlashSession<'a>>,
}
struct GptPlan<'a> {
    output: &'a std::path::Path,
    candidate: Option<wpi_core::boot_gpt::Capture>,
}
impl PublicDriver<'_> {
    fn binding(&self, id: &str) -> Result<(), DriverError> {
        let devices: Vec<_> = nusb::list_devices()
            .wait()
            .map_err(|e| DriverError::NotReady(e.to_string()))?
            .filter(|d| wpi_core::classify_usb(d.vendor_id(), d.product_id()).is_some())
            .collect();
        if devices.len() > 1 {
            return Err(DriverError::Fatal(
                "Multiple recognized interfaces appeared; inspect connections".into(),
            ));
        }
        let d = devices
            .first()
            .filter(|d| format!("{:?}", d.id()) == id)
            .ok_or_else(|| DriverError::NotReady("Selected interface not present".into()))?;
        let mode = wpi_core::classify_usb(d.vendor_id(), d.product_id()).unwrap();
        descriptor_allowed(
            &identity(d, mode),
            &self.native.serial,
            physical_port(d).as_ref() == Some(&self.native.port),
        )
        .map_err(DriverError::Fatal)
    }
}
/// Defense in depth for this one hardware experiment: even future changes to
/// the generic codec cannot add a parameter, GPT read, context switch or write.
struct PreflightTransport<'a, T> {
    inner: &'a mut T,
    descriptor: &'a DeviceIdentity,
}
impl<T: MessageTransport> MessageTransport for PreflightTransport<'_, T> {
    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response: usize,
    ) -> wpi_protocol::Result<Vec<u8>> {
        if request != b"NOKV"
            && request != public_identity::flash_request()
            && request != wpi_protocol::flash::parameter_request("RRKH")?
            && request != wpi_protocol::flash::parameter_request("SS")?
        {
            return Err(wpi_protocol::ProtocolError::Invalid(
                "Request is outside this read-only preflight experiment".into(),
            ));
        }
        let response = self.inner.exchange(request, maximum_response)?;
        if request == b"NOKV" {
            let info = wpi_protocol::flash::parse_info(&response)?;
            let mut device = self.descriptor.clone();
            device.mode = info.mode;
            device.platform_id = info.platform_id.clone();
            validate_flash(&ProbeResult {
                device,
                info: Some(info),
                normal: None,
                firmware: None,
            })
            .map_err(wpi_protocol::ProtocolError::Invalid)?;
        }
        Ok(response)
    }
}
impl IdentityDriver for PublicDriver<'_> {
    fn finish_prepared(
        &mut self,
        normal: &Snapshot,
        cancelled: &AtomicBool,
    ) -> Result<Option<wpi_core::spec_a_session::Report>, String> {
        let Some(prepared) = self.prepared else {
            return Ok(None);
        };
        self.binding(&normal.probe.device.id)
            .map_err(|e| e.message())?;
        let flash = self
            .prepared_flash
            .take()
            .ok_or("Prepared Flash handoff is missing; no session may complete")?;
        let (returning, _) = crate::spec_a_session::capture_normal_bound(
            &normal.probe.device.id,
            prepared,
            cancelled,
            |_| {},
        )?;
        self.binding(&normal.probe.device.id)
            .map_err(|e| e.message())?;
        Ok(Some(flash.verify_return_session(returning)?))
    }
    fn boot_gpt(
        &mut self,
        probe: &ProbeResult,
        _baseline: &Snapshot,
        cancelled: &AtomicBool,
    ) -> Result<Option<wpi_core::boot_gpt::Report>, String> {
        if self.gpt.is_none() {
            return Ok(None);
        }
        if self.gpt.as_ref().unwrap().candidate.is_some() {
            return Err(
                "A second BootManager arrival cannot replace the captured primary GPT".into(),
            );
        }
        wpi_core::boot_gpt::validate_info(
            probe
                .info
                .as_ref()
                .ok_or("BootManager information missing")?,
        )
        .map_err(|e| e.to_string())?;
        self.binding(&probe.device.id).map_err(|e| e.message())?;
        let (descriptor, mut transport) = open_selected(&probe.device.id)?;
        if descriptor.vendor_id != probe.device.vendor_id
            || descriptor.product_id != probe.device.product_id
            || descriptor.serial != probe.device.serial
        {
            return Err("BootManager descriptor changed before capture".into());
        }
        transport.deadline = Some(Instant::now() + Duration::from_secs(8));
        let candidate = wpi_core::boot_gpt::read(
            &mut transport,
            self.flash_sectors
                .ok_or("Fresh Flash capacity required before GPT capture")?,
            |_| !cancelled.load(Ordering::Acquire),
        )
        .map_err(|e| e.to_string())?;
        self.binding(&probe.device.id).map_err(|e| e.message())?;
        let report = candidate.report(
            &self
                .reference
                .ok_or("GPT source reference missing")?
                .summary()
                .primary_gpt_sha256,
        );
        self.gpt.as_mut().unwrap().candidate = Some(candidate);
        Ok(Some(report))
    }
    fn finish_gpt(
        &mut self,
        normal: &Snapshot,
        baseline: &Snapshot,
        cancelled: &AtomicBool,
    ) -> Result<Option<wpi_core::boot_gpt::Report>, String> {
        if self.gpt.is_none() {
            return Ok(None);
        }
        validate(normal, baseline, DeviceMode::Normal)?;
        self.binding(&normal.probe.device.id)
            .map_err(|e| e.message())?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled before GPT publication".into());
        }
        let plan = self.gpt.as_mut().unwrap();
        let candidate = plan.candidate.take().ok_or(
            "BootManager GPT window was not captured; phone is back in Normal, no retry or output",
        )?;
        let report = candidate
            .save(
                plan.output,
                &self
                    .reference
                    .ok_or("GPT reference missing")?
                    .summary()
                    .primary_gpt_sha256,
            )
            .map_err(|e| e.to_string())?;
        Ok(Some(report))
    }
    fn preflight(
        &mut self,
        current: &Snapshot,
        baseline: &Snapshot,
        cancelled: &AtomicBool,
    ) -> Result<wpi_core::spec_a_preflight::Report, String> {
        let reference = self.reference.ok_or("Preflight reference missing")?;
        validate(current, baseline, DeviceMode::Flash)?;
        self.binding(&current.probe.device.id)
            .map_err(|e| e.message())?;
        // Finish and close the prepared probe BEFORE opening the legacy probe
        // handle. WinUSB interface ownership must never overlap here.
        if self.prepared.is_some() {
            let baseline = self
                .prepared_normal
                .take()
                .ok_or("Prepared Normal handoff is missing; stop without retry")?;
            self.prepared_flash = Some(crate::spec_a_session::capture_flash_bound(
                &current.probe.device.id,
                baseline,
                &self.native.serial,
                &self.native.port,
                cancelled,
            )?);
        }
        let (descriptor, mut transport) = open_selected(&current.probe.device.id)?;
        if descriptor.vendor_id != current.probe.device.vendor_id
            || descriptor.product_id != current.probe.device.product_id
            || descriptor.serial != current.probe.device.serial
        {
            return Err("Descriptors changed before read-only preflight".into());
        }
        transport.deadline = Some(Instant::now() + Duration::from_secs(30));
        let captured = wpi_protocol::preflight::capture_bound(
            &mut PreflightTransport {
                inner: &mut transport,
                descriptor: &descriptor,
            },
            reference.root(),
            reference.platform(),
            false,
            &baseline.public_id,
            |_| !cancelled.load(Ordering::Acquire),
        )
        .map_err(|e| e.to_string())?;
        self.binding(&current.probe.device.id)
            .map_err(|e| e.message())?;
        let mut report = wpi_core::spec_a_preflight::assess(reference, captured, false)
            .map_err(|e| e.to_string())?;
        report.normal_session_correlated = true;
        self.flash_sectors = report.flash.emmc_sectors;
        for check in &mut report.checks {
            if check.key == "normal_identity" {
                check.status = PreparationStatus::Passed;
                check.message = "Fresh Normal public ID matched both Flash bookends on a handle bound to the same physical USB port. This is local correlation, not authenticated identity.".into();
            } else if check.key == "identity_bookends" {
                check.message = "The same local public ID answered at both Flash bookends and matched the fresh Normal baseline. ID bytes remain private; identity is not authenticated.".into();
            }
        }
        Ok(report)
    }
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String> {
        let devices: Vec<_> = nusb::list_devices()
            .wait()
            .map_err(|e| e.to_string())?
            .filter(|d| wpi_core::classify_usb(d.vendor_id(), d.product_id()).is_some())
            .collect();
        if devices.len() > 1 {
            return Err("Multiple recognized interfaces; no candidate was queried".into());
        }
        let mut result = Vec::new();
        for d in devices {
            let mode = wpi_core::classify_usb(d.vendor_id(), d.product_id()).unwrap();
            let descriptor = identity(&d, mode);
            descriptor_allowed(
                &descriptor,
                &self.native.serial,
                physical_port(&d).as_ref() == Some(&self.native.port),
            )?;
            result.push(descriptor);
        }
        Ok(result)
    }
    fn arm(&mut self, id: &str) -> Result<(), String> {
        self.native.arm(id)?;
        self.observed_generation = self.native.change_generation;
        Ok(())
    }
    fn removed(&mut self, id: &str) -> Result<bool, String> {
        self.native.removed(id)
    }
    fn changed(&mut self) -> Result<bool, String> {
        self.native.drain()?;
        let changed = self.native.change_generation != self.observed_generation;
        self.observed_generation = self.native.change_generation;
        Ok(changed)
    }
    fn probe(
        &mut self,
        d: &DeviceIdentity,
        deadline: Instant,
        allow_boot: bool,
    ) -> Result<Observation, DriverError> {
        self.binding(&d.id)?;
        let (descriptor, mut transport) = open_selected(&d.id).map_err(DriverError::NotReady)?;
        if descriptor.vendor_id != d.vendor_id
            || descriptor.product_id != d.product_id
            || descriptor.serial != d.serial
        {
            return Err(DriverError::Fatal(
                "Descriptor changed before information query".into(),
            ));
        }
        transport.deadline = Some(deadline);
        read_observation(descriptor, &mut transport, allow_boot).map_err(DriverError::Fatal)
    }
    fn send(
        &mut self,
        current: &Snapshot,
        baseline: &Snapshot,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Sent, String> {
        self.binding(&current.probe.device.id)
            .map_err(|e| e.message())?;
        let (descriptor, mut transport) = open_selected(&current.probe.device.id)?;
        if descriptor.vendor_id != current.probe.device.vendor_id
            || descriptor.product_id != current.probe.device.product_id
            || descriptor.serial != current.probe.device.serial
        {
            return Err("Descriptor changed before command revalidation".into());
        }
        transport.deadline = Some(Instant::now() + Duration::from_secs(20));
        let fresh = read_snapshot(descriptor, &mut transport)?;
        validate(&fresh, baseline, current.probe.device.mode)?;
        let (from, to) = match action {
            Action::EnterFlash => (DeviceMode::Normal, DeviceMode::Flash),
            Action::ReturnNormal => (DeviceMode::Flash, DeviceMode::Normal),
            _ => return Err("Context switches are excluded from the public-ID experiment".into()),
        };
        if fresh.probe.device.mode != from {
            return Err("Command source application changed".into());
        }
        let command = wpi_protocol::mode::command(
            from,
            to,
            baseline.probe.device.family,
            fresh.probe.info.as_ref().map(|i| i.protocol_major),
        )
        .map_err(|e| e.to_string())?;
        self.binding(&fresh.probe.device.id)
            .map_err(|e| e.message())?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled after source revalidation; no mode command was sent".into());
        }
        Ok(Sent {
            requires_disconnect: command.requires_disconnect,
            uncertain: transport.send_once(&command.request).is_err(),
        })
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn pause(&mut self) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn observe<F: FnMut(&ModeTestEvent) -> bool>(
    snapshot: &Snapshot,
    baseline: &Snapshot,
    reporter: &mut Reporter<F>,
) -> Result<(), String> {
    if !(reporter.emit)(&ModeTestEvent::IdentityObservation {
        device: Box::new(redact(snapshot.probe.device.clone())),
        info: snapshot.probe.info.clone(),
        public_id_matches: snapshot.public_id == baseline.public_id,
        normal_serial_matches: (snapshot.probe.device.mode == DeviceMode::Normal)
            .then_some(snapshot.probe.device.serial == baseline.probe.device.serial),
        physical_port_matches: true,
        identity_authenticated: false,
        recovery_authorized: false,
    }) {
        return Err("Identity journal failed or cancellation requested".into());
    }
    Ok(())
}
fn send<D: IdentityDriver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    current: &Snapshot,
    baseline: &Snapshot,
    action: Action,
    cancelled: &AtomicBool,
    reporter: &mut Reporter<F>,
) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire)
        || !reporter.progress(
            OperationState::Running,
            "Revalidate public ID, profile and port before one mode request",
        )
    {
        return Err("Cancelled at safe command boundary".into());
    }
    driver.arm(&current.probe.device.id)?;
    if !reporter.progress(
        OperationState::Running,
        "About to attempt one mode command; interruption requires inspection",
    ) {
        return Err("Journal failed before mode command".into());
    }
    let sent = driver.send(current, baseline, action, cancelled)?;
    reporter.attempted += 1;
    if !sent.requires_disconnect {
        return Err("Unexpected route without required removal".into());
    }
    if !(reporter.emit)(&ModeTestEvent::Command {
        action: match action {
            Action::EnterFlash => "SetDeviceMode(Flash, HwReset)",
            _ => "NOKR from public-ID-validated FlashApp",
        },
        delivery: if sent.uncertain {
            "uncertain_no_retry"
        } else {
            "complete_out_once"
        },
    }) {
        return Err("Journal failed after command attempt".into());
    }
    if !reporter.progress(
        OperationState::AwaitingReconnect,
        "Command attempted once; await removal and fresh public-ID observation",
    ) {
        return Err("Cancelled after command attempt".into());
    }
    Ok(())
}
fn wait<D: IdentityDriver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    source: &str,
    baseline: &Snapshot,
    mode: DeviceMode,
    cancelled: &AtomicBool,
    reporter: &mut Reporter<F>,
) -> Result<Snapshot, String> {
    let limit = if mode == DeviceMode::Normal {
        NORMAL_RECONNECT_LIMIT
    } else {
        RECONNECT_LIMIT
    };
    let deadline = driver.now() + limit;
    let mut removed = false;
    let mut retired_return_interfaces = HashSet::new();
    let mut retry_open = false;
    let mut next_rediscovery = driver.now();
    while driver.now() < deadline {
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled while awaiting reconnection".into());
        }
        let trigger = if retry_open {
            "open_readiness_retry"
        } else if retired_return_interfaces.is_empty() {
            "awaiting_arrival"
        } else if driver.changed()? {
            "hotplug"
        } else if driver.now() >= next_rediscovery {
            "periodic_fallback"
        } else {
            driver.pause();
            continue;
        };
        retry_open = false;
        let enumeration_start = driver.now();
        let devices = driver.devices()?;
        let enumeration_ms =
            u64::try_from(driver.now().duration_since(enumeration_start).as_millis())
                .unwrap_or(u64::MAX);
        next_rediscovery = driver.now() + REDISCOVERY_INTERVAL;
        removed |= driver.removed(source)? || !devices.iter().any(|d| d.id == source);
        if !(reporter.emit)(&ModeTestEvent::ReconnectDiscovery {
            expected_mode: mode,
            trigger,
            enumeration_ms,
            observed_modes: devices.iter().map(|d| d.mode).collect(),
            source_removal_observed: removed,
        }) {
            return Err("Discovery journal failed or cancellation requested".into());
        }
        if driver.now() >= deadline {
            return Err("Reconnection deadline expired during USB discovery".into());
        }
        if devices.len() > 1 {
            return Err("Multiple returning interfaces; no candidate queried".into());
        }
        if removed {
            if let Some(d) = devices.first() {
                descriptor_allowed(
                    d,
                    baseline
                        .probe
                        .device
                        .serial
                        .as_deref()
                        .ok_or("Baseline serial missing")?,
                    true,
                )?;
                if mode == DeviceMode::Normal
                    && d.mode == DeviceMode::Flash
                    && retired_return_interfaces.contains(&d.id)
                {
                    // A successful boot-stage query is not a reason to keep its interface busy.
                    // Only fresh removal/arrival or the Normal USB descriptor permits another probe.
                    if !driver.removed(&d.id)? {
                        driver.pause();
                        continue;
                    }
                    retired_return_interfaces.remove(&d.id);
                }
                // Arm before the query, so arrivals occurring during it are not discarded.
                if mode == DeviceMode::Normal {
                    driver.arm(&d.id)?;
                }
                if cancelled.load(Ordering::Acquire)
                    || !(reporter.emit)(&ModeTestEvent::ReconnectProbe {
                        observed_mode: d.mode,
                        readiness: "attempting_read_only_probe",
                    })
                {
                    return Err("Cancelled or journal failed before read-only probe".into());
                }
                let observation = match driver.probe(d, deadline, mode == DeviceMode::Normal) {
                    Ok(s) => s,
                    Err(DriverError::NotReady(_)) => {
                        if !(reporter.emit)(&ModeTestEvent::ReconnectProbe {
                            observed_mode: d.mode,
                            readiness: "interface_not_ready_no_query_sent",
                        }) {
                            return Err("Readiness journal failed or cancellation requested".into());
                        }
                        retry_open = true; // Readiness before any protocol request can retry without another hotplug event.
                        driver.pause();
                        continue;
                    }
                    Err(e) => return Err(e.message()),
                };
                if driver.now() >= deadline {
                    return Err("Reconnection deadline expired during information query".into());
                }
                let snapshot = match observation {
                    Observation::Identity(s) => s,
                    Observation::Boot(probe) => {
                        if mode != DeviceMode::Normal
                            || probe.device.mode != DeviceMode::BootManager
                            || !probe
                                .info
                                .as_ref()
                                .is_some_and(|i| matches!(i.protocol_major, 1 | 2))
                        {
                            return Err(
                                "Unexpected boot observation; no identity or command permitted"
                                    .into(),
                            );
                        }
                        if cancelled.load(Ordering::Acquire) {
                            return Err("Cancelled before BootManager observation".into());
                        }
                        if let Some(report) = driver.boot_gpt(&probe, baseline, cancelled)? {
                            if !(reporter.emit)(&ModeTestEvent::BootGptCandidate { report }) {
                                return Err(
                                    "GPT candidate journal failed; no output published".into()
                                );
                            }
                        }
                        if !(reporter.emit)(&ModeTestEvent::BootObservation {
                            device: Box::new(redact(probe.device)),
                            info: probe.info,
                            public_id_verified: false,
                            physical_port_matches: true,
                            recovery_authorized: false,
                        }) {
                            return Err(
                                "Boot observation journal failed or cancellation requested".into(),
                            );
                        }
                        retired_return_interfaces.insert(d.id.clone());
                        driver.pause();
                        continue;
                    }
                };
                validate(&snapshot, baseline, snapshot.probe.device.mode)?;
                observe(&snapshot, baseline, reporter)?;
                if snapshot.probe.device.mode == mode {
                    return Ok(snapshot);
                }
                // A matching Flash observation during Normal boot never triggers another reset or busy polling.
                if mode != DeviceMode::Normal || snapshot.probe.device.mode != DeviceMode::Flash {
                    return Err("Unexpected returning application; no context command sent".into());
                }
                retired_return_interfaces.insert(d.id.clone());
            }
        }
        driver.pause();
    }
    Err(format!(
        "No validated public-ID reconnection before the {}-second deadline",
        limit.as_secs()
    ))
}
#[cfg(test)]
fn round_trip<D: IdentityDriver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    baseline: Snapshot,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    round_trip_inner(driver, baseline, false, cancelled, emit)
}
fn round_trip_inner<D: IdentityDriver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    baseline: Snapshot,
    include_preflight: bool,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    let reasons = admission(&baseline.probe.device, true);
    if !reasons.is_empty() {
        return Err(reasons.join("; "));
    }
    let mut reporter = Reporter {
        emit,
        sequence: 0,
        attempted: 0,
    };
    let result = (|| {
        observe(&baseline, &baseline, &mut reporter)?;
        send(
            driver,
            &baseline,
            &baseline,
            Action::EnterFlash,
            cancelled,
            &mut reporter,
        )?;
        let flash = wait(
            driver,
            &baseline.probe.device.id,
            &baseline,
            DeviceMode::Flash,
            cancelled,
            &mut reporter,
        )?;
        if include_preflight {
            if cancelled.load(Ordering::Acquire)
                || !reporter.progress(
                    OperationState::Running,
                    "Read-only identity-bound RRKH / SS preflight; no GPT or context switch",
                )
            {
                return Err("Cancelled before read-only preflight".into());
            }
            let report = driver.preflight(&flash, &baseline, cancelled)?;
            if report.phone_writes_enabled
                || report.recovery_authorized
                || !report.normal_session_correlated
            {
                return Err("Unexpected preflight authority or missing Normal correlation".into());
            }
            if cancelled.load(Ordering::Acquire)
                || !(reporter.emit)(&ModeTestEvent::SpecAPreflight {
                    report: Box::new(report),
                })
            {
                return Err("Preflight journal failed or cancellation requested; inspect state before any further command".into());
            }
        }
        send(
            driver,
            &flash,
            &baseline,
            Action::ReturnNormal,
            cancelled,
            &mut reporter,
        )?;
        let normal = wait(
            driver,
            &flash.probe.device.id,
            &baseline,
            DeviceMode::Normal,
            cancelled,
            &mut reporter,
        )?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled before completion; state inspection required".into());
        }
        let primary_gpt = driver.finish_gpt(&normal, &baseline, cancelled)?;
        let prepared_session = driver.finish_prepared(&normal, cancelled)?;
        if let Some(report) = prepared_session.as_ref() {
            if !report.normal_flash_normal_public_id_matches
                || !report.normal_identity_bookends_match
                || !report.normal_flash_public_id_matches
                || !report.flash_root_and_security_checked
                || !report.flash_capacity_matches_saved_layout
                || !report.source_ffu_integrity_checked
                || !report.source_sbl1_and_loader_root_bound
                || report.phone_writes_enabled
                || report.automatic_resume_allowed
                || !(reporter.emit)(&ModeTestEvent::PreparedSession {
                    report: Box::new(report.clone()),
                })
            {
                return Err(
                    "Prepared session failed its return checks or durable report save".into(),
                );
            }
        }
        if let Some(report) = primary_gpt.as_ref() {
            if !(reporter.emit)(&ModeTestEvent::BootGptSaved {
                report: report.clone(),
                normal_before_after_correlated: true,
                identity_authenticated: false,
            }) {
                return Err("Primary GPT was saved but its journal failed; inspect the existing file before proceeding".into());
            }
        }
        if !reporter.progress(
            OperationState::Completed,
            "Normal identity restored; public ID matched across both modes; no firmware writes",
        ) {
            return Err("Completion journal failed".into());
        }
        Ok(Summary {
            result: if primary_gpt.is_some() {
                "primary_gpt_preserved_normal_identity_restored"
            } else if include_preflight {
                "read_only_preflight_roundtrip_observed"
            } else {
                "public_id_normal_flash_normal_observed"
            },
            mode_commands_attempted: reporter.attempted,
            normal_reconnection: wpi_core::reconnect::compare(
                &baseline.probe.device,
                &normal.probe.device,
                DeviceMode::Normal,
            ),
            public_id_matched_in_both_modes: true,
            identity_authenticated: false,
            recovery_authorized: false,
            spec_a_preflight_completed: include_preflight,
            primary_gpt,
            prepared_session,
        })
    })();
    result.map_err(|e: String| reporter.stopped(&e))
}

#[cfg(test)]
mod tests;
