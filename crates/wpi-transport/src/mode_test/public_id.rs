//! Separate CLI-only public-ID validation experiment; the original serial-only test stays blocked.
use super::*;
use wpi_protocol::{identity as public_identity, MessageTransport};

pub const CONFIRMATION: &str = "RM875-PUBLIC-ID-ROUNDTRIP";
pub const EXPERIMENT: &str = "rm875_public_id_normal_flash_normal";
const FLASH_PLATFORM: &str = "Nokia.MSM8960.P5217.3.2.1";

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
            let normal = wpi_protocol::normal::read_info(transport).map_err(|e| e.to_string())?;
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
            let public_id =
                public_identity::read_normal(transport, 4).map_err(|e| e.to_string())?;
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
            let info = wpi_protocol::flash::read_info(transport).map_err(|e| e.to_string())?;
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
                .map_err(|e| e.to_string())?;
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
        production_mode_switching_available: false,
        recovery_authorized: false,
    })
}

pub fn run<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    confirmation: &str,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<Summary, String> {
    if confirmation != CONFIRMATION {
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
            serial,
            port,
        },
    };
    let descriptor = identity(selected, DeviceMode::Normal);
    let baseline = match driver
        .probe(&descriptor, Instant::now() + Duration::from_secs(20), false)
        .map_err(|e| e.message())?
    {
        Observation::Identity(s) => s,
        Observation::Boot(_) => return Err("Normal baseline identity is required".into()),
    };
    round_trip(&mut driver, baseline, cancelled, emit)
}

trait IdentityDriver {
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String>;
    fn arm(&mut self, id: &str) -> Result<(), String>;
    fn removed(&mut self, id: &str) -> Result<bool, String>;
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
struct PublicDriver {
    native: NativeDriver,
}
impl PublicDriver {
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
impl IdentityDriver for PublicDriver {
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
        self.native.arm(id)
    }
    fn removed(&mut self, id: &str) -> Result<bool, String> {
        self.native.removed(id)
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
    let deadline = driver.now() + RECONNECT_LIMIT;
    let mut removed = false;
    while driver.now() < deadline {
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled while awaiting reconnection".into());
        }
        let devices = driver.devices()?;
        removed |= driver.removed(source)? || !devices.iter().any(|d| d.id == source);
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
                let observation = match driver.probe(d, deadline, mode == DeviceMode::Normal) {
                    Ok(s) => s,
                    Err(DriverError::NotReady(_)) => {
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
                        driver.pause();
                        continue;
                    }
                };
                validate(&snapshot, baseline, snapshot.probe.device.mode)?;
                observe(&snapshot, baseline, reporter)?;
                if snapshot.probe.device.mode == mode {
                    return Ok(snapshot);
                }
                // Successful, matching Flash observations may repeat during Normal boot, never trigger another reset.
                if mode != DeviceMode::Normal || snapshot.probe.device.mode != DeviceMode::Flash {
                    return Err("Unexpected returning application; no context command sent".into());
                }
            }
        }
        driver.pause();
    }
    Err("No validated public-ID reconnection before the 30-second deadline".into())
}
fn round_trip<D: IdentityDriver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    baseline: Snapshot,
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
        if !reporter.progress(
            OperationState::Completed,
            "Normal identity restored; public ID matched across both modes; no firmware writes",
        ) {
            return Err("Completion journal failed".into());
        }
        Ok(Summary {
            result: "public_id_normal_flash_normal_observed",
            mode_commands_attempted: reporter.attempted,
            normal_reconnection: wpi_core::reconnect::compare(
                &baseline.probe.device,
                &normal.probe.device,
                DeviceMode::Normal,
            ),
            public_id_matched_in_both_modes: true,
            identity_authenticated: false,
            recovery_authorized: false,
        })
    })();
    result.map_err(|e: String| reporter.stopped(&e))
}

#[cfg(test)]
mod tests;
