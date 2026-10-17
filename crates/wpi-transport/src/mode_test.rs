//! Narrow native hardware-validation harness, never a production capability gate.
//! No firmware, partition, loader, security or mass-storage commands are accepted.
use super::{enumerate, identity, open_selected, probe_session, ProbeResult, PHONE_ACCESS};
use futures_core::Stream;
use nusb::{hotplug::HotplugEvent, MaybeFuture};
use serde::Serialize;
use std::{
    collections::HashSet,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use wpi_types::*;

pub const CONFIRMATION: &str = "RM875-NORMAL-FLASH-NORMAL";
const FIRMWARE: &str = "3051.50009.1451.1003";
const PLATFORM: &str = "Nokia.MSM8960.P5217";
const RECONNECT_LIMIT: Duration = Duration::from_secs(30);
const LIVE_BLOCKER: &str = "The first RM-875 experiment stopped because Flash has no USB serial. Live execution is paused pending validated public-ID correlation, Flash platform and FVER handling. Use identity-probe for explicit read-only inspection; do not repeat the mode test.";

fn live_blocker(device: &DeviceIdentity) -> Option<&'static str> {
    (device.variant.as_deref() == Some("RM-875") && device.firmware.as_deref() == Some(FIRMWARE))
        .then_some(LIVE_BLOCKER)
}
#[derive(Clone, PartialEq, Eq)]
enum PhysicalPort {
    #[cfg(target_os = "windows")]
    Windows {
        hub: std::ffi::OsString,
        number: u32,
    },
    #[cfg(not(target_os = "windows"))]
    Native { bus: String, chain: Vec<u8> },
}
fn physical_port(d: &nusb::DeviceInfo) -> Option<PhysicalPort> {
    #[cfg(target_os = "windows")]
    {
        windows_port(d.parent_instance_id(), d.port_number())
    }
    #[cfg(not(target_os = "windows"))]
    {
        if d.bus_id().is_empty() || d.port_chain().is_empty() {
            None
        } else {
            Some(PhysicalPort::Native {
                bus: d.bus_id().into(),
                chain: d.port_chain().into(),
            })
        }
    }
}
pub(super) fn port_available(id: &str) -> Result<bool, String> {
    Ok(nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .find(|d| format!("{:?}", d.id()) == id)
        .is_some_and(|d| physical_port(&d).is_some()))
}

fn binding_error(expected: &str, observed: Option<&str>, port_matches: bool) -> Option<String> {
    let serial = match observed.filter(|s| !s.trim().is_empty()) {
        None => "missing",
        Some(s) if s == expected => "match",
        Some(_) => "different",
    };
    if serial == "match" && port_matches {
        None
    } else {
        Some(format!("USB binding failed: serial={serial}, physical_port={}; no query or command was sent to the returning interface",
            if port_matches { "match" } else { "missing_or_different" }))
    }
}
#[cfg(target_os = "windows")]
fn windows_port(hub: &std::ffi::OsStr, number: u32) -> Option<PhysicalPort> {
    // nusb already uses this hub/ConnectionIndex pair to retrieve device descriptors.
    // ARM ACPI location paths need not parse as a generic bus/port chain.
    if hub.is_empty() || number == 0 {
        None
    } else {
        Some(PhysicalPort::Windows {
            hub: hub.into(),
            number,
        })
    }
}
pub mod public_id;
#[cfg(test)]
mod tests;

#[derive(Debug, Serialize)]
pub struct ModeTestPreview {
    pub experiment: &'static str,
    pub device: DeviceIdentity,
    pub eligible_for_experiment: bool,
    pub blockers: Vec<String>,
    pub actions: Vec<&'static str>,
    pub confirmation_phrase: &'static str,
    pub reconnect_timeout_seconds: u64,
    pub recovery_authorized: bool,
    pub production_mode_switching_available: bool,
    pub physical_port_binding_available: bool,
    pub hotplug_watch_available: bool,
}
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModeTestEvent {
    Progress {
        event: OperationEvent,
    },
    Observation {
        device: Box<DeviceIdentity>,
        info: Option<wpi_protocol::flash::FlashInfo>,
        correlation: ReconnectReport,
    },
    Command {
        action: &'static str,
        delivery: &'static str,
    },
    IdentityObservation {
        device: Box<DeviceIdentity>,
        info: Option<wpi_protocol::flash::FlashInfo>,
        public_id_matches: bool,
        normal_serial_matches: Option<bool>,
        physical_port_matches: bool,
        identity_authenticated: bool,
        recovery_authorized: bool,
    },
    BootObservation {
        device: Box<DeviceIdentity>,
        info: Option<wpi_protocol::flash::FlashInfo>,
        public_id_verified: bool,
        physical_port_matches: bool,
        recovery_authorized: bool,
    },
    ReconnectDiscovery {
        expected_mode: DeviceMode,
        trigger: &'static str,
        enumeration_ms: u64,
        observed_modes: Vec<DeviceMode>,
        source_removal_observed: bool,
    },
    ReconnectProbe {
        observed_mode: DeviceMode,
        readiness: &'static str,
    },
    SpecAPreflight {
        report: Box<wpi_core::spec_a_preflight::Report>,
    },
    BootGptCandidate {
        report: wpi_core::boot_gpt::Report,
    },
    BootGptSaved {
        report: wpi_core::boot_gpt::Report,
        normal_before_after_correlated: bool,
        identity_authenticated: bool,
    },
}
#[derive(Debug, Serialize)]
pub struct ModeTestSummary {
    pub result: &'static str,
    pub mode_commands_attempted: u8,
    pub normal_reconnection: ReconnectReport,
    pub recovery_authorized: bool,
}

fn redact(mut d: DeviceIdentity) -> DeviceIdentity {
    d.serial = None;
    d.id = "selected-device".into();
    d
}
fn admission(d: &DeviceIdentity, windows_arm64: bool) -> Vec<String> {
    let mut reasons = Vec::new();
    if !windows_arm64 {
        reasons.push("This first experiment is limited to native Windows ARM64.".into());
    }
    if d.mode != DeviceMode::Normal
        || d.vendor_id != 0x0421
        || d.product_id != 0x0661
        || d.variant.as_deref() != Some("RM-875")
        || d.family != BootloaderFamily::SpecA
        || d.firmware.as_deref() != Some(FIRMWARE)
    {
        reasons.push("The experiment requires normal-mode RM-875 / Spec A / firmware 3051.50009.1451.1003 / USB 0421:0661.".into());
    }
    if d.serial.as_deref().is_none_or(|s| s.trim().is_empty()) {
        reasons
            .push("A nonempty local USB serial is required for each returning interface.".into());
    }
    reasons
}

/// Read-only preview. A deserialized or edited preview is never accepted for execution.
pub fn preview(id: &str) -> Result<ModeTestPreview, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let devices = enumerate()?;
    let selected = devices
        .iter()
        .find(|d| d.id == id)
        .ok_or("Selected phone is disconnected")?;
    if selected.mode != DeviceMode::Normal {
        return Err("Preview requires the phone in normal mode".into());
    }
    let (device, mut transport) = open_selected(id)?;
    let p = probe_session(device, &mut transport, true)?;
    let mut blockers = admission(
        &p.device,
        cfg!(all(target_os = "windows", target_arch = "aarch64")),
    );
    if let Some(reason) = live_blocker(&p.device) {
        blockers.push(reason.into());
    }
    if devices.len() != 1 {
        blockers.push("Connect only the selected Lumia for this experiment.".into());
    }
    let physical_port_binding_available = nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .find(|d| format!("{:?}", d.id()) == id)
        .is_some_and(|d| physical_port(&d).is_some());
    if !physical_port_binding_available {
        blockers.push("The selected phone has no usable physical USB port binding.".into());
    }
    let hotplug_watch_available = nusb::watch_devices().is_ok();
    if !hotplug_watch_available {
        blockers.push("Native USB hotplug observation is unavailable.".into());
    }
    Ok(ModeTestPreview {
        experiment: "rm875_normal_flash_normal",
        eligible_for_experiment: blockers.is_empty(),
        blockers,
        device: redact(p.device),
        confirmation_phrase: CONFIRMATION,
        actions: vec![
            "Re-read and bind the selected normal-mode phone",
            "Send SetDeviceMode(Flash, HwReset) exactly once",
            "Observe removal and correlate the returning USB serial and physical port",
            "Read NOKV/FVER; if BootManager 1/2 is observed, send NOKS once and re-probe",
            "After a correlated FlashApp probe, send NOKR once and confirm normal-mode identity",
        ],
        reconnect_timeout_seconds: RECONNECT_LIMIT.as_secs(),
        recovery_authorized: false,
        production_mode_switching_available: false,
        physical_port_binding_available,
        hotplug_watch_available,
    })
}

/// Explicit CLI-only experiment. No browser/Tauri IPC exposes this entry point.
pub fn run<F: FnMut(&ModeTestEvent) -> bool>(
    id: &str,
    confirmation: &str,
    cancelled: &AtomicBool,
    event: F,
) -> Result<ModeTestSummary, String> {
    if confirmation != CONFIRMATION {
        return Err("The exact experimental confirmation phrase is required".into());
    }
    if !cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        return Err("Hardware mode testing is currently limited to Windows ARM64".into());
    }
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let watch = nusb::watch_devices().map_err(|e| format!("Cannot arm USB hotplug watch: {e}"))?;
    let devices: Vec<_> = nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .filter(|d| wpi_core::classify_usb(d.vendor_id(), d.product_id()).is_some())
        .collect();
    if devices.len() != 1 {
        return Err("Connect exactly one recognized Lumia for this experiment".into());
    }
    let selected = devices
        .first()
        .filter(|d| format!("{:?}", d.id()) == id)
        .ok_or("Selected phone changed; prepare a new preview")?;
    if selected.serial_number().is_none_or(|s| s.trim().is_empty())
        || physical_port(selected).is_none()
    {
        return Err("Serial and physical USB port binding are required".into());
    }
    let mut driver = NativeDriver {
        watch,
        removed: HashSet::new(),
        change_generation: 0,
        serial: selected.serial_number().unwrap().into(),
        port: physical_port(selected).unwrap(),
    };
    let descriptor = identity(selected, DeviceMode::Normal);
    let baseline = driver
        .probe(&descriptor, Instant::now() + Duration::from_secs(20))
        .map_err(|e| e.message())?;
    if let Some(reason) = live_blocker(&baseline.device) {
        return Err(reason.into());
    }
    round_trip(&mut driver, baseline.device, true, cancelled, event)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    EnterFlash,
    BootManagerToFlash(u8),
    ReturnNormal,
}
struct Sent {
    requires_disconnect: bool,
    uncertain: bool,
}
enum DriverError {
    NotReady(String),
    Fatal(String),
}
impl DriverError {
    fn message(self) -> String {
        match self {
            Self::NotReady(s) | Self::Fatal(s) => s,
        }
    }
}
trait Driver {
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String>;
    fn arm(&mut self, id: &str) -> Result<(), String>;
    fn removed(&mut self, id: &str) -> Result<bool, String>;
    fn probe(
        &mut self,
        descriptor: &DeviceIdentity,
        deadline: Instant,
    ) -> Result<ProbeResult, DriverError>;
    fn send(
        &mut self,
        current: &DeviceIdentity,
        baseline: &DeviceIdentity,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Sent, String>;
    fn now(&self) -> Instant;
    fn pause(&mut self);
}
struct NativeDriver {
    watch: nusb::hotplug::HotplugWatch,
    removed: HashSet<String>,
    change_generation: u64,
    serial: String,
    port: PhysicalPort,
}
impl NativeDriver {
    fn check_binding(&self, id: &str) -> Result<(), DriverError> {
        let d = nusb::list_devices()
            .wait()
            .map_err(|e| DriverError::NotReady(e.to_string()))?
            .find(|d| format!("{:?}", d.id()) == id)
            .ok_or_else(|| DriverError::NotReady("Selected interface is not present".into()))?;
        if let Some(reason) = binding_error(
            &self.serial,
            d.serial_number(),
            physical_port(&d).as_ref() == Some(&self.port),
        ) {
            return Err(DriverError::Fatal(reason));
        }
        Ok(())
    }
    fn drain(&mut self) -> Result<(), String> {
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..256 {
            match Pin::new(&mut self.watch).poll_next(&mut cx) {
                Poll::Ready(Some(HotplugEvent::Disconnected(id))) => {
                    self.change_generation = self
                        .change_generation
                        .checked_add(1)
                        .ok_or("USB hotplug generation overflow")?;
                    self.removed.insert(format!("{id:?}"));
                }
                Poll::Ready(Some(HotplugEvent::Connected(_))) => {
                    self.change_generation = self
                        .change_generation
                        .checked_add(1)
                        .ok_or("USB hotplug generation overflow")?;
                }
                Poll::Pending => return Ok(()),
                Poll::Ready(None) => return Err("USB hotplug watch ended".into()),
            }
        }
        Err("USB hotplug event flood; stop and inspect connections".into())
    }
}
impl Driver for NativeDriver {
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String> {
        let mut result = Vec::new();
        for d in nusb::list_devices().wait().map_err(|e| e.to_string())? {
            if let Some(mode) = wpi_core::classify_usb(d.vendor_id(), d.product_id()) {
                if let Some(reason) = binding_error(
                    &self.serial,
                    d.serial_number(),
                    physical_port(&d).as_ref() == Some(&self.port),
                ) {
                    return Err(reason);
                }
                result.push(identity(&d, mode));
            }
        }
        Ok(result)
    }
    fn arm(&mut self, id: &str) -> Result<(), String> {
        self.drain()?;
        self.removed.remove(id);
        Ok(())
    }
    fn removed(&mut self, id: &str) -> Result<bool, String> {
        self.drain()?;
        Ok(self.removed.contains(id))
    }
    fn probe(
        &mut self,
        expected: &DeviceIdentity,
        deadline: Instant,
    ) -> Result<ProbeResult, DriverError> {
        self.check_binding(&expected.id)?;
        let (descriptor, mut transport) =
            open_selected(&expected.id).map_err(DriverError::NotReady)?;
        if descriptor.serial != expected.serial
            || descriptor.vendor_id != expected.vendor_id
            || descriptor.product_id != expected.product_id
        {
            return Err(DriverError::Fatal(
                "USB identity changed before probe".into(),
            ));
        }
        transport.deadline = Some(deadline);
        probe_session(descriptor, &mut transport, true).map_err(DriverError::Fatal)
    }
    fn send(
        &mut self,
        current: &DeviceIdentity,
        baseline: &DeviceIdentity,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Sent, String> {
        self.check_binding(&current.id).map_err(|e| e.message())?;
        let (descriptor, mut transport) = open_selected(&current.id)?;
        if descriptor.serial != current.serial
            || descriptor.vendor_id != current.vendor_id
            || descriptor.product_id != current.product_id
        {
            return Err("USB identity changed before command".into());
        }
        transport.deadline = Some(Instant::now() + Duration::from_secs(20));
        let fresh = probe_session(descriptor, &mut transport, true)?;
        if wpi_core::reconnect::compare(baseline, &fresh.device, current.mode).status
            != ReconnectStatus::Correlated
        {
            return Err("Source identity or application mode changed before command".into());
        }
        let (from, to) = match action {
            Action::EnterFlash => {
                let reasons = admission(&fresh.device, true);
                if !reasons.is_empty() {
                    return Err(reasons.join("; "));
                }
                (DeviceMode::Normal, DeviceMode::Flash)
            }
            Action::BootManagerToFlash(major) => {
                if fresh.info.as_ref().map(|i| i.protocol_major) != Some(major) {
                    return Err("BootManager protocol changed before command".into());
                }
                (DeviceMode::BootManager, DeviceMode::Flash)
            }
            Action::ReturnNormal => (DeviceMode::Flash, DeviceMode::Normal),
        };
        if fresh.device.mode != from {
            return Err("Unexpected source application; no mode command was sent".into());
        }
        let command = wpi_protocol::mode::command(
            from,
            to,
            baseline.family,
            fresh.info.as_ref().map(|i| i.protocol_major),
        )
        .map_err(|e| e.to_string())?;
        if command.status_signature.is_some() {
            return Err("Acknowledged context switches are outside this experiment".into());
        }
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled after source revalidation; no mode command was sent".into());
        }
        let uncertain = transport.send_once(&command.request).is_err();
        Ok(Sent {
            requires_disconnect: command.requires_disconnect,
            uncertain,
        })
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn pause(&mut self) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Reporter<F> {
    emit: F,
    sequence: u64,
    attempted: u8,
}
impl<F: FnMut(&ModeTestEvent) -> bool> Reporter<F> {
    fn progress(&mut self, state: OperationState, message: &str) -> bool {
        self.sequence += 1;
        (self.emit)(&ModeTestEvent::Progress {
            event: OperationEvent {
                sequence: self.sequence,
                operation: Operation::SwitchMode,
                state,
                completed_bytes: 0,
                total_bytes: 0,
                message: message.into(),
            },
        })
    }
    fn stopped(&mut self, message: &str) -> String {
        self.progress(
            if self.attempted == 0 {
                OperationState::Failed
            } else {
                OperationState::RecoveryRequired
            },
            message,
        );
        format!(
            "{message}. {}",
            if self.attempted == 0 {
                "No mode-change command was attempted"
            } else {
                "A mode command may have reached the phone. Inspect its state; do not automatically retry. No firmware write was sent"
            }
        )
    }
}
fn round_trip<D: Driver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    baseline: DeviceIdentity,
    windows_arm64: bool,
    cancelled: &AtomicBool,
    emit: F,
) -> Result<ModeTestSummary, String> {
    let reasons = admission(&baseline, windows_arm64);
    if !reasons.is_empty() {
        return Err(reasons.join("; "));
    }
    let mut reporter = Reporter {
        emit,
        sequence: 0,
        attempted: 0,
    };
    let result = (|| {
        if !(reporter.emit)(&ModeTestEvent::Observation {
            device: Box::new(redact(baseline.clone())),
            info: None,
            correlation: wpi_core::reconnect::compare(&baseline, &baseline, DeviceMode::Normal),
        }) {
            return Err("Baseline journal failed before any mode command".into());
        }
        let mut current = baseline.clone();
        let first = send(
            driver,
            &baseline,
            &current,
            Action::EnterFlash,
            cancelled,
            &mut reporter,
        )?;
        let mut observed = wait(
            driver,
            &baseline,
            &current.id,
            first.requires_disconnect,
            &[DeviceMode::Flash, DeviceMode::BootManager],
            cancelled,
            &mut reporter,
        )?;
        if observed.device.mode == DeviceMode::BootManager {
            let major = observed
                .info
                .as_ref()
                .map(|i| i.protocol_major)
                .ok_or("BootManager protocol missing")?;
            if !matches!(major, 1 | 2) {
                return Err("Unreviewed BootManager protocol; no NOKS was sent".into());
            }
            current = observed.device;
            let sent = send(
                driver,
                &baseline,
                &current,
                Action::BootManagerToFlash(major),
                cancelled,
                &mut reporter,
            )?;
            observed = wait(
                driver,
                &baseline,
                &current.id,
                sent.requires_disconnect,
                &[DeviceMode::Flash],
                cancelled,
                &mut reporter,
            )?;
        }
        if observed.device.platform_id.as_deref() != Some(PLATFORM) {
            return Err(
                "FlashApp platform does not match the RM-875 experiment; stop for inspection"
                    .into(),
            );
        }
        current = observed.device;
        let returned = send(
            driver,
            &baseline,
            &current,
            Action::ReturnNormal,
            cancelled,
            &mut reporter,
        )?;
        let normal = wait(
            driver,
            &baseline,
            &current.id,
            returned.requires_disconnect,
            &[DeviceMode::Normal],
            cancelled,
            &mut reporter,
        )?;
        let report = wpi_core::reconnect::compare(&baseline, &normal.device, DeviceMode::Normal);
        if cancelled.load(Ordering::Acquire)
            || !reporter.progress(
                OperationState::Running,
                "Normal-mode identity restored; final cancellation boundary",
            )
        {
            return Err("Cancelled before recording completion".into());
        }
        reporter.progress(
            OperationState::Completed,
            "Native mode experiment completed in Normal; no firmware or partition writes",
        );
        Ok(ModeTestSummary {
            result: "normal_flash_normal_observed",
            mode_commands_attempted: reporter.attempted,
            normal_reconnection: report,
            recovery_authorized: false,
        })
    })();
    result.map_err(|e: String| reporter.stopped(&e))
}
fn send<D: Driver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    baseline: &DeviceIdentity,
    current: &DeviceIdentity,
    action: Action,
    cancelled: &AtomicBool,
    reporter: &mut Reporter<F>,
) -> Result<Sent, String> {
    if cancelled.load(Ordering::Acquire)
        || !reporter.progress(
            OperationState::Running,
            "Revalidate source before one mode-change request",
        )
    {
        return Err("Cancelled at a safe command boundary".into());
    }
    driver.arm(&current.id)?;
    // Journal this boundary before entering a driver that could deliver an uncertain command.
    if !reporter.progress(
        OperationState::Running,
        "About to attempt one mode command; interruption requires state inspection",
    ) {
        return Err("Event journal failed or cancellation requested before command".into());
    }
    let sent = driver.send(current, baseline, action, cancelled)?;
    reporter.attempted += 1;
    if !(reporter.emit)(&ModeTestEvent::Command {
        action: match action {
            Action::EnterFlash => "SetDeviceMode(Flash, HwReset)",
            Action::BootManagerToFlash(_) => "NOKS from re-probed BootManager",
            Action::ReturnNormal => "NOKR from re-probed FlashApp",
        },
        delivery: if sent.uncertain {
            "uncertain_no_retry"
        } else {
            "complete_out_once"
        },
    }) {
        return Err("Command journal failed or cancellation requested after attempt".into());
    }
    if !reporter.progress(
        OperationState::AwaitingReconnect,
        if sent.uncertain {
            "Command delivery uncertain; awaiting fresh observations without retry"
        } else {
            "Command sent once; awaiting fresh observations"
        },
    ) {
        return Err("Cancelled after command attempt".into());
    }
    Ok(sent)
}
fn wait<D: Driver, F: FnMut(&ModeTestEvent) -> bool>(
    driver: &mut D,
    baseline: &DeviceIdentity,
    source: &str,
    require_removal: bool,
    modes: &[DeviceMode],
    cancelled: &AtomicBool,
    reporter: &mut Reporter<F>,
) -> Result<ProbeResult, String> {
    let deadline = driver.now() + RECONNECT_LIMIT;
    let mut removed = !require_removal;
    while driver.now() < deadline {
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled while waiting; no further mode request was sent".into());
        }
        let devices = driver.devices()?;
        removed |= driver.removed(source)? || !devices.iter().any(|d| d.id == source);
        if devices.len() > 1 {
            return Err("Multiple returning interfaces; explicit inspection is required".into());
        }
        if removed {
            if let Some(descriptor) = devices.first() {
                if !matches!(descriptor.mode, DeviceMode::Normal | DeviceMode::Flash) {
                    return Err(
                        "Unexpected returning transport mode; no protected interface was claimed"
                            .into(),
                    );
                }
                if descriptor.serial != baseline.serial {
                    return Err(
                        "Returning USB serial differs; no query or command was sent to it".into(),
                    );
                }
                let observed = match driver.probe(descriptor, deadline) {
                    Ok(p) => p,
                    Err(DriverError::NotReady(_)) => {
                        driver.pause();
                        continue;
                    }
                    Err(e) => return Err(e.message()),
                };
                if driver.now() >= deadline {
                    return Err("Reconnection deadline expired during probe".into());
                }
                let correlation =
                    wpi_core::reconnect::compare(baseline, &observed.device, observed.device.mode);
                if correlation.status != ReconnectStatus::Correlated {
                    return Err("Fresh returning identity contradicts the baseline".into());
                }
                if !(reporter.emit)(&ModeTestEvent::Observation {
                    device: Box::new(redact(observed.device.clone())),
                    info: observed.info.clone(),
                    correlation,
                }) {
                    return Err("Observation journal failed or cancellation requested".into());
                }
                if modes.contains(&observed.device.mode) {
                    return Ok(observed);
                }
                // Normal boot can expose BootManager/Flash temporarily. Only repeat successful read-only queries.
                if modes == [DeviceMode::Normal]
                    && matches!(
                        observed.device.mode,
                        DeviceMode::Flash | DeviceMode::BootManager
                    )
                {
                    driver.pause();
                    continue;
                }
                return Err("Unexpected returning application mode".into());
            }
        }
        driver.pause();
    }
    Err("No validated returning interface before the 30-second deadline. Flash WinUSB binding may be missing; no driver was installed or changed".into())
}
