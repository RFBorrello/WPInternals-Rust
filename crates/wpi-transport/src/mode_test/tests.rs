use super::*;
use std::collections::VecDeque;

fn baseline() -> DeviceIdentity {
    DeviceIdentity {
        id: "normal-before".into(),
        vendor_id: 0x0421,
        product_id: 0x0661,
        manufacturer: Some("Nokia".into()),
        product: Some("Synthetic phone".into()),
        serial: Some("SYNTHETIC-ONLY".into()),
        model: Some("Lumia 1020".into()),
        variant: Some("RM-875".into()),
        firmware: Some(FIRMWARE.into()),
        platform_id: None,
        family: BootloaderFamily::SpecA,
        mode: DeviceMode::Normal,
        interfaces: vec![],
    }
}
fn observed(mode: DeviceMode, id: &str, major: u8) -> ProbeResult {
    let mut d = baseline();
    d.id = id.into();
    d.mode = mode;
    let info = if mode != DeviceMode::Normal {
        d.product_id = 0x066e;
        d.variant = None;
        d.model = None;
        d.family = BootloaderFamily::Unknown;
        if mode == DeviceMode::BootManager {
            d.firmware = None;
        } else {
            d.platform_id = Some(PLATFORM.into());
        }
        let app = if mode == DeviceMode::BootManager {
            1
        } else {
            2
        };
        let mut response = vec![b'N', b'O', b'K', b'V', 0, app, major, 0, 1, 0, 0];
        if mode == DeviceMode::Flash {
            response[10] = 1;
            response.push(5);
            response.extend_from_slice(&(PLATFORM.len() as u16).to_be_bytes());
            response.extend_from_slice(PLATFORM.as_bytes());
        }
        Some(wpi_protocol::flash::parse_info(&response).unwrap())
    } else {
        None
    };
    ProbeResult {
        firmware: d.firmware.clone(),
        device: d,
        info,
        normal: None,
    }
}
#[derive(Clone)]
struct Frame {
    devices: Vec<DeviceIdentity>,
    probe: Option<ProbeResult>,
    error: Option<&'static str>,
    not_ready: bool,
    removed: bool,
}
fn arrival(mode: DeviceMode, id: &str, major: u8) -> Frame {
    let p = observed(mode, id, major);
    let mut descriptor = p.device.clone();
    if mode == DeviceMode::BootManager {
        descriptor.mode = DeviceMode::Flash;
    }
    Frame {
        devices: vec![descriptor],
        probe: Some(p),
        error: None,
        not_ready: false,
        removed: false,
    }
}
fn absent() -> Frame {
    Frame {
        devices: vec![],
        probe: None,
        error: None,
        not_ready: false,
        removed: false,
    }
}
struct FakeDriver {
    frames: VecDeque<Frame>,
    current: Frame,
    clock: Instant,
    actions: Vec<Action>,
    probes: usize,
    uncertain: bool,
    send_error: bool,
    topology_error: bool,
    cancel_in_send: bool,
}
impl FakeDriver {
    fn new(frames: Vec<Frame>) -> Self {
        Self {
            frames: frames.into(),
            current: absent(),
            clock: Instant::now(),
            actions: vec![],
            probes: 0,
            uncertain: false,
            send_error: false,
            topology_error: false,
            cancel_in_send: false,
        }
    }
}
impl Driver for FakeDriver {
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String> {
        if self.topology_error {
            return Err("Different physical USB port".into());
        }
        self.current = self.frames.pop_front().unwrap_or_else(absent);
        Ok(self.current.devices.clone())
    }
    fn arm(&mut self, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn removed(&mut self, _: &str) -> Result<bool, String> {
        Ok(self.current.removed)
    }
    fn probe(&mut self, _: &DeviceIdentity, _: Instant) -> Result<ProbeResult, DriverError> {
        self.probes += 1;
        if self.current.not_ready {
            return Err(DriverError::NotReady("Interface not ready".into()));
        }
        if let Some(e) = self.current.error {
            return Err(DriverError::Fatal(e.into()));
        }
        Ok(self.current.probe.clone().unwrap())
    }
    fn send(
        &mut self,
        _: &DeviceIdentity,
        _: &DeviceIdentity,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Sent, String> {
        if self.cancel_in_send {
            cancelled.store(true, Ordering::Release);
            return Err("Cancelled after source revalidation; no mode command was sent".into());
        }
        if self.send_error {
            return Err("Source changed before mode command".into());
        }
        self.actions.push(action);
        Ok(Sent {
            requires_disconnect: !matches!(action, Action::BootManagerToFlash(2)),
            uncertain: self.uncertain,
        })
    }
    fn now(&self) -> Instant {
        self.clock
    }
    fn pause(&mut self) {
        self.clock += Duration::from_secs(5);
    }
}
fn direct() -> Vec<Frame> {
    vec![
        arrival(DeviceMode::Flash, "flash", 1),
        arrival(DeviceMode::Normal, "normal-after", 0),
    ]
}
fn run_fake(driver: &mut FakeDriver) -> Result<ModeTestSummary, String> {
    round_trip(driver, baseline(), true, &AtomicBool::new(false), |_| true)
}

#[test]
fn round_trip_sends_only_two_mode_commands_and_redacts_observations() {
    let mut d = FakeDriver::new(direct());
    let mut log = Vec::new();
    let r = round_trip(&mut d, baseline(), true, &AtomicBool::new(false), |e| {
        log.push(serde_json::to_value(e).unwrap());
        true
    })
    .unwrap();
    assert_eq!(d.actions, [Action::EnterFlash, Action::ReturnNormal]);
    assert_eq!(r.mode_commands_attempted, 2);
    assert!(!r.recovery_authorized);
    assert_eq!(r.normal_reconnection.status, ReconnectStatus::Correlated);
    assert!(!serde_json::to_string(&log)
        .unwrap()
        .contains("SYNTHETIC-ONLY"));
    assert_eq!(log.last().unwrap()["event"]["state"], "completed");
}
#[test]
fn bootmanager_versions_use_hotplug_removal_or_in_place_probe() {
    for major in [1, 2] {
        let mut frames = vec![arrival(DeviceMode::BootManager, "boot", major)];
        if major == 1 {
            frames.push(arrival(DeviceMode::Flash, "boot", 1));
        }
        let mut flash = arrival(DeviceMode::Flash, "boot", 1);
        flash.removed = major == 1;
        frames.push(flash);
        frames.push(arrival(DeviceMode::Normal, "normal-after", 0));
        let mut d = FakeDriver::new(frames);
        run_fake(&mut d).unwrap();
        assert_eq!(
            d.actions,
            [
                Action::EnterFlash,
                Action::BootManagerToFlash(major),
                Action::ReturnNormal
            ]
        );
        assert_eq!(d.probes, 3);
    }
}
#[test]
fn uncertain_delivery_is_inspected_without_retrying_the_command() {
    let mut d = FakeDriver::new(direct());
    d.uncertain = true;
    run_fake(&mut d).unwrap();
    assert_eq!(d.actions, [Action::EnterFlash, Action::ReturnNormal]);
    let mut d = FakeDriver::new(vec![]);
    d.uncertain = true;
    assert!(run_fake(&mut d).unwrap_err().contains("30-second deadline"));
    assert_eq!(d.actions, [Action::EnterFlash]);
}
#[test]
fn wrong_or_missing_identity_and_ambiguous_devices_never_receive_queries_or_resets() {
    for kind in ["wrong", "missing", "multiple", "topology", "transport"] {
        let mut f = arrival(DeviceMode::Flash, "flash", 1);
        match kind {
            "wrong" => f.devices[0].serial = Some("OTHER".into()),
            "missing" => f.devices[0].serial = None,
            "multiple" => f.devices.push(f.devices[0].clone()),
            "transport" => {
                f.devices[0].mode = DeviceMode::MassStorage;
                f.devices[0].product_id = 0x0660;
            }
            _ => {}
        }
        let mut d = FakeDriver::new(vec![f]);
        d.topology_error = kind == "topology";
        assert!(run_fake(&mut d).is_err());
        assert_eq!(d.actions, [Action::EnterFlash]);
        assert_eq!(d.probes, 0);
    }
}
#[test]
fn protocol_failures_platform_mismatch_and_unknown_bootmanager_stop_without_reset() {
    for kind in ["timeout", "malformed", "platform", "protocol", "firmware"] {
        let mut f = arrival(
            if kind == "protocol" {
                DeviceMode::BootManager
            } else {
                DeviceMode::Flash
            },
            "flash",
            3,
        );
        match kind {
            "timeout" => f.error = Some("USB IN timed out"),
            "malformed" => f.error = Some("Invalid NOKV response"),
            "platform" => f.probe.as_mut().unwrap().device.platform_id = Some("DIFFERENT".into()),
            "firmware" => f.probe.as_mut().unwrap().device.firmware = Some("DIFFERENT".into()),
            _ => {}
        }
        let mut d = FakeDriver::new(vec![f]);
        assert!(run_fake(&mut d).is_err());
        assert_eq!(d.actions, [Action::EnterFlash]);
        assert_eq!(d.probes, 1);
    }
}
#[test]
fn interface_readiness_can_retry_open_but_not_an_interrupted_query() {
    let mut f = arrival(DeviceMode::Flash, "flash", 1);
    f.not_ready = true;
    let mut frames = vec![f];
    frames.extend(direct());
    let mut d = FakeDriver::new(frames);
    run_fake(&mut d).unwrap();
    assert_eq!(d.actions.len(), 2);
    assert_eq!(d.probes, 3);
}
#[test]
fn normal_boot_transients_are_read_only_and_do_not_trigger_extra_mode_commands() {
    let mut d = FakeDriver::new(vec![
        arrival(DeviceMode::Flash, "flash", 1),
        arrival(DeviceMode::BootManager, "boot-return", 1),
        arrival(DeviceMode::Normal, "normal-after", 0),
    ]);
    run_fake(&mut d).unwrap();
    assert_eq!(d.actions, [Action::EnterFlash, Action::ReturnNormal]);
    assert_eq!(d.probes, 3);
}
#[test]
fn cancellation_and_journal_failure_before_and_after_commands_are_distinct() {
    let mut d = FakeDriver::new(direct());
    assert!(round_trip(&mut d, baseline(), true, &AtomicBool::new(true), |_| true).is_err());
    assert!(d.actions.is_empty());
    let mut d = FakeDriver::new(direct());
    assert!(round_trip(&mut d, baseline(), true, &AtomicBool::new(false), |_| false).is_err());
    assert!(d.actions.is_empty());
    let mut d = FakeDriver::new(direct());
    assert!(round_trip(
        &mut d,
        baseline(),
        true,
        &AtomicBool::new(false),
        |e| !matches!(e, ModeTestEvent::Command { .. })
    )
    .is_err());
    assert_eq!(d.actions, [Action::EnterFlash]);
    assert_eq!(d.probes, 0);
    let mut d = FakeDriver::new(direct());
    d.cancel_in_send = true;
    let error = run_fake(&mut d).unwrap_err();
    assert!(error.contains("No mode-change command was attempted"));
    assert!(d.actions.is_empty());
}
#[test]
fn exact_admission_and_source_change_reject_before_any_mode_command() {
    for kind in ["host", "firmware", "variant", "serial", "mode"] {
        let mut b = baseline();
        let mut d = FakeDriver::new(direct());
        match kind {
            "firmware" => b.firmware = Some("DIFFERENT".into()),
            "variant" => b.variant = Some("RM-1040".into()),
            "serial" => b.serial = None,
            "mode" => b.mode = DeviceMode::Flash,
            _ => {}
        }
        assert!(round_trip(&mut d, b, kind != "host", &AtomicBool::new(false), |_| true).is_err());
        assert!(d.actions.is_empty());
    }
    let mut d = FakeDriver::new(direct());
    d.send_error = true;
    assert!(run_fake(&mut d).is_err());
    assert!(d.actions.is_empty());
}

#[test]
fn native_access_lock_blocks_parallel_probes_and_releases_on_drop() {
    let lock = PHONE_ACCESS.try_lock().unwrap();
    assert!(super::super::probe("not-a-real-device")
        .unwrap_err()
        .contains("Another native phone"));
    drop(lock);
    assert!(PHONE_ACCESS.try_lock().is_ok());
}

#[cfg(target_os = "windows")]
#[test]
fn windows_physical_binding_uses_hub_and_connection_index_not_location_parser() {
    use std::ffi::OsStr;
    let hub = OsStr::new("USB\\ROOT_HUB30\\SYNTHETIC");
    let other = OsStr::new("USB\\ROOT_HUB30\\OTHER");
    assert!(windows_port(OsStr::new(""), 1).is_none());
    assert!(windows_port(hub, 0).is_none());
    assert!(windows_port(hub, 2) == windows_port(hub, 2));
    assert!(windows_port(hub, 2) != windows_port(hub, 3));
    assert!(windows_port(hub, 2) != windows_port(other, 2));
}
