use super::*;
use std::collections::VecDeque;
use wpi_protocol::replay::{Exchange, ReplayTransport};

fn public_id(seed: u8) -> public_identity::PublicId {
    public_identity::parse_normal(
        &serde_json::to_vec(
            &serde_json::json!({"jsonrpc":"2.0","id":4,"result":{"PublicId":vec![seed;20]}}),
        )
        .unwrap(),
        4,
    )
    .unwrap()
}
fn baseline() -> Snapshot {
    Snapshot {
        public_id: public_id(42),
        probe: ProbeResult {
            device: DeviceIdentity {
                id: "normal-before".into(),
                vendor_id: 0x0421,
                product_id: 0x0661,
                manufacturer: None,
                product: None,
                serial: Some("PRIVATE-NORMAL".into()),
                model: Some("Lumia 1020".into()),
                variant: Some("RM-875".into()),
                firmware: Some(FIRMWARE.into()),
                platform_id: None,
                family: BootloaderFamily::SpecA,
                mode: DeviceMode::Normal,
                interfaces: vec![],
            },
            firmware: Some(FIRMWARE.into()),
            normal: None,
            info: None,
        },
    }
}
fn snapshot(mode: DeviceMode, id: &str) -> Snapshot {
    let mut s = baseline();
    s.probe.device.id = id.into();
    s.probe.device.mode = mode;
    if mode == DeviceMode::Flash {
        let d = &mut s.probe.device;
        d.product_id = 0x066e;
        d.serial = None;
        d.model = None;
        d.variant = None;
        d.firmware = None;
        d.family = BootloaderFamily::Unknown;
        d.platform_id = Some(FLASH_PLATFORM.into());
        s.probe.firmware = None;
        s.probe.info = Some(wpi_protocol::flash::FlashInfo {
            mode,
            protocol_major: 1,
            protocol_minor: 18,
            version_major: 2,
            version_minor: 2,
            platform_id: Some(FLASH_PLATFORM.into()),
            transfer_size: None,
            write_buffer_size: None,
            emmc_sectors: None,
            secure_ffu: None,
            secure_boot: None,
            protocol_mask: None,
        });
    }
    s
}
#[derive(Clone)]
struct Frame {
    observations: Vec<Snapshot>,
    not_ready: bool,
    error: Option<&'static str>,
    removed: bool,
    port_matches: bool,
}
fn frame(mode: DeviceMode, id: &str) -> Frame {
    Frame {
        observations: vec![snapshot(mode, id)],
        not_ready: false,
        error: None,
        removed: false,
        port_matches: true,
    }
}
fn empty() -> Frame {
    Frame {
        observations: vec![],
        not_ready: false,
        error: None,
        removed: false,
        port_matches: true,
    }
}
fn direct() -> Vec<Frame> {
    vec![
        frame(DeviceMode::Flash, "flash"),
        frame(DeviceMode::Normal, "normal-after"),
    ]
}
struct Fake {
    frames: VecDeque<Frame>,
    current: Frame,
    clock: Instant,
    actions: Vec<Action>,
    probes: usize,
    source_before_flash: Snapshot,
    source_before_normal: Snapshot,
    uncertain: bool,
    cancel_after_probe: bool,
}
impl Fake {
    fn new(frames: Vec<Frame>) -> Self {
        Self {
            frames: frames.into(),
            current: empty(),
            clock: Instant::now(),
            actions: vec![],
            probes: 0,
            source_before_flash: baseline(),
            source_before_normal: snapshot(DeviceMode::Flash, "flash"),
            uncertain: false,
            cancel_after_probe: false,
        }
    }
}
impl IdentityDriver for Fake {
    fn devices(&mut self) -> Result<Vec<DeviceIdentity>, String> {
        self.current = self.frames.pop_front().unwrap_or_else(empty);
        if !self.current.port_matches {
            return Err("Physical USB port changed".into());
        }
        Ok(self
            .current
            .observations
            .iter()
            .map(|s| {
                let mut d = s.probe.device.clone();
                if d.mode == DeviceMode::BootManager {
                    d.mode = DeviceMode::Flash;
                }
                d
            })
            .collect())
    }
    fn arm(&mut self, _: &str) -> Result<(), String> {
        self.current.removed = false;
        Ok(())
    }
    fn removed(&mut self, _: &str) -> Result<bool, String> {
        Ok(self.current.removed)
    }
    fn probe(
        &mut self,
        _: &DeviceIdentity,
        _: Instant,
        allow_boot: bool,
    ) -> Result<Observation, DriverError> {
        self.probes += 1;
        if self.current.not_ready {
            return Err(DriverError::NotReady("WinUSB not yet ready".into()));
        }
        if let Some(e) = self.current.error {
            return Err(DriverError::Fatal(e.into()));
        }
        let snapshot = self.current.observations[0].clone();
        if allow_boot
            && snapshot.probe.device.mode == DeviceMode::BootManager
            && snapshot
                .probe
                .info
                .as_ref()
                .is_some_and(|i| matches!(i.protocol_major, 1 | 2))
        {
            Ok(Observation::Boot(snapshot.probe))
        } else {
            Ok(Observation::Identity(snapshot))
        }
    }
    fn send(
        &mut self,
        current: &Snapshot,
        baseline: &Snapshot,
        action: Action,
        cancelled: &AtomicBool,
    ) -> Result<Sent, String> {
        let fresh = if action == Action::EnterFlash {
            &self.source_before_flash
        } else {
            &self.source_before_normal
        };
        validate(fresh, baseline, current.probe.device.mode)?;
        if self.cancel_after_probe {
            cancelled.store(true, Ordering::Release);
        }
        if cancelled.load(Ordering::Acquire) {
            return Err("Cancelled after source revalidation".into());
        }
        self.actions.push(action);
        Ok(Sent {
            requires_disconnect: true,
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
fn run_fake(fake: &mut Fake) -> Result<Summary, String> {
    round_trip(fake, baseline(), &AtomicBool::new(false), |_| true)
}

#[test]
fn missing_flash_serial_requires_public_id_and_only_two_commands_are_sent() {
    let mut fake = Fake::new(direct());
    let mut log = vec![];
    let summary = round_trip(&mut fake, baseline(), &AtomicBool::new(false), |e| {
        log.push(serde_json::to_value(e).unwrap());
        true
    })
    .unwrap();
    assert_eq!(fake.actions, [Action::EnterFlash, Action::ReturnNormal]);
    assert_eq!(summary.mode_commands_attempted, 2);
    assert!(summary.public_id_matched_in_both_modes);
    assert_eq!(
        summary.normal_reconnection.status,
        ReconnectStatus::Correlated
    );
    assert!(!summary.recovery_authorized);
    let text = serde_json::to_string(&log).unwrap();
    assert!(!text.contains("PRIVATE-NORMAL"));
    assert!(!text.contains("42,42"));
    assert_eq!(log.last().unwrap()["event"]["state"], "completed");
}
#[test]
fn wrong_public_id_port_available_serial_or_usb_mode_stops_before_return_reset() {
    for kind in [
        "public_id",
        "port",
        "serial",
        "usb",
        "multiple",
        "bootmanager",
    ] {
        let mut f = frame(DeviceMode::Flash, "flash");
        match kind {
            "public_id" => f.observations[0].public_id = public_id(43),
            "port" => f.port_matches = false,
            "serial" => f.observations[0].probe.device.serial = Some("PRIVATE-OTHER".into()),
            "usb" => f.observations[0].probe.device.product_id = 0x066f,
            "multiple" => f.observations.push(f.observations[0].clone()),
            "bootmanager" => {
                f.observations[0].probe.device.mode = DeviceMode::BootManager;
                f.observations[0].probe.info.as_mut().unwrap().mode = DeviceMode::BootManager;
            }
            _ => unreachable!(),
        }
        let mut fake = Fake::new(vec![f]);
        assert!(run_fake(&mut fake).is_err(), "{kind}");
        assert_eq!(fake.actions, [Action::EnterFlash]);
        if matches!(kind, "port" | "serial" | "usb" | "multiple") {
            assert_eq!(fake.probes, 0);
        }
    }
}
#[test]
fn changed_command_handle_identity_blocks_out_before_and_after_entering_flash() {
    for phase in ["enter", "return"] {
        let mut fake = Fake::new(direct());
        if phase == "enter" {
            fake.source_before_flash.public_id = public_id(43);
        } else {
            fake.source_before_normal.public_id = public_id(43);
        }
        assert!(run_fake(&mut fake).is_err());
        assert_eq!(fake.actions.len(), usize::from(phase == "return"));
    }
}
#[test]
fn exact_flash_profile_and_fresh_normal_firmware_serial_and_public_id_are_required() {
    for kind in [
        "platform",
        "protocol",
        "version",
        "info_platform",
        "normal_firmware",
        "normal_serial",
        "normal_id",
        "normal_variant",
    ] {
        let mut frames = direct();
        match kind {
            "platform" => {
                frames[0].observations[0].probe.device.platform_id =
                    Some("Nokia.MSM8960.P5217".into())
            }
            "info_platform" => {
                frames[0].observations[0]
                    .probe
                    .info
                    .as_mut()
                    .unwrap()
                    .platform_id = Some("OTHER".into())
            }
            "protocol" => {
                frames[0].observations[0]
                    .probe
                    .info
                    .as_mut()
                    .unwrap()
                    .protocol_minor = 19
            }
            "version" => {
                frames[0].observations[0]
                    .probe
                    .info
                    .as_mut()
                    .unwrap()
                    .version_minor = 3
            }
            "normal_firmware" => {
                frames[1].observations[0].probe.device.firmware = Some("CHANGED".into())
            }
            "normal_serial" => frames[1].observations[0].probe.device.serial = None,
            "normal_id" => frames[1].observations[0].public_id = public_id(43),
            "normal_variant" => {
                frames[1].observations[0].probe.device.variant = Some("RM-876".into())
            }
            _ => unreachable!(),
        }
        let mut fake = Fake::new(frames);
        assert!(run_fake(&mut fake).is_err(), "{kind}");
        assert_eq!(
            fake.actions.len(),
            if kind.starts_with("normal_") { 2 } else { 1 }
        );
    }
}
#[test]
fn stale_arrival_timeout_and_failed_information_query_never_retry_mode_or_query() {
    let mut stale = frame(DeviceMode::Flash, "normal-before");
    stale.observations[0].probe.device.serial = None;
    let mut fake = Fake::new(vec![stale]);
    assert!(run_fake(&mut fake).unwrap_err().contains("30-second"));
    assert_eq!(fake.probes, 0);
    for message in [
        "disconnected",
        "malformed terminal response",
        "USB IN timeout",
    ] {
        let mut f = frame(DeviceMode::Flash, "flash");
        f.error = Some(message);
        let mut fake = Fake::new(vec![f]);
        assert!(run_fake(&mut fake).unwrap_err().contains(message));
        assert_eq!(fake.probes, 1);
        assert_eq!(fake.actions, [Action::EnterFlash]);
    }
    let mut fake = Fake::new(vec![]);
    fake.uncertain = true;
    assert!(run_fake(&mut fake).is_err());
    assert_eq!(fake.actions, [Action::EnterFlash]);
    let mut fake = Fake::new(direct());
    fake.uncertain = true;
    run_fake(&mut fake).unwrap();
    assert_eq!(fake.actions.len(), 2);
}
#[test]
fn only_interface_readiness_can_retry_and_normal_boot_transients_never_add_resets() {
    let mut early = frame(DeviceMode::Flash, "flash");
    early.not_ready = true;
    let mut frames = vec![early];
    frames.extend(direct());
    let mut fake = Fake::new(frames);
    run_fake(&mut fake).unwrap();
    assert_eq!(fake.probes, 3);
    assert_eq!(fake.actions.len(), 2);
    let mut fake = Fake::new(vec![
        frame(DeviceMode::Flash, "flash"),
        frame(DeviceMode::Flash, "boot-transient"),
        frame(DeviceMode::Normal, "normal-after"),
    ]);
    run_fake(&mut fake).unwrap();
    assert_eq!(fake.actions.len(), 2);
    assert_eq!(fake.probes, 3);
}
#[test]
fn cancellation_and_journal_errors_stop_at_each_command_boundary() {
    let mut fake = Fake::new(direct());
    assert!(round_trip(&mut fake, baseline(), &AtomicBool::new(true), |_| true).is_err());
    assert!(fake.actions.is_empty());
    for kind in [
        "baseline",
        "before_command",
        "after_command",
        "flash_observation",
        "completion",
    ] {
        let mut fake = Fake::new(direct());
        let mut observations = 0;
        let result = round_trip(
            &mut fake,
            baseline(),
            &AtomicBool::new(false),
            |e| match e {
                ModeTestEvent::IdentityObservation { .. } => {
                    observations += 1;
                    !(kind == "baseline" || kind == "flash_observation" && observations == 2)
                }
                ModeTestEvent::Command { .. } => kind != "after_command",
                ModeTestEvent::Progress { event } => {
                    !(kind == "before_command" && event.message.starts_with("About to")
                        || kind == "completion" && event.state == OperationState::Completed)
                }
                _ => true,
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fake.actions.len(),
            match kind {
                "baseline" | "before_command" => 0,
                "completion" => 2,
                _ => 1,
            }
        );
    }
    let mut fake = Fake::new(direct());
    fake.cancel_after_probe = true;
    assert!(run_fake(&mut fake).is_err());
    assert!(fake.actions.is_empty());
}
#[test]
fn blank_baseline_serial_unknown_firmware_and_old_confirmation_cannot_admit() {
    let mut b = baseline();
    b.probe.device.serial = None;
    let mut fake = Fake::new(direct());
    assert!(round_trip(&mut fake, b, &AtomicBool::new(false), |_| true).is_err());
    assert!(fake.actions.is_empty());
    let mut b = baseline();
    b.probe.device.firmware = Some("UNKNOWN".into());
    let mut fake = Fake::new(direct());
    assert!(round_trip(&mut fake, b, &AtomicBool::new(false), |_| true).is_err());
    assert!(fake.actions.is_empty());
    assert!(run(
        "not-a-device",
        super::super::CONFIRMATION,
        &AtomicBool::new(false),
        |_| true
    )
    .unwrap_err()
    .contains("confirmation"));
}
#[test]
fn terminal_codec_failure_reports_only_safe_metadata_and_does_not_send_fver() {
    let info = snapshot(DeviceMode::Flash, "flash").probe.info.unwrap();
    let mut nokv = vec![b'N', b'O', b'K', b'V', 0, 2, 1, 18, 2, 2, 1, 5];
    nokv.extend_from_slice(&(FLASH_PLATFORM.len() as u16).to_be_bytes());
    nokv.extend_from_slice(FLASH_PLATFORM.as_bytes());
    assert_eq!(
        wpi_protocol::flash::parse_info(&nokv).unwrap().platform_id,
        info.platform_id
    );
    let response = b"PRIVATE-PUBLIC-ID-MUST-NOT-LEAK".to_vec();
    let mut replay = ReplayTransport::new(vec![
        Exchange {
            request: b"NOKV".to_vec(),
            response: nokv,
            error: None,
        },
        Exchange {
            request: public_identity::flash_request(),
            response,
            error: None,
        },
    ]);
    let mut device = snapshot(DeviceMode::Flash, "flash").probe.device;
    device.mode = DeviceMode::Flash;
    let error = match read_snapshot(device, &mut replay) {
        Ok(_) => panic!("malformed terminal accepted"),
        Err(e) => e,
    };
    assert!(error.contains("response_length="));
    assert!(!error.contains("PRIVATE"));
    assert!(error.contains("signature=unrecognized"));
    assert!(replay.finished());
}

#[test]
fn snapshot_queries_use_normal_public_id_four_and_flash_terminal_without_fver() {
    let normal_queries = [
        (
            0,
            "ReadManufacturerModelName",
            "ManufacturerModelName",
            "RM-875_eu",
        ),
        (1, "ReadProductCode", "ProductCode", "SYNTHETIC"),
        (2, "ReadSwVersion", "SwVersion", FIRMWARE),
    ];
    let mut exchanges = normal_queries
        .into_iter()
        .map(|(id, method, key, value)| Exchange {
            request: wpi_protocol::normal::request(id, method).unwrap(),
            response: serde_json::to_vec(
                &serde_json::json!({"jsonrpc":"2.0","id":id,"result":{key:value}}),
            )
            .unwrap(),
            error: None,
        })
        .collect::<Vec<_>>();
    exchanges.push(Exchange {
        request: public_identity::normal_request(4),
        response: serde_json::to_vec(
            &serde_json::json!({"jsonrpc":"2.0","id":4,"result":{"PublicId":vec![42;20]}}),
        )
        .unwrap(),
        error: None,
    });
    let mut replay = ReplayTransport::new(exchanges);
    let normal =
        read_snapshot(baseline().probe.device, &mut replay).unwrap_or_else(|e| panic!("{e}"));
    assert!(replay.finished());
    assert!(normal.public_id == public_id(42));
    let mut nokv = vec![b'N', b'O', b'K', b'V', 0, 2, 1, 18, 2, 2, 1, 5];
    nokv.extend_from_slice(&(FLASH_PLATFORM.len() as u16).to_be_bytes());
    nokv.extend_from_slice(FLASH_PLATFORM.as_bytes());
    let mut terminal = vec![0; 32];
    terminal[..6].copy_from_slice(b"NOKXFT");
    terminal[20..24].copy_from_slice(&36u32.to_be_bytes());
    terminal[24..28].copy_from_slice(&0x10000u32.to_le_bytes());
    terminal[28..32].copy_from_slice(&28u32.to_le_bytes());
    terminal.extend_from_slice(&3u32.to_le_bytes());
    terminal.extend_from_slice(&20u32.to_le_bytes());
    terminal.extend_from_slice(&[42; 20]);
    let mut replay = ReplayTransport::new(vec![
        Exchange {
            request: b"NOKV".to_vec(),
            response: nokv,
            error: None,
        },
        Exchange {
            request: public_identity::flash_request(),
            response: terminal,
            error: None,
        },
    ]);
    let flash = read_snapshot(
        snapshot(DeviceMode::Flash, "flash").probe.device,
        &mut replay,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(replay.finished());
    assert!(flash.public_id == normal.public_id);
    assert!(flash.probe.device.firmware.is_none());
}
#[test]
fn unexpected_flash_profile_stops_after_nokv_without_terminal_query() {
    let response = vec![b'N', b'O', b'K', b'V', 0, 1, 1, 18, 2, 2, 0];
    let mut replay = ReplayTransport::new(vec![Exchange {
        request: b"NOKV".to_vec(),
        response,
        error: None,
    }]);
    assert!(read_snapshot(
        snapshot(DeviceMode::Flash, "flash").probe.device,
        &mut replay
    )
    .is_err());
    assert!(replay.finished());
}

fn boot_frame(major: u8) -> Frame {
    let mut frame = frame(DeviceMode::Flash, "boot-stage");
    frame.observations[0].probe.device.mode = DeviceMode::BootManager;
    let info = frame.observations[0].probe.info.as_mut().unwrap();
    info.mode = DeviceMode::BootManager;
    info.protocol_major = major;
    frame
}
#[test]
fn bootmanager_observation_after_nokr_remains_unverified_and_never_adds_a_command() {
    for major in [1, 2] {
        let mut fake = Fake::new(vec![
            frame(DeviceMode::Flash, "flash"),
            boot_frame(major),
            frame(DeviceMode::Normal, "normal-after"),
        ]);
        let mut boot_records = vec![];
        let summary = round_trip(&mut fake, baseline(), &AtomicBool::new(false), |event| {
            if matches!(event, ModeTestEvent::BootObservation { .. }) {
                boot_records.push(serde_json::to_value(event).unwrap());
            }
            true
        })
        .unwrap();
        assert_eq!(fake.actions, [Action::EnterFlash, Action::ReturnNormal]);
        assert_eq!(summary.mode_commands_attempted, 2);
        assert_eq!(boot_records.len(), 1);
        assert_eq!(boot_records[0]["public_id_verified"], false);
        assert_eq!(boot_records[0]["device"]["serial"], serde_json::Value::Null);
    }
}
#[test]
fn bootmanager_codec_only_sends_nokv_and_never_becomes_a_command_snapshot() {
    for major in [1, 2] {
        let response = vec![b'N', b'O', b'K', b'V', 0, 1, major, 0, 1, 0, 0];
        let mut replay = ReplayTransport::new(vec![Exchange {
            request: b"NOKV".to_vec(),
            response: response.clone(),
            error: None,
        }]);
        assert!(matches!(
            read_observation(
                snapshot(DeviceMode::Flash, "boot").probe.device,
                &mut replay,
                true
            )
            .unwrap_or_else(|e| panic!("{e}")),
            Observation::Boot(_)
        ));
        assert!(replay.finished());
        let mut replay = ReplayTransport::new(vec![Exchange {
            request: b"NOKV".to_vec(),
            response,
            error: None,
        }]);
        assert!(read_snapshot(
            snapshot(DeviceMode::Flash, "boot").probe.device,
            &mut replay
        )
        .is_err());
        assert!(replay.finished());
    }
    let mut fake = Fake::new(direct());
    fake.source_before_normal = boot_frame(1).observations.remove(0);
    assert!(run_fake(&mut fake).is_err());
    assert_eq!(fake.actions, [Action::EnterFlash]);
}
#[test]
fn boot_observation_timeout_unknown_protocol_and_topology_changes_cannot_complete_or_reset() {
    for kind in ["timeout", "protocol", "port", "multiple"] {
        let mut boot = boot_frame(if kind == "protocol" { 3 } else { 1 });
        if kind == "port" {
            boot.port_matches = false;
        }
        if kind == "multiple" {
            boot.observations.push(boot.observations[0].clone());
        }
        let mut fake = Fake::new(vec![frame(DeviceMode::Flash, "flash"), boot]);
        assert!(run_fake(&mut fake).is_err(), "{kind}");
        assert_eq!(fake.actions, [Action::EnterFlash, Action::ReturnNormal]);
    }
}

#[test]
fn repeated_boot_interface_is_observed_once_and_retired_until_normal_even_if_id_is_reused() {
    let boot = boot_frame(1);
    let mut racing = boot.clone();
    racing.error = Some("USB OUT timed out during boot departure");
    let mut normal = frame(DeviceMode::Normal, "boot-stage");
    normal.removed = false;
    let mut fake = Fake::new(vec![
        frame(DeviceMode::Flash, "flash"),
        boot,
        racing.clone(),
        racing,
        normal,
    ]);
    let mut boot_count = 0;
    let result = round_trip(&mut fake, baseline(), &AtomicBool::new(false), |event| {
        if matches!(event, ModeTestEvent::BootObservation { .. }) {
            boot_count += 1;
        }
        true
    })
    .unwrap();
    assert_eq!(boot_count, 1);
    assert_eq!(fake.probes, 3);
    assert_eq!(result.mode_commands_attempted, 2);
    assert_eq!(fake.actions, [Action::EnterFlash, Action::ReturnNormal]);
}
#[test]
fn retired_interface_requires_new_removal_before_another_boot_probe_and_deadline_never_resets() {
    let boot = boot_frame(1);
    let mut returned = boot.clone();
    returned.removed = true;
    let mut fake = Fake::new(vec![
        frame(DeviceMode::Flash, "flash"),
        boot.clone(),
        returned,
        frame(DeviceMode::Normal, "normal-after"),
    ]);
    run_fake(&mut fake).unwrap();
    assert_eq!(fake.probes, 4);
    let mut frames = vec![frame(DeviceMode::Flash, "flash")];
    frames.extend(vec![boot; 8]);
    frames.push(frame(DeviceMode::Normal, "too-late"));
    let mut fake = Fake::new(frames);
    let start = fake.clock;
    assert!(run_fake(&mut fake).unwrap_err().contains("30-second"));
    assert_eq!(fake.probes, 2);
    assert_eq!(fake.clock - start, RECONNECT_LIMIT);
    assert_eq!(fake.actions.len(), 2);
}
#[test]
fn matching_flash_transient_also_retires_without_querying_it_again_or_masking_wrong_normal_id() {
    for changed in [false, true] {
        let transient = frame(DeviceMode::Flash, "transient");
        let mut repeated = transient.clone();
        repeated.error = Some("must not query retired interface");
        let mut normal = frame(DeviceMode::Normal, "normal-after");
        if changed {
            normal.observations[0].public_id = public_id(43);
        }
        let mut fake = Fake::new(vec![
            frame(DeviceMode::Flash, "flash"),
            transient,
            repeated,
            normal,
        ]);
        assert_eq!(run_fake(&mut fake).is_err(), changed);
        assert_eq!(fake.probes, 3);
        assert_eq!(fake.actions.len(), 2);
    }
}
