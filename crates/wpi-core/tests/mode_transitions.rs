use wpi_core::{
    mode_replay::{self, Observation, ReplayObservation, TransitionError},
    reconnect,
};
use wpi_protocol::{
    mode, normal,
    replay::{Exchange, ReplayTransport},
};
use wpi_types::*;

fn phone() -> DeviceIdentity {
    DeviceIdentity {
        id: "original".into(),
        vendor_id: 0x0421,
        product_id: 0x0661,
        manufacturer: Some("Nokia".into()),
        product: Some("Lumia 909".into()),
        serial: Some("SYNTHETIC-ONLY".into()),
        model: Some("Lumia 1020".into()),
        variant: Some("RM-875".into()),
        firmware: Some("3051.test".into()),
        platform_id: None,
        family: BootloaderFamily::SpecA,
        mode: DeviceMode::Normal,
        interfaces: vec![],
    }
}
fn exchange(request: Vec<u8>, response: Vec<u8>) -> Exchange {
    Exchange {
        request,
        response,
        error: None,
    }
}
fn normal_info(firmware: &str) -> Vec<Exchange> {
    [
        (
            "ReadManufacturerModelName",
            "ManufacturerModelName",
            "RM-875_eu",
        ),
        ("ReadProductCode", "ProductCode", "TEST"),
        ("ReadSwVersion", "SwVersion", firmware),
    ]
    .into_iter()
    .enumerate()
    .map(|(id, (method, key, value))| {
        exchange(
            normal::request(id as u32, method).unwrap(),
            serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":id,"result":{key:value}}))
                .unwrap(),
        )
    })
    .collect()
}
fn source(error: Option<&str>) -> ReplayTransport {
    let mut e = normal_info("3051.test");
    e.push(Exchange {
        request: mode::command(
            DeviceMode::Normal,
            DeviceMode::Flash,
            BootloaderFamily::SpecA,
            None,
        )
        .unwrap()
        .request,
        response: vec![],
        error: error.map(str::to_owned),
    });
    ReplayTransport::new(e)
}
fn flash_info(mode: u8) -> Vec<Exchange> {
    let platform = b"Nokia.MSM8960.P5217";
    let mut r = vec![b'N', b'O', b'K', b'V', 0, mode, 1, 0, 1, 0, 1, 5];
    r.extend_from_slice(&(platform.len() as u16).to_be_bytes());
    r.extend_from_slice(platform);
    let mut e = vec![exchange(b"NOKV".to_vec(), r)];
    if mode == 2 {
        let mut r = vec![0; 17];
        r[..6].copy_from_slice(b"NOKXFR");
        r[16] = 10;
        r.extend_from_slice(b"3051.test\0");
        e.push(exchange(
            wpi_protocol::flash::parameter_request("FVER").unwrap(),
            r,
        ));
    }
    e
}
fn arrival(serial: Option<&str>, app: u8, elapsed_ms: u32) -> ReplayObservation {
    let mut d = phone();
    d.id = "new-interface".into();
    d.product_id = 0x066e;
    d.serial = serial.map(str::to_owned);
    d.mode = DeviceMode::Flash;
    ReplayObservation {
        elapsed_ms,
        observation: Observation::Connected {
            devices: vec![d],
            probe: flash_info(app),
        },
    }
}
fn disconnected() -> ReplayObservation {
    ReplayObservation {
        elapsed_ms: 1,
        observation: Observation::Disconnected,
    }
}

#[test]
fn normal_to_flash_revalidates_and_correlates_without_authorizing_writes() {
    for error in [
        None,
        Some("timeout after partial OUT"),
        Some("disconnected during send"),
    ] {
        let mut t = source(error);
        let mut events = vec![];
        let result = mode_replay::run(
            &phone(),
            DeviceMode::Flash,
            &mut t,
            vec![
                disconnected(),
                ReplayObservation {
                    elapsed_ms: 2,
                    observation: Observation::PermissionRequired,
                },
                arrival(Some("SYNTHETIC-ONLY"), 2, 3),
            ],
            |e| {
                events.push(e.clone());
                true
            },
        )
        .unwrap();
        assert_eq!(result.status, ReconnectStatus::Correlated);
        assert!(!result.recovery_authorized);
        assert!(t.finished());
        assert_eq!(events.last().unwrap().state, OperationState::Completed);
        assert!(events.windows(2).all(|w| w[0].sequence < w[1].sequence));
        assert!(result
            .checks
            .iter()
            .any(|c| c.key == "variant" && c.status == PreparationStatus::Unverified));
    }
}
#[test]
fn wrong_phone_missing_serial_wrong_mode_and_ambiguous_arrivals_stop() {
    for o in [
        arrival(Some("DIFFERENT"), 2, 2),
        arrival(None, 2, 2),
        arrival(Some("SYNTHETIC-ONLY"), 1, 2),
        ReplayObservation {
            elapsed_ms: 2,
            observation: Observation::Connected {
                devices: vec![phone(), phone()],
                probe: vec![],
            },
        },
    ] {
        let mut t = source(None);
        assert!(matches!(
            mode_replay::run(
                &phone(),
                DeviceMode::Flash,
                &mut t,
                vec![disconnected(), o],
                |_| true
            ),
            Err(TransitionError::RecoveryRequired(_))
        ));
        assert!(t.finished());
    }
}
#[test]
fn stale_arrivals_and_permission_waits_cannot_bypass_disconnect_or_deadline() {
    for observations in [
        vec![arrival(Some("SYNTHETIC-ONLY"), 2, 2)],
        vec![
            disconnected(),
            ReplayObservation {
                elapsed_ms: 29_999,
                observation: Observation::PermissionRequired,
            },
            arrival(Some("SYNTHETIC-ONLY"), 2, 30_000),
        ],
    ] {
        let mut t = source(None);
        assert!(
            mode_replay::run(&phone(), DeviceMode::Flash, &mut t, observations, |_| true)
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(t.finished());
    }
}
#[test]
fn cancellation_before_and_after_command_has_distinct_outcomes() {
    let mut t = source(None);
    assert!(matches!(
        mode_replay::run(&phone(), DeviceMode::Flash, &mut t, vec![], |_| false),
        Err(TransitionError::Cancelled)
    ));
    assert!(!t.finished());
    let mut t = source(None);
    assert!(matches!(
        mode_replay::run(&phone(), DeviceMode::Flash, &mut t, vec![], |e| e.state
            != OperationState::AwaitingReconnect),
        Err(TransitionError::RecoveryRequired(_))
    ));
    assert!(t.finished());
    let mut t = source(None);
    let timeline = vec![
        disconnected(),
        ReplayObservation {
            elapsed_ms: 2,
            observation: Observation::PermissionRequired,
        },
        arrival(Some("SYNTHETIC-ONLY"), 2, 3),
    ];
    assert!(matches!(
        mode_replay::run(&phone(), DeviceMode::Flash, &mut t, timeline, |e| !e
            .message
            .starts_with("Renew device")),
        Err(TransitionError::RecoveryRequired(_))
    ));
}
#[test]
fn malformed_or_interrupted_returning_probe_never_retries() {
    for response in [vec![b'N'], vec![b'N', b'O', b'K', b'U']] {
        let mut o = arrival(Some("SYNTHETIC-ONLY"), 2, 2);
        if let Observation::Connected { probe, .. } = &mut o.observation {
            probe[0].response = response;
        }
        let mut t = source(None);
        assert!(matches!(
            mode_replay::run(
                &phone(),
                DeviceMode::Flash,
                &mut t,
                vec![disconnected(), o],
                |_| true
            ),
            Err(TransitionError::RecoveryRequired(_))
        ));
    }
    let mut o = arrival(Some("SYNTHETIC-ONLY"), 2, 2);
    if let Observation::Connected { probe, .. } = &mut o.observation {
        probe[0].error = Some("timeout".into());
    }
    assert!(mode_replay::run(
        &phone(),
        DeviceMode::Flash,
        &mut source(None),
        vec![disconnected(), o],
        |_| true
    )
    .is_err());
}
#[test]
fn source_changed_and_invalid_timeline_fail_before_command() {
    let mut t = ReplayTransport::new(normal_info("changed"));
    assert!(matches!(
        mode_replay::run(&phone(), DeviceMode::Flash, &mut t, vec![], |_| true),
        Err(TransitionError::Preflight(_))
    ));
    let mut t = source(None);
    assert!(matches!(
        mode_replay::run(
            &phone(),
            DeviceMode::Flash,
            &mut t,
            vec![arrival(None, 2, 2), disconnected()],
            |_| true
        ),
        Err(TransitionError::Preflight(_))
    ));
    assert!(!t.finished());
    assert!(mode_replay::run(
        &phone(),
        DeviceMode::Flash,
        &mut t,
        vec![disconnected(); 65],
        |_| true
    )
    .is_err());
}
#[test]
fn normal_probe_stops_on_invalid_first_response() {
    let mut e = normal_info("3051.test");
    e[0].response = br#"{"jsonrpc":"2.0","id":99,"result":{}}"#.to_vec();
    let mut t = ReplayTransport::new(e);
    assert!(normal::read_info(&mut t).is_err());
    assert!(!t.finished());
}
#[test]
fn reconnect_rejects_contradictions_and_does_not_use_model_as_unique_identity() {
    let a = phone();
    for changed in ["variant", "firmware", "family", "serial", "usb"] {
        let mut b = a.clone();
        match changed {
            "variant" => b.variant = Some("RM-876".into()),
            "firmware" => b.firmware = Some("changed".into()),
            "family" => b.family = BootloaderFamily::SpecB,
            "serial" => b.serial = Some("another".into()),
            _ => b.product_id = 0x0660,
        }
        assert_eq!(
            reconnect::compare(&a, &b, DeviceMode::Normal).status,
            ReconnectStatus::Mismatch
        );
    }
    let mut b = a.clone();
    b.serial = Some("  ".into());
    assert_eq!(
        reconnect::compare(&a, &b, DeviceMode::Normal).status,
        ReconnectStatus::Unverified
    );
    let mut unknown = a.clone();
    unknown.variant = Some("RM-9999".into());
    assert_eq!(
        reconnect::compare(&unknown, &unknown, DeviceMode::Normal).status,
        ReconnectStatus::Unverified
    );
    let mut a = a;
    a.platform_id = Some("expected".into());
    b = a.clone();
    b.platform_id = Some("different".into());
    assert_eq!(
        reconnect::compare(&a, &b, DeviceMode::Normal).status,
        ReconnectStatus::Mismatch
    );
}
#[test]
fn preview_is_redacted_and_cannot_bypass_live_gate() {
    let mut p = reconnect::prepare(
        Some(phone()),
        DeviceMode::Flash,
        None,
        Host::Browser,
        TransportKind::WebUsb,
    );
    assert!(p.route.is_some());
    assert!(p.requires_disconnect);
    assert!(!p.plan.executable);
    assert!(!serde_json::to_string(&p)
        .unwrap()
        .contains("SYNTHETIC-ONLY"));
    p.plan.executable = true;
    p.plan.blockers.clear();
    assert!(wpi_core::operations::OperationCoordinator::default()
        .start(&p.plan)
        .is_err());
}

#[test]
fn bootmanager_protocol_versions_require_different_arrival_sequences() {
    for (major, removed, success) in [(1, false, false), (1, true, true), (2, false, true)] {
        let mut d = phone();
        d.product_id = 0x066e;
        d.mode = DeviceMode::BootManager;
        if major == 2 {
            d.variant = Some("RM-1040".into());
            d.model = Some("Lumia 730".into());
            d.family = BootloaderFamily::SpecB;
        }
        let mut e = flash_info(1);
        e[0].response[6] = major;
        e.push(exchange(b"NOKS".to_vec(), vec![]));
        let mut t = ReplayTransport::new(e);
        let mut timeline = vec![];
        if removed {
            timeline.push(disconnected());
        }
        timeline.push(arrival(Some("SYNTHETIC-ONLY"), 2, 2));
        assert_eq!(
            mode_replay::run(&d, DeviceMode::Flash, &mut t, timeline, |_| true).is_ok(),
            success
        );
        assert!(t.finished());
    }
}

#[test]
fn flash_to_normal_reboots_once_and_checks_fresh_normal_info() {
    let mut d = phone();
    d.mode = DeviceMode::Flash;
    d.product_id = 0x066e;
    d.platform_id = Some("Nokia.MSM8960.P5217".into());
    let mut e = flash_info(2);
    e.push(exchange(b"NOKR".to_vec(), vec![]));
    let mut t = ReplayTransport::new(e);
    let arrival = ReplayObservation {
        elapsed_ms: 2,
        observation: Observation::Connected {
            devices: vec![phone()],
            probe: normal_info("3051.test"),
        },
    };
    assert!(mode_replay::run(
        &d,
        DeviceMode::Normal,
        &mut t,
        vec![disconnected(), arrival],
        |_| true
    )
    .is_ok());
    assert!(t.finished());
}

#[test]
fn in_place_context_change_is_probed_and_events_follow_coordinator_states() {
    let mut d = phone();
    d.mode = DeviceMode::Flash;
    d.product_id = 0x066e;
    let mut e = flash_info(2);
    e[0].response[6] = 2;
    let mut ack = vec![0; 8];
    ack[..6].copy_from_slice(b"NOKXCB");
    e.push(exchange(b"NOKXCBP".to_vec(), ack));
    let mut t = ReplayTransport::new(e);
    let coordinator = wpi_core::operations::OperationCoordinator::default();
    let plan = wpi_core::operations::prepare(
        Operation::DeviceInfo,
        Some(phone()),
        Host::Windows,
        TransportKind::Usb,
        vec![],
    );
    let mut session = coordinator.start(&plan).unwrap();
    mode_replay::run(
        &d,
        DeviceMode::PhoneInfo,
        &mut t,
        vec![arrival(Some("SYNTHETIC-ONLY"), 3, 1)],
        |e| {
            session
                .transition(e.state, e.completed_bytes, e.total_bytes, &e.message)
                .unwrap();
            true
        },
    )
    .unwrap();
    assert!(t.finished());
}
