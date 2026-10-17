use wpi_protocol::{
    flash, identity,
    preflight::{self, GptReadStatus, RootKeyHash},
    replay::{Exchange, ReplayTransport},
    MessageTransport, ProtocolError,
};

fn nokv(locked: bool) -> Vec<u8> {
    let mut r = b"NOKV\0\x02\x01\x12\x02\x02\x02".to_vec();
    let platform = b"Nokia.MSM8960.P5217.1";
    r.extend_from_slice(&[5, 0, platform.len() as u8]);
    r.extend_from_slice(platform);
    r.extend_from_slice(&[15, 0, 8, 3, 1, u8::from(locked), 1, 0, 0, 1, 1]);
    r
}
fn terminal() -> Vec<u8> {
    let mut r = vec![0; 60];
    r[..6].copy_from_slice(b"NOKXFT");
    r[20..24].copy_from_slice(&36u32.to_be_bytes());
    r[24..28].copy_from_slice(&0x10000u32.to_le_bytes());
    r[28..32].copy_from_slice(&28u32.to_le_bytes());
    r[32..36].copy_from_slice(&3u32.to_le_bytes());
    r[36..40].copy_from_slice(&20u32.to_le_bytes());
    r[40..].fill(42);
    r
}
fn parameter(p: &[u8]) -> Vec<u8> {
    let mut r = vec![0; 17];
    r[..6].copy_from_slice(b"NOKXFR");
    r[16] = p.len() as u8;
    r.extend_from_slice(p);
    r
}
fn step(request: &[u8], response: Vec<u8>) -> Exchange {
    Exchange {
        request: request.into(),
        response,
        error: None,
    }
}
fn exchanges(locked: bool, gpt: bool) -> Vec<Exchange> {
    let mut e = vec![
        step(b"NOKV", nokv(locked)),
        step(&identity::flash_request(), terminal()),
        step(
            &flash::parameter_request("RRKH").unwrap(),
            parameter(&[7; 32]),
        ),
        step(
            &flash::parameter_request("SS").unwrap(),
            parameter(&[0, 1, u8::from(locked), 1, 0, 0, 1, 1]),
        ),
    ];
    if gpt && !locked {
        let mut r = vec![0; 8 + preflight::PRIMARY_SIZE];
        r[..4].copy_from_slice(b"NOKT");
        e.push(step(b"NOKT", r));
    }
    e.extend([
        step(b"NOKV", nokv(locked)),
        step(&identity::flash_request(), terminal()),
    ]);
    e
}
fn run(t: &mut impl MessageTransport, gpt: bool) -> wpi_protocol::Result<preflight::Capture> {
    preflight::capture(
        t,
        &RootKeyHash::parse(&[7; 32]).unwrap(),
        "Nokia.MSM8960.P5217",
        gpt,
        |_| true,
    )
}

#[test]
fn exact_reference_requests_and_locked_context_never_send_switch_or_gpt() {
    assert_eq!(flash::parameter_request("RRKH").unwrap(), b"NOKXFR\0RRKH");
    assert_eq!(flash::parameter_request("SS").unwrap(), b"NOKXFR\0SS\0\0");
    for (locked, requested, status) in [
        (true, true, GptReadStatus::ContextSwitchRequired),
        (true, false, GptReadStatus::NotRequested),
        (false, true, GptReadStatus::Read),
        (false, false, GptReadStatus::NotRequested),
    ] {
        let mut replay = ReplayTransport::new(exchanges(locked, requested));
        let capture = run(&mut replay, requested).unwrap();
        assert!(capture.matches_reference(
            &RootKeyHash::parse(&[7; 32]).unwrap(),
            "Nokia.MSM8960.P5217"
        ));
        assert!(!capture.matches_reference(
            &RootKeyHash::parse(&[8; 32]).unwrap(),
            "Nokia.MSM8960.P5217"
        ));
        let capture = capture.into_observation();
        assert_eq!(capture.gpt_status, status);
        assert_eq!(capture.primary_gpt.is_some(), !locked && requested);
        assert!(replay.finished());
    }
}

#[test]
fn strict_application_security_rejects_ambiguous_envelopes_and_future_encodings() {
    let good = nokv(true);
    for len in 0..good.len() {
        assert!(preflight::parse_application(&good[..len]).is_err());
    }
    for r in [
        {
            let mut r = good.clone();
            r.push(0);
            r
        },
        {
            let mut r = good.clone();
            r[10] = 3;
            r.extend_from_slice(&[5, 0, 1, b'X']);
            r
        },
        {
            let mut r = good.clone();
            let at = r.len() - 8;
            r[at] = 4;
            r
        },
        {
            let mut r = good.clone();
            let at = r.len() - 8;
            r[at + 2] = 2;
            r
        },
        vec![0; 65537],
    ] {
        assert!(preflight::parse_application(&r).is_err());
    }
    let mut authenticated = good;
    let at = authenticated.len() - 8;
    authenticated[at + 5] = 2;
    assert!(
        preflight::parse_application(&authenticated)
            .unwrap()
            .1
            .unwrap()
            .authenticated
    );
    for n in [0, 1, 7, 9, 255] {
        assert!(preflight::parse_security(&vec![0; n]).is_err());
    }
    let mut ss = [0; 8];
    ss[5] = 2;
    assert!(preflight::parse_security(&ss).is_err());
    for n in [0, 31, 33, 255] {
        assert!(RootKeyHash::parse(&vec![1; n]).is_err());
    }
    for b in [0, 255] {
        assert!(RootKeyHash::parse(&[b; 32]).is_err());
    }
    assert_eq!(
        format!("{:?}", RootKeyHash::parse(&[7; 32]).unwrap()),
        "RootKeyHash([redacted])"
    );
}

struct Counted {
    replay: ReplayTransport,
    queries: usize,
}
impl MessageTransport for Counted {
    fn exchange(&mut self, r: &[u8], n: usize) -> wpi_protocol::Result<Vec<u8>> {
        self.queries += 1;
        self.replay.exchange(r, n)
    }
}
#[test]
fn failures_and_cancellation_at_every_query_stop_without_retry_or_recovery() {
    let good = exchanges(false, true);
    for i in 0..good.len() {
        for error in ["disconnected", "timed out", "partial OUT transfer"] {
            let mut bad = good.clone();
            bad[i].error = Some(error.into());
            let mut t = Counted {
                replay: ReplayTransport::new(bad),
                queries: 0,
            };
            assert!(run(&mut t, true).is_err());
            assert_eq!(t.queries, i + 1);
        }
        let mut t = Counted {
            replay: ReplayTransport::new(good.clone()),
            queries: 0,
        };
        let mut boundaries = 0;
        let result = preflight::capture(
            &mut t,
            &RootKeyHash::parse(&[7; 32]).unwrap(),
            "Nokia.MSM8960.P5217",
            true,
            |_| {
                let yes = boundaries != i;
                boundaries += 1;
                yes
            },
        );
        assert!(result.is_err());
        assert_eq!(t.queries, i);
    }
    let mut t = Counted {
        replay: ReplayTransport::new(good),
        queries: 0,
    };
    let result = preflight::capture(
        &mut t,
        &RootKeyHash::parse(&[7; 32]).unwrap(),
        "Nokia.MSM8960.P5217",
        true,
        |stage| stage != "Finish read-only preflight",
    );
    assert!(result.is_err());
    assert!(t.replay.finished());
}
#[test]
fn contradiction_blank_root_bad_status_mode_and_identity_changes_fail_closed() {
    let root_response = parameter(&[7; 32]);
    for len in 0..root_response.len() {
        let mut e = exchanges(true, true);
        e[2].response = root_response[..len].to_vec();
        let mut t = Counted {
            replay: ReplayTransport::new(e),
            queries: 0,
        };
        assert!(run(&mut t, true).is_err());
        assert_eq!(t.queries, 3);
    }
    for (index, response) in [
        (0, {
            let mut r = nokv(true);
            r[5] = 1;
            r
        }),
        (0, {
            let mut r = nokv(true);
            r[14] = b'X';
            r
        }),
        (1, b"NOKU".to_vec()),
        (2, parameter(&[0; 32])),
        (2, parameter(&[8; 32])),
        (2, {
            let mut r = parameter(&[7; 32]);
            r[7] = 1;
            r
        }),
        (2, {
            let mut r = parameter(&[7; 32]);
            r.push(0);
            r
        }),
        (3, parameter(&[0, 1, 0, 1, 0, 0, 1, 1])),
        (4, {
            let mut r = nokv(true);
            r[9] += 1;
            r
        }),
        (5, {
            let mut r = terminal();
            r[40] += 1;
            r
        }),
    ] {
        let mut e = exchanges(true, true);
        e[index].response = response;
        let mut t = Counted {
            replay: ReplayTransport::new(e),
            queries: 0,
        };
        assert!(run(&mut t, true).is_err(), "index {index}");
        assert_eq!(t.queries, index + 1);
    }
}
#[test]
fn missing_application_security_skips_gpt_and_never_inferrs_access_from_ss_alone() {
    let mut e = exchanges(false, false);
    for i in [0, 4] {
        let r = &mut e[i].response;
        let len = r.len();
        r.truncate(len - 11);
        r[10] = 1;
    }
    let mut t = ReplayTransport::new(e);
    assert_eq!(
        run(&mut t, true).unwrap().into_observation().gpt_status,
        GptReadStatus::SecurityEvidenceMissing
    );
    assert!(t.finished());
}
#[test]
fn primary_wire_bounds_signature_status_and_surplus_are_checked() {
    let mut r = vec![0; 8 + preflight::PRIMARY_SIZE];
    r[..4].copy_from_slice(b"NOKT");
    assert_eq!(
        preflight::parse_primary_gpt(&r).unwrap().len(),
        preflight::PRIMARY_SIZE
    );
    for len in [0, 4, 7, 8, r.len() - 1] {
        assert!(preflight::parse_primary_gpt(&r[..len]).is_err());
    }
    r.push(0);
    assert!(preflight::parse_primary_gpt(&r).is_err());
    r.pop();
    r[6] = 1;
    assert!(matches!(
        preflight::parse_primary_gpt(&r),
        Err(ProtocolError::Status(256))
    ));
    r[6] = 0;
    r[0] = 0;
    assert!(preflight::parse_primary_gpt(&r).is_err());
}

#[test]
fn bound_capture_rejects_a_different_normal_id_before_security_queries() {
    let normal_id = |seed: u8| {
        identity::parse_normal(
            &serde_json::to_vec(
                &serde_json::json!({"jsonrpc":"2.0","id":4,"result":{"PublicId":vec![seed;20]}}),
            )
            .unwrap(),
            4,
        )
        .unwrap()
    };
    for seed in [42, 43] {
        let mut t = Counted {
            replay: ReplayTransport::new(exchanges(true, false)),
            queries: 0,
        };
        let result = preflight::capture_bound(
            &mut t,
            &RootKeyHash::parse(&[7; 32]).unwrap(),
            "Nokia.MSM8960.P5217",
            false,
            &normal_id(seed),
            |_| true,
        );
        if seed == 42 {
            assert!(result.is_ok());
            assert!(t.replay.finished());
        } else {
            assert!(result.is_err());
            assert_eq!(t.queries, 2);
        }
    }
}
