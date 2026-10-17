use std::io::Cursor;
use wpi_core::recovery_replay::{self, RecoveryError};
use wpi_protocol::{
    flash,
    replay::{Exchange, ReplayTransport},
    MessageTransport,
};
use wpi_types::OperationState;
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic.ffu");
fn exchanges(v2: bool) -> Vec<Exchange> {
    let platform = b"SYNTHETIC.LUMIA.TEST";
    let mut info = vec![b'N', b'O', b'K', b'V', 0, 2, 2, 0, 1, 0, 3];
    info.extend([5, 0, platform.len() as u8]);
    info.extend(platform);
    info.extend([0x10, 0, 3, 1, 0, if v2 { 4 } else { 1 }]);
    info.extend([2, 0, 4, 0, 0, 0x20, 0]);
    let mut transcript = vec![
        Exchange {
            request: b"NOKV".to_vec(),
            response: info,
            error: None,
        },
        Exchange {
            request: flash::ffu_header_v1(&FFU[..12288]).unwrap(),
            response: b"NOKXFS\0\0".to_vec(),
            error: None,
        },
    ];
    let buffer = if v2 { 8192 } else { 4096 };
    for (i, chunk) in FFU[12288..].chunks(buffer).enumerate() {
        let progress = ((i + 1) * buffer * 100 / 24576) as u8;
        transcript.push(Exchange {
            request: if v2 {
                flash::ffu_payload_v2(chunk, progress).unwrap()
            } else {
                flash::ffu_payload_v1(chunk, progress).unwrap()
            },
            response: b"NOKXFS\0\0".to_vec(),
            error: None,
        });
    }
    transcript
}
#[test]
fn cancellation_before_header_leaves_all_simulated_writes_unsubmitted() {
    for v2 in [false, true] {
        let transcript = exchanges(v2);
        let mut transport = ReplayTransport::new(transcript.clone());
        let mut states = Vec::new();
        let result = recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |event| {
            states.push(event.state);
            false
        });
        assert!(matches!(result, Err(RecoveryError::Cancelled)));
        assert!(!states.contains(&OperationState::RecoveryRequired));
        assert!(!states.contains(&OperationState::Completed));
        // NOKV was consumed; every header/payload exchange must remain queued.
        assert_remaining(&mut transport, &transcript[1..]);
    }
}
#[test]
fn cancellation_after_header_stops_at_each_payload_boundary_and_requires_recovery() {
    for v2 in [false, true] {
        let transcript = exchanges(v2);
        let payload_count = transcript.len() - 2;
        let buffer = if v2 { 8192 } else { 4096 };
        for stop in 0..payload_count {
            let mut transport = ReplayTransport::new(transcript.clone());
            let mut boundaries = 0;
            let mut terminal = None;
            let result = recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |event| {
                terminal = Some((event.state, event.completed_bytes));
                if event.state == OperationState::Running {
                    boundaries += 1;
                    // First Running event is before the header, then payloads.
                    return boundaries != stop + 2;
                }
                true
            });
            assert!(matches!(result, Err(RecoveryError::RecoveryRequired(_))));
            assert_eq!(
                terminal,
                Some((OperationState::RecoveryRequired, (stop * buffer) as u64))
            );
            assert_remaining(&mut transport, &transcript[2 + stop..]);
        }
    }
}
fn assert_remaining(transport: &mut ReplayTransport, expected: &[Exchange]) {
    for exchange in expected {
        assert_eq!(
            transport.exchange(&exchange.request, 65536).unwrap(),
            exchange.response
        );
    }
    assert!(transport.finished());
}
#[test]
fn v1_and_v2_stock_replay_complete_with_monotonic_progress() {
    for v2 in [false, true] {
        let mut transport = ReplayTransport::new(exchanges(v2));
        let mut last = 0;
        let mut terminal = None;
        recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |event| {
            assert!(event.completed_bytes >= last);
            last = event.completed_bytes;
            terminal = Some(event.state);
            true
        })
        .unwrap();
        assert!(transport.finished());
        assert_eq!(last, 24576);
        assert_eq!(terminal, Some(OperationState::Completed));
    }
}
#[test]
fn failed_payload_ack_requires_inspection_and_never_retries() {
    let mut transcript = exchanges(false);
    transcript[2].error = Some("disconnect after payload submission".into());
    let mut transport = ReplayTransport::new(transcript);
    let mut terminal = None;
    let error = recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |event| {
        terminal = Some(event.state);
        true
    })
    .unwrap_err();
    assert!(matches!(error, RecoveryError::RecoveryRequired(_)));
    assert_eq!(terminal, Some(OperationState::RecoveryRequired));
    assert!(!transport.finished());
}
#[test]
fn platform_mismatch_is_rejected_before_any_simulated_write() {
    let mut transcript = exchanges(false);
    let response = &mut transcript[0].response;
    response[14] = b'X';
    let mut transport = ReplayTransport::new(transcript);
    assert!(matches!(
        recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |_| true),
        Err(RecoveryError::Preflight(_))
    ));
    assert!(!transport.finished());
}
