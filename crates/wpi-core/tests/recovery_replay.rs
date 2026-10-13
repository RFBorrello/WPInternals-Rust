use std::io::Cursor;
use wpi_core::recovery_replay::{self, RecoveryError};
use wpi_protocol::{
    flash,
    replay::{Exchange, ReplayTransport},
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
