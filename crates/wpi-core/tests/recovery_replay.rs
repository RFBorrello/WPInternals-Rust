use std::io::Cursor;
use wpi_core::recovery_journal::{Entry, Kind};
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
fn acknowledgement_faults() -> [(Vec<u8>, Option<&'static str>); 8] {
    [
        (Vec::new(), Some("timeout after command submission")),
        (Vec::new(), Some("disconnect after command submission")),
        (Vec::new(), None),
        (b"NOKXFS\0".to_vec(), None),
        (b"NOKXFT\0\0".to_vec(), None),
        (b"NOKXFS\0\x01".to_vec(), None),
        (b"NOKU".to_vec(), None),
        (vec![0; 65537], None),
    ]
}
#[test]
fn uncertain_or_invalid_header_ack_stops_without_retrying_or_sending_payloads() {
    let faults = acknowledgement_faults();
    for v2 in [false, true] {
        for (case, (response, error)) in faults.iter().enumerate() {
            let mut transcript = exchanges(v2);
            transcript[1].response = response.clone();
            transcript[1].error = error.map(str::to_owned);
            let mut transport = ReplayTransport::new(transcript.clone());
            let mut states = Vec::new();
            let result = recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |event| {
                states.push((event.state, event.completed_bytes));
                event.state != OperationState::RecoveryRequired
            });
            assert!(
                matches!(result, Err(RecoveryError::RecoveryRequired(_))),
                "v2={v2}, case={case}"
            );
            assert_eq!(states.last(), Some(&(OperationState::RecoveryRequired, 0)));
            assert!(!states
                .iter()
                .any(|(state, _)| *state == OperationState::Completed));
            // All payloads remain queued: no retry, reset, or continued transfer.
            assert_remaining(&mut transport, &transcript[2..]);
        }
    }
}
#[test]
fn failed_payload_ack_requires_inspection_and_never_retries() {
    let faults = acknowledgement_faults();
    for v2 in [false, true] {
        let mut expected = exchanges(v2);
        let payload_count = expected.len() - 2;
        let buffer = if v2 { 8192 } else { 4096 };
        // Keep a guard queued even after the final payload: an unexpected retry
        // would otherwise hit an empty replay and could escape this assertion.
        expected.push(Exchange {
            request: b"UNSUBMITTED".to_vec(),
            response: Vec::new(),
            error: None,
        });
        for stop in 0..payload_count {
            for (case, (response, error)) in faults.iter().enumerate() {
                let mut transcript = expected.clone();
                transcript[2 + stop].response = response.clone();
                transcript[2 + stop].error = error.map(str::to_owned);
                let mut transport = ReplayTransport::new(transcript.clone());
                let mut terminal = None;
                let result = recovery_replay::run(&mut Cursor::new(FFU), &mut transport, |event| {
                    terminal = Some((event.state, event.completed_bytes));
                    event.state != OperationState::RecoveryRequired
                });
                assert!(
                    matches!(result, Err(RecoveryError::RecoveryRequired(_))),
                    "v2={v2}, payload={stop}, case={case}"
                );
                assert_eq!(
                    terminal,
                    Some((OperationState::RecoveryRequired, (stop * buffer) as u64))
                );
                assert_remaining(&mut transport, &transcript[3 + stop..]);
            }
        }
    }
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

fn journal_baseline(v2: bool) -> Vec<Entry> {
    let mut records = Vec::new();
    let mut transport = ReplayTransport::new(exchanges(v2));
    recovery_replay::run_journaled(
        &mut Cursor::new(FFU),
        &mut transport,
        |_| true,
        |e| {
            records.push(e.clone());
            Ok(())
        },
    )
    .unwrap();
    assert!(transport.finished());
    records
}
#[test]
fn journal_binds_image_records_intent_before_ack_and_never_grants_resume() {
    for v2 in [false, true] {
        let records = journal_baseline(v2);
        let expected_hash = wpi_image::stream::sha256(&mut Cursor::new(FFU)).unwrap();
        let payload_count = exchanges(v2).len() - 2;
        assert_eq!(records.len(), 4 + 2 * payload_count);
        assert_eq!(records[0].kind, Kind::Ready);
        assert_eq!(records[1].kind, Kind::HeaderIntent);
        assert!(!records[1].header_acknowledged && records[1].state_inspection_required);
        assert_eq!(records[2].kind, Kind::HeaderAcknowledged);
        let mut last = 0;
        for (i, e) in records.iter().enumerate() {
            assert_eq!(e.sequence, i as u64 + 1);
            assert_eq!(e.image_sha256, expected_hash);
            assert_eq!(e.image_bytes, FFU.len() as u64);
            assert!(e.acknowledged_payload_bytes >= last);
            assert!(e.replay_only && e.fresh_device_checks_required);
            assert!(!e.automatic_resume_allowed && !e.phone_writes_enabled);
            last = e.acknowledged_payload_bytes;
        }
        for pair in records[3..records.len() - 1].chunks_exact(2) {
            assert_eq!(pair[0].kind, Kind::PayloadIntent);
            assert_eq!(pair[1].kind, Kind::PayloadAcknowledged);
            assert_eq!(pair[0].acknowledged_payload_bytes, pair[0].payload_offset);
            assert_eq!(
                pair[1].acknowledged_payload_bytes,
                pair[0].payload_offset + pair[0].payload_bytes
            );
        }
        let last = records.last().unwrap();
        assert_eq!(last.kind, Kind::Completed);
        assert_eq!(last.acknowledged_payload_bytes, 24576);
        assert!(last.state_inspection_required);
    }
}
#[test]
fn journal_save_failure_at_every_checkpoint_stops_before_the_next_submission() {
    for v2 in [false, true] {
        let records = journal_baseline(v2);
        let buffer = if v2 { 8192 } else { 4096 };
        for failed in &records {
            let mut transcript = exchanges(v2);
            let completed = transcript.len();
            transcript.push(Exchange {
                request: b"UNSUBMITTED".to_vec(),
                response: Vec::new(),
                error: None,
            });
            let mut transport = ReplayTransport::new(transcript.clone());
            let mut calls = 0;
            let result = recovery_replay::run_journaled(
                &mut Cursor::new(FFU),
                &mut transport,
                |_| true,
                |e| {
                    calls += 1;
                    if e.sequence == failed.sequence {
                        Err(std::io::Error::other("disk full"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(calls, failed.sequence);
            let consumed = match failed.kind {
                Kind::Ready | Kind::HeaderIntent => {
                    assert!(matches!(result, Err(RecoveryError::Journal(_))));
                    1
                }
                Kind::HeaderAcknowledged => 2,
                Kind::PayloadIntent => 2 + (failed.payload_offset / buffer) as usize,
                Kind::PayloadAcknowledged => 3 + (failed.payload_offset / buffer) as usize,
                Kind::Completed => completed,
                _ => panic!("Unexpected checkpoint"),
            };
            if consumed > 1 {
                assert!(matches!(result, Err(RecoveryError::RecoveryRequired(_))));
            }
            assert_remaining(&mut transport, &transcript[consumed..]);
        }
    }
}
#[test]
fn journal_keeps_uncertain_payload_intent_without_recording_a_false_ack() {
    let mut transcript = exchanges(false);
    let failed = transcript.len() - 1;
    transcript[failed].error = Some("lost final acknowledgement".into());
    let mut records = Vec::new();
    let result = recovery_replay::run_journaled(
        &mut Cursor::new(FFU),
        &mut ReplayTransport::new(transcript),
        |_| true,
        |e| {
            records.push(e.clone());
            Ok(())
        },
    );
    assert!(matches!(result, Err(RecoveryError::RecoveryRequired(_))));
    let last = records.last().unwrap();
    assert_eq!(last.kind, Kind::RecoveryRequired);
    assert_eq!(last.acknowledged_payload_bytes, 20480);
    assert_eq!(last.payload_offset, 20480);
    assert_eq!(last.payload_bytes, 4096);
    assert_eq!(records[records.len() - 2].kind, Kind::PayloadIntent);
    assert!(!records.iter().any(|e| e.kind == Kind::Completed));
}
#[test]
fn journal_distinguishes_cancellation_before_and_after_header_submission() {
    for stop in [1, 2] {
        let mut records = Vec::new();
        let mut calls = 0;
        let result = recovery_replay::run_journaled(
            &mut Cursor::new(FFU),
            &mut ReplayTransport::new(exchanges(false)),
            |_| {
                calls += 1;
                calls != stop
            },
            |e| {
                records.push(e.clone());
                Ok(())
            },
        );
        let last = records.last().unwrap();
        if stop == 1 {
            assert!(matches!(result, Err(RecoveryError::Cancelled)));
            assert_eq!(last.kind, Kind::Cancelled);
            assert!(!last.state_inspection_required);
        } else {
            assert!(matches!(result, Err(RecoveryError::RecoveryRequired(_))));
            assert_eq!(last.kind, Kind::RecoveryRequired);
            assert!(last.header_acknowledged && last.state_inspection_required);
        }
    }
}
#[test]
fn file_journal_preserves_existing_output_and_is_unusable_after_save_failure() {
    use wpi_core::recovery_journal::FileJournal;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.jsonl");
    let records = journal_baseline(false);
    let mut file = FileJournal::create(&path).unwrap();
    for e in &records {
        file.append(e).unwrap();
    }
    drop(file);
    let bytes = std::fs::read(&path).unwrap();
    assert!(FileJournal::create(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let parsed: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(parsed.len(), records.len());
    assert_eq!(parsed.last().unwrap()["kind"], "completed");
    let broken = dir.path().join("broken.jsonl");
    let mut file = FileJournal::create(&broken).unwrap();
    let mut oversized = records[0].clone();
    oversized.image_sha256 = "x".repeat(2049);
    assert!(file.append(&oversized).is_err());
    assert!(file.append(&records[0]).is_err());
    assert_eq!(std::fs::metadata(broken).unwrap().len(), 0);
}
