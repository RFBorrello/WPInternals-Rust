use serde::Deserialize;
use wpi_core::spec_a_programmer_replay::{self, Error, Region};
use wpi_protocol::{
    qualcomm::encode_hdlc,
    replay::{Exchange, ReplayTransport},
    MessageTransport,
};
use wpi_types::{Operation, OperationState};

#[derive(Deserialize)]
struct OwnedRegion {
    start_bytes: u32,
    data: Vec<u8>,
}
#[derive(Deserialize)]
struct Fixture {
    regions: Vec<OwnedRegion>,
    exchanges: Vec<Exchange>,
}
fn fixture() -> Fixture {
    serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/spec-a-programmer-v1.json"
    ))
    .unwrap()
}
fn regions(fixture: &Fixture) -> Vec<Region<'_>> {
    fixture
        .regions
        .iter()
        .map(|r| Region {
            start_bytes: r.start_bytes,
            data: &r.data,
        })
        .collect()
}
fn sentinel() -> Exchange {
    Exchange {
        request: b"UNSUBMITTED".to_vec(),
        response: Vec::new(),
        error: None,
    }
}
fn remaining(transport: &mut ReplayTransport, expected: &[Exchange]) {
    for exchange in expected {
        assert_eq!(
            transport.exchange(&exchange.request, 8192).unwrap(),
            exchange.response
        );
    }
    assert!(transport.finished());
}
fn confirmed(exchanges: &[Exchange]) -> u64 {
    exchanges
        .iter()
        .filter(|e| e.request[0] == 7)
        .map(|e| (e.request.len() - 5) as u64)
        .sum()
}

#[test]
fn complete_programmer_phase_matches_reference_with_monotonic_acknowledged_progress() {
    let fixture = fixture();
    let mut transport = ReplayTransport::new(fixture.exchanges.clone());
    let mut events = Vec::new();
    spec_a_programmer_replay::run(&regions(&fixture), &mut transport, |event| {
        events.push(event.clone());
        event.state != OperationState::Completed // Completion cannot be undone.
    })
    .unwrap();
    assert!(transport.finished());
    assert_eq!(events.len(), fixture.exchanges.len() + 1);
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.operation, Operation::UnlockBootloader);
        assert_eq!(event.sequence, index as u64 + 1);
        assert_eq!(event.total_bytes, 2563);
        assert_eq!(
            event.completed_bytes,
            confirmed(&fixture.exchanges[..index])
        );
    }
    assert_eq!(events.last().unwrap().state, OperationState::Completed);
    assert!(events
        .last()
        .unwrap()
        .message
        .contains("unlock is not established"));
}

#[test]
fn failure_at_every_command_stops_without_retry_close_or_reboot() {
    let fixture = fixture();
    for index in 0..fixture.exchanges.len() {
        let good = &fixture.exchanges[index].response;
        let mut bad_crc = good.clone();
        bad_crc[1] ^= 1;
        let faults = [
            (Vec::new(), Some("timeout after submission")),
            (Vec::new(), Some("disconnect after partial transfer")),
            (Vec::new(), None),
            (good[..good.len() - 1].to_vec(), None),
            (bad_crc, None),
            (encode_hdlc(&[0x0e]).unwrap(), None),
            (encode_hdlc(&[8, 0xff, 0xff, 0xff, 0xff]).unwrap(), None),
            (vec![0; 8193], None),
            ([good.as_slice(), good.as_slice()].concat(), None),
        ];
        for (case, (response, error)) in faults.into_iter().enumerate() {
            let mut transcript = fixture.exchanges.clone();
            transcript[index].response = response;
            transcript[index].error = error.map(str::to_string);
            transcript.push(sentinel());
            let mut transport = ReplayTransport::new(transcript.clone());
            let mut terminal = None;
            let mut completed = false;
            let result =
                spec_a_programmer_replay::run(&regions(&fixture), &mut transport, |event| {
                    terminal = Some((event.state, event.completed_bytes));
                    completed |= event.state == OperationState::Completed;
                    event.state != OperationState::RecoveryRequired
                });
            match result {
                Err(Error::Interrupted {
                    acknowledged_bytes,
                    write_attempted,
                    ..
                }) => {
                    assert_eq!(acknowledged_bytes, confirmed(&fixture.exchanges[..index]));
                    assert_eq!(write_attempted, index >= 3);
                    assert_eq!(
                        terminal,
                        Some((OperationState::RecoveryRequired, acknowledged_bytes))
                    );
                }
                other => panic!("command={index}, fault={case}: {other:?}"),
            }
            assert!(!completed);
            // A sentinel catches extra commands even after a lost reboot ACK.
            remaining(&mut transport, &transcript[index + 1..]);
        }
    }
}

#[test]
fn cancellation_at_every_command_boundary_never_sends_the_next_command() {
    let fixture = fixture();
    for stop in 0..fixture.exchanges.len() {
        let mut transcript = fixture.exchanges.clone();
        transcript.push(sentinel());
        let mut transport = ReplayTransport::new(transcript.clone());
        let mut calls = 0;
        let mut terminal = None;
        let result = spec_a_programmer_replay::run(&regions(&fixture), &mut transport, |event| {
            terminal = Some((event.state, event.completed_bytes));
            if event.state == OperationState::Running {
                calls += 1;
                calls != stop + 1
            } else {
                false
            }
        });
        let done = confirmed(&fixture.exchanges[..stop]);
        if stop == 0 {
            assert!(matches!(result, Err(Error::Cancelled)));
            assert_eq!(terminal, Some((OperationState::Cancelled, 0)));
        } else {
            match result {
                Err(Error::Interrupted {
                    acknowledged_bytes,
                    write_attempted,
                    ..
                }) => {
                    assert_eq!(acknowledged_bytes, done);
                    assert_eq!(write_attempted, stop > 3);
                }
                other => panic!("boundary={stop}: {other:?}"),
            }
            assert_eq!(terminal, Some((OperationState::RecoveryRequired, done)));
        }
        remaining(&mut transport, &transcript[stop..]);
    }
}

#[test]
fn invalid_regions_are_rejected_before_any_event_or_request() {
    let fixture = fixture();
    let one = [1];
    let oversized = vec![0; 16 * 1024 * 1024 + 1];
    let full = &oversized[..16 * 1024 * 1024];
    let invalid = [
        vec![],
        vec![Region {
            start_bytes: 0,
            data: &[],
        }],
        vec![Region {
            start_bytes: 0,
            data: &oversized,
        }],
        vec![Region {
            start_bytes: u32::MAX,
            data: &[1, 2],
        }],
        vec![
            Region {
                start_bytes: 0,
                data: &[1, 2],
            },
            Region {
                start_bytes: 1,
                data: &one,
            },
        ],
        (0..33)
            .map(|i| Region {
                start_bytes: i,
                data: &one,
            })
            .collect(),
        (0..5)
            .map(|i| Region {
                start_bytes: i * 16 * 1024 * 1024,
                data: full,
            })
            .collect(),
    ];
    for regions in invalid {
        let mut transport = ReplayTransport::new(fixture.exchanges.clone());
        assert!(matches!(
            spec_a_programmer_replay::run(&regions, &mut transport, |_| panic!("preflight only")),
            Err(Error::Preflight(_))
        ));
        remaining(&mut transport, &fixture.exchanges);
    }
}

#[test]
fn adjacent_regions_keep_caller_order_and_the_final_32_bit_byte_is_addressable() {
    let regions = [
        Region {
            start_bytes: u32::MAX,
            data: &[0x7d],
        },
        Region {
            start_bytes: u32::MAX - 1,
            data: &[0x7e],
        },
    ];
    // Deliberately descending order: validation may sort intervals for overlap
    // checks, but the programming sequence must retain caller-selected ordering.
    let mut transcript = fixture().exchanges[..3].to_vec();
    for (address, byte) in [(u32::MAX, 0x7d), (u32::MAX - 1, 0x7e)] {
        let mut request = vec![7];
        request.extend_from_slice(&address.to_le_bytes());
        request.push(byte);
        let mut ack = vec![8];
        ack.extend_from_slice(&address.to_le_bytes());
        transcript.push(Exchange {
            request,
            response: encode_hdlc(&ack).unwrap(),
            error: None,
        });
    }
    transcript.extend_from_slice(&fixture().exchanges[7..]);
    let mut transport = ReplayTransport::new(transcript);
    spec_a_programmer_replay::run(&regions, &mut transport, |_| true).unwrap();
    assert!(transport.finished());
}
