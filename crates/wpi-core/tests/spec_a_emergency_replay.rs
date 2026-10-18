use std::io::Cursor;
use wpi_core::spec_a_emergency_replay::{
    self as emergency, Binding, Endpoint, EntryPlan, Error, Loader, Observation, Scenario,
    TimedObservation,
};
use wpi_protocol::{
    flash, identity,
    preflight::RootKeyHash,
    qualcomm::{encode_hdlc, v1},
    replay::{Exchange, FramedExchange, FramedReplayTransport, ReplayTransport},
    MessageTransport,
};
use wpi_types::{OperationEvent, OperationState};

const CHUNK: usize = 0x20000;
const LOADER: &[u8] = include_bytes!("../../../tests/fixtures/spec-a/loader.mbn");
fn sha(bytes: &[u8]) -> String {
    wpi_image::stream::sha256(&mut Cursor::new(bytes)).unwrap()
}
fn hash_bytes(bytes: &[u8]) -> Vec<u8> {
    sha(bytes)
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn root_bytes() -> Vec<u8> {
    hash_bytes(include_bytes!(
        "../../../tests/fixtures/image-issuer/root.der"
    ))
}
fn root() -> RootKeyHash {
    RootKeyHash::parse(&root_bytes()).unwrap()
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn rehash(bytes: &mut [u8]) {
    for index in 0..4 {
        let digest = hash_bytes(&bytes[(index + 1) * CHUNK..(index + 2) * CHUNK]);
        bytes[32 + index * 32..64 + index * 32].copy_from_slice(&digest);
    }
}
fn ffu() -> Vec<u8> {
    let basic = include_bytes!("../../../tests/fixtures/synthetic.ffu");
    let mut bytes = vec![0; CHUNK * 5];
    bytes[..32].copy_from_slice(&basic[..32]);
    put(&mut bytes, 16, 128);
    put(&mut bytes, 28, 128);
    bytes[CHUNK..CHUNK + 4096].copy_from_slice(&basic[4096..8192]);
    put(&mut bytes, CHUNK + 20, 128);
    bytes[CHUNK * 2..CHUNK * 2 + 248].copy_from_slice(&basic[8192..8192 + 248]);
    put(&mut bytes, CHUNK * 2 + 204, CHUNK as u32);
    put(&mut bytes, CHUNK * 2 + 208, 2);
    put(&mut bytes, CHUNK * 2 + 212, 40);
    for (i, value) in [2, 1, 0, 0, 2, 0, 1, 1, 0, 0].iter().enumerate() {
        put(&mut bytes, CHUNK * 2 + 248 + i * 4, *value);
    }
    bytes[CHUNK * 4..CHUNK * 4 + 24576].copy_from_slice(&basic[12288..]);
    rehash(&mut bytes);
    bytes
}
fn terminal(value: u8) -> Vec<u8> {
    let mut r = vec![0; 60];
    r[..6].copy_from_slice(b"NOKXFT");
    r[20..24].copy_from_slice(&36u32.to_be_bytes());
    r[24..28].copy_from_slice(&0x10000u32.to_le_bytes());
    r[28..32].copy_from_slice(&28u32.to_le_bytes());
    r[32..36].copy_from_slice(&3u32.to_le_bytes());
    r[36..40].copy_from_slice(&20u32.to_le_bytes());
    r[40..].fill(value);
    r
}
fn binding() -> Binding {
    Binding {
        public_id: identity::parse_flash(&terminal(42)).unwrap(),
        physical_port: "synthetic-port-1".into(),
    }
}
fn parameter(bytes: &[u8]) -> Vec<u8> {
    let mut r = vec![0; 17];
    r[..6].copy_from_slice(b"NOKXFR");
    r[16] = bytes.len() as u8;
    r.extend_from_slice(bytes);
    r
}
fn plain(request: Vec<u8>, response: Vec<u8>) -> Exchange {
    Exchange {
        request,
        response,
        error: None,
    }
}
fn framed(request: Vec<u8>, response: &[u8]) -> FramedExchange {
    FramedExchange {
        request,
        fragments: encode_hdlc(response)
            .unwrap()
            .chunks(1)
            .map(|b| b.to_vec())
            .collect(),
        error: None,
    }
}
fn arrivals(endpoint: Endpoint) -> Vec<TimedObservation> {
    vec![
        TimedObservation {
            elapsed_ms: 10,
            observation: Observation::Disconnected,
        },
        TimedObservation {
            elapsed_ms: 20,
            observation: Observation::Connected {
                endpoint,
                physical_port: "synthetic-port-1".into(),
                candidates: 1,
            },
        },
    ]
}
fn transcripts(bytes: &[u8]) -> (Vec<Exchange>, Vec<FramedExchange>, Vec<FramedExchange>) {
    let mut info = b"NOKV\0\x02\x01\x12\x02\x02\x03".to_vec();
    let platform = b"SYNTHETIC.LUMIA.TEST";
    info.extend_from_slice(&[5, 0, platform.len() as u8]);
    info.extend_from_slice(platform);
    info.extend_from_slice(&[15, 0, 8, 3, 1, 1, 1, 0, 0, 1, 1]);
    info.extend_from_slice(&[0x10, 0, 3, 1, 0, 1]);
    let mut flash = vec![
        plain(b"NOKV".to_vec(), info.clone()),
        plain(identity::flash_request(), terminal(42)),
        plain(
            flash::parameter_request("RRKH").unwrap(),
            parameter(&root_bytes()),
        ),
        plain(
            flash::parameter_request("SS").unwrap(),
            parameter(&[0, 1, 1, 1, 0, 0, 1, 1]),
        ),
        plain(b"NOKV".to_vec(), info),
        plain(identity::flash_request(), terminal(42)),
        plain(
            flash::ffu_header_v1(&bytes[..CHUNK * 3]).unwrap(),
            b"NOKXFS\0\0".to_vec(),
        ),
        plain(
            flash::ffu_payload_v1(&vec![0; CHUNK], 0).unwrap(),
            b"NOKXFS\0\0".to_vec(),
        ),
        plain(b"NOKR".to_vec(), vec![]),
    ];
    flash.push(plain(b"UNSUBMITTED".to_vec(), vec![]));
    let vectors: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../tests/fixtures/spec-a-dload.json"))
            .unwrap();
    let expected: Vec<Exchange> = serde_json::from_value(vectors["exchanges"].clone()).unwrap();
    let mut download: Vec<_> = expected
        .into_iter()
        .map(|e| FramedExchange {
            request: e.request,
            fragments: e.response.chunks(1).map(|b| b.to_vec()).collect(),
            error: e.error,
        })
        .collect();
    download.push(framed(b"UNSUBMITTED".to_vec(), &[2]));
    let programmer = vec![
        framed(v1::hello(), &[2]),
        framed(b"UNSUBMITTED".to_vec(), &[2]),
    ];
    (flash, download, programmer)
}
fn scenario(
    flash: Vec<Exchange>,
    download: Vec<FramedExchange>,
    programmer: Vec<FramedExchange>,
) -> Scenario {
    Scenario {
        source_port: "synthetic-port-1".into(),
        source_candidates: 1,
        flash: ReplayTransport::new(flash),
        download: FramedReplayTransport::new(download),
        programmer: FramedReplayTransport::new(programmer),
        download_arrivals: arrivals(Endpoint::Download),
        programmer_arrivals: arrivals(Endpoint::Programmer),
    }
}
fn prepare(bytes: &[u8]) -> (EntryPlan, Loader) {
    (
        EntryPlan::read(&mut Cursor::new(bytes), &sha(bytes), |_, _| true).unwrap(),
        Loader::prepare(LOADER, &sha(LOADER), &root()).unwrap(),
    )
}
fn remaining(scenario: &mut Scenario, f: &[Exchange], d: &[FramedExchange], p: &[FramedExchange]) {
    for step in f {
        assert_eq!(
            scenario.flash.exchange(&step.request, 65536).unwrap(),
            step.response
        );
    }
    assert!(scenario.flash.finished());
    for (transport, steps) in [(&mut scenario.download, d), (&mut scenario.programmer, p)] {
        for step in steps {
            let response: Vec<_> = step.fragments.iter().flatten().copied().collect();
            assert_eq!(transport.exchange(&step.request, 8192).unwrap(), response);
        }
        assert!(transport.finished());
    }
}

#[test]
fn full_entry_upload_and_programmer_handshake_replay_is_redacted_and_not_an_unlock() {
    let bytes = ffu();
    let (entry, loader) = prepare(&bytes);
    let (f, d, p) = transcripts(&bytes);
    let mut scenario = scenario(f.clone(), d.clone(), p.clone());
    let mut last = 0;
    let mut seq = 0;
    let report = emergency::run(&entry, &loader, &binding(), &mut scenario, |e| {
        assert!(e.completed_bytes >= last);
        last = e.completed_bytes;
        seq += 1;
        assert_eq!(e.sequence, seq);
        true
    })
    .unwrap();
    assert_eq!(report.acknowledged_ram_bytes, LOADER.len() as u64);
    assert!(
        report.replay_only
            && report.programmer_hello_acknowledged
            && report.root_fingerprint_matched
    );
    assert!(
        !report.device_identity_authenticated
            && !report.data_preservation_validated
            && !report.phone_contacted
            && !report.phone_writes_enabled
    );
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("synthetic-port-1"));
    remaining(&mut scenario, &f[9..], &d[d.len() - 1..], &p[1..]);
}

#[test]
fn every_submitted_command_fault_stops_without_retry_or_loader_fallback() {
    let bytes = ffu();
    let (entry, loader) = prepare(&bytes);
    let (base_f, base_d, base_p) = transcripts(&bytes);
    for endpoint in 0..3 {
        let count = match endpoint {
            0 => 9,
            1 => base_d.len() - 1,
            _ => 1,
        };
        for index in 0..count {
            for fault in 0..5 {
                let (mut f, mut d, mut p) = (base_f.clone(), base_d.clone(), base_p.clone());
                if endpoint == 0 {
                    if fault < 2 {
                        f[index].error = Some(
                            if fault == 0 {
                                "timeout"
                            } else {
                                "disconnect after partial request"
                            }
                            .into(),
                        );
                    } else {
                        f[index].response = if fault == 2 {
                            vec![0xff]
                        } else if fault == 3 {
                            vec![0; 65537]
                        } else {
                            b"NOKU".to_vec()
                        };
                    }
                } else {
                    let step = if endpoint == 1 {
                        &mut d[index]
                    } else {
                        &mut p[index]
                    };
                    match fault {
                        0 => {
                            step.fragments.truncate(2);
                            step.error = Some("timeout after partial reply".into());
                        }
                        1 => {
                            step.fragments.clear();
                            step.error = Some("disconnect after partial request".into());
                        }
                        2 => {
                            step.fragments.pop();
                        }
                        3 => {
                            step.fragments = vec![encode_hdlc(&[0xe]).unwrap()];
                        }
                        _ => {
                            step.fragments = vec![vec![0; 8193]];
                        }
                    }
                }
                let mut scene = scenario(f, d, p);
                let mut completed = false;
                let result = emergency::run(&entry, &loader, &binding(), &mut scene, |e| {
                    completed |= e.state == OperationState::Completed;
                    true
                });
                assert!(!completed);
                if endpoint == 0 && index < 6 {
                    assert!(matches!(result, Err(Error::Preflight(_))));
                } else {
                    match result {
                        Err(Error::RecoveryRequired {
                            acknowledged_ram_bytes,
                            storage_submission_attempted,
                            loader_start_attempted,
                            ..
                        }) => {
                            let expected = if endpoint == 0 {
                                0
                            } else if endpoint == 1 {
                                (index.saturating_sub(2) * 256).min(LOADER.len())
                            } else {
                                LOADER.len()
                            };
                            assert_eq!(acknowledged_ram_bytes, expected as u64);
                            assert!(storage_submission_attempted);
                            assert_eq!(
                                loader_start_attempted,
                                endpoint == 2 || (endpoint == 1 && index == base_d.len() - 2)
                            );
                        }
                        other => {
                            panic!("endpoint={endpoint}, command={index}, fault={fault}: {other:?}")
                        }
                    }
                }
                let fi = if endpoint == 0 { index + 1 } else { 9 };
                let di = if endpoint == 0 {
                    0
                } else if endpoint == 1 {
                    index + 1
                } else {
                    base_d.len() - 1
                };
                let pi = if endpoint == 2 { index + 1 } else { 0 };
                remaining(&mut scene, &base_f[fi..], &base_d[di..], &base_p[pi..]);
            }
        }
    }
}

fn counts(events: &[OperationEvent]) -> (usize, usize, usize) {
    let mut c = (0, 0, 0);
    for e in events.iter().filter(|e| e.state == OperationState::Running) {
        match e.message.as_str() {
            "Finish read-only preflight" => {}
            "DLOAD alive" | "DLOAD root" | "RAM upload" | "loader start" => c.1 += 1,
            "programmer hello" => c.2 += 1,
            _ => c.0 += 1,
        }
    }
    c
}
#[test]
fn cancellation_at_every_event_boundary_leaves_all_later_commands_queued() {
    let bytes = ffu();
    let (entry, loader) = prepare(&bytes);
    let (f, d, p) = transcripts(&bytes);
    let mut baseline = Vec::new();
    emergency::run(
        &entry,
        &loader,
        &binding(),
        &mut scenario(f.clone(), d.clone(), p.clone()),
        |e| {
            baseline.push(e.clone());
            true
        },
    )
    .unwrap();
    for stop in 0..baseline.len() - 1 {
        let mut scene = scenario(f.clone(), d.clone(), p.clone());
        let mut calls = 0;
        let result = emergency::run(&entry, &loader, &binding(), &mut scene, |e| {
            calls += 1;
            e.sequence != stop as u64 + 1
        });
        let (fi, di, pi) = counts(&baseline[..stop]);
        if fi <= 6 {
            assert!(matches!(result, Err(Error::Cancelled)));
        } else {
            assert!(matches!(result, Err(Error::RecoveryRequired { .. })));
        }
        assert_eq!(calls, stop + 2); // requested boundary plus the terminal event
        remaining(&mut scene, &f[fi..], &d[di..], &p[pi..]);
    }
}

#[test]
fn changed_public_id_or_root_never_reaches_upload_and_reconnections_cannot_guess_identity() {
    let bytes = ffu();
    let (entry, loader) = prepare(&bytes);
    let (f, d, p) = transcripts(&bytes);
    for changed_index in [1, 5] {
        let mut changed_f = f.clone();
        changed_f[changed_index].response = terminal(43);
        let mut scene = scenario(changed_f, d.clone(), p.clone());
        assert!(matches!(
            emergency::run(&entry, &loader, &binding(), &mut scene, |_| true),
            Err(Error::Preflight(_))
        ));
        remaining(&mut scene, &f[changed_index + 1..], &d, &p);
    }
    for candidates in [0, 2] {
        let mut scene = scenario(f.clone(), d.clone(), p.clone());
        scene.source_candidates = candidates;
        assert!(matches!(
            emergency::run(&entry, &loader, &binding(), &mut scene, |_| true),
            Err(Error::Preflight(_))
        ));
        remaining(&mut scene, &f, &d, &p);
    }
    let mut changed_d = d.clone();
    let mut rk = vec![0x18, 1, 0];
    rk.extend_from_slice(&[7; 32]);
    changed_d[1].fragments = vec![encode_hdlc(&rk).unwrap()];
    let mut scene = scenario(f.clone(), changed_d, p.clone());
    assert!(matches!(
        emergency::run(&entry, &loader, &binding(), &mut scene, |_| true),
        Err(Error::RecoveryRequired {
            acknowledged_ram_bytes: 0,
            ..
        })
    ));
    remaining(&mut scene, &f[9..], &d[2..], &p);
    for phase in 0..2 {
        for case in 0..8 {
            let mut scene = scenario(f.clone(), d.clone(), p.clone());
            let timeline = if phase == 0 {
                &mut scene.download_arrivals
            } else {
                &mut scene.programmer_arrivals
            };
            match case {
                0 => timeline.clear(),
                1 => {
                    timeline.remove(0);
                }
                2 => timeline[1].elapsed_ms = 30_001,
                3 => timeline[1].elapsed_ms = 1,
                4 => {
                    if let Observation::Connected { physical_port, .. } =
                        &mut timeline[1].observation
                    {
                        *physical_port = "different-port".into();
                    }
                }
                5 => {
                    if let Observation::Connected { candidates, .. } = &mut timeline[1].observation
                    {
                        *candidates = 2;
                    }
                }
                6 => {
                    if let Observation::Connected { endpoint, .. } = &mut timeline[1].observation {
                        *endpoint = if phase == 0 {
                            Endpoint::Programmer
                        } else {
                            Endpoint::Download
                        };
                    }
                }
                _ => timeline.push(timeline[1].clone()),
            }
            assert!(matches!(
                emergency::run(&entry, &loader, &binding(), &mut scene, |_| true),
                Err(Error::RecoveryRequired { .. })
            ));
            remaining(
                &mut scene,
                &f[9..],
                if phase == 0 { &d } else { &d[d.len() - 1..] },
                &p,
            );
        }
    }
}

#[test]
fn entry_profile_and_loader_selection_fail_before_any_replay() {
    let bytes = ffu();
    for (at, value) in [
        (CHUNK * 2 + 264, 0u32),
        (CHUNK * 2 + 260, 1),
        (CHUNK * 3, 1),
    ] {
        let mut bad = bytes.clone();
        put(&mut bad, at, value);
        rehash(&mut bad);
        assert!(EntryPlan::read(&mut Cursor::new(&bad), &sha(&bad), |_, _| true).is_err());
    }
    assert!(EntryPlan::read(&mut Cursor::new(&bytes), &"0".repeat(64), |_, _| true).is_err());
    let mut checkpoints = 0;
    let mut previous = 0;
    EntryPlan::read(&mut Cursor::new(&bytes), &sha(&bytes), |_, _| {
        checkpoints += 1;
        true
    })
    .unwrap();
    EntryPlan::read(&mut Cursor::new(&bytes), &sha(&bytes), |done, total| {
        assert!(done >= previous && done <= total);
        previous = done;
        true
    })
    .unwrap();
    for stop in 0..checkpoints {
        let mut calls = 0;
        assert!(matches!(
            EntryPlan::read(&mut Cursor::new(&bytes), &sha(&bytes), |_, _| {
                calls += 1;
                calls != stop + 1
            }),
            Err(wpi_image::ImageError::Cancelled)
        ));
        assert_eq!(calls, stop + 1);
    }
    assert!(Loader::prepare(LOADER, &"0".repeat(64), &root()).is_err());
    assert!(Loader::prepare(LOADER, &sha(LOADER), &RootKeyHash::parse(&[7; 32]).unwrap()).is_err());
    assert!(Loader::prepare(&[], &sha(&[]), &root()).is_err());
    let mut missing_marker = LOADER.to_vec();
    missing_marker[80 + 64] ^= 1;
    assert!(Loader::prepare(&missing_marker, &sha(&missing_marker), &root()).is_err());
    let hex = include_bytes!("../../../tests/fixtures/spec-a/loader.hex");
    Loader::prepare(hex, &sha(hex), &root()).unwrap();
}
