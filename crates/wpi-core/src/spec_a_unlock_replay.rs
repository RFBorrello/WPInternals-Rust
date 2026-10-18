//! Joined Spec A entry/upload + first boot-transfer REPLAY. Not a live unlock.
use crate::{
    spec_a_emergency_replay::{self as emergency, Binding, EntryPlan, Loader, Scenario},
    spec_a_journal::{Artifacts, Entry, Journal, Kind, Phase, Step},
    spec_a_programmer_replay::{self as programmer, Region},
};
use serde::Serialize;
use wpi_image::spec_a::programmer_plan::Plan;
use wpi_types::{Operation, OperationEvent, OperationState};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Joined replay preflight: {0}")]
    Preflight(String),
    #[error("Replay cancelled before entry submission")]
    Cancelled,
    #[error("Inspect device state before continuing: {0}")]
    RecoveryRequired(String),
    #[error("Replay journal save failed (state inspection required: {state_inspection_required}): {message}")]
    Journal {
        state_inspection_required: bool,
        message: String,
    },
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub journal_entries: u64,
    pub acknowledged_ram_bytes: u64,
    pub acknowledged_boot_bytes: u64,
    pub replay_only: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
    pub device_unlock_verified: bool,
    pub data_preservation_validated: bool,
    pub automatic_resume_allowed: bool,
}

/// Plans must be constructed from local verified inputs, not deserialized
/// reports. The sink must durably save each entry before returning Ok.
/// All transports are concrete replay types; no OS/USB/serial writer is accepted.
pub fn run<F: FnMut(&OperationEvent) -> bool, J: FnMut(&Entry) -> std::io::Result<()>>(
    entry: &EntryPlan,
    loader: &Loader,
    boot: &Plan,
    binding: &Binding,
    scenario: &mut Scenario,
    event: F,
    sink: J,
) -> Result<Report, Error> {
    let layout = &boot.report().layout;
    check_source(entry, &layout.source_ffu_sha256, &layout.source_platform)?;
    let (input, decoded) = loader.fingerprints();
    let artifacts = Artifacts {
        source_ffu_sha256: layout.source_ffu_sha256.clone(),
        package_sha256: layout.package_sha256.clone(),
        saved_primary_sha256: layout.saved_primary_sha256.clone(),
        candidate_primary_sha256: layout.candidate_primary_sha256.clone(),
        loader_input_sha256: input.into(),
        loader_decoded_sha256: decoded.into(),
    };
    let regions: Vec<_> = boot
        .regions()
        .iter()
        .map(|r| Region {
            start_bytes: r.start_bytes(),
            data: r.bytes(),
        })
        .collect();
    run_parts(
        entry, loader, &regions, artifacts, binding, scenario, event, sink,
    )
}
fn check_source(entry: &EntryPlan, digest: &str, platform: &str) -> Result<(), Error> {
    let (expected_digest, expected_platform) = entry.source();
    if !digest.eq_ignore_ascii_case(expected_digest) || platform != expected_platform {
        return Err(Error::Preflight(
            "Entry FFU and boot package source differ".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_parts<F: FnMut(&OperationEvent) -> bool, J: FnMut(&Entry) -> std::io::Result<()>>(
    entry: &EntryPlan,
    loader: &Loader,
    regions: &[Region<'_>],
    artifacts: Artifacts,
    binding: &Binding,
    scenario: &mut Scenario,
    event: F,
    sink: J,
) -> Result<Report, Error> {
    let total_boot = programmer::validate(regions).map_err(|e| Error::Preflight(e.to_string()))?;
    for digest in [
        &artifacts.source_ffu_sha256,
        &artifacts.package_sha256,
        &artifacts.saved_primary_sha256,
        &artifacts.candidate_primary_sha256,
        &artifacts.loader_input_sha256,
        &artifacts.loader_decoded_sha256,
    ] {
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Preflight("Invalid artifact fingerprint".into()));
        }
    }
    let mut journal = Journal::new(artifacts, total_boot, sink);
    let mut events = Events {
        event,
        sequence: 0,
        phase_offset: 0,
        done: 0,
        total: total_boot + loader.byte_len(),
        cancelled: false,
    };
    if let Err(error) = journal.mark(Kind::Ready, Phase::Preparation, Step::Prepared) {
        return Err(finish_failure(
            &mut journal,
            &mut events,
            false,
            error.to_string(),
        ));
    }
    let result = emergency::run_checkpointed(
        entry,
        loader,
        binding,
        scenario,
        |e| events.forward(e),
        |c| journal.save(c),
    );
    if let Err(error) = result {
        return Err(finish_failure(
            &mut journal,
            &mut events,
            matches!(error, emergency::Error::Cancelled),
            error.to_string(),
        ));
    }
    if let Err(error) = journal.mark(Kind::PhaseComplete, Phase::EntryUpload, Step::Handoff) {
        return Err(finish_failure(
            &mut journal,
            &mut events,
            false,
            error.to_string(),
        ));
    }
    events.phase_offset = journal.entry.acknowledged_ram_bytes;
    if !events.emit(
        OperationState::Running,
        "Replay loader phase saved; boot-transfer boundary",
    ) {
        return Err(finish_failure(
            &mut journal,
            &mut events,
            true,
            "cancelled at phase handoff".into(),
        ));
    }
    let result = programmer::continue_checkpointed(
        regions,
        &mut scenario.programmer,
        |e| events.forward(e),
        |c| journal.save(c),
    );
    if let Err(error) = result {
        return Err(finish_failure(
            &mut journal,
            &mut events,
            matches!(error, programmer::Error::Cancelled),
            error.to_string(),
        ));
    }
    if let Err(error) = journal.mark(
        Kind::TransferComplete,
        Phase::BootTransfer,
        Step::ProgrammerReboot,
    ) {
        return Err(finish_failure(
            &mut journal,
            &mut events,
            false,
            error.to_string(),
        ));
    }
    events.done = events.total;
    events.emit(
        OperationState::Completed,
        "Joined replay transfers saved; device unlock/boot is not established",
    );
    Ok(Report {
        journal_entries: journal.entry.sequence,
        acknowledged_ram_bytes: journal.entry.acknowledged_ram_bytes,
        acknowledged_boot_bytes: journal.entry.acknowledged_boot_bytes,
        replay_only: true,
        phone_contacted: false,
        phone_writes_enabled: false,
        device_unlock_verified: false,
        data_preservation_validated: false,
        automatic_resume_allowed: false,
    })
}

fn finish_failure<J: FnMut(&Entry) -> std::io::Result<()>, F: FnMut(&OperationEvent) -> bool>(
    journal: &mut Journal<J>,
    events: &mut Events<F>,
    cancelled: bool,
    mut message: String,
) -> Error {
    if !journal.failed {
        let kind = if journal.entry.state_inspection_required {
            Kind::RecoveryRequired
        } else if cancelled {
            Kind::Cancelled
        } else {
            Kind::Failed
        };
        if let Err(error) = journal.mark(kind, journal.entry.phase, journal.entry.step) {
            message = format!("Terminal journal save failed: {error}; phase error: {message}");
        }
    }
    let inspection = journal.entry.state_inspection_required;
    events.emit(
        if inspection {
            OperationState::RecoveryRequired
        } else if journal.failed {
            OperationState::Failed
        } else if cancelled {
            OperationState::Cancelled
        } else {
            OperationState::Failed
        },
        "Joined replay stopped; inspect returned error and last durable intent",
    );
    if journal.failed {
        Error::Journal {
            state_inspection_required: inspection,
            message: format!(
                "{}; {message}",
                journal.failure.as_deref().unwrap_or("journal save failed")
            ),
        }
    } else if inspection {
        Error::RecoveryRequired(message)
    } else if cancelled {
        Error::Cancelled
    } else {
        Error::Preflight(message)
    }
}

struct Events<F> {
    event: F,
    sequence: u64,
    phase_offset: u64,
    done: u64,
    total: u64,
    cancelled: bool,
}
impl<F: FnMut(&OperationEvent) -> bool> Events<F> {
    fn emit(&mut self, state: OperationState, message: &str) -> bool {
        self.sequence += 1;
        let proceed = (self.event)(&OperationEvent {
            sequence: self.sequence,
            operation: Operation::UnlockBootloader,
            state,
            completed_bytes: self.done,
            total_bytes: self.total,
            message: message.into(),
        });
        self.cancelled |= !proceed;
        proceed
    }
    fn forward(&mut self, e: &OperationEvent) -> bool {
        self.done = self.phase_offset + e.completed_bytes;
        if matches!(
            e.state,
            OperationState::Completed
                | OperationState::Failed
                | OperationState::RecoveryRequired
                | OperationState::Cancelled
        ) {
            // Child terminal callbacks do not publish an overall completion.
            return !self.cancelled;
        }
        self.emit(e.state, &e.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emergency::{Endpoint, Observation, TimedObservation};
    use std::{cell::RefCell, io::Cursor};
    use wpi_protocol::{
        flash, identity,
        preflight::RootKeyHash,
        qualcomm::{encode_hdlc, v1},
        replay::{Exchange, FramedExchange, FramedReplayTransport, ReplayTransport},
        MessageTransport,
    };
    #[allow(dead_code)]
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/spec_a_emergency.rs"
        ));
    }
    use support::*;
    #[derive(serde::Deserialize)]
    struct OwnedRegion {
        start_bytes: u32,
        data: Vec<u8>,
    }
    struct Fixture {
        entry: EntryPlan,
        loader: Loader,
        owners: Vec<OwnedRegion>,
        artifacts: Artifacts,
        flash: Vec<Exchange>,
        download: Vec<FramedExchange>,
        programmer: Vec<FramedExchange>,
    }
    impl Fixture {
        fn new() -> Self {
            let bytes = ffu();
            let (entry, loader) = prepare(&bytes);
            let golden: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../tests/fixtures/spec-a-programmer-v1.json"
            ))
            .unwrap();
            let owners = serde_json::from_value(golden["regions"].clone()).unwrap();
            let commands: Vec<Exchange> =
                serde_json::from_value(golden["exchanges"].clone()).unwrap();
            let (flash, download, first_programmer) = transcripts(&bytes);
            let mut programmer = vec![first_programmer[0].clone()];
            programmer.extend(commands[1..].iter().map(|e| FramedExchange {
                request: e.request.clone(),
                fragments: e.response.chunks(2).map(|b| b.to_vec()).collect(),
                error: None,
            }));
            programmer.push(first_programmer.last().unwrap().clone());
            let (input, decoded) = loader.fingerprints();
            let artifacts = Artifacts {
                source_ffu_sha256: sha(&bytes),
                package_sha256: sha(b"synthetic package"),
                saved_primary_sha256: sha(b"synthetic saved primary"),
                candidate_primary_sha256: sha(b"synthetic candidate"),
                loader_input_sha256: input.into(),
                loader_decoded_sha256: decoded.into(),
            };
            Self {
                entry,
                loader,
                owners,
                artifacts,
                flash,
                download,
                programmer,
            }
        }
        fn scene(&self) -> Scenario {
            scenario(
                self.flash.clone(),
                self.download.clone(),
                self.programmer.clone(),
            )
        }
        fn run<F: FnMut(&OperationEvent) -> bool, J: FnMut(&Entry) -> std::io::Result<()>>(
            &self,
            scene: &mut Scenario,
            events: F,
            sink: J,
        ) -> Result<Report, Error> {
            let regions: Vec<_> = self
                .owners
                .iter()
                .map(|r| Region {
                    start_bytes: r.start_bytes,
                    data: &r.data,
                })
                .collect();
            run_parts(
                &self.entry,
                &self.loader,
                &regions,
                self.artifacts.clone(),
                &binding(),
                scene,
                events,
                sink,
            )
        }
        fn remaining(&self, scene: &mut Scenario, counts: (usize, usize, usize)) {
            remaining(
                scene,
                &self.flash[counts.0..],
                &self.download[counts.1..],
                &self.programmer[counts.2..],
            );
        }
    }
    fn command_counts(records: &[Entry]) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for e in records {
            if e.step == Step::SourcePreflight && e.kind == Kind::PhaseComplete {
                c.0 = 6;
            }
            if !matches!(e.kind, Kind::Acknowledged | Kind::Submitted) {
                continue;
            }
            match (e.phase, e.step) {
                (_, Step::FfuHeader | Step::BoundaryZero | Step::EntryReboot) => c.0 += 1,
                (_, Step::DloadAlive | Step::DloadRoot | Step::RamUpload | Step::LoaderStart) => {
                    c.1 += 1
                }
                (Phase::EntryUpload, Step::ProgrammerHello) | (Phase::BootTransfer, _) => c.2 += 1,
                _ => {}
            }
        }
        c
    }
    fn event_counts(events: &[OperationEvent]) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for e in events.iter().filter(|e| e.state == OperationState::Running) {
            match e.message.as_str() {
                "Finish read-only preflight"
                | "Replay loader phase saved; boot-transfer boundary" => {}
                "DLOAD alive" | "DLOAD root" | "RAM upload" | "loader start" => c.1 += 1,
                "programmer hello" => c.2 += 1,
                other if other.starts_with("Replay programmer ") => c.2 += 1,
                _ => c.0 += 1,
            }
        }
        c
    }
    #[test]
    fn joined_phases_share_one_handshake_and_publish_only_durably_saved_transfer_completion() {
        let f = Fixture::new();
        let records = RefCell::new(Vec::<Entry>::new());
        let mut scene = f.scene();
        let mut last = 0;
        let mut sequence = 0;
        let mut completions = 0;
        let report = f
            .run(
                &mut scene,
                |e| {
                    sequence += 1;
                    assert_eq!(e.sequence, sequence);
                    assert!(e.completed_bytes >= last);
                    last = e.completed_bytes;
                    assert_eq!(e.total_bytes, 9171);
                    if e.state == OperationState::Completed {
                        completions += 1;
                        assert_eq!(
                            records.borrow().last().unwrap().kind,
                            Kind::TransferComplete
                        );
                        return false;
                    }
                    true
                },
                |e| {
                    records.borrow_mut().push(e.clone());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(completions, 1);
        assert_eq!(last, 9171);
        assert_eq!(report.acknowledged_ram_bytes, 6608);
        assert_eq!(report.acknowledged_boot_bytes, 2563);
        assert!(
            !report.device_unlock_verified
                && !report.phone_writes_enabled
                && !report.data_preservation_validated
                && !report.automatic_resume_allowed
        );
        let records = records.into_inner();
        assert_eq!(records.len(), 90);
        for (index, e) in records.iter().enumerate() {
            assert_eq!(e.sequence, index as u64 + 1);
            assert_eq!(
                serde_json::to_value(&e.artifacts).unwrap(),
                serde_json::to_value(&f.artifacts).unwrap()
            );
            assert!(e.replay_only && e.fresh_device_checks_required);
            assert!(
                !e.automatic_resume_allowed
                    && !e.phone_writes_enabled
                    && !e.device_unlock_verified
                    && !e.data_preservation_validated
            );
            if e.kind == Kind::Intent {
                let ack = &records[index + 1];
                assert!(matches!(ack.kind, Kind::Acknowledged | Kind::Submitted));
                assert_eq!(ack.step, e.step);
                assert_eq!(ack.address, e.address);
                assert_eq!(ack.bytes, e.bytes);
            }
        }
        assert_eq!(
            records
                .iter()
                .filter(|e| e.step == Step::ProgrammerHello && e.kind == Kind::Intent)
                .count(),
            1
        );
        let serialized = serde_json::to_string(&records).unwrap();
        assert!(!serialized.contains("synthetic-port-1"));
        f.remaining(&mut scene, command_counts(&records));
    }
    #[test]
    fn persistence_failure_at_every_checkpoint_stops_before_the_next_command() {
        let f = Fixture::new();
        let mut baseline = Vec::new();
        f.run(
            &mut f.scene(),
            |_| true,
            |e| {
                baseline.push(e.clone());
                Ok(())
            },
        )
        .unwrap();
        for (failed, expected) in baseline.iter().enumerate() {
            let mut records = Vec::new();
            let mut scene = f.scene();
            let mut completed = false;
            let result = f.run(
                &mut scene,
                |e| {
                    completed |= e.state == OperationState::Completed;
                    true
                },
                |e| {
                    if e.sequence == expected.sequence {
                        return Err(std::io::Error::other("simulated disk full"));
                    }
                    records.push(e.clone());
                    Ok(())
                },
            );
            assert!(!completed);
            assert_eq!(records.len(), failed);
            assert_eq!(
                serde_json::to_value(&records).unwrap(),
                serde_json::to_value(&baseline[..failed]).unwrap()
            );
            assert!(
                matches!(result, Err(Error::Journal { state_inspection_required, message }) if state_inspection_required == expected.state_inspection_required && message.contains("simulated disk full"))
            );
            // A failed ACK save follows a submitted command; a failed intent save
            // precedes submission. Include the failing checkpoint to count that.
            f.remaining(&mut scene, command_counts(&baseline[..=failed]));
        }
    }
    #[test]
    fn cancellation_at_every_boundary_does_not_enter_the_next_phase_or_command() {
        let f = Fixture::new();
        let mut baseline = Vec::new();
        f.run(
            &mut f.scene(),
            |e| {
                baseline.push(e.clone());
                true
            },
            |_| Ok(()),
        )
        .unwrap();
        for stop in 0..baseline.len() - 1 {
            let mut scene = f.scene();
            let mut records = Vec::new();
            let mut completions = 0;
            let result = f.run(
                &mut scene,
                |e| {
                    completions += usize::from(e.state == OperationState::Completed);
                    e.sequence != stop as u64 + 1
                },
                |e| {
                    records.push(e.clone());
                    Ok(())
                },
            );
            let counts = event_counts(&baseline[..stop]);
            assert_eq!(completions, 0);
            assert!(!records.iter().any(|e| e.kind == Kind::TransferComplete));
            if counts.0 <= 6 {
                assert!(matches!(result, Err(Error::Cancelled)));
                assert_eq!(records.last().unwrap().kind, Kind::Cancelled);
            } else {
                assert!(matches!(result, Err(Error::RecoveryRequired(_))));
                assert_eq!(records.last().unwrap().kind, Kind::RecoveryRequired);
            }
            f.remaining(&mut scene, counts);
        }
    }
    #[test]
    fn lost_final_write_reply_retains_an_uncertain_intent_and_terminal_save_errors_are_reported() {
        let f = Fixture::new();
        for fail_terminal in [false, true] {
            let mut scene = f.scene();
            let mut programmer = f.programmer.clone();
            programmer[6].error = Some("lost final write reply".into());
            scene.programmer = FramedReplayTransport::new(programmer);
            let mut records = Vec::new();
            let result = f.run(
                &mut scene,
                |_| true,
                |e| {
                    if fail_terminal && e.kind == Kind::RecoveryRequired {
                        return Err(std::io::Error::other("terminal disk full"));
                    }
                    records.push(e.clone());
                    Ok(())
                },
            );
            if fail_terminal {
                assert!(
                    matches!(result, Err(Error::Journal { state_inspection_required: true, message }) if message.contains("terminal disk full"))
                );
            } else {
                assert!(matches!(result, Err(Error::RecoveryRequired(_))));
            }
            let last_write = records
                .iter()
                .rev()
                .find(|e| e.step == Step::BootWrite && e.kind == Kind::Intent)
                .unwrap();
            assert_eq!(last_write.address, Some(4096));
            assert_eq!(last_write.bytes, 512);
            assert_eq!(last_write.acknowledged_boot_bytes, 2051);
            assert!(!records.iter().any(|e| e.kind == Kind::TransferComplete));
            f.remaining(&mut scene, (9, 29, 7));
        }
        let mut scene = f.scene();
        let mut last_state = OperationState::Prepared;
        let result = f.run(
            &mut scene,
            |e| {
                last_state = e.state;
                false
            },
            |e| {
                if e.kind == Kind::Cancelled {
                    Err(std::io::Error::other("cancel checkpoint disk full"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(
            matches!(result, Err(Error::Journal { state_inspection_required: false, message }) if message.contains("cancel checkpoint disk full"))
        );
        assert_eq!(last_state, OperationState::Failed);
        f.remaining(&mut scene, (0, 0, 0));
    }
    #[test]
    fn artifact_coherence_and_native_file_protection_cannot_be_bypassed_by_reports() {
        let f = Fixture::new();
        assert!(check_source(&f.entry, &"0".repeat(64), f.entry.source().1).is_err());
        assert!(check_source(&f.entry, f.entry.source().0, "different").is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("joined.jsonl");
        let mut file = crate::spec_a_journal::FileJournal::create(&path).unwrap();
        let mut records = Vec::new();
        f.run(
            &mut f.scene(),
            |_| true,
            |e| {
                file.append(e)?;
                records.push(e.clone());
                Ok(())
            },
        )
        .unwrap();
        drop(file);
        let bytes = std::fs::read(&path).unwrap();
        assert!(crate::spec_a_journal::FileJournal::create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let lines: Vec<serde_json::Value> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 90);
        assert_eq!(lines.last().unwrap()["kind"], "transfer_complete");
        let broken = dir.path().join("broken.jsonl");
        let mut file = crate::spec_a_journal::FileJournal::create(&broken).unwrap();
        let mut too_large = records[0].clone();
        too_large.artifacts.package_sha256 = "x".repeat(4097);
        assert!(file.append(&too_large).is_err());
        assert!(file.append(&records[0]).is_err());
        assert_eq!(std::fs::metadata(broken).unwrap().len(), 0);
    }
}
