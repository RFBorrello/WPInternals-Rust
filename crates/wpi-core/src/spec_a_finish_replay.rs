//! Failure-contained rehearsal of one composed Spec A boot-integrity stage.
//! Concrete replay transport only. Does not assert successful device unlock.
use serde::Serialize;
use wpi_image::spec_a::finish_plan::{Plan, Region, SecondPass, StageBinding};
use wpi_protocol::{flash, replay::ReplayTransport, MessageTransport};
use wpi_types::{Operation, OperationEvent, OperationState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Variables,
    FirstEfiesp,
    InstalledEfiesp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Intent,
    Acknowledged,
    TransferComplete,
}
#[derive(Debug, Serialize)]
pub struct Checkpoint {
    pub schema: u32,
    pub binding: StageBinding,
    pub sequence: u64,
    pub stage: Stage,
    pub kind: Kind,
    pub start_sector: Option<u32>,
    pub byte_length: u64,
    pub payload_sha256: Option<String>,
    pub acknowledged_bytes: u64,
    pub total_bytes: u64,
    pub replay_only: bool,
    pub automatic_resume_allowed: bool,
    pub device_unlock_verified: bool,
}
#[derive(Debug, thiserror::Error)]
#[error("Spec A finish stage stopped (state inspection required: {state_inspection_required}): {message}")]
pub struct Error {
    pub state_inspection_required: bool,
    pub message: String,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub stage: Stage,
    pub acknowledged_bytes: u64,
    pub journal_entries: u64,
    pub replay_only: bool,
    pub phone_writes_enabled: bool,
    pub device_unlock_verified: bool,
    pub return_to_windows_verified: bool,
    pub automatic_resume_allowed: bool,
}
/// New regular JSONL file, synced before a command may be submitted. No append
/// continuation or automatic resume; an I/O failure permanently retires the sink.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileJournal(crate::journal_file::FileSink);
#[cfg(not(target_arch = "wasm32"))]
impl FileJournal {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(crate::journal_file::FileSink::create(path)?))
    }
    pub fn append(&mut self, point: &Checkpoint) -> std::io::Result<()> {
        self.0.append(point, 4096)
    }
}
pub fn run<F: FnMut(&OperationEvent) -> bool, J: FnMut(&Checkpoint) -> std::io::Result<()>>(
    plan: &Plan,
    stage: Stage,
    transport: &mut ReplayTransport,
    event: F,
    sink: J,
) -> Result<Report, Error> {
    let regions = match stage {
        Stage::Variables => plan.nv_regions(),
        Stage::FirstEfiesp => plan.efiesp_regions(),
        Stage::InstalledEfiesp => {
            return Err(Error {
                state_inspection_required: false,
                message: "An installed-image second-pass object is required".into(),
            })
        }
    };
    run_regions(
        regions,
        stage,
        plan.stage_binding(stage == Stage::Variables),
        transport,
        event,
        sink,
    )
}
pub fn run_second_pass<
    F: FnMut(&OperationEvent) -> bool,
    J: FnMut(&Checkpoint) -> std::io::Result<()>,
>(
    plan: &SecondPass,
    transport: &mut ReplayTransport,
    event: F,
    sink: J,
) -> Result<Report, Error> {
    run_regions(
        plan.regions(),
        Stage::InstalledEfiesp,
        plan.binding().clone(),
        transport,
        event,
        sink,
    )
}

fn run_regions<F: FnMut(&OperationEvent) -> bool, J: FnMut(&Checkpoint) -> std::io::Result<()>>(
    regions: &[Region],
    stage: Stage,
    binding: StageBinding,
    transport: &mut ReplayTransport,
    mut event: F,
    mut sink: J,
) -> Result<Report, Error> {
    let parts: Vec<_> = regions
        .iter()
        .map(|r| (r.start_sector(), r.bytes()))
        .collect();
    run_parts(&parts, stage, binding, transport, &mut event, &mut sink)
}
fn run_parts<F: FnMut(&OperationEvent) -> bool, J: FnMut(&Checkpoint) -> std::io::Result<()>>(
    regions: &[(u32, &[u8])],
    stage: Stage,
    binding: StageBinding,
    transport: &mut ReplayTransport,
    mut event: F,
    mut sink: J,
) -> Result<Report, Error> {
    use sha2::{Digest, Sha256};
    let total = regions.iter().map(|r| r.1.len() as u64).sum();
    let mut point = Checkpoint {
        schema: 1,
        binding,
        sequence: 0,
        stage,
        kind: Kind::Intent,
        start_sector: None,
        byte_length: 0,
        payload_sha256: None,
        acknowledged_bytes: 0,
        total_bytes: total,
        replay_only: true,
        automatic_resume_allowed: false,
        device_unlock_verified: false,
    };
    let mut submitted = false;
    let mut event_sequence = 0;
    let mut progress = |state, done, message: &str| {
        event_sequence += 1;
        event(&OperationEvent {
            sequence: event_sequence,
            operation: Operation::UnlockBootloader,
            state,
            completed_bytes: done,
            total_bytes: total,
            message: message.into(),
        })
    };
    let result: Result<(), String> = (|| {
        for region in regions {
            for (index, bytes) in region.1.chunks(2 * 1024 * 1024).enumerate() {
                if !progress(
                    OperationState::Running,
                    point.acknowledged_bytes,
                    "Before next Spec A finish-stage replay command",
                ) {
                    return Err("Cancelled at a command boundary".into());
                }
                let start = u64::from(region.0) + index as u64 * 4096;
                let start = u32::try_from(start).map_err(|_| "Sector address overflow")?;
                let percent = if total == 0 {
                    0
                } else {
                    (point.acknowledged_bytes * 100 / total) as u8
                };
                let request =
                    flash::sectors_v1(start, bytes, percent).map_err(|e| e.to_string())?;
                point.sequence += 1;
                point.kind = Kind::Intent;
                point.start_sector = Some(start);
                point.byte_length = bytes.len() as u64;
                point.payload_sha256 = Some(format!("{:x}", Sha256::digest(bytes)));
                sink(&point).map_err(|e| format!("Intent journal failed: {e}"))?;
                // Once durable intent exists, a restart cannot establish whether
                // submission happened. Even an immediate exchange error is uncertain.
                submitted = true;
                let reply = transport
                    .exchange(&request, 65536)
                    .map_err(|e| e.to_string())?;
                flash::sectors_v1_status(&reply).map_err(|e| e.to_string())?;
                point.acknowledged_bytes += bytes.len() as u64;
                point.sequence += 1;
                point.kind = Kind::Acknowledged;
                sink(&point).map_err(|e| format!("Acknowledgement journal failed: {e}"))?;
            }
        }
        point.sequence += 1;
        point.kind = Kind::TransferComplete;
        point.start_sector = None;
        point.byte_length = 0;
        point.payload_sha256 = None;
        sink(&point).map_err(|e| format!("Completion journal failed: {e}"))?;
        Ok(())
    })();
    if let Err(message) = result {
        progress(if submitted {OperationState::RecoveryRequired} else {OperationState::Failed},point.acknowledged_bytes,
            "Stage stopped; inspect last durable intent and current device state before any further command");
        return Err(Error {
            state_inspection_required: submitted,
            message,
        });
    }
    progress(
        OperationState::Completed,
        point.acknowledged_bytes,
        "Stage transcript saved; device unlock and return to Windows remain unverified",
    );
    Ok(Report {
        stage,
        acknowledged_bytes: point.acknowledged_bytes,
        journal_entries: point.sequence,
        replay_only: true,
        phone_writes_enabled: false,
        device_unlock_verified: false,
        return_to_windows_verified: false,
        automatic_resume_allowed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wpi_protocol::replay::Exchange;
    fn binding() -> StageBinding {
        StageBinding {
            source_ffu_sha256: "a".repeat(64),
            package_sha256: "b".repeat(64),
            before_primary_sha256: "c".repeat(64),
            after_primary_sha256: "d".repeat(64),
        }
    }
    fn steps(parts: &[(u32, &[u8])]) -> Vec<Exchange> {
        let total: u64 = parts.iter().map(|p| p.1.len() as u64).sum();
        let mut done = 0;
        let mut result = Vec::new();
        for (start, data) in parts {
            for (index, chunk) in data.chunks(2 * 1024 * 1024).enumerate() {
                result.push(Exchange {
                    request: flash::sectors_v1(
                        *start + index as u32 * 4096,
                        chunk,
                        (done * 100 / total) as u8,
                    )
                    .unwrap(),
                    response: b"NOKF\0\0\0\0".to_vec(),
                    error: None,
                });
                done += chunk.len() as u64;
            }
        }
        result
    }
    #[test]
    fn command_chunks_intents_acknowledgements_and_progress_are_ordered() {
        let large = vec![0x7e; 2 * 1024 * 1024 + 512];
        let tail = vec![0x31; 1024];
        let parts = [(100, large.as_slice()), (9000, tail.as_slice())];
        let mut transport = ReplayTransport::new(steps(&parts));
        let mut events = Vec::new();
        let mut points = Vec::new();
        let report = run_parts(
            &parts,
            Stage::FirstEfiesp,
            binding(),
            &mut transport,
            |e| {
                events.push(e.clone());
                true
            },
            |p| {
                points.push(serde_json::to_value(p).unwrap());
                Ok(())
            },
        )
        .unwrap();
        assert!(transport.finished());
        assert_eq!(report.journal_entries, 7);
        assert_eq!(report.acknowledged_bytes, (large.len() + tail.len()) as u64);
        assert!(
            !report.phone_writes_enabled
                && !report.device_unlock_verified
                && !report.return_to_windows_verified
                && !report.automatic_resume_allowed
        );
        assert_eq!(points[0]["kind"], "intent");
        assert_eq!(points[1]["kind"], "acknowledged");
        assert_eq!(points[2]["start_sector"], 4196);
        assert_eq!(points[2]["byte_length"], 512);
        assert!(
            events
                .windows(2)
                .all(|p| p[0].completed_bytes <= p[1].completed_bytes
                    && p[0].sequence < p[1].sequence)
        );
        assert_eq!(events.last().unwrap().state, OperationState::Completed);
    }
    #[test]
    fn every_transport_fault_cancellation_and_journal_failure_stops_without_followup_commands() {
        let a = vec![7; 512];
        let b = vec![8; 512];
        let parts = [(100, a.as_slice()), (200, b.as_slice())];
        let steps = steps(&parts);
        for at in 0..steps.len() {
            for fault in 0..5 {
                let mut broken = steps.clone();
                match fault {
                    0 => broken[at].error = Some("disconnect after submission".into()),
                    1 => broken[at].response = vec![],
                    2 => broken[at].response = b"NOKF\0\0\0\x01".to_vec(),
                    3 => broken[at].response = b"NOKF\0\0\0\0X".to_vec(),
                    _ => broken[at].response = b"NOKU\0\0\0\0".to_vec(),
                }
                let mut transport = ReplayTransport::new(broken);
                let mut points = 0;
                let error = run_parts(
                    &parts,
                    Stage::Variables,
                    binding(),
                    &mut transport,
                    |_| true,
                    |_| {
                        points += 1;
                        Ok(())
                    },
                )
                .unwrap_err();
                assert!(error.state_inspection_required);
                assert_eq!(points, at * 2 + 1);
                for later in &steps[at + 1..] {
                    assert_eq!(
                        transport.exchange(&later.request, 65536).unwrap(),
                        later.response
                    );
                }
                assert!(transport.finished());
            }
            let mut transport = ReplayTransport::new(steps.clone());
            let mut calls = 0;
            let error = run_parts(
                &parts,
                Stage::Variables,
                binding(),
                &mut transport,
                |_| {
                    calls += 1;
                    calls != at + 1
                },
                |_| Ok(()),
            )
            .unwrap_err();
            assert_eq!(error.state_inspection_required, at > 0);
            for later in &steps[at..] {
                assert_eq!(
                    transport.exchange(&later.request, 65536).unwrap(),
                    later.response
                );
            }
            assert!(transport.finished());
        }
        for at in 0usize..5 {
            let mut transport = ReplayTransport::new(steps.clone());
            let mut saves = 0;
            let error = run_parts(
                &parts,
                Stage::Variables,
                binding(),
                &mut transport,
                |_| true,
                |_| {
                    let current = saves;
                    saves += 1;
                    if current == at {
                        Err(std::io::Error::other("disk full"))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert_eq!(saves, at + 1);
            assert_eq!(error.state_inspection_required, at > 0);
            let consumed = at.div_ceil(2);
            for later in &steps[consumed..] {
                assert_eq!(
                    transport.exchange(&later.request, 65536).unwrap(),
                    later.response
                );
            }
            assert!(transport.finished());
        }
    }
}
