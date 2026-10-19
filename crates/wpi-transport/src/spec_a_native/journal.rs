//! Advisory inspection only. Imported records never authorize execution/resume.
use super::{hash, Binding, Record};
use serde::Serialize;
use std::io::{BufRead, BufReader, Read};

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub complete_records: u64,
    pub last_stage: Option<String>,
    pub unmatched_intent: bool,
    pub torn_final_record: bool,
    pub completion_reported: bool,
    pub storage_may_have_changed: bool,
    pub state_inspection_required: bool,
    pub imported_evidence_authenticated: bool,
    pub automatic_resume_allowed: bool,
}
fn digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn binding_valid(b: &Binding) -> bool {
    [
        &b.source_ffu_sha256,
        &b.package_sha256,
        &b.saved_primary_sha256,
        &b.boot_primary_sha256,
        &b.nv_primary_sha256,
        &b.loader_input_sha256,
        &b.loader_decoded_sha256,
        &b.donor_sha256,
    ]
    .into_iter()
    .all(|s| digest(s))
        && (512..=u64::from(u32::MAX)).contains(&b.capacity_sectors)
}
pub fn inspect<R: Read>(input: R) -> Result<Inspection, String> {
    let mut reader = BufReader::new(input);
    let mut total = 0usize;
    let mut count = 0;
    let mut binding_hash = None;
    let mut pending: Option<Record> = None;
    let mut terminal = false;
    let mut report = Inspection {
        complete_records: 0,
        last_stage: None,
        unmatched_intent: false,
        torn_final_record: false,
        completion_reported: false,
        storage_may_have_changed: false,
        state_inspection_required: true,
        imported_evidence_authenticated: false,
        automatic_resume_allowed: false,
    };
    loop {
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take(8193)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n;
        if n > 8192 || total > 64 * 1024 * 1024 {
            return Err("Native journal exceeds line/file bounds".into());
        }
        if line.last() != Some(&b'\n') {
            report.torn_final_record = true;
            break;
        }
        let point: Record =
            serde_json::from_slice(&line).map_err(|_| "Invalid native journal record")?;
        count += 1;
        if terminal
            || point.schema != 1
            || point.sequence != count
            || point.automatic_resume_allowed
            || !digest(&point.binding_sha256)
            || (report.storage_may_have_changed && !point.storage_may_have_changed)
        {
            return Err("Inconsistent native journal sequence, terminal state or binding".into());
        }
        if count == 1 {
            let b = point
                .prepared_binding
                .as_ref()
                .ok_or("Native journal must begin with prepared artifacts")?;
            if point.kind != "prepared"
                || !binding_valid(b)
                || hash(&serde_json::to_vec(b).map_err(|e| e.to_string())?) != point.binding_sha256
            {
                return Err("Native prepared binding is invalid".into());
            }
            binding_hash = Some(point.binding_sha256.clone());
        } else if point.prepared_binding.is_some()
            || binding_hash.as_deref() != Some(&point.binding_sha256)
        {
            return Err("Native journal artifacts changed".into());
        }
        report.storage_may_have_changed |= point.storage_may_have_changed;
        report.last_stage = Some(point.stage.clone());
        match point.kind.as_str() {
            "intent" | "acknowledged_or_submitted" => {
                if point.request_bytes == 0
                    || point.request_bytes > 32 * 1024 * 1024 + 32
                    || !point.request_sha256.as_deref().is_some_and(digest)
                    || (point.storage_start_bytes.is_none() && point.storage_payload_bytes != 0)
                    || point.storage_payload_bytes > point.request_bytes
                    || point.storage_start_bytes.is_some_and(|a| {
                        a.checked_add(point.storage_payload_bytes as u64).is_none()
                    })
                {
                    return Err("Invalid native command metadata".into());
                }
                if point.kind == "intent" {
                    if pending.is_some() {
                        return Err(
                            "A second native intent cannot resolve an uncertain command".into()
                        );
                    }
                    pending = Some(point);
                } else {
                    let intent = pending
                        .take()
                        .ok_or("Native acknowledgement has no preceding intent")?;
                    if intent.stage != point.stage
                        || intent.request_sha256 != point.request_sha256
                        || intent.request_bytes != point.request_bytes
                        || intent.storage_start_bytes != point.storage_start_bytes
                        || intent.storage_payload_bytes != point.storage_payload_bytes
                        || intent.storage_may_have_changed != point.storage_may_have_changed
                    {
                        return Err("Native acknowledgement differs from its intent".into());
                    }
                }
            }
            "prepared"
            | "verified"
            | "manual_setup_selected"
            | "awaiting_driver_setup"
            | "awaiting_storage_setup"
            | "awaiting_manual_restart"
            | "completed"
            | "recovery_required" => {
                if point.request_sha256.is_some()
                    || point.request_bytes != 0
                    || point.storage_start_bytes.is_some()
                    || point.storage_payload_bytes != 0
                    || (pending.is_some() && point.kind != "recovery_required")
                    || (point.kind == "prepared" && count != 1)
                {
                    return Err("Invalid native stage transition".into());
                }
                report.completion_reported = point.kind == "completed";
                terminal = matches!(point.kind.as_str(), "completed" | "recovery_required");
            }
            _ => return Err("Unknown native journal record kind".into()),
        }
    }
    if count == 0 {
        return Err("Native journal has no complete prepared record".into());
    }
    report.complete_records = count;
    report.unmatched_intent = pending.is_some();
    report.state_inspection_required =
        report.torn_final_record || report.unmatched_intent || !report.completion_reported;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_a_native::{tests::binding, Journal};
    fn transcript() -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native.jsonl");
        let mut journal = Journal::create(&path, binding()).unwrap();
        journal.append("prepared", "pinned", None).unwrap();
        journal.storage = true;
        journal.append("intent", "write", Some(b"x")).unwrap();
        journal
            .append("acknowledged_or_submitted", "write", Some(b"x"))
            .unwrap();
        journal
            .append("completed", "returned Normal", None)
            .unwrap();
        std::fs::read(path).unwrap()
    }
    #[test]
    fn manual_setup_checkpoint_retains_storage_uncertainty_without_resume_authority() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.jsonl");
        let mut journal = Journal::create(&path, binding()).unwrap();
        journal.append("prepared", "pinned", None).unwrap();
        journal
            .append("manual_setup_selected", "explicit policy", None)
            .unwrap();
        journal.storage = true;
        journal
            .append("awaiting_driver_setup", "observed target", None)
            .unwrap();
        journal
            .append("awaiting_storage_setup", "bound disk state pending", None)
            .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let report = inspect(bytes.as_slice()).unwrap();
        assert!(report.storage_may_have_changed && report.state_inspection_required);
        assert!(!report.completion_reported && !report.automatic_resume_allowed);
        journal
            .append("recovery_required", "setup expired", None)
            .unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(inspect(bytes.as_slice()).unwrap().state_inspection_required);
        // A setup marker cannot erase an unresolved storage-command intent.
        let path = dir.path().join("pending.jsonl");
        let mut journal = Journal::create(&path, binding()).unwrap();
        journal.append("prepared", "pinned", None).unwrap();
        journal.storage = true;
        journal.append("intent", "entry", Some(b"payload")).unwrap();
        journal
            .append("awaiting_driver_setup", "invalid transition", None)
            .unwrap();
        assert!(inspect(std::fs::read(&path).unwrap().as_slice()).is_err());
    }
    #[test]
    fn every_torn_line_and_unmatched_intent_remain_uncertain_and_never_admit_resume() {
        let bytes = transcript();
        let complete = inspect(bytes.as_slice()).unwrap();
        assert!(complete.completion_reported && !complete.state_inspection_required);
        assert!(!complete.imported_evidence_authenticated && !complete.automatic_resume_allowed);
        let first_end = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
        for n in first_end..bytes.len() {
            let report = inspect(&bytes[..n]).unwrap();
            assert!(report.state_inspection_required);
            assert!(!report.completion_reported);
            assert!(!report.automatic_resume_allowed);
        }
    }
    #[test]
    fn corrupt_sequences_bindings_acks_unknown_fields_and_oversized_lines_fail() {
        let bytes = transcript();
        let records: Vec<serde_json::Value> = String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        for (row, key, value) in [
            (1, "sequence", serde_json::json!(10)),
            (2, "request_sha256", serde_json::json!("0".repeat(64))),
            (2, "stage", serde_json::json!("different")),
            (1, "binding_sha256", serde_json::json!("0".repeat(64))),
            (3, "automatic_resume_allowed", serde_json::json!(true)),
            (2, "storage_may_have_changed", serde_json::json!(false)),
            (0, "unknown", serde_json::json!(true)),
        ] {
            let mut changed = records.clone();
            changed[row][key] = value;
            let bytes: String = changed
                .iter()
                .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
                .collect();
            assert!(inspect(bytes.as_bytes()).is_err());
        }
        assert!(inspect(vec![b'x'; 8193].as_slice()).is_err());
    }
}
