//! Read-only inspection of finish-stage replay journals. Never execution input.
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Read};
#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    source_ffu_sha256: String,
    package_sha256: String,
    before_primary_sha256: String,
    after_primary_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema: u32,
    binding: Binding,
    sequence: u64,
    stage: String,
    kind: String,
    start_sector: Option<u32>,
    byte_length: u64,
    payload_sha256: Option<String>,
    acknowledged_bytes: u64,
    total_bytes: u64,
    replay_only: bool,
    automatic_resume_allowed: bool,
    device_unlock_verified: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub complete_records_validated: u64,
    pub torn_tail: bool,
    pub stage: Option<String>,
    pub last_checkpoint: Option<String>,
    pub acknowledged_bytes: u64,
    pub total_bytes: Option<u64>,
    pub last_command_uncertain: bool,
    pub stage_transfer_complete: bool,
    pub replay_only: bool,
    pub device_unlock_verified: bool,
    pub automatic_resume_allowed: bool,
    pub next_steps: Vec<&'static str>,
}
fn invalid() -> io::Error {
    io::Error::other(
        "Invalid, inconsistent or unsupported finish-stage journal; never replay its commands",
    )
}
fn sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
/// Bound each line to 4096 bytes and the complete input to 128 MiB. A torn last
/// line is reported separately; a malformed COMPLETE record rejects the file.
/// This validates metadata consistency, not authenticity or physical execution.
pub fn inspect<R: BufRead>(mut reader: R) -> io::Result<Report> {
    let mut previous: Option<Wire> = None;
    let mut pending: Option<(u32, u64, String)> = None;
    let mut records = 0;
    let mut consumed = 0usize;
    let mut torn = false;
    loop {
        let mut line = Vec::new();
        let n = (&mut reader).take(4098).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        consumed = consumed.checked_add(n).ok_or_else(invalid)?;
        if n > 4097 || (line.last() != Some(&b'\n') && n > 4096) || consumed > 128 * 1024 * 1024 {
            return Err(invalid());
        }
        if line.last() != Some(&b'\n') {
            torn = true;
            break;
        }
        line.pop();
        if line.len() > 4096 {
            return Err(invalid());
        }
        let wire: Wire = serde_json::from_slice(&line).map_err(|_| invalid())?;
        if wire.schema != 1
            || wire.sequence != records + 1
            || !wire.replay_only
            || wire.automatic_resume_allowed
            || wire.device_unlock_verified
            || !["variables", "first_efiesp", "installed_efiesp"].contains(&wire.stage.as_str())
            || wire.total_bytes == 0
            || wire.total_bytes > 129 * 1024 * 1024
            || wire.acknowledged_bytes > wire.total_bytes
            || [
                &wire.binding.source_ffu_sha256,
                &wire.binding.package_sha256,
                &wire.binding.before_primary_sha256,
                &wire.binding.after_primary_sha256,
            ]
            .iter()
            .any(|s| !sha(s))
        {
            return Err(invalid());
        }
        let acknowledged = previous.as_ref().map_or(0, |p| p.acknowledged_bytes);
        if previous.as_ref().is_some_and(|p| {
            p.stage != wire.stage
                || p.binding != wire.binding
                || p.total_bytes != wire.total_bytes
                || p.kind == "transfer_complete"
        }) {
            return Err(invalid());
        }
        match wire.kind.as_str() {
            "intent" => {
                if pending.is_some()
                    || wire.acknowledged_bytes != acknowledged
                    || wire.byte_length == 0
                    || !wire.byte_length.is_multiple_of(512)
                    || wire.byte_length > 2 * 1024 * 1024
                    || wire.payload_sha256.as_deref().is_none_or(|s| !sha(s))
                {
                    return Err(invalid());
                }
                let start = wire.start_sector.ok_or_else(invalid)?;
                if u64::from(start) + wire.byte_length / 512 > u64::from(u32::MAX) + 1 {
                    return Err(invalid());
                }
                pending = Some((
                    start,
                    wire.byte_length,
                    wire.payload_sha256.clone().unwrap(),
                ));
            }
            "acknowledged" => {
                let (start, len, hash) = pending.take().ok_or_else(invalid)?;
                if wire.start_sector != Some(start)
                    || wire.byte_length != len
                    || wire.payload_sha256.as_deref() != Some(&hash)
                    || wire.acknowledged_bytes
                        != acknowledged.checked_add(len).ok_or_else(invalid)?
                {
                    return Err(invalid());
                }
            }
            "transfer_complete" => {
                if pending.is_some()
                    || wire.start_sector.is_some()
                    || wire.payload_sha256.is_some()
                    || wire.byte_length != 0
                    || acknowledged != wire.total_bytes
                    || wire.acknowledged_bytes != acknowledged
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        records += 1;
        previous = Some(wire);
    }
    if records == 0 && !torn {
        return Err(invalid());
    }
    let complete = !torn
        && previous
            .as_ref()
            .is_some_and(|p| p.kind == "transfer_complete");
    let mut next = vec![
        "This is replay metadata, not evidence that a physical phone was modified or unlocked.",
        "Never resume a write from this file or automatically restore source firmware.",
    ];
    if complete {
        next.push("Only this stage's transfer is recorded complete; mode, installed bytes and return to Windows still require fresh inspection.");
    } else {
        next.push("Retain the original journal. An unmatched intent or torn tail cannot distinguish an unsent command from an accepted command with a lost acknowledgement.");
    }
    Ok(Report {
        complete_records_validated: records,
        torn_tail: torn,
        stage: previous.as_ref().map(|p| p.stage.clone()),
        last_checkpoint: previous.as_ref().map(|p| p.kind.clone()),
        acknowledged_bytes: previous.as_ref().map_or(0, |p| p.acknowledged_bytes),
        total_bytes: previous.as_ref().map(|p| p.total_bytes),
        last_command_uncertain: torn || pending.is_some(),
        stage_transfer_complete: complete,
        replay_only: true,
        device_unlock_verified: false,
        automatic_resume_allowed: false,
        next_steps: next,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn line(sequence: u64, kind: &str, ack: u64) -> serde_json::Value {
        serde_json::json!({"schema":1,"binding":{"source_ffu_sha256":"a".repeat(64),"package_sha256":"b".repeat(64),"before_primary_sha256":"c".repeat(64),"after_primary_sha256":"d".repeat(64)},
            "sequence":sequence,"stage":"variables","kind":kind,"start_sector":100,"byte_length":512,"payload_sha256":"e".repeat(64),"acknowledged_bytes":ack,"total_bytes":512,
            "replay_only":true,"automatic_resume_allowed":false,"device_unlock_verified":false})
    }
    fn jsonl(records: &[serde_json::Value]) -> Vec<u8> {
        let mut b = Vec::new();
        for r in records {
            b.extend(serde_json::to_vec(r).unwrap());
            b.push(b'\n');
        }
        b
    }
    #[test]
    fn unmatched_intent_and_every_torn_tail_remain_uncertain_and_never_grant_resume() {
        let first = line(1, "intent", 0);
        let second = line(2, "acknowledged", 512);
        let bytes = jsonl(&[first.clone(), second.clone()]);
        let first_len = jsonl(&[first]).len();
        for n in 1..bytes.len() {
            let r = inspect(std::io::Cursor::new(&bytes[..n])).unwrap();
            assert!(
                !r.stage_transfer_complete
                    && !r.automatic_resume_allowed
                    && !r.device_unlock_verified
            );
            assert!(r.last_command_uncertain);
            assert_eq!(
                r.complete_records_validated,
                if n < first_len { 0 } else { 1 }
            );
        }
        let r = inspect(std::io::Cursor::new(bytes)).unwrap();
        assert!(!r.last_command_uncertain && !r.stage_transfer_complete);
    }
    #[test]
    fn complete_stage_is_distinct_from_unlock_and_corrupt_or_mixed_records_fail() {
        let mut end = line(3, "transfer_complete", 512);
        end["start_sector"] = serde_json::Value::Null;
        end["payload_sha256"] = serde_json::Value::Null;
        end["byte_length"] = 0.into();
        let good = vec![line(1, "intent", 0), line(2, "acknowledged", 512), end];
        assert!(
            inspect(std::io::Cursor::new(jsonl(&good)))
                .unwrap()
                .stage_transfer_complete
        );
        for key in [
            "sequence",
            "acknowledged_bytes",
            "total_bytes",
            "start_sector",
            "payload_sha256",
            "stage",
            "automatic_resume_allowed",
            "binding",
            "unknown",
        ] {
            let mut records = good.clone();
            records[1][key] = serde_json::json!(true);
            assert!(
                inspect(std::io::Cursor::new(jsonl(&records))).is_err(),
                "{key}"
            );
        }
        assert!(inspect(std::io::Cursor::new(Vec::<u8>::new())).is_err());
        assert!(inspect(std::io::Cursor::new(vec![b'x'; 4099])).is_err());
        assert!(inspect(std::io::Cursor::new(jsonl(&[good[1].clone()]))).is_err());
    }
}
