//! Metadata-only replay journals. Files never grant recovery/resume authority.
use serde::Serialize;
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Ready,
    HeaderIntent,
    HeaderAcknowledged,
    PayloadIntent,
    PayloadAcknowledged,
    Cancelled,
    RecoveryRequired,
    Completed,
}
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub schema: u32,
    pub sequence: u64,
    pub kind: Kind,
    pub image_sha256: String,
    pub image_bytes: u64,
    pub total_payload_bytes: u64,
    pub acknowledged_payload_bytes: u64,
    pub payload_offset: u64,
    pub payload_bytes: u64,
    pub header_acknowledged: bool,
    pub state_inspection_required: bool,
    pub fresh_device_checks_required: bool,
    pub automatic_resume_allowed: bool,
    pub replay_only: bool,
    pub phone_writes_enabled: bool,
}
/// A newly created JSONL file. Each append must flush and sync before the replay
/// can advance. A failed append poisons the sink; partial bytes are kept for
/// inspection, never repaired or silently appended to on restart.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileJournal(crate::journal_file::FileSink);
#[cfg(not(target_arch = "wasm32"))]
impl FileJournal {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(crate::journal_file::FileSink::create(path)?))
    }
    pub fn append(&mut self, entry: &Entry) -> std::io::Result<()> {
        self.0.append(entry, 2048)
    }
}
