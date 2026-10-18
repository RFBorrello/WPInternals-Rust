//! Metadata-only checkpoints for the joined Spec A REPLAY. No resume authority.
use serde::Serialize;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparation,
    EntryUpload,
    BootTransfer,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Ready,
    Intent,
    Acknowledged,
    Submitted,
    AwaitingArrival,
    ArrivalMatched,
    PhaseComplete,
    TransferComplete,
    Cancelled,
    Failed,
    RecoveryRequired,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Prepared,
    SourcePreflight,
    FfuHeader,
    BoundaryZero,
    EntryReboot,
    DownloadArrival,
    DloadAlive,
    DloadRoot,
    RamUpload,
    LoaderStart,
    ProgrammerArrival,
    ProgrammerHello,
    Handoff,
    SecurityMode,
    Open,
    BootWrite,
    Close,
    ProgrammerReboot,
}
impl Step {
    pub(crate) fn emergency(label: &str) -> Self {
        match label {
            "FFU header" => Self::FfuHeader,
            "boundary zero chunk" => Self::BoundaryZero,
            "DLOAD alive" => Self::DloadAlive,
            "DLOAD root" => Self::DloadRoot,
            "RAM upload" => Self::RamUpload,
            "loader start" => Self::LoaderStart,
            "programmer hello" => Self::ProgrammerHello,
            _ => unreachable!("private phase labels are fixed"),
        }
    }
    pub(crate) fn programmer(label: &str) -> Self {
        match label {
            "hello" => Self::ProgrammerHello,
            "security mode" => Self::SecurityMode,
            "open" => Self::Open,
            "write" => Self::BootWrite,
            "close" => Self::Close,
            "reboot" => Self::ProgrammerReboot,
            _ => unreachable!("private phase labels are fixed"),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct Checkpoint {
    pub phase: Phase,
    pub kind: Kind,
    pub step: Step,
    pub address: Option<u32>,
    pub bytes: u64,
}
impl Checkpoint {
    pub(crate) fn new(phase: Phase, kind: Kind, step: Step) -> Self {
        Self {
            phase,
            kind,
            step,
            address: None,
            bytes: 0,
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Artifacts {
    pub source_ffu_sha256: String,
    pub package_sha256: String,
    pub saved_primary_sha256: String,
    pub candidate_primary_sha256: String,
    pub loader_input_sha256: String,
    pub loader_decoded_sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub schema: u32,
    pub sequence: u64,
    pub artifacts: Artifacts,
    pub phase: Phase,
    pub kind: Kind,
    pub step: Step,
    pub address: Option<u32>,
    pub bytes: u64,
    pub acknowledged_ram_bytes: u64,
    pub acknowledged_boot_bytes: u64,
    pub total_boot_bytes: u64,
    pub state_inspection_required: bool,
    pub fresh_device_checks_required: bool,
    pub automatic_resume_allowed: bool,
    pub replay_only: bool,
    pub phone_writes_enabled: bool,
    pub device_unlock_verified: bool,
    pub data_preservation_validated: bool,
}
pub(crate) struct Journal<J> {
    pub entry: Entry,
    pub failed: bool,
    pub failure: Option<String>,
    sink: J,
}
impl<J: FnMut(&Entry) -> std::io::Result<()>> Journal<J> {
    pub(crate) fn new(artifacts: Artifacts, total_boot_bytes: u64, sink: J) -> Self {
        Self {
            failed: false,
            failure: None,
            sink,
            entry: Entry {
                schema: 1,
                sequence: 0,
                artifacts,
                phase: Phase::Preparation,
                kind: Kind::Ready,
                step: Step::Prepared,
                address: None,
                bytes: 0,
                acknowledged_ram_bytes: 0,
                acknowledged_boot_bytes: 0,
                total_boot_bytes,
                state_inspection_required: false,
                fresh_device_checks_required: true,
                automatic_resume_allowed: false,
                replay_only: true,
                phone_writes_enabled: false,
                device_unlock_verified: false,
                data_preservation_validated: false,
            },
        }
    }
    pub(crate) fn save(&mut self, checkpoint: Checkpoint) -> std::io::Result<()> {
        if self.failed {
            return Err(std::io::Error::other("Journal failed earlier"));
        }
        let e = &mut self.entry;
        e.sequence += 1;
        e.phase = checkpoint.phase;
        e.kind = checkpoint.kind;
        e.step = checkpoint.step;
        e.address = checkpoint.address;
        e.bytes = checkpoint.bytes;
        if checkpoint.kind == Kind::Intent
            && matches!(
                checkpoint.step,
                Step::FfuHeader | Step::BoundaryZero | Step::BootWrite | Step::LoaderStart
            )
        {
            e.state_inspection_required = true;
        }
        if checkpoint.kind == Kind::Acknowledged {
            if checkpoint.step == Step::RamUpload {
                e.acknowledged_ram_bytes += checkpoint.bytes;
            }
            if checkpoint.step == Step::BootWrite {
                e.acknowledged_boot_bytes += checkpoint.bytes;
            }
        }
        let result = (self.sink)(e);
        self.failed = result.is_err();
        if let Err(error) = &result {
            self.failure = Some(error.to_string());
        }
        result
    }
    pub(crate) fn mark(&mut self, kind: Kind, phase: Phase, step: Step) -> std::io::Result<()> {
        self.save(Checkpoint::new(phase, kind, step))
    }
}
/// Creates new JSONL only; flush + sync for every bounded record. No import,
/// continuation, repair or automatic resume. Failed appends poison the sink.
#[cfg(not(target_arch = "wasm32"))]
pub struct FileJournal(crate::journal_file::FileSink);
#[cfg(not(target_arch = "wasm32"))]
impl FileJournal {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(crate::journal_file::FileSink::create(path)?))
    }
    pub fn append(&mut self, entry: &Entry) -> std::io::Result<()> {
        self.0.append(entry, 4096)
    }
}
