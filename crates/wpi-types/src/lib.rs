//! Serializable contracts shared by native, CLI and WebAssembly frontends.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceMode {
    Normal,
    Flash,
    BootManager,
    PhoneInfo,
    MassStorage,
    Emergency,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootloaderFamily {
    SpecA,
    SpecB,
    Wp7,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    Windows,
    Macos,
    Linux,
    Browser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Usb,
    Serial,
    BlockDevice,
    WebUsb,
    LocalFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    Verified,
    Experimental,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    InspectFirmware,
    ExtractPartition,
    InspectGpt,
    ConvertGpt,
    InspectFilesystem,
    PatchFiles,
    DeviceInfo,
    SwitchMode,
    StockFlash,
    UnlockBootloader,
    RestoreBootloader,
    EnableRoot,
    DisableRoot,
    Backup,
    Restore,
    CustomFlash,
}

impl Operation {
    pub fn writes_device(self) -> bool {
        matches!(
            self,
            Self::StockFlash
                | Self::UnlockBootloader
                | Self::RestoreBootloader
                | Self::EnableRoot
                | Self::DisableRoot
                | Self::Restore
                | Self::CustomFlash
        )
    }
    pub fn offline(self) -> bool {
        matches!(
            self,
            Self::InspectFirmware
                | Self::ExtractPartition
                | Self::InspectGpt
                | Self::ConvertGpt
                | Self::InspectFilesystem
                | Self::PatchFiles
        )
    }
    pub const ALL: [Self; 16] = [
        Self::InspectFirmware,
        Self::ExtractPartition,
        Self::InspectGpt,
        Self::ConvertGpt,
        Self::InspectFilesystem,
        Self::PatchFiles,
        Self::DeviceInfo,
        Self::SwitchMode,
        Self::StockFlash,
        Self::UnlockBootloader,
        Self::RestoreBootloader,
        Self::EnableRoot,
        Self::DisableRoot,
        Self::Backup,
        Self::Restore,
        Self::CustomFlash,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbInterface {
    pub number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub id: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub model: Option<String>,
    pub variant: Option<String>,
    pub firmware: Option<String>,
    pub platform_id: Option<String>,
    pub family: BootloaderFamily,
    pub mode: DeviceMode,
    pub interfaces: Vec<UsbInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub operation: Operation,
    pub status: SupportStatus,
    pub executable: bool,
    pub reason: String,
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub device_id: Option<String>,
    pub host: Host,
    pub transport: TransportKind,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub platform_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationPlan {
    pub operation: Operation,
    pub device: Option<DeviceIdentity>,
    pub host: Host,
    pub transport: TransportKind,
    pub artifacts: Vec<ArtifactIdentity>,
    pub executable: bool,
    pub blockers: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Prepared,
    Running,
    AwaitingReconnect,
    Cancelling,
    Cancelled,
    Completed,
    RecoveryRequired,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationEvent {
    pub sequence: u64,
    pub operation: Operation,
    pub state: OperationState,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationStatus {
    Passed,
    Failed,
    Missing,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparationCheck {
    pub key: String,
    pub label: String,
    pub status: PreparationStatus,
    pub message: String,
}

/// Advisory checklist only. This cannot grant any device-write capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPreparation {
    pub plan: OperationPlan,
    pub checks: Vec<PreparationCheck>,
}

/// Advisory mode-change preview. Never grants live USB execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeTransitionPreparation {
    pub plan: OperationPlan,
    pub source: DeviceMode,
    pub target: DeviceMode,
    pub route: Option<String>,
    pub requires_disconnect: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconnectStatus {
    Correlated,
    Mismatch,
    Unverified,
}

/// USB serial correlation is not authenticated identity or write authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectReport {
    pub status: ReconnectStatus,
    pub expected_mode: DeviceMode,
    pub observed_mode: DeviceMode,
    pub checks: Vec<PreparationCheck>,
    pub recovery_authorized: bool,
}
