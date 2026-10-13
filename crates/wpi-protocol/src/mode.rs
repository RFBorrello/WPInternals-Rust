//! Selected mode-change routes from WPInternals 2.9.2 SwitchModeViewModel
//! and NokiaFlashModel. Copyright (c) 2018 Rene Lergner; see THIRD_PARTY_NOTICES.
//! Pure builders only. No USB handle or physical-device executor.
use crate::{ProtocolError, Result};
use wpi_types::{BootloaderFamily, DeviceMode};

#[derive(Debug, Clone)]
pub struct ModeCommand {
    pub request: Vec<u8>,
    pub status_signature: Option<&'static [u8]>,
    pub requires_disconnect: bool,
    pub name: &'static str,
}

pub fn command(
    source: DeviceMode,
    target: DeviceMode,
    family: BootloaderFamily,
    protocol_major: Option<u8>,
) -> Result<ModeCommand> {
    use DeviceMode::*;
    if !matches!(family, BootloaderFamily::SpecA | BootloaderFamily::SpecB) {
        return Err(ProtocolError::Unsupported);
    }
    let (request, signature, disconnect, name) = match (source, target) {
        (Normal, Flash) => (
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc":"2.0", "id":3, "method":"SetDeviceMode",
                "params":{"DeviceMode":"Flash", "ResetMethod":"HwReset", "MessageVersion":0}
            }))
            .map_err(|e| ProtocolError::Invalid(e.to_string()))?,
            None,
            true,
            "Normal to Flash: SetDeviceMode / HwReset",
        ),
        (Flash | BootManager, Normal) => (b"NOKR".to_vec(), None, true, "Reboot to Normal: NOKR"),
        (BootManager, Flash) if matches!(protocol_major, Some(1 | 2)) => (
            b"NOKS".to_vec(),
            None,
            protocol_major == Some(1),
            "BootManager to Flash: NOKS (version-specific reconnection)",
        ),
        (Flash, BootManager) if protocol_major == Some(2) => (
            b"NOKXCBB".to_vec(),
            Some(&b"NOKXCB"[..]),
            false,
            "Flash to BootManager context",
        ),
        (Flash, PhoneInfo) if protocol_major == Some(2) => (
            b"NOKXCBP".to_vec(),
            Some(&b"NOKXCB"[..]),
            false,
            "Flash to PhoneInfo context",
        ),
        (PhoneInfo, Flash) if protocol_major == Some(2) => (
            b"NOKXCBF".to_vec(),
            Some(&b"NOKXCB"[..]),
            false,
            "PhoneInfo to Flash context",
        ),
        _ => return Err(ProtocolError::Unsupported),
    };
    Ok(ModeCommand {
        request,
        status_signature: signature,
        requires_disconnect: disconnect,
        name,
    })
}
