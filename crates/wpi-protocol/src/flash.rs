use crate::{be16, be32, field, MessageTransport, ProtocolError, Result};
use serde::{Deserialize, Serialize};
use wpi_types::DeviceMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashInfo {
    pub mode: DeviceMode,
    pub protocol_major: u8,
    pub protocol_minor: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub platform_id: Option<String>,
    pub transfer_size: Option<u32>,
    pub write_buffer_size: Option<u32>,
    pub emmc_sectors: Option<u32>,
    pub secure_ffu: Option<bool>,
    pub secure_boot: Option<bool>,
    pub protocol_mask: Option<u16>,
}
pub fn parse_info(response: &[u8]) -> Result<FlashInfo> {
    if response.starts_with(b"NOKU") {
        return Err(ProtocolError::Unsupported);
    }
    if field(response, 0, 4)? != b"NOKV" {
        return Err(ProtocolError::Invalid(
            "unexpected NOKV response signature".into(),
        ));
    }
    field(response, 0, 11)?;
    let mode = match response[5] {
        1 => DeviceMode::BootManager,
        2 => DeviceMode::Flash,
        3 => DeviceMode::PhoneInfo,
        _ => {
            return Err(ProtocolError::Invalid(
                "unknown flash application type".into(),
            ))
        }
    };
    let mut info = FlashInfo {
        mode,
        protocol_major: response[6],
        protocol_minor: response[7],
        version_major: response[8],
        version_minor: response[9],
        platform_id: None,
        transfer_size: None,
        write_buffer_size: None,
        emmc_sectors: None,
        secure_ffu: None,
        secure_boot: None,
        protocol_mask: None,
    };
    let mut offset = 11;
    for _ in 0..response[10] {
        let id = field(response, offset, 1)?[0];
        let len = be16(response, offset + 1)? as usize;
        let payload = field(response, offset + 3, len)?;
        match id {
            1 => info.transfer_size = Some(be32(payload, 0)?),
            2 => info.write_buffer_size = Some(be32(payload, 0)?),
            3 => info.emmc_sectors = Some(be32(payload, 0)?),
            5 => {
                info.platform_id = Some(
                    String::from_utf8_lossy(payload)
                        .trim_matches(['\0', ' '])
                        .to_owned(),
                )
            }
            0x0f => {
                field(payload, 0, 8)?;
                info.secure_boot = Some(payload[1] == 1);
                info.secure_ffu = Some(payload[2] == 1);
            }
            0x10 => info.protocol_mask = Some(be16(payload, 1)?),
            _ => {}
        }
        offset += 3 + len;
    }
    Ok(info)
}
pub fn read_info<T: MessageTransport>(transport: &mut T) -> Result<FlashInfo> {
    parse_info(&transport.exchange(b"NOKV", 65536)?)
}
pub fn parameter_request(name: &str) -> Result<Vec<u8>> {
    if name.is_empty() || name.len() > 4 || !name.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(ProtocolError::Invalid(
            "parameter must be 1–4 uppercase ASCII characters".into(),
        ));
    }
    let mut request = vec![0; 11];
    request[..6].copy_from_slice(b"NOKXFR");
    request[7..7 + name.len()].copy_from_slice(name.as_bytes());
    Ok(request)
}
pub fn parse_parameter(response: &[u8]) -> Result<Vec<u8>> {
    check_status(response, b"NOKXFR")?;
    let length = field(response, 16, 1)?[0] as usize;
    Ok(field(response, 17, length)?.to_vec())
}
pub fn check_status(response: &[u8], signature: &[u8]) -> Result<()> {
    if response.starts_with(b"NOKU") {
        return Err(ProtocolError::Unsupported);
    }
    if field(response, 0, signature.len())? != signature {
        return Err(ProtocolError::Invalid(
            "unexpected response signature".into(),
        ));
    }
    let status = be16(response, 6)?;
    if status != 0 {
        return Err(ProtocolError::Status(status));
    }
    Ok(())
}
/// Spec A raw-sector command (NokiaFlashModel.FlashSectors in pinned 2.9.2).
/// A pure builder; accepting these bytes is not a transport write permission.
pub fn sectors_v1(start_sector: u32, payload: &[u8], progress: u8) -> Result<Vec<u8>> {
    if payload.is_empty()
        || !payload.len().is_multiple_of(512)
        || payload.len() > 2 * 1024 * 1024
        || progress > 100
        || u64::from(start_sector) + payload.len() as u64 / 512 > u64::from(u32::MAX) + 1
    {
        return Err(ProtocolError::Invalid(
            "Invalid Spec A sector write bounds".into(),
        ));
    }
    let mut request = vec![0; 64 + payload.len()];
    request[..4].copy_from_slice(b"NOKF");
    request[11..15].copy_from_slice(&start_sector.to_be_bytes());
    request[15..19].copy_from_slice(&(payload.len() as u32 / 512).to_be_bytes());
    request[19] = progress;
    request[64..].copy_from_slice(payload);
    Ok(request)
}
/// Unlike upstream's unchecked raw return, require an exact status envelope.
/// No echo/readback exists here, so acknowledgement cannot prove stored bytes.
pub fn sectors_v1_status(response: &[u8]) -> Result<()> {
    check_status(response, b"NOKF")?;
    if response.len() != 8 {
        return Err(ProtocolError::Invalid(
            "Unexpected NOKF acknowledgement length".into(),
        ));
    }
    Ok(())
}
/// Pure command builders: no public UI executes these until hardware evidence exists.
pub fn context_request(mode: DeviceMode) -> Result<Vec<u8>> {
    Ok(match mode {
        DeviceMode::PhoneInfo => b"NOKXCBP".to_vec(),
        DeviceMode::BootManager => b"NOKXCBB".to_vec(),
        DeviceMode::Flash => b"NOKXCBF".to_vec(),
        _ => return Err(ProtocolError::Unsupported),
    })
}
pub fn ffu_header_v1(header: &[u8]) -> Result<Vec<u8>> {
    if header.is_empty() || header.len() > 32 * 1024 * 1024 {
        return Err(ProtocolError::Invalid("invalid FFU header length".into()));
    }
    let mut request = vec![0; header.len() + 32];
    request[..6].copy_from_slice(b"NOKXFS");
    request[6..8].copy_from_slice(&1u16.to_be_bytes());
    request[11] = 1;
    request[12..16].copy_from_slice(&11u32.to_be_bytes());
    request[16..20].copy_from_slice(&(header.len() as u32 + 12).to_be_bytes());
    request[24..28].copy_from_slice(&(header.len() as u32).to_be_bytes());
    request[32..].copy_from_slice(header);
    Ok(request)
}
pub fn ffu_payload_v1(payload: &[u8], progress: u8) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > 4 * 1024 * 1024 || progress > 100 {
        return Err(ProtocolError::Invalid(
            "invalid FFU payload/progress".into(),
        ));
    }
    let mut request = vec![0; payload.len() + 28];
    request[..6].copy_from_slice(b"NOKXFS");
    request[6..8].copy_from_slice(&1u16.to_be_bytes());
    request[8] = progress;
    request[11] = 1;
    request[12..16].copy_from_slice(&12u32.to_be_bytes());
    request[16..20].copy_from_slice(&(payload.len() as u32 + 8).to_be_bytes());
    request[20..24].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    request[28..].copy_from_slice(payload);
    Ok(request)
}

pub fn ffu_payload_v2(payload: &[u8], progress: u8) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > 4 * 1024 * 1024 || progress > 100 {
        return Err(ProtocolError::Invalid(
            "invalid FFU payload/progress".into(),
        ));
    }
    let mut request = vec![0; payload.len() + 32];
    request[..6].copy_from_slice(b"NOKXFS");
    request[6..8].copy_from_slice(&4u16.to_be_bytes());
    request[8] = progress;
    request[11] = 1;
    request[12..16].copy_from_slice(&0x1bu32.to_be_bytes());
    request[16..20].copy_from_slice(&(payload.len() as u32 + 12).to_be_bytes());
    request[20..24].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    request[32..].copy_from_slice(payload);
    Ok(request)
}
