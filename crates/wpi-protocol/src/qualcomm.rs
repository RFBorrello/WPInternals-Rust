//! Qualcomm HDLC framing and Sahara packet validation. Never sends a programmer.
pub mod dload;
pub mod v1;
use crate::{field, ProtocolError, Result};
use serde::{Deserialize, Serialize};

pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffff
}
pub fn encode_hdlc(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > 65536 {
        return Err(ProtocolError::Invalid("invalid HDLC payload size".into()));
    }
    let mut result = vec![0x7e];
    for b in payload.iter().copied().chain(crc16(payload).to_le_bytes()) {
        if matches!(b, 0x7d | 0x7e) {
            result.extend([0x7d, b ^ 0x20]);
        } else {
            result.push(b);
        }
    }
    result.push(0x7e);
    Ok(result)
}
pub fn decode_hdlc(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 5
        || frame.len() > 131078
        || frame.first() != Some(&0x7e)
        || frame.last() != Some(&0x7e)
    {
        return Err(ProtocolError::Invalid(
            "incomplete or oversized HDLC frame".into(),
        ));
    }
    let mut decoded = Vec::new();
    let mut escaped = false;
    for byte in &frame[1..frame.len() - 1] {
        if escaped {
            decoded.push(byte ^ 0x20);
            escaped = false;
        } else if *byte == 0x7d {
            escaped = true;
        } else if *byte == 0x7e {
            return Err(ProtocolError::Invalid("unexpected HDLC delimiter".into()));
        } else {
            decoded.push(*byte);
        }
    }
    if escaped || decoded.len() < 3 {
        return Err(ProtocolError::Invalid(
            "truncated HDLC escape/checksum".into(),
        ));
    }
    let checksum = u16::from_le_bytes(decoded[decoded.len() - 2..].try_into().unwrap());
    decoded.truncate(decoded.len() - 2);
    if checksum != crc16(&decoded) {
        return Err(ProtocolError::Invalid("HDLC checksum mismatch".into()));
    }
    Ok(decoded)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaharaHello {
    pub version: u32,
    pub minimum_version: u32,
    pub maximum_packet: u32,
    pub mode: u32,
}
pub fn parse_sahara_hello(packet: &[u8]) -> Result<SaharaHello> {
    fn le(bytes: &[u8], at: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(field(bytes, at, 4)?.try_into().unwrap()))
    }
    if le(packet, 0)? != 1 || le(packet, 4)? != 48 || packet.len() != 48 {
        return Err(ProtocolError::Invalid("invalid Sahara HELLO".into()));
    }
    let hello = SaharaHello {
        version: le(packet, 8)?,
        minimum_version: le(packet, 12)?,
        maximum_packet: le(packet, 16)?,
        mode: le(packet, 20)?,
    };
    if hello.minimum_version > hello.version
        || hello.maximum_packet < 8
        || hello.maximum_packet > 16 * 1024 * 1024
        || hello.mode > 3
    {
        return Err(ProtocolError::Invalid("invalid Sahara limits".into()));
    }
    Ok(hello)
}
