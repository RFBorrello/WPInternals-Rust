//! Lumia Spec A programmer commands from WPInternals 2.9.2, pinned commit
//! d8fd0aa516b16dc094df0422a3adc525af005c29, Models/QualcommFlasher.cs and
//! Models/QualcommSerial.cs. Copyright (c) 2018 Rene Lergner; MIT.
//! These are unframed requests; replies are HDLC frames. No device I/O here.
use super::decode_hdlc;
use crate::{ProtocolError, Result};

pub const MAX_WRITE_BYTES: usize = 0x400;
pub const MAX_REPLY_FRAME: usize = 0x2000;
pub const SECURITY_MODE_ZERO: &[u8] = &[0x17, 0];
pub const OPEN_BOOT_PARTITION: &[u8] = &[0x1b, 0x21];
pub const CLOSE_PARTITION: &[u8] = &[0x15];
pub const REBOOT: &[u8] = &[0x0b];

pub fn hello() -> Vec<u8> {
    let mut bytes = vec![0x01];
    bytes.extend_from_slice(b"QCOM fast download protocol host");
    bytes.extend_from_slice(&[2, 2, 1]);
    bytes
}

pub fn write(start_bytes: u32, data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty()
        || data.len() > MAX_WRITE_BYTES
        || u64::from(start_bytes) + data.len() as u64 > u64::from(u32::MAX) + 1
    {
        return Err(ProtocolError::Invalid(
            "invalid V1 byte-addressed write range".into(),
        ));
    }
    let mut request = Vec::with_capacity(5 + data.len());
    request.push(0x07);
    request.extend_from_slice(&start_bytes.to_le_bytes());
    request.extend_from_slice(data);
    Ok(request)
}

#[derive(Debug, Clone, Copy)]
pub enum Ack {
    Hello,
    SecurityMode,
    Open,
    Write(u32),
    Close,
    Reboot,
}

/// Check the complete bounded frame and upstream's acknowledgement prefix.
/// Write replies must echo the exact byte address. Additional decoded reply
/// metadata is accepted, as upstream does, but has no interpreted meaning here.
pub fn check_ack(frame: &[u8], expected: Ack) -> Result<()> {
    if frame.len() > MAX_REPLY_FRAME {
        return Err(ProtocolError::Invalid("V1 reply exceeds limit".into()));
    }
    let decoded = decode_hdlc(frame)?;
    let mut prefix = vec![match expected {
        Ack::Hello => 0x02,
        Ack::SecurityMode => 0x18,
        Ack::Open => 0x1c,
        Ack::Write(_) => 0x08,
        Ack::Close => 0x16,
        Ack::Reboot => 0x0c,
    }];
    if let Ack::Write(address) = expected {
        prefix.extend_from_slice(&address.to_le_bytes());
    }
    if !decoded.starts_with(&prefix) {
        return Err(ProtocolError::Invalid(
            "V1 acknowledgement code or byte address mismatch".into(),
        ));
    }
    Ok(())
}
