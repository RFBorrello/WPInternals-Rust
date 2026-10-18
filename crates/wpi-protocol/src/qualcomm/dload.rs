//! Legacy DLOAD (not Sahara) from WPInternals 2.9.2 QualcommDownload.cs,
//! pinned d8fd0aa516b16dc094df0422a3adc525af005c29. Rene Lergner, MIT.
//! Requests AND replies are HDLC framed. No transport or programmer execution.
use super::{decode_hdlc, encode_hdlc, v1::MAX_REPLY_FRAME};
use crate::{preflight::RootKeyHash, ProtocolError, Result};

pub const MAX_MEMORY_BYTES: usize = 256;
pub const LOADER_ADDRESS: u32 = 0x2a000000;

pub fn alive() -> Result<Vec<u8>> {
    encode_hdlc(&[6])
}
pub fn root_key() -> Result<Vec<u8>> {
    encode_hdlc(&[0x18])
}
pub fn start(address: u32) -> Result<Vec<u8>> {
    let mut payload = vec![5];
    payload.extend_from_slice(&address.to_be_bytes());
    encode_hdlc(&payload)
}
pub fn memory(address: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty()
        || bytes.len() > MAX_MEMORY_BYTES
        || u64::from(address) + bytes.len() as u64 > u64::from(u32::MAX) + 1
    {
        return Err(ProtocolError::Invalid(
            "DLOAD memory range is invalid".into(),
        ));
    }
    let mut payload = vec![0x0f];
    payload.extend_from_slice(&address.to_be_bytes());
    payload.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(bytes);
    encode_hdlc(&payload)
}
fn reply(frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() > MAX_REPLY_FRAME {
        return Err(ProtocolError::Invalid("DLOAD reply exceeds bound".into()));
    }
    decode_hdlc(frame)
}
pub fn check_ack(frame: &[u8]) -> Result<()> {
    if !reply(frame)?.starts_with(&[2]) {
        return Err(ProtocolError::Invalid("DLOAD ACK code mismatch".into()));
    }
    Ok(())
}
pub fn parse_root(frame: &[u8]) -> Result<RootKeyHash> {
    let decoded = reply(frame)?;
    if decoded.len() != 35 || decoded[..3] != [0x18, 1, 0] {
        return Err(ProtocolError::Invalid("DLOAD root reply is invalid".into()));
    }
    RootKeyHash::parse(&decoded[3..])
}

/// Bounded single-frame assembly across reads, including split escapes/CRC.
/// An error poisons the decoder; no truncation, trailing frames or resync.
#[derive(Default)]
pub struct ReplyDecoder {
    bytes: Vec<u8>,
    escaped: bool,
    finished: bool,
    failed: bool,
}
impl ReplyDecoder {
    pub fn push(&mut self, fragment: &[u8]) -> Result<Option<Vec<u8>>> {
        let result = self.push_inner(fragment);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn push_inner(&mut self, fragment: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.failed
            || self.finished
            || fragment.is_empty()
            || self.bytes.len().saturating_add(fragment.len()) > MAX_REPLY_FRAME
        {
            return Err(ProtocolError::Invalid(
                "unusable, empty or oversized framed reply".into(),
            ));
        }
        for (index, byte) in fragment.iter().copied().enumerate() {
            if self.bytes.is_empty() {
                if byte != 0x7e {
                    return Err(ProtocolError::Invalid(
                        "missing HDLC opening delimiter".into(),
                    ));
                }
            } else if self.escaped {
                self.escaped = false;
            } else if byte == 0x7d {
                self.escaped = true;
            } else if byte == 0x7e {
                if index + 1 != fragment.len() {
                    return Err(ProtocolError::Invalid(
                        "trailing bytes after HDLC frame".into(),
                    ));
                }
                self.bytes.push(byte);
                decode_hdlc(&self.bytes)?;
                self.finished = true;
                return Ok(Some(std::mem::take(&mut self.bytes)));
            }
            self.bytes.push(byte);
        }
        Ok(None)
    }
}
