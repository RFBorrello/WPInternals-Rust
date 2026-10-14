//! Lumia wire codecs derived from WPinternals 2.9.2; no OS or device handles.
//! Copyright (c) 2018 Rene Lergner. See THIRD_PARTY_NOTICES.md.
pub mod block_replay;
pub mod flash;
pub mod identity;
pub mod mode;
pub mod normal;
pub mod qualcomm;
pub mod replay;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid protocol message: {0}")]
    Invalid(String),
    #[error("Command not supported by this device")]
    Unsupported,
    #[error("Device returned status 0x{0:04X}")]
    Status(u16),
    #[error("Transport: {0}")]
    Transport(String),
}
pub type Result<T> = std::result::Result<T, ProtocolError>;
pub trait MessageTransport {
    /// One serialized request/response exchange. Implementations must bound responses and timeouts.
    fn exchange(&mut self, request: &[u8], maximum_response: usize) -> Result<Vec<u8>>;
}
pub(crate) fn field(bytes: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(
            at..at
                .checked_add(size)
                .ok_or_else(|| ProtocolError::Invalid("offset overflow".into()))?,
        )
        .ok_or_else(|| ProtocolError::Invalid("truncated response".into()))
}
pub(crate) fn be16(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(field(bytes, at, 2)?.try_into().unwrap()))
}
pub(crate) fn be32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(field(bytes, at, 4)?.try_into().unwrap()))
}
