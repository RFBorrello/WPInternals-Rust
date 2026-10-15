//! Bounded offline image operations. No raw device handles or host mounting.
pub mod catalog;
pub mod ffu;
pub mod filesystem;
pub mod firmware;
pub mod gpt;
pub mod integrity;
mod partition;
pub mod patch;
pub mod stream;

use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;

pub const SECTOR_SIZE: u64 = 512;
pub const MAX_METADATA: usize = 32 * 1024 * 1024;
pub const COPY_BUFFER: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid image: {0}")]
    Invalid(String),
    #[error("Unsupported image: {0}")]
    Unsupported(String),
    #[error("Operation cancelled at a safe boundary")]
    Cancelled,
}
pub type Result<T> = std::result::Result<T, ImageError>;
pub(crate) fn invalid(message: impl Into<String>) -> ImageError {
    ImageError::Invalid(message.into())
}
pub(crate) fn slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("offset overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("truncated structure"))
}
pub(crate) fn u32le(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(bytes, at, 4)?.try_into().unwrap()))
}
pub(crate) fn u64le(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(slice(bytes, at, 8)?.try_into().unwrap()))
}
pub(crate) fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>> {
    if length > MAX_METADATA {
        return Err(invalid("metadata allocation exceeds 32 MiB"));
    }
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
