//! Bounded backup engine restricted to concrete replay block data.
//! Native storage identity/exclusive-access adapters are not implemented here.
use serde::{Deserialize, Serialize};
use std::{
    io::{Error, ErrorKind, Read},
    path::Path,
};
use wpi_image::{ImageError, Result};
use wpi_protocol::block_replay::ReplayBlockSource;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub source_kind: String,
    pub source_size: u64,
    pub sector_size: u32,
    pub first_sector: u64,
    pub sector_count: u64,
    pub bytes: u64,
    pub sha256: String,
}
struct ReplayReader<'a> {
    source: &'a mut ReplayBlockSource,
    offset: u64,
    remaining: u64,
}
impl Read for ReplayReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let length = self.remaining.min(buffer.len() as u64) as usize;
        let data = self
            .source
            .read_at(self.offset, length)
            .map_err(|error| Error::new(ErrorKind::UnexpectedEof, error))?;
        buffer[..length].copy_from_slice(&data);
        self.offset += length as u64;
        self.remaining -= length as u64;
        Ok(length)
    }
}
pub fn create<F: FnMut(u64, u64) -> bool>(
    source: &mut ReplayBlockSource,
    first_sector: u64,
    sector_count: u64,
    output: &Path,
    progress: F,
) -> Result<BackupManifest> {
    let sector_size = source.sector_size();
    let start = first_sector
        .checked_mul(sector_size as u64)
        .ok_or_else(|| ImageError::Invalid("backup start overflow".into()))?;
    let length = sector_count
        .checked_mul(sector_size as u64)
        .ok_or_else(|| ImageError::Invalid("backup length overflow".into()))?;
    if length == 0
        || start
            .checked_add(length)
            .is_none_or(|end| end > source.size())
    {
        return Err(ImageError::Invalid(
            "backup range exceeds source disk".into(),
        ));
    }
    let source_size = source.size();
    let mut reader = ReplayReader {
        source,
        offset: start,
        remaining: length,
    };
    let mut sha256 = String::new();
    crate::artifacts::write_new(output, |writer| {
        sha256 = wpi_image::stream::copy_hashed(&mut reader, writer, length, progress)?;
        Ok(())
    })?;
    Ok(BackupManifest {
        source_kind: "replay_only".into(),
        source_size,
        sector_size,
        first_sector,
        sector_count,
        bytes: length,
        sha256,
    })
}
