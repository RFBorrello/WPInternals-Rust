//! Bounded read-only backup copying. The native adapter owns identity, geometry
//! and exclusive-access validation; public plans never authorize raw disk access.
use serde::{Deserialize, Serialize};
use std::{
    io::{Error, Read},
    path::Path,
};
use wpi_image::{ImageError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub size: u64,
    pub sector_size: u32,
}
pub trait ReadOnlySource {
    fn geometry(&self) -> Geometry;
    /// Revalidate the held source handle. Must not reopen or substitute a disk.
    fn validate(&mut self) -> Result<()>;
    /// One exact bounded read. Short reads/disconnects fail; no retries.
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()>;
}
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
struct Reader<'a, S> {
    source: &'a mut S,
    offset: u64,
    remaining: u64,
}
impl<S: ReadOnlySource> Read for Reader<'_, S> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = b
            .len()
            .min(self.remaining.min(wpi_image::COPY_BUFFER as u64) as usize);
        if n == 0 {
            return Ok(0);
        }
        self.source
            .read_at(self.offset, &mut b[..n])
            .map_err(Error::other)?;
        self.offset += n as u64;
        self.remaining -= n as u64;
        Ok(n)
    }
}
pub fn create<S: ReadOnlySource, F: FnMut(u64, u64) -> bool>(
    source: &mut S,
    source_kind: &str,
    first_sector: u64,
    sector_count: u64,
    output: &Path,
    mut progress: F,
) -> Result<BackupManifest> {
    let geometry = source.geometry();
    if !matches!(geometry.sector_size, 512 | 4096)
        || geometry.size == 0
        || !geometry
            .size
            .is_multiple_of(u64::from(geometry.sector_size))
    {
        return Err(ImageError::Invalid("Invalid backup source geometry".into()));
    }
    let start = first_sector
        .checked_mul(u64::from(geometry.sector_size))
        .ok_or_else(|| ImageError::Invalid("Backup start overflow".into()))?;
    let length = sector_count
        .checked_mul(u64::from(geometry.sector_size))
        .ok_or_else(|| ImageError::Invalid("Backup length overflow".into()))?;
    if length == 0
        || start
            .checked_add(length)
            .is_none_or(|end| end > geometry.size)
    {
        return Err(ImageError::Invalid("Backup range exceeds source".into()));
    }
    if !progress(0, length) {
        return Err(ImageError::Cancelled);
    }
    source.validate()?;
    if source.geometry() != geometry {
        return Err(ImageError::Invalid("Source geometry changed".into()));
    }
    let mut sha256 = String::new();
    crate::artifacts::write_new(output, |writer| {
        let mut reader = Reader {
            source,
            offset: start,
            remaining: length,
        };
        sha256 = wpi_image::stream::copy_hashed(&mut reader, writer, length, &mut progress)?;
        reader.source.validate()?;
        if reader.source.geometry() != geometry {
            return Err(ImageError::Invalid("Source geometry changed".into()));
        }
        if !progress(length, length) {
            return Err(ImageError::Cancelled);
        }
        Ok(())
    })?;
    Ok(BackupManifest {
        source_kind: source_kind.into(),
        source_size: geometry.size,
        sector_size: geometry.sector_size,
        first_sector,
        sector_count,
        bytes: length,
        sha256,
    })
}
