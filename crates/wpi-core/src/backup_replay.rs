//! Replay adapter for the shared bounded read-only backup engine.
pub use crate::backup::BackupManifest;
use crate::backup::{Geometry, ReadOnlySource};
use std::path::Path;
use wpi_image::{ImageError, Result};
use wpi_protocol::block_replay::ReplayBlockSource;
impl ReadOnlySource for ReplayBlockSource {
    fn geometry(&self) -> Geometry {
        Geometry {
            size: self.size(),
            sector_size: self.sector_size(),
        }
    }
    fn validate(&mut self) -> Result<()> {
        Ok(())
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let bytes = ReplayBlockSource::read_at(self, offset, buffer.len())
            .map_err(|e| ImageError::Invalid(e.to_string()))?;
        buffer.copy_from_slice(&bytes);
        Ok(())
    }
}
pub fn create<F: FnMut(u64, u64) -> bool>(
    source: &mut ReplayBlockSource,
    first_sector: u64,
    sector_count: u64,
    output: &Path,
    progress: F,
) -> Result<BackupManifest> {
    crate::backup::create(
        source,
        "replay_only",
        first_sector,
        sector_count,
        output,
        progress,
    )
}
