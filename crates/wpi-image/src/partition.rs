//! Bounded, read-only partition-relative access over sparse FFU mappings.
use crate::{ffu::FfuMetadata, gpt::Gpt, invalid, ImageError, Result, SECTOR_SIZE};
use std::io::{self, Read, Seek, SeekFrom};
const LIMIT: usize = 64 * 1024;
const IO_BUDGET: u64 = 16 * 1024 * 1024;
/// A partition-relative view of sparse FFU mappings. All host reads are bounded;
/// corrupt filesystem metadata cannot seek outside or consume unbounded I/O.
pub(crate) struct Partition<'a, R, F> {
    reader: &'a mut R,
    ffu: &'a FfuMetadata,
    start: u64,
    length: u64,
    position: u64,
    cache_at: u64,
    cache: Vec<u8>,
    fetched: u64,
    calls: u32,
    progress: F,
    cancelled: bool,
}
impl<R: Read + Seek, F: FnMut(u64, u64) -> bool> Read for Partition<'_, R, F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !(self.progress)(self.fetched, IO_BUDGET) {
            self.cancelled = true;
            return Err(io::Error::other("Operation cancelled"));
        }
        self.calls += 1;
        if self.calls > 65536 {
            return Err(io::Error::other(
                "Partition metadata read-call budget exceeded",
            ));
        }
        let n = buffer
            .len()
            .min((self.length - self.position).min(LIMIT as u64) as usize);
        if n == 0 {
            return Ok(0);
        }
        if self.position < self.cache_at || self.position >= self.cache_at + self.cache.len() as u64
        {
            self.cache_at = self.position / LIMIT as u64 * LIMIT as u64;
            let count = (self.length - self.cache_at).min(LIMIT as u64) as usize;
            if self.fetched + count as u64 > IO_BUDGET {
                return Err(io::Error::other("Partition metadata I/O exceeds 16 MiB"));
            }
            self.fetched += count as u64;
            self.cache = self
                .ffu
                .read_disk(self.reader, self.start + self.cache_at, count)
                .map_err(io::Error::other)?;
        }
        let at = (self.position - self.cache_at) as usize;
        let n = n.min(self.cache.len() - at);
        buffer[..n].copy_from_slice(&self.cache[at..at + n]);
        self.position += n as u64;
        Ok(n)
    }
}
impl<R, F> Seek for Partition<'_, R, F> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::End(p) => i128::from(self.length) + i128::from(p),
            SeekFrom::Current(p) => i128::from(self.position) + i128::from(p),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::other(
                "Partition metadata seek outside partition bounds",
            ));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

pub(crate) fn with_partition<R: Read + Seek, F: FnMut(u64, u64) -> bool, T>(
    name: &str,
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    progress: F,
    action: impl FnOnce(&mut Partition<'_, R, F>) -> Result<Option<T>>,
) -> Result<Option<T>> {
    let partitions: Vec<_> = gpt.partitions.iter().filter(|p| p.name == name).collect();
    if partitions.is_empty() {
        return Ok(None);
    }
    if partitions.len() != 1 {
        return Err(invalid(format!("Ambiguous {name} partition")));
    }
    let p = partitions[0];
    let start = p
        .first_sector
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| invalid("Partition offset overflow"))?;
    let length = p
        .last_sector
        .checked_sub(p.first_sector)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| invalid("Partition length overflow"))?;
    start
        .checked_add(length)
        .ok_or_else(|| invalid("Partition extent overflow"))?;
    let mut partition = Partition {
        reader,
        ffu,
        start,
        length,
        position: 0,
        cache_at: 0,
        cache: vec![],
        fetched: 0,
        calls: 0,
        progress,
        cancelled: false,
    };
    let result = action(&mut partition);
    if partition.cancelled {
        return Err(ImageError::Cancelled);
    }
    result
}
