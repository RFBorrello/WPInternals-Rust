//! Bounded, read-only partition-relative access over sparse FFU mappings.
use crate::{ffu::FfuMetadata, gpt::Gpt, invalid, ImageError, Result, SECTOR_SIZE};
use std::collections::VecDeque;
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
    // FAT alternates allocation-table and data reads. Eight LRU pages avoid
    // thrashing while retaining a 512 KiB cache and the same total I/O budget.
    cache: VecDeque<(u64, Vec<u8>)>,
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
        let cache_at = self.position / LIMIT as u64 * LIMIT as u64;
        let cached = self.cache.iter().position(|(at, _)| *at == cache_at);
        let page = if let Some(index) = cached {
            self.cache.remove(index).unwrap()
        } else {
            let count = (self.length - cache_at).min(LIMIT as u64) as usize;
            if self.fetched + count as u64 > IO_BUDGET {
                return Err(io::Error::other("Partition metadata I/O exceeds 16 MiB"));
            }
            self.fetched += count as u64;
            let bytes = self
                .ffu
                .read_disk(self.reader, self.start + cache_at, count)
                .map_err(io::Error::other)?;
            (cache_at, bytes)
        };
        let at = (self.position - cache_at) as usize;
        let n = n.min(page.1.len() - at);
        buffer[..n].copy_from_slice(&page.1[at..at + n]);
        if self.cache.len() == 8 {
            self.cache.pop_back();
        }
        self.cache.push_front(page);
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
        cache: VecDeque::new(),
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    #[test]
    fn fat_allocation_and_data_reads_share_bounded_lru_without_budget_bypass() {
        let mut disk = Cursor::new(vec![0; 4 * 1024 * 1024]);
        fatfs::format_volume(&mut disk, fatfs::FormatVolumeOptions::new()).unwrap();
        let fs = fatfs::FileSystem::new(&mut disk, fatfs::FsOptions::new()).unwrap();
        let root = fs.root_dir();
        let mut file = root.create_file("boot.bin").unwrap();
        let bytes = vec![0x5a; 1024 * 1024];
        file.write_all(&bytes).unwrap();
        drop(file);
        drop(root);
        fs.unmount().unwrap();
        let mut ffu = FfuMetadata::open(&mut Cursor::new(
            include_bytes!("../../../tests/fixtures/synthetic.ffu").as_slice(),
        ))
        .unwrap();
        ffu.header_size = 0;
        ffu.payload_size = disk.get_ref().len() as u64;
        ffu.total_size = ffu.payload_size;
        ffu.mappings = vec![crate::ffu::Mapping {
            disk_access: 0,
            disk_chunk: 0,
            chunk_count: ffu.payload_size / ffu.chunk_size as u64,
            payload_chunk: 0,
        }];
        let mut p = Partition {
            reader: &mut disk,
            ffu: &ffu,
            start: 0,
            length: ffu.payload_size,
            position: 0,
            cache: VecDeque::new(),
            fetched: 0,
            calls: 0,
            progress: |_, _| true,
            cancelled: false,
        };
        let read = crate::filesystem::read_small_fat_file(&mut p, "boot.bin", 2 * 1024 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(read, bytes);
        assert!(p.fetched < 4 * 1024 * 1024);
        assert!(p.cache.len() <= 8);
        let mut exhausted = false;
        for i in 0..400 {
            p.seek(SeekFrom::Start((i % 64) * LIMIT as u64)).unwrap();
            if p.read_exact(&mut [0]).is_err() {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted);
        assert!(p.fetched <= IO_BUDGET);
        assert!(p.cache.len() <= 8);
    }
}
