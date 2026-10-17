//! Small deterministic stored-ZIP writer, limited to local offline packages.
//! No compression, ZIP64, archive extraction, paths supplied by users or device I/O.
use crate::{invalid, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
pub const MAX_SIZE: u64 = 512 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub crc32: u32,
    pub data_offset: u64,
}
struct Record {
    file: FileRecord,
    local: Vec<u8>,
    offset: u64,
}
pub struct Archive<'a, W> {
    writer: &'a mut W,
    records: Vec<Record>,
    position: u64,
}
pub struct Entry<'a, W> {
    writer: &'a mut W,
    size: u64,
    written: u64,
    crc: crc32fast::Hasher,
    hash: Sha256,
}
impl<W: Write> Write for Entry<'_, W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() as u64 > self.size - self.written {
            return Err(std::io::Error::other("ZIP entry exceeds declared size"));
        }
        let n = self.writer.write(b)?;
        self.written += n as u64;
        self.crc.update(&b[..n]);
        self.hash.update(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
fn short(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn long(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn local_header(name: &str) -> Vec<u8> {
    let mut header = Vec::new();
    long(&mut header, 0x04034b50);
    for n in [20, 8, 0, 0, 33] {
        short(&mut header, n);
    }
    for _ in 0..3 {
        long(&mut header, 0);
    }
    short(&mut header, name.len() as u16);
    short(&mut header, 0);
    header.extend_from_slice(name.as_bytes());
    header
}
impl<'a, W: Write> Archive<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Self {
            writer,
            records: Vec::new(),
            position: 0,
        }
    }
    pub fn files(&self) -> Vec<FileRecord> {
        self.records.iter().map(|r| r.file.clone()).collect()
    }
    pub fn add<F: FnOnce(&mut Entry<'_, W>) -> Result<()>>(
        &mut self,
        name: &str,
        size: u64,
        produce: F,
    ) -> Result<()> {
        if self.records.len() >= 128
            || !name.is_ascii()
            || name.len() > 128
            || name.is_empty()
            || crate::patch::safe_relative_path(name)? != name
            || self
                .records
                .iter()
                .any(|r| r.file.path.eq_ignore_ascii_case(name))
            || size > 128 * 1024 * 1024
            || self.position + size + 512 > MAX_SIZE
        {
            return Err(invalid("ZIP name, entry count or size limit exceeded"));
        }
        let header = local_header(name);
        let offset = self.position;
        self.writer.write_all(&header)?;
        let data_offset = offset + header.len() as u64;
        let mut entry = Entry {
            writer: self.writer,
            size,
            written: 0,
            crc: crc32fast::Hasher::new(),
            hash: Sha256::new(),
        };
        produce(&mut entry)?;
        if entry.written != size {
            return Err(invalid("ZIP entry is incomplete"));
        }
        let crc32 = entry.crc.finalize();
        let sha256 = hex::encode(entry.hash.finalize());
        let mut descriptor = Vec::new();
        long(&mut descriptor, 0x08074b50);
        long(&mut descriptor, crc32);
        long(&mut descriptor, size as u32);
        long(&mut descriptor, size as u32);
        self.writer.write_all(&descriptor)?;
        self.position = data_offset + size + 16;
        self.records.push(Record {
            file: FileRecord {
                path: name.into(),
                size,
                sha256,
                crc32,
                data_offset,
            },
            local: header,
            offset,
        });
        Ok(())
    }
    pub fn bytes(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.add(name, bytes.len() as u64, |e| {
            e.write_all(bytes)?;
            Ok(())
        })
    }
    pub fn finish(mut self) -> Result<Finished> {
        let central_at = self.position;
        let mut central = Vec::new();
        for r in &self.records {
            long(&mut central, 0x02014b50);
            short(&mut central, 20);
            short(&mut central, 20);
            short(&mut central, 8);
            short(&mut central, 0);
            short(&mut central, 0);
            short(&mut central, 33);
            long(&mut central, r.file.crc32);
            long(&mut central, r.file.size as u32);
            long(&mut central, r.file.size as u32);
            short(&mut central, r.file.path.len() as u16);
            for _ in 0..4 {
                short(&mut central, 0);
            }
            long(&mut central, 0);
            long(&mut central, r.offset as u32);
            central.extend_from_slice(r.file.path.as_bytes());
        }
        let length = central.len();
        long(&mut central, 0x06054b50);
        short(&mut central, 0);
        short(&mut central, 0);
        short(&mut central, self.records.len() as u16);
        short(&mut central, self.records.len() as u16);
        long(&mut central, length as u32);
        long(&mut central, central_at as u32);
        short(&mut central, 0);
        if central_at + central.len() as u64 > MAX_SIZE {
            return Err(invalid("ZIP directory exceeds package size limit"));
        }
        self.writer.write_all(&central)?;
        self.writer.flush()?;
        self.position += central.len() as u64;
        Ok(Finished {
            records: self.records,
            central_at,
            central,
            size: self.position,
        })
    }
}
pub struct Finished {
    records: Vec<Record>,
    central_at: u64,
    central: Vec<u8>,
    pub size: u64,
}
impl Finished {
    /// Re-read the actual output, including headers, descriptors and directory.
    /// Integrity is checked against the builder's independent in-memory records.
    pub fn verify<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
        &self,
        reader: &mut R,
        progress: F,
    ) -> Result<String> {
        self.verify_records(reader, progress, true).map(|r| r.0)
    }
    fn verify_records<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
        &self,
        reader: &mut R,
        mut progress: F,
        compare_hashes: bool,
    ) -> Result<(String, Vec<FileRecord>)> {
        if reader.seek(SeekFrom::End(0))? != self.size {
            return Err(invalid("ZIP output length mismatch"));
        }
        let mut total_hash = Sha256::new();
        fn check<R: Read>(reader: &mut R, expected: &[u8], hash: &mut Sha256) -> Result<()> {
            let mut bytes = vec![0; expected.len()];
            reader.read_exact(&mut bytes)?;
            if bytes != expected {
                return Err(invalid("ZIP metadata verification failed"));
            }
            hash.update(&bytes);
            Ok(())
        }
        reader.seek(SeekFrom::Start(0))?;
        let mut files = Vec::new();
        // Keep per-entry verification separate from metadata byte comparisons.
        for r in &self.records {
            if reader.stream_position()? != r.offset {
                return Err(invalid("ZIP entry offset mismatch"));
            }
            check(reader, &r.local, &mut total_hash)?;
            let mut remaining = r.file.size;
            let mut hash = Sha256::new();
            let mut crc = crc32fast::Hasher::new();
            let mut buffer = vec![0; 65536];
            while remaining > 0 {
                if !progress(r.file.data_offset + r.file.size - remaining, self.size) {
                    return Err(crate::ImageError::Cancelled);
                }
                let n = remaining.min(65536) as usize;
                reader.read_exact(&mut buffer[..n])?;
                hash.update(&buffer[..n]);
                crc.update(&buffer[..n]);
                total_hash.update(&buffer[..n]);
                remaining -= n as u64;
            }
            let sha256 = hex::encode(hash.finalize());
            if (compare_hashes && sha256 != r.file.sha256) || crc.finalize() != r.file.crc32 {
                return Err(invalid("ZIP entry hash/CRC mismatch"));
            }
            files.push(FileRecord {
                sha256,
                ..r.file.clone()
            });
            // Include the verified data descriptor in the whole-package digest.
            let mut descriptor = Vec::new();
            long(&mut descriptor, 0x08074b50);
            long(&mut descriptor, r.file.crc32);
            long(&mut descriptor, r.file.size as u32);
            long(&mut descriptor, r.file.size as u32);
            check(reader, &descriptor, &mut total_hash)?;
        }
        if reader.stream_position()? != self.central_at {
            return Err(invalid("ZIP central offset mismatch"));
        }
        check(reader, &self.central, &mut total_hash)?;
        if !progress(self.size, self.size) {
            return Err(crate::ImageError::Cancelled);
        }
        Ok((hex::encode(total_hash.finalize()), files))
    }
}
/// Import only this project's exact stored-ZIP dialect. No extraction, compression,
/// ZIP64, extras, comments, gaps or arbitrary paths. Returned hashes are calculated
/// from file bytes, not trusted from a JSON report. Integrity is not authenticity.
pub fn inspect<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    progress: F,
) -> Result<(String, Vec<FileRecord>)> {
    use crate::{read_at, slice, u32le};
    let short_at = |b: &[u8], at| -> Result<u16> {
        Ok(u16::from_le_bytes(slice(b, at, 2)?.try_into().unwrap()))
    };
    let size = reader.seek(SeekFrom::End(0))?;
    if !(22..=MAX_SIZE).contains(&size) {
        return Err(invalid("Unsupported package size"));
    }
    let end = read_at(reader, size - 22, 22)?;
    let count = short_at(&end, 10)?;
    let central_size = u32le(&end, 12)? as usize;
    let central_at = u32le(&end, 16)? as u64;
    if u32le(&end, 0)? != 0x06054b50
        || short_at(&end, 4)? != 0
        || short_at(&end, 6)? != 0
        || short_at(&end, 8)? != count
        || !(1..=128).contains(&count)
        || short_at(&end, 20)? != 0
        || central_size > 128 * (46 + 128)
        || central_at + central_size as u64 + 22 != size
    {
        return Err(invalid("Unsupported package directory"));
    }
    let mut central = read_at(reader, central_at, central_size)?;
    let mut records = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    let mut at = 0;
    let mut offset = 0;
    for _ in 0..count {
        let b = slice(&central, at, 46)?;
        let len = short_at(b, 28)? as usize;
        let name = std::str::from_utf8(slice(&central, at + 46, len)?)
            .map_err(|_| invalid("Package name is not UTF-8"))?;
        let length = u32le(b, 24)? as u64;
        if u32le(b, 0)? != 0x02014b50
            || [4, 6, 8, 10, 12, 14]
                .into_iter()
                .zip([20, 20, 8, 0, 0, 33])
                .any(|(i, expected)| short_at(b, i).ok() != Some(expected))
            || !name.is_ascii()
            || name.is_empty()
            || len > 128
            || crate::patch::safe_relative_path(name)? != name
            || !names.insert(name.to_ascii_uppercase())
            || length > 128 * 1024 * 1024
            || u32le(b, 20)? as u64 != length
            || b[30..42].iter().any(|v| *v != 0)
            || u32le(b, 42)? as u64 != offset
        {
            return Err(invalid("Unsupported package entry"));
        }
        let local = local_header(name);
        let data_offset = offset + local.len() as u64;
        let next = data_offset + length + 16;
        if next > central_at {
            return Err(invalid("Package entry exceeds data area"));
        }
        records.push(Record {
            file: FileRecord {
                path: name.into(),
                size: length,
                crc32: u32le(b, 16)?,
                sha256: String::new(),
                data_offset,
            },
            local,
            offset,
        });
        offset = next;
        at += 46 + len;
    }
    if at != central_size || offset != central_at {
        return Err(invalid("Package has unaccounted bytes"));
    }
    central.extend_from_slice(&end);
    Finished {
        records,
        central_at,
        central,
        size,
    }
    .verify_records(reader, progress, false)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn imported_packages_verify_streaming_and_reject_structural_corruption() {
        let mut out = Cursor::new(Vec::new());
        let mut a = Archive::new(&mut out);
        a.bytes("original/one.bin", &[42; 70000]).unwrap();
        a.bytes("prepared/two.bin", b"two").unwrap();
        let done = a.finish().unwrap();
        let original = out.into_inner();
        let (digest, files) = inspect(&mut Cursor::new(&original), |_, _| true).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(&original)));
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].sha256, super::super::hash(&[42; 70000]));
        for at in [
            0,
            6,
            26,
            30,
            files[0].data_offset as usize,
            (files[0].data_offset + files[0].size) as usize,
            done.central_at as usize,
            done.central_at as usize + 10,
            done.central_at as usize + 24,
            done.central_at as usize + 28,
            done.central_at as usize + 30,
            done.central_at as usize + 42,
            original.len() - 1,
        ] {
            let mut damaged = original.clone();
            damaged[at] ^= 1;
            assert!(
                inspect(&mut Cursor::new(damaged), |_, _| true).is_err(),
                "at {at}"
            );
        }
        for len in [0, 21, 100, original.len() - 1] {
            assert!(inspect(&mut Cursor::new(&original[..len]), |_, _| true).is_err());
        }
        let mut extra = original.clone();
        extra.push(0);
        assert!(inspect(&mut Cursor::new(extra), |_, _| true).is_err());
        assert!(matches!(
            inspect(&mut Cursor::new(&original), |_, _| false),
            Err(crate::ImageError::Cancelled)
        ));
        let mut oversized = original;
        let at = oversized.len() - 10;
        oversized[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect(&mut Cursor::new(oversized), |_, _| true).is_err());
    }
    #[test]
    fn imported_directory_paths_duplicates_limits_and_read_sizes_are_bounded() {
        let mut out = Cursor::new(Vec::new());
        let mut a = Archive::new(&mut out);
        a.bytes("original/one.bin", &[1; 70000]).unwrap();
        a.bytes("prepared/two.bin", b"two").unwrap();
        let done = a.finish().unwrap();
        let original = out.into_inner();
        let first = done.central_at as usize;
        let second = first + 46 + "original/one.bin".len();
        let mut duplicate = original.clone();
        duplicate[second + 46..second + 46 + 16].copy_from_slice(b"original/one.bin");
        assert!(inspect(&mut Cursor::new(duplicate), |_, _| true).is_err());
        let mut unsafe_path = original.clone();
        unsafe_path[first + 46..first + 49].copy_from_slice(b"../");
        assert!(inspect(&mut Cursor::new(unsafe_path), |_, _| true).is_err());
        let mut huge = original.clone();
        for i in [20, 24] {
            huge[first + i..first + i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        assert!(inspect(&mut Cursor::new(huge), |_, _| true).is_err());
        let mut count = original.clone();
        let at = count.len() - 22;
        for i in [8, 10] {
            count[at + i..at + i + 2].copy_from_slice(&129u16.to_le_bytes());
        }
        assert!(inspect(&mut Cursor::new(count), |_, _| true).is_err());
        struct Bounded(Cursor<Vec<u8>>);
        impl Read for Bounded {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                assert!(b.len() <= 65536);
                self.0.read(b)
            }
        }
        impl Seek for Bounded {
            fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
                self.0.seek(p)
            }
        }
        assert!(inspect(&mut Bounded(Cursor::new(original)), |_, _| true).is_ok());
    }
    #[test]
    fn metadata_data_descriptors_and_directory_are_reread_and_corruption_rejected() {
        let mut out = Cursor::new(Vec::new());
        let mut archive = Archive::new(&mut out);
        archive.bytes("original/test.bin", b"source bytes").unwrap();
        let done = archive.finish().unwrap();
        assert_eq!(
            done.verify(&mut out, |_, _| true).unwrap(),
            hex::encode(Sha256::digest(out.get_ref()))
        );
        let original = out.into_inner();
        for at in [
            0,
            30,
            done.records[0].file.data_offset as usize,
            done.central_at as usize,
            original.len() - 1,
        ] {
            let mut damaged = original.clone();
            damaged[at] ^= 1;
            assert!(done.verify(&mut Cursor::new(damaged), |_, _| true).is_err());
        }
        assert!(done
            .verify(&mut Cursor::new(&original[..original.len() - 1]), |_, _| {
                true
            })
            .is_err());
        assert!(matches!(
            done.verify(&mut Cursor::new(original), |_, _| false),
            Err(crate::ImageError::Cancelled)
        ));
    }
    #[test]
    fn size_path_duplicate_and_partial_write_failures_cannot_validate() {
        let mut out = Vec::new();
        let mut archive = Archive::new(&mut out);
        assert!(archive
            .add("test", 4, |e| {
                e.write_all(b"x")?;
                Ok(())
            })
            .is_err());
        let mut out = Vec::new();
        let mut archive = Archive::new(&mut out);
        assert!(archive
            .add("test", 1, |e| {
                e.write_all(b"xx")?;
                Ok(())
            })
            .is_err());
        let mut out = Vec::new();
        let mut archive = Archive::new(&mut out);
        assert!(archive.bytes("../escape", b"").is_err());
        archive.bytes("test", b"x").unwrap();
        assert!(archive.bytes("TEST", b"x").is_err());
        struct Fail(usize);
        impl Write for Fail {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Err(std::io::Error::other("disconnect"));
                }
                let n = b.len().min(self.0);
                self.0 -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Fail(40);
        let mut archive = Archive::new(&mut sink);
        assert!(archive.bytes("test.bin", &[42; 100]).is_err());
    }
}
