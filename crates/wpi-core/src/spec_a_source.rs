//! Seekable view of a pinned FFU: retained headers, verified payload chunks.
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use wpi_image::ffu::FfuMetadata;

pub(crate) struct Source<'a, R> {
    source: &'a mut R,
    header: &'a [u8],
    ffu: FfuMetadata,
    position: u64,
    verify_reads: bool,
    cached: Option<(u64, Vec<u8>)>,
}
impl<'a, R: Read + Seek> Source<'a, R> {
    pub(crate) fn new(
        source: &'a mut R,
        header: &'a [u8],
        total: u64,
        verify_reads: bool,
    ) -> wpi_image::Result<Self> {
        let ffu = FfuMetadata::read_headers(&mut std::io::Cursor::new(header), total)?;
        if ffu.header_size != header.len() as u64 {
            return Err(wpi_image::ImageError::Invalid(
                "Pinned FFU header length differs".into(),
            ));
        }
        Ok(Self {
            source,
            header,
            ffu,
            position: 0,
            verify_reads,
            cached: None,
        })
    }
}
impl<R: Read + Seek> Read for Source<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() || self.position == self.ffu.total_size {
            return Ok(0);
        }
        if self.position < self.header.len() as u64 {
            let at = self.position as usize;
            let n = out.len().min(self.header.len() - at);
            out[..n].copy_from_slice(&self.header[at..at + n]);
            self.position += n as u64;
            return Ok(n);
        }
        if !self.verify_reads {
            self.source.seek(SeekFrom::Start(self.position))?;
            let limit = (out.len() as u64).min(self.ffu.total_size - self.position) as usize;
            let n = self.source.read(&mut out[..limit])?;
            self.position += n as u64;
            return Ok(n);
        }
        let chunk = u64::from(self.ffu.chunk_size);
        let start = self.position / chunk * chunk;
        if self.cached.as_ref().is_none_or(|c| c.0 != start) {
            let index = (start - self.ffu.security_size) / chunk;
            let hash_at = self
                .ffu
                .hash_table_offset
                .checked_add(
                    index
                        .checked_mul(32)
                        .ok_or_else(|| std::io::Error::other("Pinned hash offset overflow"))?,
                )
                .ok_or_else(|| std::io::Error::other("Pinned hash offset overflow"))?;
            if self.ffu.hash_algorithm != 0x800c
                || index >= u64::from(self.ffu.hash_table_size) / 32
            {
                return Err(std::io::Error::other(
                    "Pinned SHA-256 table does not cover the requested chunk",
                ));
            }
            let expected = self
                .header
                .get(hash_at as usize..hash_at as usize + 32)
                .ok_or_else(|| std::io::Error::other("Pinned hash is outside retained headers"))?;
            let mut bytes = vec![0; chunk as usize];
            self.source.seek(SeekFrom::Start(start))?;
            self.source.read_exact(&mut bytes)?;
            if Sha256::digest(&bytes).as_slice() != expected {
                return Err(std::io::Error::other(
                    "Payload changed from the pinned FFU chunk hash",
                ));
            }
            self.cached = Some((start, bytes));
        }
        let (_, bytes) = self.cached.as_ref().unwrap();
        let within = (self.position - start) as usize;
        let n = out.len().min(bytes.len() - within);
        out[..n].copy_from_slice(&bytes[within..within + n]);
        self.position += n as u64;
        Ok(n)
    }
}
impl<R> Seek for Source<'_, R> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let at = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.ffu.total_size) + i128::from(n),
        };
        if at < 0 || at > i128::from(self.ffu.total_size) {
            return Err(std::io::Error::other(
                "Pinned FFU seek outside source bounds",
            ));
        }
        self.position = at as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn fixture() -> (Vec<u8>, Vec<u8>, FfuMetadata) {
        let bytes = include_bytes!("../../../tests/fixtures/synthetic-spec-a-package.ffu").to_vec();
        let ffu = FfuMetadata::open(&mut Cursor::new(&bytes)).unwrap();
        let header = bytes[..ffu.header_size as usize].to_vec();
        (bytes, header, ffu)
    }
    #[test]
    fn retained_headers_and_verified_chunk_cache_do_not_reread_mutable_bytes() {
        let (mut bytes, header, ffu) = fixture();
        bytes[..header.len()].fill(0);
        let mut source = Cursor::new(bytes);
        let mut pinned = Source::new(&mut source, &header, ffu.total_size, true).unwrap();
        let reference = crate::spec_a_preflight::Reference::read(&mut pinned).unwrap();
        assert!(!reference.summary().full_ffu_integrity_checked);
        assert_eq!(reference.platform(), ffu.platform_id);
        pinned.seek(SeekFrom::Start(ffu.header_size)).unwrap();
        let mut first = vec![0; ffu.chunk_size as usize];
        pinned.read_exact(&mut first).unwrap();
        pinned.source.get_mut()[ffu.header_size as usize] ^= 1;
        pinned.seek(SeekFrom::Start(ffu.header_size)).unwrap();
        let mut cached = vec![0; first.len()];
        pinned.read_exact(&mut cached).unwrap();
        assert_eq!(first, cached);
    }
    #[test]
    fn changed_payload_cannot_be_approved_by_replacing_the_live_hash_table() {
        let (mut bytes, header, ffu) = fixture();
        let at = ffu.header_size as usize;
        bytes[at] ^= 1;
        let index = (ffu.header_size - ffu.security_size) / u64::from(ffu.chunk_size);
        let digest = Sha256::digest(&bytes[at..at + ffu.chunk_size as usize]);
        let hash = ffu.hash_table_offset as usize + index as usize * 32;
        bytes[hash..hash + 32].copy_from_slice(&digest);
        let mut original = Cursor::new(bytes.clone());
        assert!(ffu.verify_hashes(&mut original, |_, _| true).is_ok());
        let mut source = Cursor::new(bytes);
        let mut pinned = Source::new(&mut source, &header, ffu.total_size, false).unwrap();
        assert!(ffu.verify_hashes(&mut pinned, |_, _| true).is_err());
        let mut pinned = Source::new(&mut source, &header, ffu.total_size, true).unwrap();
        pinned.seek(SeekFrom::Start(ffu.header_size)).unwrap();
        assert!(pinned.read_exact(&mut [0; 1]).is_err());
    }
    #[test]
    fn truncated_chunks_bad_seeks_and_short_headers_fail() {
        let (bytes, header, ffu) = fixture();
        let mut source = Cursor::new(&bytes[..ffu.header_size as usize + 1]);
        assert!(Source::new(
            &mut source,
            &header[..header.len() - 1],
            ffu.total_size,
            true
        )
        .is_err());
        let mut pinned = Source::new(&mut source, &header, ffu.total_size, true).unwrap();
        assert!(pinned.seek(SeekFrom::End(1)).is_err());
        assert!(pinned.seek(SeekFrom::Current(-1)).is_err());
        pinned.seek(SeekFrom::Start(ffu.header_size)).unwrap();
        assert!(pinned.read_exact(&mut [0; 1]).is_err());
        pinned.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(pinned.read(&mut [0; 1]).unwrap(), 0);
    }
}
