//! Incremental full-file SHA-256 and FFU chunk-table verification. No image-size
//! allocation, seeking, platform APIs or trust decisions. Feed bytes in file order.
use crate::{ffu::FfuMetadata, invalid, slice, ImageError, Result, COPY_BUFFER, MAX_METADATA};
use sha2::{Digest, Sha256};
use std::io::Cursor;

pub struct Verification {
    pub sha256: String,
    pub chunk_count: u64,
    pub first_mismatch: Option<u64>,
}
pub struct FfuVerifier {
    metadata: FfuMetadata,
    headers: Vec<u8>,
    hashes: Vec<u8>,
    full_hash: Sha256,
    chunk_hash: Sha256,
    received: u64,
    chunk_bytes: usize,
    chunks: u64,
    first_mismatch: Option<u64>,
    failed: bool,
}
impl FfuVerifier {
    pub fn new(headers: &[u8], total_size: u64) -> Result<Self> {
        if headers.len() > MAX_METADATA {
            return Err(invalid("FFU verification headers exceed 32 MiB"));
        }
        let metadata = FfuMetadata::read_headers(&mut Cursor::new(headers), total_size)?;
        if headers.len() as u64 != metadata.header_size {
            return Err(invalid("verification needs the exact FFU headers"));
        }
        if metadata.hash_algorithm != 0x800c {
            return Err(ImageError::Unsupported(
                "FFU hash algorithm is not SHA-256".into(),
            ));
        }
        let count = (metadata.total_size - metadata.security_size) / u64::from(metadata.chunk_size);
        if count.checked_mul(32) != Some(u64::from(metadata.hash_table_size)) {
            return Err(invalid("SHA-256 table length mismatch"));
        }
        let hashes = slice(
            headers,
            metadata.hash_table_offset as usize,
            metadata.hash_table_size as usize,
        )?
        .to_vec();
        Ok(Self {
            metadata,
            headers: headers.to_vec(),
            hashes,
            full_hash: Sha256::new(),
            chunk_hash: Sha256::new(),
            received: 0,
            chunk_bytes: 0,
            chunks: 0,
            first_mismatch: None,
            failed: false,
        })
    }
    pub fn metadata(&self) -> &FfuMetadata {
        &self.metadata
    }
    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed {
            return Err(invalid("verification session has failed"));
        }
        let result = self.update_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn update_inner(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > COPY_BUFFER {
            return Err(invalid("verification input exceeds 1 MiB"));
        }
        let end = self
            .received
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.metadata.total_size)
            .ok_or_else(|| invalid("verification exceeds expected file length"))?;
        if self.received < self.headers.len() as u64 {
            let n = bytes.len().min(self.headers.len() - self.received as usize);
            if bytes[..n] != self.headers[self.received as usize..self.received as usize + n] {
                return Err(invalid(
                    "FFU headers changed after inspection; reselect the file",
                ));
            }
        }
        self.full_hash.update(bytes);
        // The security region is part of the fingerprint but is not in its own
        // chunk table. Image/store headers and every payload chunk are checked.
        let skip = self
            .metadata
            .security_size
            .saturating_sub(self.received)
            .min(bytes.len() as u64) as usize;
        let mut remaining = &bytes[skip..];
        while !remaining.is_empty() {
            let n = remaining
                .len()
                .min(self.metadata.chunk_size as usize - self.chunk_bytes);
            self.chunk_hash.update(&remaining[..n]);
            self.chunk_bytes += n;
            remaining = &remaining[n..];
            if self.chunk_bytes == self.metadata.chunk_size as usize {
                let digest = std::mem::take(&mut self.chunk_hash).finalize();
                let at = self.chunks as usize * 32;
                if digest.as_slice() != &self.hashes[at..at + 32] && self.first_mismatch.is_none() {
                    self.first_mismatch = Some(self.chunks);
                }
                self.chunks += 1;
                self.chunk_bytes = 0;
            }
        }
        self.received = end;
        Ok(())
    }
    pub fn finish(self) -> Result<Verification> {
        if self.failed
            || self.received != self.metadata.total_size
            || self.chunk_bytes != 0
            || self.chunks != self.hashes.len() as u64 / 32
        {
            return Err(invalid(
                "verification is failed or incomplete; no complete fingerprint is available",
            ));
        }
        Ok(Verification {
            sha256: hex::encode(self.full_hash.finalize()),
            chunk_count: self.chunks,
            first_mismatch: self.first_mismatch,
        })
    }
}
