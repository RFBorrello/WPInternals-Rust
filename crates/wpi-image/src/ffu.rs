//! Legacy single-store FFU layout ported from WPinternals 2.9.2 Models/FFU.cs.
//! Copyright (c) 2018 Rene Lergner. See THIRD_PARTY_NOTICES.md.
use crate::{invalid, read_at, slice, u32le, ImageError, Result, MAX_METADATA, SECTOR_SIZE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub disk_access: u32,
    pub disk_chunk: u64,
    pub chunk_count: u64,
    pub payload_chunk: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfuMetadata {
    pub platform_id: String,
    pub chunk_size: u32,
    pub security_size: u64,
    pub image_size: u64,
    pub store_size: u64,
    pub header_size: u64,
    pub payload_size: u64,
    pub total_size: u64,
    pub hash_algorithm: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u32,
    pub catalog_size: u32,
    pub manifest: String,
    pub mappings: Vec<Mapping>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadSegment {
    pub output_offset: u64,
    pub file_offset: Option<u64>,
    pub length: u64,
}

fn aligned(size: u64, chunk: u64) -> Result<u64> {
    size.checked_add(chunk - 1)
        .map(|n| n / chunk * chunk)
        .ok_or_else(|| invalid("FFU size overflow"))
}
fn header_length(size: u64) -> Result<usize> {
    if size > MAX_METADATA as u64 {
        return Err(invalid("FFU headers exceed 32 MiB"));
    }
    Ok(size as usize)
}

impl FfuMetadata {
    /// Parses only headers, and checks all payload bounds against the external file length.
    /// The reader may contain headers alone (used by the browser's incremental file reader).
    pub fn read_headers<R: Read + Seek>(reader: &mut R, total_size: u64) -> Result<Self> {
        let security = read_at(reader, 0, 32)?;
        if slice(&security, 4, 12)? != b"SignedImage " {
            return Err(invalid("missing FFU SignedImage signature"));
        }
        let chunk_size = u32le(&security, 16)?
            .checked_mul(1024)
            .ok_or_else(|| invalid("chunk size overflow"))?;
        if !(512..=4 * 1024 * 1024).contains(&chunk_size) || !chunk_size.is_power_of_two() {
            return Err(invalid("invalid FFU chunk size"));
        }
        let sec_header = u32le(&security, 0)?;
        if sec_header < 32 {
            return Err(invalid("security header is shorter than 32 bytes"));
        }
        let catalog_size = u32le(&security, 24)?;
        let hash_table_size = u32le(&security, 28)?;
        let security_size = aligned(
            sec_header as u64 + catalog_size as u64 + hash_table_size as u64,
            chunk_size as u64,
        )?;
        header_length(security_size)?;
        let image = read_at(reader, security_size, 24)?;
        if slice(&image, 4, 12)? != b"ImageFlash  " {
            return Err(invalid("missing FFU ImageFlash signature"));
        }
        let image_header = u32le(&image, 0)?;
        if image_header < 24 {
            return Err(invalid("image header is shorter than 24 bytes"));
        }
        // Security and image headers express chunk size in KiB; the store
        // header's block size is in bytes. Do not compare the raw fields.
        let image_chunk = u32le(&image, 20)?
            .checked_mul(1024)
            .ok_or_else(|| invalid("image chunk size overflow"))?;
        if image_chunk != chunk_size {
            return Err(invalid("image and security chunk sizes differ"));
        }
        let manifest_size = u32le(&image, 16)?;
        let image_size = aligned(
            image_header as u64 + manifest_size as u64,
            chunk_size as u64,
        )?;
        let store_offset = security_size
            .checked_add(image_size)
            .ok_or_else(|| invalid("header overflow"))?;
        header_length(store_offset)?;
        let manifest_bytes = read_at(
            reader,
            security_size + image_header as u64,
            manifest_size as usize,
        )?;
        let manifest =
            String::from_utf8(manifest_bytes).map_err(|_| invalid("manifest is not UTF-8"))?;
        let short_store = read_at(reader, store_offset, 248)?;
        let major = u16::from_le_bytes(slice(&short_store, 4, 2)?.try_into().unwrap());
        if major != 1 {
            return Err(ImageError::Unsupported(format!(
                "FFU store version {major}; only single-store version 1 is supported"
            )));
        }
        if u32le(&short_store, 204)? != chunk_size {
            return Err(invalid("store and security chunk sizes differ"));
        }
        let platform_id = String::from_utf8_lossy(slice(&short_store, 12, 192)?)
            .trim_end_matches(['\0', ' '])
            .to_owned();
        let count = u32le(&short_store, 208)? as usize;
        let write_length = u32le(&short_store, 212)? as usize;
        let validate_length = u32le(&short_store, 220)? as usize;
        let store_size = aligned(
            248u64 + write_length as u64 + validate_length as u64,
            chunk_size as u64,
        )?;
        let header_size = store_offset
            .checked_add(store_size)
            .ok_or_else(|| invalid("header overflow"))?;
        header_length(header_size)?;
        if header_size > total_size {
            return Err(invalid("headers exceed file length"));
        }
        if count > write_length / 16 {
            return Err(invalid("descriptor count exceeds descriptor region"));
        }
        let descriptors = read_at(
            reader,
            store_offset + 248 + validate_length as u64,
            write_length,
        )?;
        let mut at = 0usize;
        let mut payload_chunks = 0u64;
        let mut mappings = Vec::new();
        for _ in 0..count {
            let locations = u32le(&descriptors, at)? as usize;
            let chunks = u32le(&descriptors, at + 4)? as u64;
            if locations == 0 || chunks == 0 {
                return Err(invalid("empty FFU write descriptor"));
            }
            let entry_length = locations
                .checked_mul(8)
                .and_then(|n| n.checked_add(8))
                .ok_or_else(|| invalid("descriptor overflow"))?;
            slice(&descriptors, at, entry_length)?;
            if mappings.len().saturating_add(locations) > MAX_METADATA / 32 {
                return Err(invalid("too many FFU disk locations"));
            }
            for location in 0..locations {
                let pos = at + 8 + location * 8;
                let disk_access = u32le(&descriptors, pos)?;
                if !matches!(disk_access, 0 | 2) {
                    return Err(ImageError::Unsupported(format!(
                        "FFU disk access method {disk_access}"
                    )));
                }
                let disk_chunk = u32le(&descriptors, pos + 4)? as u64;
                mappings.push(Mapping {
                    disk_access,
                    disk_chunk,
                    chunk_count: chunks,
                    payload_chunk: payload_chunks,
                });
            }
            payload_chunks = payload_chunks
                .checked_add(chunks)
                .ok_or_else(|| invalid("payload count overflow"))?;
            at += entry_length;
        }
        if at != write_length {
            return Err(invalid("write descriptor length mismatch"));
        }
        let payload_size = payload_chunks
            .checked_mul(chunk_size as u64)
            .ok_or_else(|| invalid("payload overflow"))?;
        if header_size.checked_add(payload_size) != Some(total_size) {
            return Err(invalid("FFU file length does not match declared payload"));
        }
        Ok(Self {
            platform_id,
            chunk_size,
            security_size,
            image_size,
            store_size,
            header_size,
            payload_size,
            total_size,
            hash_algorithm: u32le(&security, 20)?,
            hash_table_offset: sec_header as u64 + catalog_size as u64,
            hash_table_size,
            catalog_size,
            manifest,
            mappings,
        })
    }
    pub fn open<R: Read + Seek>(reader: &mut R) -> Result<Self> {
        let size = reader.seek(SeekFrom::End(0))?;
        Self::read_headers(reader, size)
    }
    /// Sparse logical disk reads. Later descriptors override earlier mappings, as upstream does.
    /// End-relative descriptors are deliberately excluded: these APIs expose primary partitions,
    /// not a synthesized disk with an assumed capacity and potentially misplaced backup GPT.
    pub fn segments(&self, start: u64, length: u64) -> Result<Vec<ReadSegment>> {
        let end = start
            .checked_add(length)
            .ok_or_else(|| invalid("disk range overflow"))?;
        let chunk = self.chunk_size as u64;
        let highest = self
            .mappings
            .iter()
            .filter(|m| m.disk_access == 0)
            .map(|m| (m.disk_chunk + m.chunk_count) * chunk)
            .max()
            .unwrap_or(0);
        if end > highest {
            return Err(invalid("disk range exceeds FFU primary mappings"));
        }
        let mut boundaries = vec![start, end];
        for m in self.mappings.iter().filter(|m| m.disk_access == 0) {
            for boundary in [m.disk_chunk * chunk, (m.disk_chunk + m.chunk_count) * chunk] {
                if start < boundary && boundary < end {
                    boundaries.push(boundary);
                }
            }
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        boundaries
            .windows(2)
            .map(|range| {
                let pos = range[0];
                let file_offset = self
                    .mappings
                    .iter()
                    .rev()
                    .find(|m| {
                        m.disk_access == 0
                            && m.disk_chunk * chunk <= pos
                            && pos < (m.disk_chunk + m.chunk_count) * chunk
                    })
                    .map(|m| {
                        self.header_size + m.payload_chunk * chunk + pos - m.disk_chunk * chunk
                    });
                Ok(ReadSegment {
                    output_offset: pos - start,
                    file_offset,
                    length: range[1] - pos,
                })
            })
            .collect()
    }
    pub fn read_disk<R: Read + Seek>(
        &self,
        reader: &mut R,
        start: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        if length > MAX_METADATA {
            return Err(invalid("disk metadata exceeds limit"));
        }
        let mut result = vec![0; length];
        for segment in self.segments(start, length as u64)? {
            if let Some(offset) = segment.file_offset {
                reader.seek(SeekFrom::Start(offset))?;
                reader.read_exact(
                    &mut result[segment.output_offset as usize
                        ..(segment.output_offset + segment.length) as usize],
                )?;
            }
        }
        Ok(result)
    }
    pub fn gpt<R: Read + Seek>(&self, reader: &mut R) -> Result<crate::gpt::Gpt> {
        let header = self.read_disk(reader, SECTOR_SIZE, 512)?;
        let table_lba = crate::u64le(&header, 72)?;
        let table_size = (u32le(&header, 80)? as u64)
            .checked_mul(u32le(&header, 84)? as u64)
            .ok_or_else(|| invalid("GPT table overflow"))?;
        let table = self.read_disk(
            reader,
            table_lba
                .checked_mul(SECTOR_SIZE)
                .ok_or_else(|| invalid("GPT offset overflow"))?,
            header_length(table_size)?,
        )?;
        crate::gpt::Gpt::from_parts(&header, &table, None)
    }
    pub fn extract<R: Read + Seek, W: Write, F: FnMut(u64, u64) -> bool>(
        &self,
        reader: &mut R,
        writer: &mut W,
        start: u64,
        length: u64,
        mut progress: F,
    ) -> Result<()> {
        let mut buffer = vec![0; crate::COPY_BUFFER];
        let mut completed = 0u64;
        for segment in self.segments(start, length)? {
            if let Some(offset) = segment.file_offset {
                reader.seek(SeekFrom::Start(offset))?;
            }
            let mut remaining = segment.length;
            while remaining > 0 {
                if !progress(completed, length) {
                    return Err(ImageError::Cancelled);
                }
                let n = remaining.min(buffer.len() as u64) as usize;
                if segment.file_offset.is_some() {
                    reader.read_exact(&mut buffer[..n])?;
                } else {
                    buffer[..n].fill(0);
                }
                writer.write_all(&buffer[..n])?;
                completed += n as u64;
                remaining -= n as u64;
            }
        }
        writer.flush()?;
        if !progress(completed, length) {
            return Err(ImageError::Cancelled);
        }
        Ok(())
    }
    /// Verifies SHA-256 chunk hashes. This does NOT authenticate the signing catalog.
    pub fn verify_hashes<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
        &self,
        reader: &mut R,
        mut progress: F,
    ) -> Result<()> {
        if self.hash_algorithm != 0x800c {
            return Err(ImageError::Unsupported(
                "FFU hash algorithm is not SHA-256".into(),
            ));
        }
        let count = (self.total_size - self.security_size) / self.chunk_size as u64;
        if count.checked_mul(32) != Some(self.hash_table_size as u64) {
            return Err(invalid("SHA-256 table length mismatch"));
        }
        let hashes = read_at(
            reader,
            self.hash_table_offset,
            self.hash_table_size as usize,
        )?;
        let mut chunk = vec![0; self.chunk_size as usize];
        reader.seek(SeekFrom::Start(self.security_size))?;
        for index in 0..count {
            if !progress(index, count) {
                return Err(ImageError::Cancelled);
            }
            reader.read_exact(&mut chunk)?;
            if Sha256::digest(&chunk).as_slice()
                != &hashes[index as usize * 32..index as usize * 32 + 32]
            {
                return Err(invalid(format!("FFU hash mismatch at chunk {index}")));
            }
        }
        progress(count, count);
        Ok(())
    }
}
