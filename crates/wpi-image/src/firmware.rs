//! Bounded PLAT SWVERSION scan, matching the upstream 2.9.2 source location.
//! The result is observed image metadata, not proof of phone acceptance.
use crate::{ffu::FfuMetadata, gpt::Gpt, invalid, ImageError, Result, SECTOR_SIZE};
use std::io::{Read, Seek};
pub mod mainos;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VersionEvidence {
    pub version: String,
    pub sources: Vec<String>,
}
/// PLAT is the upstream source. When absent, consult the narrowly supported
/// MainOS OEM package profile; filenames never supply a version.
pub fn inspect<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    mut progress: F,
) -> Result<Option<VersionEvidence>> {
    if let Some(version) = read_version(reader, ffu, gpt, &mut progress)? {
        return Ok(Some(VersionEvidence {
            version,
            sources: vec!["PLAT SWVERSION".into()],
        }));
    }
    mainos::read(reader, ffu, gpt, progress)
}
const MARKER: &[u8] = b"SWVERSION=";
const MAX_VALUE: usize = 128;
const BLOCK: usize = 64 * 1024;
const MAX_PLAT: u64 = 64 * 1024 * 1024;
pub fn components(version: &str) -> Option<[u32; 4]> {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 4
        || parts
            .iter()
            .any(|s| s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
        parts[3].parse().ok()?,
    ])
}
pub fn scan_version(bytes: &[u8]) -> Result<Option<String>> {
    scan_chunk(bytes, true)
}
pub fn scan_chunk(bytes: &[u8], final_chunk: bool) -> Result<Option<String>> {
    let mut found = None;
    for start in 0..bytes.len().saturating_sub(MARKER.len() - 1) {
        if !bytes[start..].starts_with(MARKER) {
            continue;
        }
        let tail = &bytes[start + MARKER.len()..];
        let Some(end) = tail
            .iter()
            .take(MAX_VALUE + 1)
            .position(|b| matches!(b, 0 | b'\r' | b'\n'))
        else {
            // An incomplete suffix is handled by the bounded streaming scanner.
            if tail.len() <= MAX_VALUE && !final_chunk {
                continue;
            }
            return Err(invalid(
                "PLAT SWVERSION exceeds 128 bytes or lacks a terminator",
            ));
        };
        let value = std::str::from_utf8(&tail[..end])
            .map_err(|_| invalid("PLAT SWVERSION is not ASCII firmware metadata"))?;
        if components(value).is_none() {
            return Err(invalid(
                "PLAT SWVERSION must contain four bounded numeric components",
            ));
        }
        if found.as_deref().is_some_and(|old| old != value) {
            return Err(invalid("Contradictory PLAT SWVERSION values"));
        }
        found = Some(value.to_owned());
    }
    Ok(found)
}
pub fn read_version<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    mut progress: F,
) -> Result<Option<String>> {
    let partitions: Vec<_> = gpt.partitions.iter().filter(|p| p.name == "PLAT").collect();
    if partitions.is_empty() {
        return Ok(None);
    }
    if partitions.len() != 1 {
        return Err(invalid("Ambiguous PLAT partition"));
    }
    let p = partitions[0];
    let start = p
        .first_sector
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| invalid("PLAT offset overflow"))?;
    let length = p
        .last_sector
        .checked_sub(p.first_sector)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| invalid("PLAT size overflow"))?;
    if length > MAX_PLAT {
        return Err(ImageError::Unsupported("PLAT scan exceeds 64 MiB".into()));
    }
    let mut carry = Vec::new();
    let mut result = None;
    let mut done = 0;
    while done < length {
        if !progress(done, length) {
            return Err(ImageError::Cancelled);
        }
        let n = (length - done).min(BLOCK as u64) as usize;
        carry.extend_from_slice(&ffu.read_disk(reader, start + done, n)?);
        if let Some(version) = scan_chunk(&carry, false)? {
            if result.as_ref().is_some_and(|old| old != &version) {
                return Err(invalid("Contradictory PLAT SWVERSION values"));
            }
            result = Some(version);
        }
        let keep = (MAX_VALUE + MARKER.len()).min(carry.len());
        carry = carry[carry.len() - keep..].to_vec();
        done += n as u64;
    }
    if let Some(version) = scan_chunk(&carry, true)? {
        if result.as_ref().is_some_and(|old| old != &version) {
            return Err(invalid("Contradictory PLAT SWVERSION values"));
        }
        result = Some(version);
    }
    if !progress(length, length) {
        return Err(ImageError::Cancelled);
    }
    Ok(result)
}
