//! Bounded primary/backup GPT consistency for already opened read-only sources.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wpi_core::backup::ReadOnlySource;
use wpi_image::{gpt::Gpt, ImageError, Result};
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageInspection {
    pub experimental: bool,
    pub hardware_validated: bool,
    pub device_identity_authenticated: bool,
    pub source_size: u64,
    pub sector_size: u32,
    pub gpt_sha256: String,
    pub gpt: Gpt,
}
fn bad(s: &str) -> ImageError {
    ImageError::Invalid(s.into())
}
fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn table<S: ReadOnlySource>(s: &mut S, h: &[u8]) -> Result<Vec<u8>> {
    let size = u64::from(u32at(h, 80))
        .checked_mul(u64::from(u32at(h, 84)))
        .filter(|n| *n > 0 && *n <= 1024 * 1024)
        .ok_or_else(|| bad("Storage GPT table exceeds 1 MiB"))?;
    let offset = u64at(h, 72)
        .checked_mul(512)
        .ok_or_else(|| bad("Storage GPT table offset overflow"))?;
    let length = size.div_ceil(512) * 512;
    if offset
        .checked_add(length)
        .is_none_or(|end| end > s.geometry().size)
    {
        return Err(bad("Storage GPT table exceeds disk"));
    }
    let mut bytes = vec![0; length as usize];
    s.read_at(offset, &mut bytes)?;
    bytes.truncate(size as usize);
    Ok(bytes)
}
pub fn inspect<S: ReadOnlySource>(s: &mut S) -> Result<StorageInspection> {
    let geometry = s.geometry();
    if geometry.sector_size != 512 || geometry.size < 68 * 512 || !geometry.size.is_multiple_of(512)
    {
        return Err(bad("Unsupported storage geometry"));
    }
    let last = geometry.size / 512 - 1;
    let mut primary = [0; 512];
    s.read_at(512, &mut primary)?;
    let entries = table(s, &primary)?;
    let gpt = Gpt::from_parts(&primary, &entries, Some(geometry.size))?;
    if gpt.current_lba != 1
        || gpt.backup_lba != last
        || u64at(&primary, 72) < 2
        || u64at(&primary, 72)
            .checked_add((entries.len() as u64).div_ceil(512))
            .is_none_or(|end| end > gpt.first_usable_sector)
    {
        return Err(bad("Unexpected primary GPT placement"));
    }
    let mut secondary = [0; 512];
    s.read_at(last * 512, &mut secondary)?;
    let other_entries = table(s, &secondary)?;
    let other = Gpt::from_parts(&secondary, &other_entries, Some(geometry.size))?;
    if other.current_lba != last
        || other.backup_lba != 1
        || u64at(&secondary, 72) <= gpt.last_usable_sector
        || u64at(&secondary, 72).checked_add((other_entries.len() as u64).div_ceil(512))
            != Some(last)
        || other.disk_guid != gpt.disk_guid
        || other.first_usable_sector != gpt.first_usable_sector
        || other.last_usable_sector != gpt.last_usable_sector
        || other.entry_count != gpt.entry_count
        || other.entry_size != gpt.entry_size
        || entries != other_entries
    {
        return Err(bad("Primary and backup GPT disagree"));
    }
    let mut names = std::collections::BTreeSet::new();
    for p in &gpt.partitions {
        if p.name.is_empty() || !names.insert(p.name.to_ascii_uppercase()) {
            return Err(bad("Empty or duplicate storage partition names"));
        }
    }
    for required in ["EFIESP", "MainOS", "Data"] {
        gpt.partition(required)?;
    }
    let mut hash = Sha256::new();
    hash.update(b"WPI read-only storage GPT v1\0");
    hash.update(geometry.size.to_le_bytes());
    hash.update(primary);
    hash.update(&entries);
    hash.update(secondary);
    hash.update(&other_entries);
    Ok(StorageInspection {
        experimental: true,
        hardware_validated: false,
        device_identity_authenticated: false,
        source_size: geometry.size,
        sector_size: 512,
        gpt_sha256: hex::encode(hash.finalize()),
        gpt,
    })
}
pub fn range(i: &StorageInspection, partition: Option<&str>) -> Result<(u64, u64)> {
    if let Some(name) = partition {
        let p = i.gpt.partition(name)?;
        Ok((p.first_sector, p.last_sector - p.first_sector + 1))
    } else {
        Ok((0, i.source_size / 512))
    }
}
