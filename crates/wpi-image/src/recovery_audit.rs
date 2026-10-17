//! Offline audit of the legacy Windows Phone INI FFU manifest and GPT templates.
//! No flash emulator, disk materialization, device query or execution authority.
use crate::{
    ffu::FfuMetadata, gpt::Gpt, invalid, read_at, spec_a::layout, stream, u64le, ImageError, Result,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
};

#[derive(Debug, Serialize)]
pub struct PartitionRule {
    pub name: String,
    pub total_sectors: Option<u64>,
    pub use_all_space: bool,
    pub required_to_flash: Option<bool>,
}
#[derive(Debug, Serialize)]
pub struct Manifest {
    pub sector_size: u64,
    pub minimum_sector_count: u64,
    pub partitions: Vec<PartitionRule>,
}
fn number(s: &str) -> Result<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("Expected a bounded decimal manifest value"));
    }
    s.parse().map_err(|_| invalid("Manifest integer overflow"))
}
fn boolean(s: &str) -> Result<bool> {
    if s.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if s.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(invalid("Invalid manifest boolean"))
    }
}
/// Narrow INI profile; the human-readable FullFlash preamble is not interpreted.
/// Duplicate sections/keys, unknown layout sections and ambiguous names fail.
/// Unused per-partition keys are retained only during parsing, never executed.
pub fn parse_manifest(text: &str) -> Result<Manifest> {
    if text.len() > 128 * 1024 || text.contains('\0') {
        return Err(invalid("Manifest exceeds profile limits"));
    }
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    let mut started = false;
    for line in text.split(['\r', '\n']) {
        if line.len() > 4096 {
            return Err(invalid("Manifest line exceeds limit"));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if line.starts_with('[') {
            let name = line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .ok_or_else(|| invalid("Malformed manifest section"))?
                .to_ascii_lowercase();
            if !started && name == "fullflash" {
                continue;
            }
            if name == "store" && !started {
                started = true;
            } else if !started || name != "partition" {
                return Err(invalid("Unsupported or repeated manifest layout section"));
            }
            if sections.len() >= 129 {
                return Err(invalid("Too many manifest partitions"));
            }
            sections.push((name, BTreeMap::new()));
        } else if started {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("Malformed layout property"))?;
            let key = key.trim().to_ascii_lowercase();
            let fields = &mut sections.last_mut().unwrap().1;
            if key.is_empty()
                || !key.is_ascii()
                || fields.len() >= 64
                || fields.insert(key, value.trim().into()).is_some()
            {
                return Err(invalid("Duplicate or unsupported manifest key"));
            }
        }
    }
    let store = sections
        .first()
        .filter(|(name, _)| name == "store")
        .ok_or_else(|| invalid("Missing manifest Store"))?;
    let required = |map: &BTreeMap<String, String>, key: &str| {
        map.get(key)
            .cloned()
            .ok_or_else(|| invalid(format!("Missing manifest {key}")))
    };
    let sector_size = number(&required(&store.1, "sectorsize")?)?;
    let minimum_sector_count = number(&required(&store.1, "minsectorcount")?)?;
    if sector_size != 512
        || minimum_sector_count < 68
        || minimum_sector_count.checked_mul(512).is_none()
    {
        return Err(invalid("Unsupported manifest disk geometry"));
    }
    let mut names = BTreeSet::new();
    let mut partitions = Vec::new();
    for (_, fields) in sections.iter().skip(1) {
        let name = required(fields, "name")?;
        if name.is_empty()
            || name.len() > 36
            || !name.is_ascii()
            || !names.insert(name.to_ascii_uppercase())
        {
            return Err(invalid("Invalid or duplicate manifest partition name"));
        }
        if fields
            .get("primary")
            .is_some_and(|s| !s.eq_ignore_ascii_case(&name))
        {
            return Err(invalid(
                "Partition Primary aliases are outside this audit profile",
            ));
        }
        let total_sectors = fields.get("totalsectors").map(|s| number(s)).transpose()?;
        let used = fields.get("usedsectors").map(|s| number(s)).transpose()?;
        let use_all_space = fields
            .get("useallspace")
            .map(|s| boolean(s))
            .transpose()?
            .unwrap_or(false);
        let required_to_flash = fields
            .get("requiredtoflash")
            .map(|s| boolean(s))
            .transpose()?;
        if total_sectors == Some(0)
            || (total_sectors.is_none() && !use_all_space)
            || used.zip(total_sectors).is_some_and(|(u, t)| u > t)
        {
            return Err(invalid("Invalid manifest partition size"));
        }
        partitions.push(PartitionRule {
            name,
            total_sectors,
            use_all_space,
            required_to_flash,
        });
    }
    if partitions.is_empty() || partitions.iter().filter(|p| p.use_all_space).count() > 1 {
        return Err(invalid("Unsupported empty or multiply expanding layout"));
    }
    Ok(Manifest {
        sector_size,
        minimum_sector_count,
        partitions,
    })
}
#[derive(Debug, Serialize)]
pub struct AttributeDifference {
    pub partition: String,
    pub primary_attributes: String,
    pub backup_attributes: String,
}
#[derive(Debug, Serialize)]
pub struct BackupTemplate {
    pub current_lba: u64,
    pub alternate_lba: u64,
    pub matches_source_primary_entries: bool,
    pub header_and_table_crc_valid: bool,
    pub attribute_differences: Vec<AttributeDifference>,
}
#[derive(Debug, Serialize)]
pub struct EndRelativePayload {
    pub disk_chunk_index: u64,
    pub chunk_count: u64,
    pub payload_chunk: u64,
    pub inspected_as_single_final_chunk: bool,
    pub all_zero: Option<bool>,
    pub backup_template: Option<BackupTemplate>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub kind: &'static str,
    pub source_ffu_sha256: String,
    pub saved_primary_sha256: String,
    pub platform: String,
    pub chunk_integrity_verified: bool,
    pub manifest: Manifest,
    pub recorded_capacity_sectors: u64,
    pub capacity_meets_manifest_minimum: bool,
    pub source_template_capacity_sectors: u64,
    pub template_capacity_equals_manifest_minimum: bool,
    pub expanding_partitions: Vec<String>,
    pub beginning_relative_mapping_count: usize,
    pub end_relative_payloads: Vec<EndRelativePayload>,
    pub partitions_with_changed_ranges: Vec<String>,
    pub device_layout_expansion_validated: bool,
    pub recovery_validated: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
    pub execution_blockers: Vec<String>,
}
fn pinned(actual: &str, expected: &str) -> bool {
    expected.len() == 64
        && expected.bytes().all(|b| b.is_ascii_hexdigit())
        && actual.eq_ignore_ascii_case(expected)
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn analyze<R: Read + Seek, F: FnMut(&str, u64, u64) -> bool>(
    source: &mut R,
    primary: &[u8],
    capacity: u64,
    expected_primary_sha256: &str,
    expected_ffu_sha256: &str,
    mut progress: F,
) -> Result<Report> {
    if primary.len() != layout::PRIMARY_SIZE
        || !pinned(&hash(primary), expected_primary_sha256)
        || capacity < 68
        || capacity.checked_mul(512).is_none()
        || u64le(primary, 544)? != capacity - 1
        || u64le(primary, 552)? < 34
        || u64le(primary, 560)?
            .checked_add(33)
            .is_none_or(|n| n > capacity - 1)
    {
        return Err(invalid(
            "Saved primary integrity or recorded capacity mismatch",
        ));
    }
    let live = layout::prepare(primary, false)?.original;
    let ffu = FfuMetadata::open(source)?;
    if ffu.total_size > 16 * 1024 * 1024 * 1024 {
        return Err(invalid("FFU exceeds audit limit"));
    }
    let manifest = parse_manifest(&ffu.manifest)?;
    let source_primary = ffu.read_disk(source, 0, layout::PRIMARY_SIZE)?;
    let original = ffu.gpt(source)?;
    if original.current_lba != 1
        || original.entry_count != 128
        || original.entry_size != 128
        || u64le(&source_primary, 584)? != 2
    {
        return Err(invalid("Unsupported source primary GPT geometry"));
    }
    if manifest.partitions.len() != original.partitions.len() {
        return Err(invalid("Manifest and GPT partition counts differ"));
    }
    for p in &manifest.partitions {
        let g = original.partition(&p.name)?;
        if p.total_sectors
            .is_some_and(|n| g.last_sector - g.first_sector + 1 != n)
        {
            return Err(invalid("Manifest partition size differs from GPT template"));
        }
    }
    let mut end_relative_payloads = Vec::new();
    let mut beginning_relative_mapping_count = 0;
    for m in &ffu.mappings {
        if m.disk_access == 0 {
            beginning_relative_mapping_count += 1;
            if m.disk_chunk
                .checked_add(m.chunk_count)
                .and_then(|n| n.checked_mul(ffu.chunk_size as u64))
                .is_none_or(|n| n > capacity * 512)
            {
                return Err(invalid(
                    "FFU beginning-relative mapping exceeds recorded capacity",
                ));
            }
        } else {
            if end_relative_payloads.len() >= 128 {
                return Err(invalid("Too many end-relative payloads"));
            }
            let inspect = m.disk_chunk == 0 && m.chunk_count == 1 && ffu.chunk_size >= 33 * 512;
            let mut entry = EndRelativePayload {
                disk_chunk_index: m.disk_chunk,
                chunk_count: m.chunk_count,
                payload_chunk: m.payload_chunk,
                inspected_as_single_final_chunk: inspect,
                all_zero: None,
                backup_template: None,
            };
            if inspect {
                let b = read_at(
                    source,
                    ffu.header_size + m.payload_chunk * ffu.chunk_size as u64,
                    ffu.chunk_size as usize,
                )?;
                entry.all_zero = Some(b.iter().all(|v| *v == 0));
                let h = &b[b.len() - 512..];
                if h.starts_with(b"EFI PART") {
                    if u64le(h, 72)?.checked_add(32) != Some(u64le(h, 24)?) {
                        return Err(invalid("Unsupported backup template table geometry"));
                    }
                    let table = &b[b.len() - 33 * 512..b.len() - 512];
                    let backup = Gpt::from_parts(h, table, None)?;
                    if backup.entry_count != 128
                        || backup.entry_size != 128
                        || backup.current_lba != original.backup_lba
                        || backup.backup_lba != original.current_lba
                        || backup.disk_guid != original.disk_guid
                        || backup.first_usable_sector != original.first_usable_sector
                        || backup.last_usable_sector != original.last_usable_sector
                    {
                        return Err(invalid("Backup template contradicts source primary"));
                    }
                    // A source FFU may carry different primary/backup attributes.
                    // Preserve that evidence; do not pretend the templates match or
                    // infer how FlashApp applies those bits. Other differences are
                    // outside this narrow audit profile and still fail closed.
                    for (a, b) in source_primary[1024..]
                        .chunks_exact(128)
                        .zip(table.chunks_exact(128))
                    {
                        if a[..48] != b[..48]
                            || a[56..] != b[56..]
                            || (a[..16].iter().all(|v| *v == 0) && a != b)
                        {
                            return Err(invalid(
                                "Backup template differs beyond partition attributes",
                            ));
                        }
                    }
                    let attribute_differences = original
                        .partitions
                        .iter()
                        .zip(&backup.partitions)
                        .filter(|(a, b)| a.attributes != b.attributes)
                        .map(|(a, b)| AttributeDifference {
                            partition: a.name.clone(),
                            primary_attributes: format!("0x{:016x}", a.attributes),
                            backup_attributes: format!("0x{:016x}", b.attributes),
                        })
                        .collect();
                    entry.backup_template = Some(BackupTemplate {
                        current_lba: backup.current_lba,
                        alternate_lba: backup.backup_lba,
                        matches_source_primary_entries: table == &source_primary[1024..],
                        header_and_table_crc_valid: true,
                        attribute_differences,
                    });
                }
            }
            end_relative_payloads.push(entry);
        }
    }
    let mut cancelled = false;
    ffu.verify_hashes(source, |d, t| {
        let keep = progress("Verify FFU chunks", d, t);
        cancelled |= !keep;
        keep
    })?;
    if cancelled {
        return Err(ImageError::Cancelled);
    }
    source.seek(SeekFrom::Start(0))?;
    let digest = stream::copy_hashed(source, &mut std::io::sink(), ffu.total_size, |d, t| {
        progress("Fingerprint FFU", d, t)
    })?;
    if !pinned(&digest, expected_ffu_sha256) {
        return Err(invalid("Selected FFU fingerprint mismatch"));
    }
    let expanding_partitions = manifest
        .partitions
        .iter()
        .filter(|p| p.use_all_space)
        .map(|p| p.name.clone())
        .collect();
    let partitions_with_changed_ranges = live
        .partitions
        .iter()
        .filter(|p| {
            original
                .partition(&p.name)
                .is_ok_and(|r| r.first_sector != p.first_sector || r.last_sector != p.last_sector)
        })
        .map(|p| p.name.clone())
        .collect();
    let template_capacity = original
        .backup_lba
        .checked_add(1)
        .ok_or_else(|| invalid("Template capacity overflow"))?;
    let capacity_meets_manifest_minimum = capacity >= manifest.minimum_sector_count;
    let template_capacity_equals_manifest_minimum =
        template_capacity == manifest.minimum_sector_count;
    let mut blockers = vec![
        "Recorded capacity meets only a manifest size constraint; runtime GPT/NTFS expansion and device acceptance remain unvalidated.".into(),
        "End-relative payloads are source-image instructions/templates, not a captured installed backup GPT; placement is not emulated.".into(),
        "A stock FFU recovery can replace the OS and user-data layout; personal-file preservation and recovery are separate.".into(),
        "Firmware downgrade/product applicability, OEM policy, native execution and interrupted-write recovery are unvalidated.".into(),
        "Emergency entry in pinned Spec A upstream writes GPT regions and uploads/runs a programmer; it is not a read-only backup route.".into(),
        "Installed boot/EFIESP originals and live backup GPT are missing. Determine feasible preservation or an independently validated alternative recovery strategy.".into(),
    ];
    if !capacity_meets_manifest_minimum {
        blockers.push("Recorded disk is below the FFU manifest minimum.".into());
    }
    if end_relative_payloads.iter().any(|p| {
        p.backup_template
            .as_ref()
            .is_some_and(|b| !b.attribute_differences.is_empty())
    }) {
        blockers.push("Source primary/backup templates have differing partition attributes; runtime interpretation is unvalidated, and no template is normalized or substituted.".into());
    }
    if !progress("Complete offline recovery audit", 1, 1) {
        return Err(ImageError::Cancelled);
    }
    Ok(Report {
        schema: 1,
        kind: "wpi-stock-recovery-file-audit",
        source_ffu_sha256: digest,
        saved_primary_sha256: hash(primary),
        platform: ffu.platform_id,
        chunk_integrity_verified: true,
        manifest,
        recorded_capacity_sectors: capacity,
        capacity_meets_manifest_minimum,
        source_template_capacity_sectors: template_capacity,
        template_capacity_equals_manifest_minimum,
        expanding_partitions,
        beginning_relative_mapping_count,
        end_relative_payloads,
        partitions_with_changed_ranges,
        device_layout_expansion_validated: false,
        recovery_validated: false,
        phone_contacted: false,
        phone_writes_enabled: false,
        execution_blockers: blockers,
    })
}
