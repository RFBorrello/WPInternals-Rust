//! Advisory local layout analysis only. No output sectors, restore commands,
//! device handles or execution authority. A saved GPT is historical evidence.
use super::{archive, layout, package::Manifest};
use crate::{gpt::Partition, invalid, read_at, u64le, Result};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    io::{Read, Seek},
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Range {
    pub first_sector: u64,
    pub last_sector: u64,
}

impl From<&Partition> for Range {
    fn from(p: &Partition) -> Self {
        Self {
            first_sector: p.first_sector,
            last_sector: p.last_sector,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Difference {
    pub partition: String,
    pub reference: Option<Range>,
    pub installed: Range,
    pub candidate: Range,
    pub reference_identity_matches: bool,
    pub reference_attributes_match: bool,
    pub candidate_identity_preserved: bool,
}
#[derive(Debug, Serialize)]
pub struct Payload {
    pub path: String,
    pub sha256: String,
    pub byte_length: u64,
    pub source_reference_start_sector: u64,
    pub candidate_start_sector: u64,
    pub candidate_capacity_bytes: u64,
    pub fits: bool,
    pub source_and_live_partition_identity_match: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub kind: &'static str,
    pub package_sha256: String,
    pub manifest_sha256: String,
    pub source_ffu_sha256: String,
    pub source_platform: String,
    pub saved_primary_sha256: String,
    pub candidate_primary_sha256: String,
    pub recorded_capacity_sectors: u64,
    pub reference_capacity_sectors: u64,
    pub partition_count: usize,
    pub disk_identity_matches_reference: bool,
    pub primary_matches_reference: bool,
    pub normalized_backup_pairs: Vec<String>,
    pub partitions: Vec<Difference>,
    pub payloads: Vec<Payload>,
    pub all_payloads_fit: bool,
    pub unaffected_partition_entries_preserved: bool,
    pub required_installed_partition_captures: Vec<String>,
    pub backup_gpt_captured: bool,
    pub installed_partitions_preserved: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
    pub execution_blockers: Vec<String>,
}
fn digest_matches(actual: &str, expected: &str) -> bool {
    expected.len() == 64
        && expected.bytes().all(|b| b.is_ascii_hexdigit())
        && actual.eq_ignore_ascii_case(expected)
}
pub(super) fn member<'a>(
    files: &'a [archive::FileRecord],
    path: &str,
) -> Result<&'a archive::FileRecord> {
    files
        .iter()
        .find(|f| f.path == path)
        .ok_or_else(|| invalid(format!("Missing package member {path}")))
}
pub(super) fn read_member<R: Read + Seek>(
    r: &mut R,
    f: &archive::FileRecord,
    max: u64,
) -> Result<Vec<u8>> {
    if f.size > max {
        return Err(invalid("Package metadata exceeds limit"));
    }
    let b = read_at(r, f.data_offset, f.size as usize)?;
    if super::hash(&b) != f.sha256 {
        return Err(invalid("Package changed after verification"));
    }
    Ok(b)
}
fn same<T: Serialize>(a: &T, b: &T) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}
fn placements(m: &Manifest, files: &[archive::FileRecord], prepared: bool) -> Result<()> {
    let mut names: Vec<String> = layout::BOOT.iter().map(|s| s.to_string()).collect();
    let (prefix, gpt, entries) = if prepared {
        names.push("HACK".into());
        ("prepared", &m.prepared_gpt, &m.prepared)
    } else {
        names.extend(
            m.normalized_backup_pairs
                .iter()
                .map(|n| format!("BACKUP_{n}")),
        );
        ("original", &m.source_gpt, &m.restore)
    };
    names.push("EFIESP".into());
    let mut expected: BTreeSet<_> = names.iter().map(|n| format!("{prefix}/{n}.img")).collect();
    let primary = format!("{prefix}/GPT-primary.bin");
    expected.insert(primary.clone());
    if entries.len() != expected.len() {
        return Err(invalid("Unexpected placement count"));
    }
    for p in entries {
        if !expected.remove(&p.path) {
            return Err(invalid("Unexpected or duplicate placement"));
        }
        let f = member(files, &p.path)?;
        if p.byte_length != f.size || f.size == 0 {
            return Err(invalid("Placement size mismatch"));
        }
        if p.path == primary {
            if p.reference_start_sector != 0 || p.byte_length != layout::PRIMARY_SIZE as u64 {
                return Err(invalid("Invalid primary placement"));
            }
        } else {
            let name = p
                .path
                .strip_prefix(&format!("{prefix}/"))
                .unwrap()
                .strip_suffix(".img")
                .unwrap();
            let target = gpt.partition(name)?;
            let capacity = target.byte_range()?.1;
            if p.reference_start_sector != target.first_sector
                || f.size > capacity
                || ((!prepared || matches!(name, "SBL1" | "HACK" | "EFIESP")) && f.size != capacity)
            {
                return Err(invalid("Placement contradicts source layout"));
            }
        }
    }
    Ok(())
}
/// Verify a saved primary against explicitly supplied historical capacity/digest,
/// verify a pinned package, then calculate a live-derived candidate IN MEMORY.
/// Digests provide integrity, not OEM authenticity or fresh device identity.
pub fn analyze<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    package: &mut R,
    primary: &[u8],
    recorded_capacity_sectors: u64,
    expected_primary_sha256: &str,
    expected_package_sha256: &str,
    progress: F,
) -> Result<Report> {
    Ok(verify(
        package,
        primary,
        recorded_capacity_sectors,
        expected_primary_sha256,
        expected_package_sha256,
        progress,
    )?
    .report)
}

pub(super) struct Verified {
    pub report: Report,
    pub files: Vec<archive::FileRecord>,
    pub candidate: layout::Layout,
}

pub(super) fn verify<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    package: &mut R,
    primary: &[u8],
    recorded_capacity_sectors: u64,
    expected_primary_sha256: &str,
    expected_package_sha256: &str,
    progress: F,
) -> Result<Verified> {
    if primary.len() != layout::PRIMARY_SIZE
        || !digest_matches(&super::hash(primary), expected_primary_sha256)
        || recorded_capacity_sectors < 68
        || recorded_capacity_sectors.checked_mul(512).is_none()
        || u64le(primary, 544)? != recorded_capacity_sectors - 1
        || u64le(primary, 552)? < 34
        || u64le(primary, 560)?
            .checked_add(33)
            .is_none_or(|n| n > recorded_capacity_sectors - 1)
    {
        return Err(invalid(
            "Saved primary digest or recorded disk geometry mismatch",
        ));
    }
    let (package_sha256, files) = archive::inspect(package, progress)?;
    if !digest_matches(&package_sha256, expected_package_sha256) {
        return Err(invalid("Package digest differs from selected reference"));
    }
    let manifest_file = member(&files, "manifest.json")?;
    let m: Manifest = serde_json::from_slice(&read_member(package, manifest_file, 1024 * 1024)?)
        .map_err(|e| invalid(format!("Invalid package manifest: {e}")))?;
    if m.schema != 1
        || m.kind != "wpi-spec-a-offline-reference"
        || m.upstream_revision != super::UPSTREAM
        || m.source_platform != "Nokia.MSM8960.P5217"
        || m.source_chunk_integrity != "passed"
        || m.phone_writes_enabled
        || m.originals_are_installed_backup
        || m.backup_gpt_captured
        || !digest_matches(&m.source_ffu_sha256, &m.source_ffu_sha256)
        || m.files.len() + 1 != files.len()
    {
        return Err(invalid("Unsupported reference package manifest or scope"));
    }
    for f in &m.files {
        if f.path == "manifest.json" || !same(f, member(&files, &f.path)?) {
            return Err(invalid(
                "Manifest file record differs from verified archive",
            ));
        }
    }
    let names: BTreeSet<_> = m.files.iter().map(|f| &f.path).collect();
    if names.len() != m.files.len() {
        return Err(invalid("Duplicate manifest file record"));
    }
    let original = read_member(
        package,
        member(&files, "original/GPT-primary.bin")?,
        layout::PRIMARY_SIZE as u64,
    )?;
    let reference = layout::prepare(&original, m.external_sbl3)?;
    let encoded = read_member(
        package,
        member(&files, "prepared/GPT-primary.bin")?,
        layout::PRIMARY_SIZE as u64,
    )?;
    if !same(&m.source_gpt, &reference.original)
        || !same(&m.prepared_gpt, &reference.prepared)
        || reference.bytes != encoded
        || m.normalized_backup_pairs != reference.swapped
    {
        return Err(invalid(
            "Reference GPT or normalization differs from manifest",
        ));
    }
    placements(&m, &files, false)?;
    placements(&m, &files, true)?;
    let candidate = layout::prepare(primary, m.external_sbl3)?;
    let live = &candidate.original;
    let unaffected_partition_entries_preserved = live
        .partitions
        .iter()
        .filter(|p| {
            !layout::BOOT.iter().any(|n| p.name.eq_ignore_ascii_case(n))
                && !candidate
                    .swapped
                    .iter()
                    .any(|n| p.name.eq_ignore_ascii_case(&format!("BACKUP_{n}")))
        })
        .all(|p| {
            candidate
                .prepared
                .partition(&p.name)
                .is_ok_and(|c| same(p, c))
        });
    if !unaffected_partition_entries_preserved
        || live.disk_guid != candidate.prepared.disk_guid
        || live.backup_lba != candidate.prepared.backup_lba
        || live.first_usable_sector != candidate.prepared.first_usable_sector
        || live.last_usable_sector != candidate.prepared.last_usable_sector
    {
        return Err(invalid(
            "Candidate unexpectedly changes unrelated partitions or disk geometry",
        ));
    }
    let partitions = live
        .partitions
        .iter()
        .map(|p| {
            let r = reference.original.partition(&p.name).ok();
            let c = candidate.prepared.partition(&p.name)?;
            Ok(Difference {
                partition: p.name.clone(),
                reference: r.map(Range::from),
                installed: p.into(),
                candidate: c.into(),
                reference_identity_matches: r
                    .is_some_and(|r| r.guid == p.guid && r.type_guid == p.type_guid),
                reference_attributes_match: r.is_some_and(|r| r.attributes == p.attributes),
                candidate_identity_preserved: p.guid == c.guid && p.type_guid == c.type_guid,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut payloads = Vec::new();
    for p in m
        .prepared
        .iter()
        .filter(|p| p.path != "prepared/GPT-primary.bin")
    {
        let name = p
            .path
            .strip_prefix("prepared/")
            .unwrap()
            .strip_suffix(".img")
            .unwrap();
        let c = candidate.prepared.partition(name)?;
        let r = reference.prepared.partition(name)?;
        let capacity = c.byte_range()?.1;
        payloads.push(Payload {
            path: p.path.clone(),
            sha256: member(&files, &p.path)?.sha256.clone(),
            byte_length: p.byte_length,
            source_reference_start_sector: p.reference_start_sector,
            candidate_start_sector: c.first_sector,
            candidate_capacity_bytes: capacity,
            fits: p.byte_length <= capacity,
            source_and_live_partition_identity_match: r.guid == c.guid
                && r.type_guid == c.type_guid,
        });
    }
    let all_payloads_fit = payloads.iter().all(|p| p.fits);
    let mut captures: BTreeSet<String> = layout::BOOT.iter().map(|s| s.to_string()).collect();
    captures.extend(candidate.swapped.iter().map(|n| format!("BACKUP_{n}")));
    captures.insert("EFIESP".into());
    let mut blockers = vec![
        "Advisory historical-file analysis only; no fresh device identity, capacity or security authority.".into(),
        "Candidate GPT is live-derived; the reference ZIP still contains its source GPT and must not be flashed as-is.".into(),
        "Installed boot/EFIESP originals and backup GPT have not been acquired; source FFU originals are not substitutes.".into(),
        "Locked-phone mass-storage backup access is unvalidated; a feasible capture or alternative recovery path requires research.".into(),
        "Firmware applicability/downgrade, patched boot chain, donor/BCD bindings, programmer and SBL3 acceptance remain unvalidated.".into(),
        "No reviewed unlock executor or validated recovery path; file integrity and payload fit do not authorize writes.".into(),
    ];
    if !all_payloads_fit {
        blockers.push(
            "At least one prepared payload exceeds the live-derived candidate partition.".into(),
        );
    }
    if payloads
        .iter()
        .any(|p| p.path == "prepared/SBL1.img" && p.byte_length != p.candidate_capacity_bytes)
    {
        blockers.push("SBL1 payload length differs from live-derived SBL1 geometry; rebuild and revalidate its HACK relationship.".into());
    }
    let report = Report {
        schema: 1,
        kind: "wpi-spec-a-live-layout-advisory",
        package_sha256,
        manifest_sha256: manifest_file.sha256.clone(),
        source_ffu_sha256: m.source_ffu_sha256,
        source_platform: m.source_platform,
        saved_primary_sha256: super::hash(primary),
        candidate_primary_sha256: super::hash(&candidate.bytes),
        recorded_capacity_sectors,
        reference_capacity_sectors: reference
            .original
            .backup_lba
            .checked_add(1)
            .ok_or_else(|| invalid("Reference capacity overflow"))?,
        partition_count: live.partitions.len(),
        disk_identity_matches_reference: live.disk_guid == reference.original.disk_guid,
        primary_matches_reference: primary == original,
        normalized_backup_pairs: candidate.swapped.clone(),
        partitions,
        payloads,
        all_payloads_fit,
        unaffected_partition_entries_preserved,
        required_installed_partition_captures: captures.into_iter().collect(),
        backup_gpt_captured: false,
        installed_partitions_preserved: false,
        phone_contacted: false,
        phone_writes_enabled: false,
        execution_blockers: blockers,
    };
    Ok(Verified {
        report,
        files,
        candidate,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{ffu::FfuMetadata, patch::PatchCatalog};
    use std::io::{Cursor, Write};
    pub(crate) fn fixture() -> (Vec<u8>, Vec<u8>) {
        let source = include_bytes!("../../../../tests/fixtures/synthetic-spec-a-package.ffu");
        let catalog = PatchCatalog::parse(&format!(r#"<PatchDefinitions><PatchDefinition Name="SecureBootHack-V1.1-EFIESP"><TargetVersions><TargetVersion Description="synthetic"><TargetFiles><TargetFile Path="{}" HashOriginal="{}" HashPatched="{}"><Patches><Patch Address="0x2" OriginalBytes="6364" PatchedBytes="5859" /></Patches><Obsolete /></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>"#,super::super::efiesp::PATH,crate::patch::sha1(b"abcdefgh"),crate::patch::sha1(b"abXYefgh"))).unwrap();
        let mut input = Cursor::new(source);
        let ffu = FfuMetadata::open(&mut input).unwrap();
        let mut primary = ffu.read_disk(&mut input, 0, layout::PRIMARY_SIZE).unwrap();
        let mut out = Cursor::new(Vec::new());
        super::super::package::build_with_catalog(
            &mut input,
            None,
            &[],
            b"abcdefgh",
            &mut Cursor::new(Vec::new()),
            &mut out,
            |_, _, _| true,
            &catalog,
        )
        .unwrap();
        // A different installed disk, extra capacity, shifted EFIESP and an active
        // TZ slot above its backup. All GUIDs here are invented fixture values.
        primary[544..552].copy_from_slice(&0x8000u64.to_le_bytes());
        primary[560..568].copy_from_slice(&0x7fdfu64.to_le_bytes());
        primary[568..584].fill(0x99);
        let tz = 1024 + 4 * 128;
        let mut backup = primary[tz..tz + 128].to_vec();
        backup[16..32].fill(0x88);
        backup[56..128].fill(0);
        for (i, c) in "BACKUP_TZ".encode_utf16().enumerate() {
            backup[56 + i * 2..58 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        primary[1024 + 8 * 128..1024 + 9 * 128].copy_from_slice(&backup);
        primary[tz + 32..tz + 40].copy_from_slice(&0x3000u64.to_le_bytes());
        primary[tz + 40..tz + 48].copy_from_slice(&0x300fu64.to_le_bytes());
        let esp = 1024 + 7 * 128;
        primary[esp + 32..esp + 40].copy_from_slice(&0x4000u64.to_le_bytes());
        primary[esp + 40..esp + 48].copy_from_slice(&0x5fffu64.to_le_bytes());
        primary[esp + 16..esp + 32].fill(0x77);
        fix_crc(&mut primary);
        // Exercise the narrow RM-875 package scope using invented payloads.
        // This metadata is a fixture claim, not firmware applicability evidence.
        (
            mutate_manifest(&out.into_inner(), |m| {
                m.source_platform = "Nokia.MSM8960.P5217".into()
            }),
            primary,
        )
    }
    fn fix_crc(p: &mut [u8]) {
        let table = crc32fast::hash(&p[1024..]);
        p[600..604].copy_from_slice(&table.to_le_bytes());
        p[528..532].fill(0);
        let header = crc32fast::hash(&p[512..604]);
        p[528..532].copy_from_slice(&header.to_le_bytes());
    }
    fn check(zip: &[u8], primary: &[u8]) -> Result<Report> {
        analyze(
            &mut Cursor::new(zip),
            primary,
            0x8001,
            &super::super::hash(primary),
            &super::super::hash(zip),
            |_, _| true,
        )
    }
    #[test]
    fn live_geometry_slot_normalization_payload_offsets_and_privacy_are_independent_of_reference() {
        let (zip, primary) = fixture();
        let original = primary.clone();
        let r = check(&zip, &primary).unwrap();
        assert_eq!(primary, original);
        assert_eq!(r.recorded_capacity_sectors, 0x8001);
        assert_eq!(r.normalized_backup_pairs, ["TZ"]);
        assert!(r.all_payloads_fit && r.unaffected_partition_entries_preserved);
        assert!(
            !r.phone_contacted
                && !r.phone_writes_enabled
                && !r.installed_partitions_preserved
                && !r.backup_gpt_captured
        );
        assert!(!r.primary_matches_reference && !r.disk_identity_matches_reference);
        let tz = r.partitions.iter().find(|p| p.partition == "TZ").unwrap();
        assert_eq!(
            (tz.installed.first_sector, tz.candidate.first_sector),
            (0x3000, 0x1a0)
        );
        assert!(tz.candidate_identity_preserved);
        let esp = r
            .payloads
            .iter()
            .find(|p| p.path == "prepared/EFIESP.img")
            .unwrap();
        assert_eq!(
            (
                esp.source_reference_start_sector,
                esp.candidate_start_sector
            ),
            (0x200, 0x4000)
        );
        assert!(!esp.source_and_live_partition_identity_match);
        assert!(r
            .required_installed_partition_captures
            .contains(&"BACKUP_TZ".to_string()));
        let json = serde_json::to_string(&r).unwrap();
        for id in [
            "99999999-9999-9999-9999-999999999999",
            "77777777-7777-7777-7777-777777777777",
        ] {
            assert!(!json.contains(id));
        }
        assert_eq!(
            r.candidate_primary_sha256,
            super::super::hash(&layout::prepare(&primary, false).unwrap().bytes)
        );
    }
    #[test]
    fn oversize_payload_is_reported_without_a_write_grant() {
        let (zip, mut primary) = fixture();
        // Shrink normalized TZ capacity from 16 sectors to one.
        let backup = 1024 + 8 * 128;
        primary[backup + 40..backup + 48].copy_from_slice(&0x1a0u64.to_le_bytes());
        fix_crc(&mut primary);
        let r = check(&zip, &primary).unwrap();
        assert!(!r.all_payloads_fit && !r.phone_writes_enabled);
        let p = r
            .payloads
            .iter()
            .find(|p| p.path == "prepared/TZ.img")
            .unwrap();
        assert_eq!(p.candidate_capacity_bytes, 512);
        assert!(!p.fits);
        assert!(r.execution_blockers.iter().any(|s| s.contains("exceeds")));
    }
    #[test]
    fn malformed_historical_primary_digest_capacity_duplicates_and_prior_modification_fail() {
        let (zip, primary) = fixture();
        for n in [0, 512, primary.len() - 1] {
            assert!(check(&zip, &primary[..n]).is_err());
        }
        let mut large = primary.clone();
        large.push(0);
        assert!(check(&zip, &large).is_err());
        for at in [528, 600, 1024] {
            let mut p = primary.clone();
            p[at] ^= 1;
            assert!(check(&zip, &p).is_err());
        }
        let mut duplicate = primary.clone();
        let id = duplicate[1040..1056].to_vec();
        duplicate[1168..1184].copy_from_slice(&id);
        fix_crc(&mut duplicate);
        assert!(check(&zip, &duplicate).is_err());
        let mut modified = primary.clone();
        modified[1080..1152].fill(0);
        for (i, c) in "HACK".encode_utf16().enumerate() {
            modified[1080 + i * 2..1082 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        fix_crc(&mut modified);
        assert!(check(&zip, &modified).is_err());
        for capacity in [0, 34, 0x8000, u64::MAX] {
            assert!(analyze(
                &mut Cursor::new(&zip),
                &primary,
                capacity,
                &super::super::hash(&primary),
                &super::super::hash(&zip),
                |_, _| true
            )
            .is_err());
        }
        assert!(analyze(
            &mut Cursor::new(&zip),
            &primary,
            0x8001,
            &"0".repeat(64),
            &super::super::hash(&zip),
            |_, _| true
        )
        .is_err());
        assert!(analyze(
            &mut Cursor::new(&zip),
            &primary,
            0x8001,
            &super::super::hash(&primary),
            &"0".repeat(64),
            |_, _| true
        )
        .is_err());
        assert!(matches!(
            analyze(
                &mut Cursor::new(&zip),
                &primary,
                0x8001,
                &super::super::hash(&primary),
                &super::super::hash(&zip),
                |_, _| false
            ),
            Err(crate::ImageError::Cancelled)
        ));
    }
    // Rebuild a structurally valid ZIP with consistent CRCs/hashes. This tests
    // semantic manifest checks, rather than stopping on the outer ZIP CRC.
    fn mutate_manifest(zip: &[u8], mutate: impl FnOnce(&mut Manifest)) -> Vec<u8> {
        let (_, files) = archive::inspect(&mut Cursor::new(zip), |_, _| true).unwrap();
        let f = member(&files, "manifest.json").unwrap();
        let mut m: Manifest =
            serde_json::from_slice(&zip[f.data_offset as usize..(f.data_offset + f.size) as usize])
                .unwrap();
        let mut out = Cursor::new(Vec::new());
        let mut a = archive::Archive::new(&mut out);
        for f in files.iter().filter(|f| f.path != "manifest.json") {
            a.add(&f.path, f.size, |e| {
                e.write_all(&zip[f.data_offset as usize..(f.data_offset + f.size) as usize])?;
                Ok(())
            })
            .unwrap();
        }
        m.files = a.files();
        mutate(&mut m);
        a.bytes("manifest.json", &serde_json::to_vec_pretty(&m).unwrap())
            .unwrap();
        a.finish().unwrap();
        out.into_inner()
    }
    #[test]
    fn internally_consistent_but_false_manifests_cannot_substitute_layout_or_enable_writes() {
        let (zip, primary) = fixture();
        let mutations: [fn(&mut Manifest); 9] = [
            |m| m.phone_writes_enabled = true,
            |m| m.originals_are_installed_backup = true,
            |m| m.backup_gpt_captured = true,
            |m| m.prepared[1].reference_start_sector += 1,
            |m| m.restore[1].byte_length += 1,
            |m| m.prepared_gpt.backup_lba += 1,
            |m| m.source_platform = "unreviewed".into(),
            |m| m.files[0].sha256 = "0".repeat(64),
            |m| m.files[1] = m.files[0].clone(),
        ];
        for mutate in mutations {
            assert!(check(&mutate_manifest(&zip, mutate), &primary).is_err());
        }
    }
}
