//! In-memory Spec A programmer-phase composition for REPLAY ONLY. No native
//! execution authority. WPInternals 2.9.2 LumiaUnlockBootloaderViewModel.cs,
//! pinned by super::UPSTREAM; Copyright (c) 2018 Rene Lergner, MIT.
use super::{layout, live_plan, MAX_BOOT_IMAGE};
use crate::{invalid, ImageError, Result};
use serde::Serialize;
use std::io::{Read, Seek};

pub const WINSECAPP_END: u64 = 0x1e7fe00;
pub const GPT_TRANSFER_BYTES: usize = 0x41ff;

/// Immutable region built from verified local files. Not deserializable and not
/// a native write grant. Borrowed bytes exist solely for a concrete replay caller.
pub struct Region {
    start_bytes: u32,
    bytes: Vec<u8>,
}
impl Region {
    pub fn start_bytes(&self) -> u32 {
        self.start_bytes
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Serialize)]
pub struct Transfer {
    pub target: String,
    pub source_path: String,
    pub start_bytes: u32,
    pub byte_length: u64,
    pub sha256: String,
    pub omitted_tail_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub kind: &'static str,
    pub layout: live_plan::Report,
    pub transfers: Vec<Transfer>,
    pub total_transfer_bytes: u64,
    pub unrelated_partition_write_ranges_excluded: bool,
    pub data_preservation_validated: bool,
    pub replay_only: bool,
    pub phone_contacted: bool,
    pub phone_writes_enabled: bool,
}

/// No serialization/import route exists for this object. Its report is advisory
/// historical evidence and cannot recreate or authorize a native execution plan.
pub struct Plan {
    regions: Vec<Region>,
    report: Report,
    source_sbl1_sha256: String,
    original_primary: Vec<u8>,
    candidate_primary: Vec<u8>,
}
impl Plan {
    pub fn original_primary(&self) -> &[u8] {
        &self.original_primary
    }
    pub fn candidate_primary(&self) -> &[u8] {
        &self.candidate_primary
    }
    pub fn source_sbl1_sha256(&self) -> &str {
        &self.source_sbl1_sha256
    }
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
}

fn boundary<F: FnMut(&str, u64, u64) -> bool>(
    progress: &mut F,
    stage: &str,
    done: u64,
    total: u64,
) -> Result<()> {
    if progress(stage, done, total) {
        Ok(())
    } else {
        Err(ImageError::Cancelled)
    }
}

/// Build the ten targeted programmer transfers in memory. It deliberately does
/// not include emergency entry, programmer upload, EFIESP or later UEFI stages.
pub fn build<R: Read + Seek, F: FnMut(&str, u64, u64) -> bool>(
    package: &mut R,
    primary: &[u8],
    recorded_capacity_sectors: u64,
    expected_primary_sha256: &str,
    expected_package_sha256: &str,
    mut progress: F,
) -> Result<Plan> {
    boundary(&mut progress, "Verify package and saved layout", 0, 0)?;
    let verified = live_plan::verify(
        package,
        primary,
        recorded_capacity_sectors,
        expected_primary_sha256,
        expected_package_sha256,
        |d, t| progress("Verify package and saved layout", d, t),
    )?;
    if !verified.report.all_payloads_fit {
        return Err(invalid("Payload does not fit the live-derived candidate"));
    }
    let candidate = &verified.candidate;
    let mut load = |path: &str| {
        live_plan::read_member(
            package,
            live_plan::member(&verified.files, path)?,
            MAX_BOOT_IMAGE as u64,
        )
    };
    boundary(&mut progress, "Check SBL1 and HACK relationship", 0, 0)?;
    let first = load("original/SBL1.img")?;
    let prepared_first = load("prepared/SBL1.img")?;
    let second = load("prepared/SBL2.img")?;
    let hack = load("prepared/HACK.img")?;
    let first_capacity = candidate.prepared.partition("SBL1")?.byte_range()?.1;
    // The upstream programmer phase removes one further sector after InsertHack
    // has shortened SBL1. Reproduce it explicitly; never truncate signed bytes.
    let first_transfer = first_capacity
        .checked_sub(512)
        .filter(|n| *n > 0)
        .ok_or_else(|| invalid("SBL1 cannot spare the programmer tail sector"))?;
    let image = super::parse(&first, 0x2800)?;
    if first.len() as u64 != first_capacity + 512
        || prepared_first.len() as u64 != first_capacity
        || first[..prepared_first.len()] != prepared_first
        || (image.image_offset + image.image_size) as u64 > first_transfer
        || hack != super::sbl1::generate(&first, &second)?
    {
        return Err(invalid("SBL1 geometry, signed-image extent or HACK relationship differs from the selected package"));
    }
    let last = layout::PRIMARY_SIZE - 1;
    if primary[last] != candidate.bytes[last] {
        return Err(invalid(
            "Omitted final GPT byte would differ from the saved installed byte",
        ));
    }
    let mut regions = Vec::new();
    let mut transfers = Vec::new();
    for (index, target) in [
        "HACK",
        "MBR",
        "GPT",
        "SBL2",
        "SBL3",
        "UEFI",
        "SBL1",
        "TZ",
        "RPM",
        "WINSECAPP",
    ]
    .iter()
    .enumerate()
    {
        boundary(
            &mut progress,
            "Compose programmer transfers",
            index as u64,
            10,
        )?;
        let (path, start, mut bytes, omitted) = match *target {
            "MBR" => ("saved-primary/MBR".into(), 0, primary[..512].to_vec(), 0),
            "GPT" => (
                "live-derived/GPT-primary".into(),
                512,
                candidate.bytes[512..512 + GPT_TRANSFER_BYTES].to_vec(),
                1,
            ),
            name => {
                let path = format!("prepared/{name}.img");
                let bytes = load(&path)?;
                let (start, capacity) = candidate.prepared.partition(name)?.byte_range()?;
                if bytes.len() as u64 > capacity {
                    return Err(invalid("Transfer exceeds candidate partition"));
                }
                let length = match name {
                    "SBL1" => first_transfer,
                    "WINSECAPP" => {
                        (bytes.len() as u64).min(WINSECAPP_END.checked_sub(start).ok_or_else(
                            || invalid("WINSECAPP starts beyond the V1 loader bound"),
                        )?)
                    }
                    _ => bytes.len() as u64,
                };
                if length == 0 || length > bytes.len() as u64 {
                    return Err(invalid("Invalid programmer transfer length"));
                }
                let omitted = bytes.len() as u64 - length;
                (path, start, bytes[..length as usize].to_vec(), omitted)
            }
        };
        let end = start
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("Transfer overflow"))?;
        if bytes.is_empty() || end > u64::from(u32::MAX) + 1 {
            return Err(invalid("Transfer exceeds V1 byte-address space"));
        }
        // Permit writes only in boot slots (including normalized backup slots),
        // never in other installed or candidate partition ranges.
        for gpt in [&candidate.original, &candidate.prepared] {
            for p in &gpt.partitions {
                let name = p.name.to_ascii_uppercase();
                if layout::BOOT.contains(&name.as_str())
                    || name == "HACK"
                    || name
                        .strip_prefix("BACKUP_")
                        .is_some_and(|n| layout::BOOT.contains(&n))
                {
                    continue;
                }
                let (p_start, p_length) = p.byte_range()?;
                if start < p_start + p_length && p_start < end {
                    return Err(invalid(format!(
                        "Transfer overlaps unrelated partition {}",
                        p.name
                    )));
                }
            }
        }
        if regions.iter().any(|r: &Region| {
            start < u64::from(r.start_bytes) + r.bytes.len() as u64
                && u64::from(r.start_bytes) < end
        }) {
            return Err(invalid("Composed transfers overlap"));
        }
        transfers.push(Transfer {
            target: (*target).into(),
            source_path: path,
            start_bytes: start as u32,
            byte_length: bytes.len() as u64,
            sha256: super::hash(&bytes),
            omitted_tail_bytes: omitted,
        });
        regions.push(Region {
            start_bytes: start as u32,
            bytes: std::mem::take(&mut bytes),
        });
    }
    boundary(&mut progress, "Compose programmer transfers", 10, 10)?;
    let total_transfer_bytes = transfers.iter().map(|t| t.byte_length).sum();
    Ok(Plan {
        regions,
        original_primary: primary.to_vec(),
        candidate_primary: verified.candidate.bytes.clone(),
        source_sbl1_sha256: super::hash(&first),
        report: Report {
            schema: 1,
            kind: "wpi-spec-a-programmer-replay-plan",
            layout: verified.report,
            transfers,
            total_transfer_bytes,
            unrelated_partition_write_ranges_excluded: true,
            data_preservation_validated: false,
            replay_only: true,
            phone_contacted: false,
            phone_writes_enabled: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_a::{archive, package::Manifest};
    use std::io::{Cursor, Write};

    fn fix_crc(primary: &mut [u8]) {
        let table_crc = crc32fast::hash(&primary[1024..]);
        primary[600..604].copy_from_slice(&table_crc.to_le_bytes());
        primary[528..532].fill(0);
        let header_crc = crc32fast::hash(&primary[512..604]);
        primary[528..532].copy_from_slice(&header_crc.to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let (zip, mut primary) = live_plan::tests::fixture();
        primary[440] = 0xa5; // Installed MBR bytes deliberately differ from the FFU.
        for (index, name, first, last) in [
            (9, "MainOS", 0x6000u64, 0x6fffu64),
            (10, "Data", 0x7000, 0x7fdf),
        ] {
            let entry = &mut primary[1024 + index * 128..1024 + (index + 1) * 128];
            entry.fill(0);
            entry[..16].fill(0x30 + index as u8);
            entry[16..32].fill(0x50 + index as u8);
            entry[32..40].copy_from_slice(&first.to_le_bytes());
            entry[40..48].copy_from_slice(&last.to_le_bytes());
            for (i, c) in name.encode_utf16().enumerate() {
                entry[56 + i * 2..58 + i * 2].copy_from_slice(&c.to_le_bytes());
            }
        }
        fix_crc(&mut primary);
        (zip, primary)
    }
    fn plan(zip: &[u8], primary: &[u8]) -> Result<Plan> {
        build(
            &mut Cursor::new(zip),
            primary,
            crate::u64le(primary, 544)? + 1,
            &super::super::hash(primary),
            &super::super::hash(zip),
            |_, _, _| true,
        )
    }
    #[test]
    fn live_derived_transfers_follow_upstream_lengths_and_exclude_installed_os_data_and_efiesp() {
        let (zip, primary) = fixture();
        let before = primary.clone();
        let plan = plan(&zip, &primary).unwrap();
        let mut source = Cursor::new(include_bytes!(
            "../../../../tests/fixtures/synthetic-spec-a-package.ffu"
        ));
        let ffu = crate::ffu::FfuMetadata::open(&mut source).unwrap();
        let gpt = ffu.gpt(&mut source).unwrap();
        let sbl1 = gpt
            .partitions
            .iter()
            .find(|p| p.name == "SBL1")
            .unwrap()
            .byte_range()
            .unwrap();
        let original = ffu.read_disk(&mut source, sbl1.0, sbl1.1 as usize).unwrap();
        assert_eq!(plan.source_sbl1_sha256(), super::super::hash(&original));
        assert_eq!(primary, before);
        let report = plan.report();
        let targets: Vec<_> = report.transfers.iter().map(|t| t.target.as_str()).collect();
        assert_eq!(
            targets,
            [
                "HACK",
                "MBR",
                "GPT",
                "SBL2",
                "SBL3",
                "UEFI",
                "SBL1",
                "TZ",
                "RPM",
                "WINSECAPP"
            ]
        );
        let candidate = layout::prepare(&primary, false).unwrap();
        assert_eq!(plan.regions()[1].bytes(), &primary[..512]);
        assert_eq!(plan.regions()[2].bytes(), &candidate.bytes[512..17407]);
        assert_eq!(report.transfers[2].byte_length, 0x41ff);
        assert_eq!(report.transfers[2].omitted_tail_bytes, 1);
        assert_eq!(
            report.transfers[6].byte_length,
            candidate
                .prepared
                .partition("SBL1")
                .unwrap()
                .byte_range()
                .unwrap()
                .1
                - 512
        );
        assert_eq!(report.transfers[6].omitted_tail_bytes, 512);
        let tz = report.transfers.iter().find(|r| r.target == "TZ").unwrap();
        assert_eq!(u64::from(tz.start_bytes), 0x1a0 * 512);
        assert_ne!(
            u64::from(tz.start_bytes),
            candidate.original.partition("TZ").unwrap().first_sector * 512
        );
        for (r, t) in plan.regions().iter().zip(&report.transfers) {
            assert_eq!(r.start_bytes(), t.start_bytes);
            assert_eq!(r.bytes().len() as u64, t.byte_length);
            assert_eq!(super::super::hash(r.bytes()), t.sha256);
            for name in ["MainOS", "Data", "EFIESP"] {
                let original = candidate.original.partition(name).unwrap();
                let prepared = candidate.prepared.partition(name).unwrap();
                assert_eq!(
                    serde_json::to_value(original).unwrap(),
                    serde_json::to_value(prepared).unwrap()
                );
                let (start, length) = original.byte_range().unwrap();
                assert!(
                    u64::from(t.start_bytes) + t.byte_length <= start
                        || u64::from(t.start_bytes) >= start + length
                );
            }
        }
        assert!(report.replay_only && report.unrelated_partition_write_ranges_excluded);
        assert!(
            !report.phone_contacted
                && !report.phone_writes_enabled
                && !report.data_preservation_validated
        );
        let json = serde_json::to_string(report).unwrap();
        assert!(!json.contains("99999999-9999-9999-9999-999999999999"));
    }
    #[test]
    fn winsecapp_tail_workaround_is_explicit_and_never_extends_past_loader_bound() {
        let (zip, mut primary) = fixture();
        primary[544..552].copy_from_slice(&0x10000u64.to_le_bytes());
        primary[560..568].copy_from_slice(&0xffdfu64.to_le_bytes());
        let at = 1024 + 6 * 128;
        primary[at + 32..at + 40].copy_from_slice(&0xf3f0u64.to_le_bytes());
        primary[at + 40..at + 48].copy_from_slice(&0xf3ffu64.to_le_bytes());
        fix_crc(&mut primary);
        let plan = plan(&zip, &primary).unwrap();
        let transfer = plan.report().transfers.last().unwrap();
        assert_eq!(
            u64::from(transfer.start_bytes) + transfer.byte_length,
            WINSECAPP_END
        );
        assert_eq!(transfer.omitted_tail_bytes, 512);
    }
    #[test]
    fn changed_sbl1_geometry_is_rejected_even_when_reference_payload_fits() {
        let (zip, mut primary) = fixture();
        primary[1056..1064].copy_from_slice(&0x2100u64.to_le_bytes());
        primary[1064..1072].copy_from_slice(&0x214fu64.to_le_bytes());
        fix_crc(&mut primary);
        assert!(plan(&zip, &primary).is_err());
    }
    fn changed_member(zip: &[u8], path: &str) -> Vec<u8> {
        let (_, files) = archive::inspect(&mut Cursor::new(zip), |_, _| true).unwrap();
        let m = live_plan::member(&files, "manifest.json").unwrap();
        let mut manifest: Manifest =
            serde_json::from_slice(&zip[m.data_offset as usize..(m.data_offset + m.size) as usize])
                .unwrap();
        let mut output = Cursor::new(Vec::new());
        let mut archive = archive::Archive::new(&mut output);
        for f in files.iter().filter(|f| f.path != "manifest.json") {
            let mut bytes = zip[f.data_offset as usize..(f.data_offset + f.size) as usize].to_vec();
            if f.path == path {
                bytes[0] ^= 1;
            }
            archive
                .add(&f.path, f.size, |w| {
                    w.write_all(&bytes)?;
                    Ok(())
                })
                .unwrap();
        }
        manifest.files = archive.files();
        archive
            .bytes("manifest.json", &serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        archive.finish().unwrap();
        output.into_inner()
    }
    #[test]
    fn internally_consistent_hashes_cannot_hide_a_changed_hack_or_sbl1_prefix() {
        let (zip, primary) = fixture();
        for path in ["prepared/HACK.img", "prepared/SBL1.img"] {
            assert!(plan(&changed_member(&zip, path), &primary).is_err());
        }
    }
    #[test]
    fn cancellation_at_every_composition_boundary_returns_no_plan() {
        let (zip, primary) = fixture();
        for stop in 0..=10 {
            let result = build(
                &mut Cursor::new(&zip),
                &primary,
                0x8001,
                &super::super::hash(&primary),
                &super::super::hash(&zip),
                |stage, done, _| stage != "Compose programmer transfers" || done != stop,
            );
            assert!(matches!(result, Err(ImageError::Cancelled)));
        }
    }

    #[test]
    fn package_mutation_after_archive_verification_is_detected_before_plan_publication() {
        use std::{
            cell::RefCell,
            io::{Read, Seek, SeekFrom},
            rc::Rc,
        };
        struct Shared(Rc<RefCell<Cursor<Vec<u8>>>>);
        impl Read for Shared {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().read(b)
            }
        }
        impl Seek for Shared {
            fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
                self.0.borrow_mut().seek(p)
            }
        }
        let (zip, primary) = fixture();
        let expected_zip = super::super::hash(&zip);
        let (_, files) = archive::inspect(&mut Cursor::new(&zip), |_, _| true).unwrap();
        let offset = live_plan::member(&files, "prepared/SBL3.img")
            .unwrap()
            .data_offset as usize;
        let shared = Rc::new(RefCell::new(Cursor::new(zip)));
        let mut changed = false;
        let result = build(
            &mut Shared(shared.clone()),
            &primary,
            0x8001,
            &super::super::hash(&primary),
            &expected_zip,
            |stage, done, _| {
                if stage == "Compose programmer transfers" && done == 0 {
                    shared.borrow_mut().get_mut()[offset] ^= 1;
                    changed = true;
                }
                true
            },
        );
        assert!(changed);
        assert!(
            matches!(result, Err(ImageError::Invalid(message)) if message.contains("changed after verification"))
        );
    }
}
