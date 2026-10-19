//! Offline GPT recovery material. Reconstructed backup metadata is explicitly
//! distinguished from captured original bytes. No storage writer or grant.
use super::{archive::Archive, layout};
use crate::{gpt::Gpt, invalid, u64le, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct Region {
    pub path: &'static str,
    pub start_sector: u64,
    pub sector_count: u64,
    pub sha256: String,
    pub captured_original: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub kind: &'static str,
    pub recorded_capacity_sectors: u64,
    pub regions: Vec<Region>,
    pub primary_sha256_matches_pin: bool,
    pub reconstructed_secondary_crc_valid: bool,
    pub primary_secondary_entries_identical: bool,
    pub original_secondary_captured: bool,
    pub original_front_padding_captured: bool,
    pub installed_boot_partitions_captured: bool,
    pub identity_authenticated: bool,
    pub phone_contacted: bool,
    pub data_preservation_validated: bool,
    pub phone_writes_enabled: bool,
    pub automatic_resume_allowed: bool,
    pub limitations: Vec<&'static str>,
}
/// Only this constructor can create a capsule; imported reports are not trusted.
pub struct Capsule {
    primary: Vec<u8>,
    secondary: Vec<u8>,
    report: Report,
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
/// Construct a reciprocal secondary from a CRC-checked primary. This accepts
/// transformed layouts (including the sector-64 unlock marker), but never a
/// partition in either GPT table. These are derived bytes, not a disk capture.
pub fn secondary_from_primary(primary: &[u8], capacity: u64) -> Result<Vec<u8>> {
    let gpt = layout::parse(primary)?;
    if !(512..=u64::from(u32::MAX)).contains(&capacity)
        || gpt.backup_lba != capacity - 1
        || gpt.first_usable_sector < 34
        || gpt.last_usable_sector >= capacity - 33
        || gpt
            .partitions
            .iter()
            .any(|p| p.first_sector < 34 || p.last_sector >= capacity - 33)
    {
        return Err(invalid("Unsupported reciprocal GPT geometry"));
    }
    Gpt::from_parts(&primary[512..1024], &primary[1024..], Some(capacity * 512))?;
    let mut secondary = primary[1024..].to_vec();
    let mut header = primary[512..1024].to_vec();
    header[24..32].copy_from_slice(&(capacity - 1).to_le_bytes());
    header[32..40].copy_from_slice(&1u64.to_le_bytes());
    header[72..80].copy_from_slice(&(capacity - 33).to_le_bytes());
    header[16..20].fill(0);
    let crc = crc32fast::hash(&header[..92]);
    header[16..20].copy_from_slice(&crc.to_le_bytes());
    let backup = Gpt::from_parts(&header, &secondary, Some(capacity * 512))?;
    if backup.disk_guid != gpt.disk_guid
        || backup.current_lba != capacity - 1
        || backup.backup_lba != 1
        || u64le(&header, 72)? != capacity - 33
    {
        return Err(invalid("Reconstructed GPT geometry differs"));
    }
    secondary.extend_from_slice(&header);
    Ok(secondary)
}
impl Capsule {
    pub fn build(primary: &[u8], capacity: u64, expected_sha256: &str) -> Result<Self> {
        if expected_sha256.len() != 64
            || !expected_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || !sha(primary).eq_ignore_ascii_case(expected_sha256)
        {
            return Err(invalid("Saved primary GPT digest differs from its pin"));
        }
        let gpt = layout::parse(primary)?;
        if !(512..=u64::from(u32::MAX)).contains(&capacity)
            || gpt.backup_lba != capacity - 1
            || gpt.first_usable_sector < 34
            || gpt.last_usable_sector >= capacity - 33
            || gpt
                .partitions
                .iter()
                .any(|p| p.first_sector < 256 || p.last_sector >= capacity - 33)
        {
            return Err(invalid(
                "Unsupported entry-recovery geometry or partition intersects metadata footprint",
            ));
        }
        // A saved primary is historical evidence, not fresh device identification.
        let secondary = secondary_from_primary(primary, capacity)?;
        let report = Report {
            schema: 1, kind: "spec_a_entry_gpt_recovery_capsule",
            recorded_capacity_sectors: capacity,
            regions: vec![
                Region { path: "captured/primary-gpt.bin", start_sector: 0,
                    sector_count: 34, sha256: sha(primary), captured_original: true },
                Region { path: "reconstructed/secondary-gpt.bin", start_sector: capacity - 33,
                    sector_count: 33, sha256: sha(&secondary), captured_original: false },
            ],
            primary_sha256_matches_pin: true, reconstructed_secondary_crc_valid: true,
            primary_secondary_entries_identical: true, original_secondary_captured: false,
            original_front_padding_captured: false, installed_boot_partitions_captured: false,
            identity_authenticated: false, phone_contacted: false,
            data_preservation_validated: false, phone_writes_enabled: false,
            automatic_resume_allowed: false,
            limitations: vec![
                "Primary provenance is supplied by the caller; no fresh phone identity or GPT was read.",
                "The secondary is derived from the saved primary, not a capture of the installed secondary; historical differences cannot be recovered.",
                "Unused sectors 34..255 and installed boot images are absent. This is GPT recovery material, not a full entry rollback or data backup.",
                "No native restore executor or physical recovery validation is provided by this capsule.",
            ],
        };
        Ok(Self {
            primary: primary.to_vec(),
            secondary,
            report,
        })
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// ZIP members contain private disk GUIDs. Keep this local; publish only a
    /// redacted report. Output publication/no-overwrite is the caller's job.
    pub fn write_zip<W: Write + std::io::Read + std::io::Seek>(
        &self,
        output: &mut W,
    ) -> Result<()> {
        let mut zip = Archive::new(output);
        zip.bytes(self.report.regions[0].path, &self.primary)?;
        zip.bytes(self.report.regions[1].path, &self.secondary)?;
        let manifest =
            serde_json::to_vec_pretty(&self.report).map_err(|e| invalid(e.to_string()))?;
        zip.bytes("manifest.json", &manifest)?;
        zip.finish()?.verify(output, |_, _| true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn primary() -> Vec<u8> {
        let mut r = std::io::Cursor::new(
            include_bytes!("../../../../tests/fixtures/synthetic-spec-a-package.ffu").as_slice(),
        );
        let f = crate::ffu::FfuMetadata::open(&mut r).unwrap();
        let mut p = f.read_disk(&mut r, 0, layout::PRIMARY_SIZE).unwrap();
        let gpt = layout::parse(&p).unwrap();
        let capacity = gpt.backup_lba + 1;
        // The compact package fixture did not reserve trailing GPT space.
        p[560..568].copy_from_slice(&(capacity - 34).to_le_bytes());
        layout::encode(&p, &gpt.partitions).unwrap()
    }
    #[test]
    fn secondary_accepts_transformed_marker_but_stock_capsule_does_not() {
        let p = primary();
        let cap = layout::parse(&p).unwrap().backup_lba + 1;
        let mut parts = layout::parse(&p).unwrap().partitions;
        let mut marker = parts[0].clone();
        marker.name = "IS_UNLOCKED_SBL3".into();
        marker.guid = uuid::Uuid::from_u128(999);
        marker.first_sector = 64;
        marker.last_sector = 64;
        parts.push(marker);
        let p = layout::encode(&p, &parts).unwrap();
        let secondary = secondary_from_primary(&p, cap).unwrap();
        assert_eq!(&secondary[..16384], &p[1024..]);
        assert!(Capsule::build(&p, cap, &sha(&p)).is_err());
        assert!(secondary_from_primary(&p, cap + 1).is_err());
        let mut bad = p.clone();
        bad[528] ^= 1;
        assert!(secondary_from_primary(&bad, cap).is_err());
    }
    #[test]
    fn capsule_preserves_original_and_reconstructs_reciprocal_secondary() {
        let p = primary();
        let capacity = layout::parse(&p).unwrap().backup_lba + 1;
        let c = Capsule::build(&p, capacity, &sha(&p)).unwrap();
        assert_eq!(c.primary, p);
        assert_eq!(&c.secondary[..16384], &p[1024..]);
        assert_eq!(c.secondary.len(), 33 * 512);
        let b = Gpt::from_parts(
            &c.secondary[16384..],
            &c.secondary[..16384],
            Some(capacity * 512),
        )
        .unwrap();
        assert_eq!(b.current_lba, capacity - 1);
        assert_eq!(b.backup_lba, 1);
        let mut zip = std::io::Cursor::new(Vec::new());
        c.write_zip(&mut zip).unwrap();
        let (_, files) = super::super::archive::inspect(&mut zip, |_, _| true).unwrap();
        assert_eq!(files.len(), 3);
        assert!(!c.report.phone_writes_enabled && !c.report.original_secondary_captured);
    }
    #[test]
    fn capsule_rejects_bad_pin_crc_capacity_and_partition_overlap() {
        let p = primary();
        let cap = layout::parse(&p).unwrap().backup_lba + 1;
        assert!(Capsule::build(&p, cap, &"0".repeat(64)).is_err());
        for n in [0, cap - 1, cap + 1, u64::MAX] {
            assert!(Capsule::build(&p, n, &sha(&p)).is_err());
        }
        for n in [0, 512, p.len() - 1] {
            assert!(Capsule::build(&p[..n], cap, &sha(&p[..n])).is_err());
        }
        let mut bad = p.clone();
        bad[528] ^= 1;
        assert!(Capsule::build(&bad, cap, &sha(&bad)).is_err());
        let mut parts = layout::parse(&p).unwrap().partitions;
        parts[0].first_sector = 34;
        let overlap = layout::encode(&p, &parts).unwrap();
        assert!(Capsule::build(&overlap, cap, &sha(&overlap)).is_err());
    }
}
