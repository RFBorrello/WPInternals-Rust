//! Targeted read-only recovery snapshot. Bounded streaming, double source reads,
//! output readback and no device commands. Captures describe the current state;
//! they cannot prove that any earlier entry or unlock preserved original bytes.
use super::{
    archive::{Archive, FileRecord},
    entry_recovery::Capsule,
    layout,
};
use crate::{gpt::Gpt, invalid, ImageError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, Write};
const COPY_BUFFER: usize = 64 * 1024;

#[derive(Debug, Serialize)]
pub struct Range {
    pub name: String,
    pub start_sector: u64,
    pub sector_count: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub kind: &'static str,
    pub capacity_sectors: u64,
    pub primary_sha256: String,
    pub ranges: Vec<Range>,
    pub files: Vec<FileRecord>,
    pub source_reread_matched: bool,
    pub captured_bytes: u64,
    pub archive_sha256: String,
    pub captured_state: &'static str,
    pub pre_unlock_originals_proven: bool,
    pub device_identity_authenticated: bool,
    pub phone_writes_enabled: bool,
    pub data_preservation_validated: bool,
    pub hardware_validated: bool,
}
struct Span {
    name: String,
    start: u64,
    size: u64,
}
pub struct Plan {
    primary: Vec<u8>,
    capacity: u64,
    spans: Vec<Span>,
    bytes: u64,
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
/// Read one bounded capture member after checking the complete archive digest
/// and all ZIP members. No paths are extracted to the host filesystem.
pub fn read_efiesp<R: Read + Seek>(input: &mut R, expected_archive: &str) -> Result<Vec<u8>> {
    use std::io::{Cursor, SeekFrom};
    if expected_archive.len() != 64 {
        return Err(invalid("Complete snapshot digest is required"));
    }
    input.seek(SeekFrom::Start(0))?;
    if input.seek(SeekFrom::End(0))? > 129 * 1024 * 1024 {
        return Err(invalid("Targeted snapshot archive exceeds bound"));
    }
    input.seek(SeekFrom::Start(0))?;
    if !crate::stream::sha256(input)?.eq_ignore_ascii_case(expected_archive) {
        return Err(invalid("Snapshot archive digest differs"));
    }
    let (_, files) = super::archive::inspect(input, |_, _| true)?;
    let members: Vec<_> = files
        .iter()
        .filter(|f| f.path == "captured/EFIESP.bin")
        .collect();
    let [member] = members.as_slice() else {
        return Err(invalid("Snapshot EFIESP is missing or ambiguous"));
    };
    if member.size == 0 || member.size > 96 * 1024 * 1024 || !member.size.is_multiple_of(512) {
        return Err(invalid("Snapshot EFIESP exceeds bound"));
    }
    input.seek(SeekFrom::Start(member.data_offset))?;
    let mut bytes = vec![0; member.size as usize];
    input.read_exact(&mut bytes)?;
    if crate::stream::sha256(&mut Cursor::new(&bytes))? != member.sha256 {
        return Err(invalid("Snapshot EFIESP changed after verification"));
    }
    Ok(bytes)
}
impl Plan {
    pub fn captured_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn new(primary: &[u8], capacity: u64, expected_primary: &str) -> Result<Self> {
        Capsule::build(primary, capacity, expected_primary)?;
        Self::compose(primary, capacity, false)
    }
    /// Capture the actual NV backup after the first unlock pass. The caller must
    /// compare this primary to its in-memory finish plan, not import a report.
    /// This deliberately makes no claim to be a pre-unlock backup.
    pub fn after_nv(primary: &[u8], capacity: u64, expected_primary: &str) -> Result<Self> {
        if expected_primary.len() != 64 || !sha(primary).eq_ignore_ascii_case(expected_primary) {
            return Err(invalid("Post-NV primary GPT digest differs"));
        }
        super::entry_recovery::secondary_from_primary(primary, capacity)?;
        let gpt = layout::parse(primary)?;
        for p in &gpt.partitions {
            if p.first_sector < 256
                && !(p.name == "IS_UNLOCKED_SBL3" && p.first_sector == 64 && p.last_sector == 64)
            {
                return Err(invalid("Unknown partition inside entry footprint"));
            }
        }
        let active = gpt.partition("UEFI_BS_NV")?;
        let backup = gpt.partition("BACKUP_BS_NV")?;
        if backup.last_sector - backup.first_sector + 1 != 512
            || backup.last_sector + 1 != active.first_sector
        {
            return Err(invalid("Unknown post-NV backup geometry"));
        }
        Self::compose(primary, capacity, true)
    }
    fn compose(primary: &[u8], capacity: u64, after_nv: bool) -> Result<Self> {
        let gpt = layout::parse(primary)?;
        let mut spans = vec![
            Span {
                name: "disk-begin".into(),
                start: 0,
                size: 128 * 1024,
            },
            Span {
                name: "disk-end".into(),
                start: (capacity - 256) * 512,
                size: 128 * 1024,
            },
        ];
        for name in layout::BOOT.into_iter().chain(["EFIESP", "UEFI_BS_NV"]) {
            let p = gpt.partition(name)?;
            let (start, size) = p.byte_range()?;
            let bound = if name == "EFIESP" {
                96 * 1024 * 1024
            } else {
                16 * 1024 * 1024
            };
            if size > bound {
                return Err(invalid("Targeted snapshot partition exceeds its bound"));
            }
            spans.push(Span {
                name: name.into(),
                start,
                size,
            });
        }
        let nv = gpt.partition("UEFI_BS_NV")?;
        if nv.last_sector - nv.first_sector + 1 != 512 {
            return Err(invalid("Unknown Spec A UEFI variable geometry"));
        }
        let next = if after_nv {
            gpt.partition("BACKUP_BS_NV")?.first_sector
        } else {
            nv.last_sector + 1
        };
        let last = next + 511;
        if last > gpt.last_usable_sector
            || gpt.partitions.iter().any(|p| {
                !(after_nv && p.name == "BACKUP_BS_NV")
                    && p.first_sector <= last
                    && p.last_sector >= next
            })
        {
            return Err(invalid(
                "Future variable destination is occupied or out of bounds",
            ));
        }
        spans.push(Span {
            name: if after_nv {
                "BACKUP_BS_NV"
            } else {
                "variable-destination"
            }
            .into(),
            start: next * 512,
            size: 256 * 1024,
        });
        let bytes = spans.iter().map(|s| s.size).sum();
        if bytes > 128 * 1024 * 1024 {
            return Err(invalid("Targeted snapshot exceeds 128 MiB"));
        }
        // Captured regions are disjoint. A Data tail may lie inside disk-end;
        // no additional Data-region capture is added that could duplicate it.
        let mut ordered: Vec<_> = spans.iter().collect();
        ordered.sort_by_key(|s| s.start);
        if ordered
            .windows(2)
            .any(|p| p[0].start + p[0].size > p[1].start)
        {
            return Err(invalid("Overlapping targeted snapshot regions"));
        }
        Ok(Self {
            primary: primary.to_vec(),
            capacity,
            spans,
            bytes,
        })
    }
    fn metadata<R: FnMut(u64, &mut [u8]) -> Result<()>>(&self, read: &mut R) -> Result<()> {
        let mut p = vec![0; layout::PRIMARY_SIZE];
        read(0, &mut p)?;
        if p != self.primary {
            return Err(invalid("Selected disk primary GPT changed"));
        }
        let mut secondary = vec![0; 33 * 512];
        read((self.capacity - 33) * 512, &mut secondary)?;
        let b = Gpt::from_parts(
            &secondary[16384..],
            &secondary[..16384],
            Some(self.capacity * 512),
        )?;
        let p_gpt = layout::parse(&p)?;
        if b.current_lba != self.capacity - 1
            || b.backup_lba != 1
            || crate::u64le(&secondary[16384..], 72)? != self.capacity - 33
            || secondary[..16384] != p[1024..]
            || b.disk_guid != p_gpt.disk_guid
            || b.entry_count != p_gpt.entry_count
            || b.entry_size != p_gpt.entry_size
            || b.first_usable_sector != p_gpt.first_usable_sector
            || b.last_usable_sector != p_gpt.last_usable_sector
        {
            return Err(invalid("Selected disk secondary GPT differs from primary"));
        }
        Ok(())
    }
    /// The native caller must hold a read-only exclusive source handle, validate
    /// its identity/geometry, and publish the output atomically only on success.
    pub fn capture<W, R, F>(&self, output: &mut W, mut read: R, mut progress: F) -> Result<Report>
    where
        W: Read + Write + Seek,
        R: FnMut(u64, &mut [u8]) -> Result<()>,
        F: FnMut(&str, u64, u64) -> bool,
    {
        if !progress("Check snapshot source", 0, self.bytes) {
            return Err(ImageError::Cancelled);
        }
        self.metadata(&mut read)?;
        let mut zip = Archive::new(output);
        let mut buffer = vec![0; COPY_BUFFER];
        let mut done = 0;
        for span in &self.spans {
            zip.add(&format!("captured/{}.bin", span.name), span.size, |entry| {
                let mut within = 0;
                while within < span.size {
                    if !progress("Capture installed ranges", done, self.bytes) {
                        return Err(ImageError::Cancelled);
                    }
                    let n = (span.size - within).min(COPY_BUFFER as u64) as usize;
                    read(span.start + within, &mut buffer[..n])?;
                    entry.write_all(&buffer[..n])?;
                    within += n as u64;
                    done += n as u64;
                }
                Ok(())
            })?;
        }
        let files = zip.files();
        done = 0;
        for (span, file) in self.spans.iter().zip(&files) {
            let mut hash = Sha256::new();
            let mut within = 0;
            while within < span.size {
                if !progress("Verify source ranges", done, self.bytes) {
                    return Err(ImageError::Cancelled);
                }
                let n = (span.size - within).min(COPY_BUFFER as u64) as usize;
                read(span.start + within, &mut buffer[..n])?;
                hash.update(&buffer[..n]);
                within += n as u64;
                done += n as u64;
            }
            if hex::encode(hash.finalize()) != file.sha256 {
                return Err(invalid("Source range changed during capture"));
            }
        }
        if !progress("Check snapshot bookends", self.bytes, self.bytes) {
            return Err(ImageError::Cancelled);
        }
        self.metadata(&mut read)?;
        let mut report = Report {
            schema: 1,
            kind: "spec_a_targeted_recovery_snapshot",
            capacity_sectors: self.capacity,
            primary_sha256: sha(&self.primary),
            ranges: self
                .spans
                .iter()
                .map(|s| Range {
                    name: s.name.clone(),
                    start_sector: s.start / 512,
                    sector_count: s.size / 512,
                })
                .collect(),
            files,
            source_reread_matched: true,
            captured_bytes: self.bytes,
            archive_sha256: String::new(),
            captured_state: "current_state_at_capture_not_proven_pre_unlock",
            pre_unlock_originals_proven: false,
            device_identity_authenticated: false,
            phone_writes_enabled: false,
            data_preservation_validated: false,
            hardware_validated: false,
        };
        let manifest = serde_json::to_vec_pretty(&report).map_err(|e| invalid(e.to_string()))?;
        zip.bytes("manifest.json", &manifest)?;
        let finished = zip.finish()?;
        report.archive_sha256 =
            finished.verify(output, |d, t| progress("Verify snapshot archive", d, t))?;
        // The manifest omits the containing archive hash (which cannot hash itself).
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn disk() -> (Vec<u8>, Vec<u8>) {
        let mut r = Cursor::new(
            include_bytes!("../../../../tests/fixtures/synthetic-spec-a-package.ffu").as_slice(),
        );
        let f = crate::ffu::FfuMetadata::open(&mut r).unwrap();
        let mut p = f.read_disk(&mut r, 0, layout::PRIMARY_SIZE).unwrap();
        let mut parts = layout::parse(&p).unwrap().partitions;
        parts
            .iter_mut()
            .find(|p| p.name == "EFIESP")
            .unwrap()
            .last_sector = 575;
        let mut nv = parts[0].clone();
        nv.name = "UEFI_BS_NV".into();
        nv.guid = uuid::Uuid::from_u128(1000);
        nv.first_sector = 9000;
        nv.last_sector = 9511;
        parts.push(nv);
        let capacity = 32768u64;
        p[544..552].copy_from_slice(&(capacity - 1).to_le_bytes());
        p[560..568].copy_from_slice(&(capacity - 34).to_le_bytes());
        let p = layout::encode(&p, &parts).unwrap();
        let mut d = vec![0x5a; capacity as usize * 512];
        d[..p.len()].copy_from_slice(&p);
        let mut h = p[512..1024].to_vec();
        h[24..32].copy_from_slice(&(capacity - 1).to_le_bytes());
        h[32..40].copy_from_slice(&1u64.to_le_bytes());
        h[72..80].copy_from_slice(&(capacity - 33).to_le_bytes());
        h[16..20].fill(0);
        let crc = crc32fast::hash(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        let at = (capacity as usize - 33) * 512;
        d[at..at + 16384].copy_from_slice(&p[1024..]);
        d[at + 16384..at + 16896].copy_from_slice(&h);
        (d, p)
    }
    #[test]
    fn post_nv_snapshot_captures_backup_not_an_unrelated_future_hole() {
        let (mut disk, p) = disk();
        let mut parts = layout::parse(&p).unwrap().partitions;
        let active = parts.iter_mut().find(|p| p.name == "UEFI_BS_NV").unwrap();
        let mut backup = active.clone();
        backup.name = "BACKUP_BS_NV".into();
        backup.guid = uuid::Uuid::from_u128(1002);
        active.first_sector += 512;
        active.last_sector += 512;
        parts.push(backup);
        let mut marker = parts[0].clone();
        marker.name = "IS_UNLOCKED_SBL3".into();
        marker.guid = uuid::Uuid::from_u128(1003);
        marker.first_sector = 64;
        marker.last_sector = 64;
        parts.push(marker);
        let p = layout::encode(&p, &parts).unwrap();
        let cap = disk.len() as u64 / 512;
        disk[..p.len()].copy_from_slice(&p);
        let secondary = super::super::entry_recovery::secondary_from_primary(&p, cap).unwrap();
        disk[(cap as usize - 33) * 512..].copy_from_slice(&secondary);
        assert!(Plan::new(&p, cap, &sha(&p)).is_err());
        let plan = Plan::after_nv(&p, cap, &sha(&p)).unwrap();
        assert!(plan
            .spans
            .iter()
            .any(|s| s.name == "BACKUP_BS_NV" && s.start == 9000 * 512));
        assert!(!plan.spans.iter().any(|s| s.name == "variable-destination"));
        let mut archive = Cursor::new(Vec::new());
        let report = plan
            .capture(
                &mut archive,
                |at, b| {
                    b.copy_from_slice(&disk[at as usize..at as usize + b.len()]);
                    Ok(())
                },
                |_, _, _| true,
            )
            .unwrap();
        assert!(!report.pre_unlock_originals_proven);
        let image = read_efiesp(&mut archive, &report.archive_sha256).unwrap();
        assert_eq!(image, disk[512 * 512..576 * 512]);
        assert!(read_efiesp(&mut archive, &"0".repeat(64)).is_err());
        archive.get_mut()[40] ^= 1;
        assert!(read_efiesp(&mut archive, &report.archive_sha256).is_err());
        assert!(Plan::after_nv(&p, cap, &"0".repeat(64)).is_err());
        parts
            .iter_mut()
            .find(|p| p.name == "IS_UNLOCKED_SBL3")
            .unwrap()
            .name = "unexpected".into();
        let wrong = layout::encode(&p, &parts).unwrap();
        assert!(Plan::after_nv(&wrong, cap, &sha(&wrong)).is_err());
    }
    #[test]
    fn bounded_snapshot_rereads_every_range_and_verifies_archive() {
        let (disk, p) = disk();
        let plan = Plan::new(&p, disk.len() as u64 / 512, &sha(&p)).unwrap();
        let mut output = Cursor::new(Vec::new());
        let mut requests = vec![];
        let report = plan
            .capture(
                &mut output,
                |at, b| {
                    assert!(b.len() <= COPY_BUFFER && b.len().is_multiple_of(512));
                    requests.push((at, b.len()));
                    b.copy_from_slice(&disk[at as usize..at as usize + b.len()]);
                    Ok(())
                },
                |_, _, _| true,
            )
            .unwrap();
        assert_eq!(report.ranges.len(), 12);
        assert!(!report.pre_unlock_originals_proven && !report.phone_writes_enabled);
        let (_, files) = super::super::archive::inspect(&mut output, |_, _| true).unwrap();
        assert_eq!(files.len(), 13);
        assert_eq!(report.archive_sha256, sha(output.get_ref()));
        for span in &plan.spans {
            let record = files
                .iter()
                .find(|r| r.path == format!("captured/{}.bin", span.name))
                .unwrap();
            assert_eq!(
                record.sha256,
                sha(&disk[span.start as usize..(span.start + span.size) as usize])
            );
        }
        assert!(requests
            .iter()
            .all(|(a, n)| *a + *n as u64 <= disk.len() as u64));
    }
    #[test]
    fn snapshot_stops_on_each_read_failure_changed_source_or_cancel_boundary() {
        let (disk, p) = disk();
        let plan = Plan::new(&p, disk.len() as u64 / 512, &sha(&p)).unwrap();
        let mut reads = 0;
        let mut boundaries = 0;
        plan.capture(
            &mut Cursor::new(Vec::new()),
            |a, b| {
                reads += 1;
                b.copy_from_slice(&disk[a as usize..a as usize + b.len()]);
                Ok(())
            },
            |_, _, _| {
                boundaries += 1;
                true
            },
        )
        .unwrap();
        for fail in 0..reads {
            let mut n = 0;
            let result = plan.capture(
                &mut Cursor::new(Vec::new()),
                |a, b| {
                    let at = n;
                    n += 1;
                    if at == fail {
                        return Err(invalid("simulated disconnect/short read"));
                    }
                    b.copy_from_slice(&disk[a as usize..a as usize + b.len()]);
                    Ok(())
                },
                |_, _, _| true,
            );
            assert!(result.is_err());
            assert_eq!(n, fail + 1);
        }
        for fail in 0..boundaries {
            let mut n = 0;
            assert!(matches!(
                plan.capture(
                    &mut Cursor::new(Vec::new()),
                    |a, b| {
                        b.copy_from_slice(&disk[a as usize..a as usize + b.len()]);
                        Ok(())
                    },
                    |_, _, _| {
                        let at = n;
                        n += 1;
                        at != fail
                    }
                ),
                Err(ImageError::Cancelled)
            ));
        }
        // A correctly sized second read that changes one range must still fail.
        let target = plan.spans[2].start;
        let mut seen = 0;
        assert!(plan
            .capture(
                &mut Cursor::new(Vec::new()),
                |a, b| {
                    b.copy_from_slice(&disk[a as usize..a as usize + b.len()]);
                    if a == target {
                        seen += 1;
                        if seen == 2 {
                            b[0] ^= 1;
                        }
                    }
                    Ok(())
                },
                |_, _, _| true
            )
            .is_err());
        let mut damaged = disk.clone();
        let n = damaged.len();
        damaged[n - 512] ^= 1;
        assert!(plan
            .capture(
                &mut Cursor::new(Vec::new()),
                |a, b| {
                    b.copy_from_slice(&damaged[a as usize..a as usize + b.len()]);
                    Ok(())
                },
                |_, _, _| true
            )
            .is_err());
    }
    #[test]
    fn unknown_geometry_missing_partitions_and_occupied_variable_destination_fail() {
        let (_, p) = disk();
        let gpt = layout::parse(&p).unwrap();
        assert!(Plan::new(&p, 32768, &"0".repeat(64)).is_err());
        let mut parts = gpt.partitions.clone();
        parts.retain(|p| p.name != "UEFI_BS_NV");
        let missing = layout::encode(&p, &parts).unwrap();
        assert!(Plan::new(&missing, 32768, &sha(&missing)).is_err());
        let mut parts = gpt.partitions.clone();
        let mut occupied = parts[0].clone();
        occupied.name = "occupied".into();
        occupied.guid = uuid::Uuid::from_u128(1001);
        occupied.first_sector = 9512;
        occupied.last_sector = 9513;
        parts.push(occupied);
        let p = layout::encode(&p, &parts).unwrap();
        assert!(Plan::new(&p, 32768, &sha(&p)).is_err());
    }
    #[test]
    fn corrupted_archive_readback_cannot_report_success() {
        struct Corrupt(Cursor<Vec<u8>>);
        impl Write for Corrupt {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }
        impl Seek for Corrupt {
            fn seek(&mut self, at: std::io::SeekFrom) -> std::io::Result<u64> {
                self.0.seek(at)
            }
        }
        impl Read for Corrupt {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(b)?;
                if n > 0 {
                    b[0] ^= 1;
                }
                Ok(n)
            }
        }
        let (disk, p) = disk();
        let plan = Plan::new(&p, 32768, &sha(&p)).unwrap();
        assert!(plan
            .capture(
                &mut Corrupt(Cursor::new(Vec::new())),
                |a, b| {
                    b.copy_from_slice(&disk[a as usize..a as usize + b.len()]);
                    Ok(())
                },
                |_, _, _| true
            )
            .is_err());
    }
}
