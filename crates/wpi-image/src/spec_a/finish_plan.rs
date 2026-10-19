//! Local composition of the missing Spec A UEFI-variable and EFIESP stages.
//! Derived from LumiaUnlockUEFI / LumiaGenerateEFIESPFlashPayload in WPInternals
//! 2.9.2 (super::UPSTREAM), Rene Lergner, MIT. No device writer or write grant.
use super::{efiesp, layout, live_plan, programmer_plan};
use crate::{invalid, u32le, ImageError, Result};
use serde::Serialize;
use std::io::{Cursor, Read, Seek, SeekFrom};

const MAX_ESP: u64 = 128 * 1024 * 1024;
const SBA_SHA: &str = "3fb77d37da8bb42cb65ff54998b5ba46ec625e3f949ec7ce3d3c2cb42bfbfb2a";
const NV_SHA: &str = "a6f1f290b1672abbb5e0eb8bf4482e033f3dc4b428f1f3374e127e461d29c7c6";
fn u16le(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        crate::slice(bytes, at, 2)?.try_into().unwrap(),
    ))
}

/// Owned, immutable sector payload. Metadata cannot be imported to create one.
pub struct Region {
    target: &'static str,
    start: u32,
    bytes: Vec<u8>,
}
impl Region {
    pub fn target(&self) -> &'static str {
        self.target
    }
    pub fn start_sector(&self) -> u32 {
        self.start
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Debug, Serialize)]
pub struct Transfer {
    pub target: &'static str,
    pub start_sector: u32,
    pub byte_length: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct StageBinding {
    pub source_ffu_sha256: String,
    pub package_sha256: String,
    pub before_primary_sha256: String,
    pub after_primary_sha256: String,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub kind: &'static str,
    pub source_ffu_sha256: String,
    pub package_sha256: String,
    pub saved_primary_sha256: String,
    pub expected_boot_primary_sha256: String,
    pub nv_primary_sha256: String,
    pub original_efiesp_sha256: String,
    pub prepared_efiesp_sha256: String,
    pub enlarged_reserved_sectors: u16,
    pub nv_stage: Vec<Transfer>,
    pub efiesp_stage: Vec<Transfer>,
    pub original_nv_partition_retained: bool,
    pub unrelated_partition_entries_preserved: bool,
    pub installed_originals_captured: bool,
    pub data_preservation_validated: bool,
    pub phone_writes_enabled: bool,
    pub phone_contacted: bool,
    pub blockers: Vec<&'static str>,
}
/// This composes the first UEFI/EFIESP pass, not a complete unlock. The engineering
/// SBL3 path subsequently needs mass-storage capture, a second EFIESP pass and a
/// correlated return to Windows. All source originals here are REFERENCE data.
pub struct Plan {
    nv: Vec<Region>,
    esp: Vec<Region>,
    primary: Vec<u8>,
    original_reserved: u16,
    report: Report,
}
impl Plan {
    pub fn primary(&self) -> &[u8] {
        &self.primary
    }
    pub fn stage_binding(&self, variables: bool) -> StageBinding {
        StageBinding {
            source_ffu_sha256: self.report.source_ffu_sha256.clone(),
            package_sha256: self.report.package_sha256.clone(),
            before_primary_sha256: if variables {
                self.report.expected_boot_primary_sha256.clone()
            } else {
                self.report.nv_primary_sha256.clone()
            },
            after_primary_sha256: self.report.nv_primary_sha256.clone(),
        }
    }
    pub fn nv_regions(&self) -> &[Region] {
        &self.nv
    }
    pub fn efiesp_regions(&self) -> &[Region] {
        &self.esp
    }
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Inspect a complete post-pass EFIESP capture on the expected layout,
    /// reconstruct the original FAT view, then patch THAT filesystem. This
    /// preserves its unrelated files instead of substituting a stock image.
    /// Input digests establish local integrity, not which phone supplied them.
    pub fn prepare_second_pass<F: FnMut(u64, u64) -> bool>(
        &self,
        captured_primary: &[u8],
        captured_efiesp: &[u8],
        expected_capture_sha256: &str,
        donor_boot: &[u8],
        progress: F,
    ) -> Result<SecondPass> {
        self.second_pass(
            captured_primary,
            captured_efiesp,
            expected_capture_sha256,
            donor_boot,
            progress,
            &crate::patch::PatchCatalog::bundled()?,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn second_pass<F: FnMut(u64, u64) -> bool>(
        &self,
        captured_primary: &[u8],
        captured_efiesp: &[u8],
        expected_capture_sha256: &str,
        donor_boot: &[u8],
        progress: F,
        catalog: &crate::patch::PatchCatalog,
    ) -> Result<SecondPass> {
        if captured_primary != self.primary || !digest(captured_efiesp, expected_capture_sha256) {
            return Err(invalid(
                "Captured layout or EFIESP digest differs; no continuation is available",
            ));
        }
        let gpt = layout::parse(captured_primary)?;
        let partition = gpt.partition("EFIESP")?;
        let (_, size) = partition.byte_range()?;
        if captured_efiesp.len() as u64 != size || size > MAX_ESP {
            return Err(invalid(
                "Captured EFIESP must exactly fill the expected partition",
            ));
        }
        for region in &self.esp {
            let at = (u64::from(region.start) - partition.first_sector) * 512;
            if captured_efiesp.get(at as usize..at as usize + region.bytes.len())
                != Some(&region.bytes)
            {
                return Err(invalid(
                    "Post-pass EFIESP does not contain the expected first-pass bytes",
                ));
            }
        }
        let mut original = captured_efiesp.to_vec();
        original[14..16].copy_from_slice(&self.original_reserved.to_le_bytes());
        let mut output = Cursor::new(Vec::new());
        let assembly = efiesp::assemble_with_catalog(
            &mut Cursor::new(original),
            &mut output,
            donor_boot,
            progress,
            catalog,
        )?;
        let new_image = output.into_inner();
        let (regions, _) = dual_efiesp(
            partition.first_sector,
            captured_efiesp,
            &new_image,
            self.original_reserved,
        )?;
        Ok(SecondPass {
            regions,
            assembly,
            captured_sha256: super::hash(captured_efiesp),
            binding: self.stage_binding(false),
        })
    }
}
pub struct SecondPass {
    regions: Vec<Region>,
    pub assembly: efiesp::AssemblyReport,
    pub captured_sha256: String,
    binding: StageBinding,
}
impl SecondPass {
    pub fn binding(&self) -> &StageBinding {
        &self.binding
    }
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }
}
fn digest(bytes: &[u8], expected: &str) -> bool {
    expected.len() == 64
        && expected.bytes().all(|c| c.is_ascii_hexdigit())
        && super::hash(bytes).eq_ignore_ascii_case(expected)
}
fn transfer(region: &Region) -> Transfer {
    Transfer {
        target: region.target,
        start_sector: region.start,
        byte_length: region.bytes.len() as u64,
        sha256: super::hash(&region.bytes),
    }
}
fn read_image<R: Read + Seek, F: FnMut(&str, u64, u64) -> bool>(
    reader: &mut R,
    file: &super::archive::FileRecord,
    progress: &mut F,
) -> Result<Vec<u8>> {
    if file.size == 0 || file.size > MAX_ESP {
        return Err(invalid("EFIESP exceeds bounded image size"));
    }
    reader.seek(SeekFrom::Start(file.data_offset))?;
    let mut bytes = Vec::with_capacity(file.size as usize);
    let digest = crate::stream::copy_hashed(reader, &mut bytes, file.size, |d, t| {
        progress("Read verified EFIESP image", d, t)
    })?;
    if digest != file.sha256 {
        return Err(invalid("EFIESP package bytes changed after verification"));
    }
    Ok(bytes)
}
fn region(target: &'static str, start: u64, bytes: Vec<u8>) -> Result<Region> {
    let sectors = bytes.len() as u64 / 512;
    if bytes.is_empty()
        || !bytes.len().is_multiple_of(512)
        || bytes.len() as u64 > MAX_ESP
        || start
            .checked_add(sectors)
            .is_none_or(|end| end > u64::from(u32::MAX) + 1)
    {
        return Err(invalid("Unaligned or out-of-range Spec A sector transfer"));
    }
    Ok(Region {
        target,
        start: start as u32,
        bytes,
    })
}
fn nv_payload() -> Result<Vec<u8>> {
    // Retain the unchanged upstream resource and pin both representations. This
    // is a UEFI variable image, not a proprietary firmware/Qualcomm programmer.
    let bytes = include_bytes!("../../../../resources/upstream/SBA");
    if !digest(bytes, SBA_SHA)
        || &bytes[..21] != b"\xffCompressedPartition\0"
        || u32le(bytes, 21)? != 1
        || u32le(bytes, 25)? != 37
        || crate::u64le(bytes, 29)? != 262144
    {
        return Err(invalid("Pinned upstream Spec A variable resource differs"));
    }
    let mut decoder = flate2::bufread::GzDecoder::new(&bytes[37..]);
    let mut result = Vec::new();
    (&mut decoder).take(262145).read_to_end(&mut result)?;
    if result.len() != 262144 || !decoder.into_inner().is_empty() || !digest(&result, NV_SHA) {
        return Err(invalid("Invalid bounded Spec A variable image"));
    }
    Ok(result)
}
fn variable_layout(primary: &[u8]) -> Result<(Vec<u8>, Region)> {
    let gpt = layout::parse(primary)?;
    if gpt
        .partitions
        .iter()
        .any(|p| p.name.eq_ignore_ascii_case("BACKUP_BS_NV"))
    {
        return Err(invalid(
            "Already modified UEFI variable layout needs separate recovery inspection",
        ));
    }
    let old = gpt.partition("UEFI_BS_NV")?;
    let count = old.last_sector - old.first_sector + 1;
    let mut active = old.clone();
    active.first_sector = old
        .last_sector
        .checked_add(1)
        .ok_or_else(|| invalid("NV range overflow"))?;
    active.last_sector = active
        .first_sector
        .checked_add(count - 1)
        .ok_or_else(|| invalid("NV range overflow"))?;
    let payload = nv_payload()?;
    if payload.len() as u64 != count * 512 {
        return Err(invalid(
            "Pinned UEFI variable image must exactly fill the new NV partition",
        ));
    }
    let mut parts = gpt.partitions.clone();
    let backup = parts
        .iter_mut()
        .find(|p| p.name.eq_ignore_ascii_case("UEFI_BS_NV"))
        .unwrap();
    backup.name = "BACKUP_BS_NV".into();
    // Deterministic marker GUIDs, as in the existing package layout transform.
    let guid = |label: &[u8]| {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(primary);
        h.update(label);
        let mut raw: [u8; 16] = h.finalize()[..16].try_into().unwrap();
        raw[6] = (raw[6] & 15) | 0x40;
        raw[8] = (raw[8] & 63) | 0x80;
        uuid::Uuid::from_bytes(raw)
    };
    backup.guid = guid(b"SpecA NV backup id");
    backup.type_guid = guid(b"SpecA NV backup type");
    parts.push(active.clone());
    // Existing parser checks CRCs, usable range, overlaps, packed entries and
    // duplicate names/GUIDs. A free adjacent hole is REQUIRED, never invented.
    let primary = layout::encode(primary, &parts)?;
    Ok((primary, region("UEFI_BS_NV", active.first_sector, payload)?))
}
fn dual_efiesp(
    start: u64,
    original: &[u8],
    patched: &[u8],
    old_reserved: u16,
) -> Result<(Vec<Region>, u16)> {
    if original.len() != patched.len()
        || original.len() as u64 > MAX_ESP
        || original.len() < 512
        || !original.len().is_multiple_of(512)
        || u16le(original, 11)? != 512
        || u16le(patched, 11)? != 512
        || old_reserved == 0
        || u16le(patched, 14)? != old_reserved
        || original[510..512] != [0x55, 0xaa]
        || patched[510..512] != [0x55, 0xaa]
    {
        return Err(invalid(
            "Spec A EFIESP requires matching bounded 512-byte-sector FAT images",
        ));
    }
    let count = original.len() as u64 / 512;
    let reserved = (count / 2)
        .checked_sub(u64::from(old_reserved))
        .and_then(|n| n.checked_add(1))
        .filter(|n| *n > u64::from(old_reserved))
        .ok_or_else(|| invalid("EFIESP is too small for two FAT views"))?
        .min(65535) as u16;
    let first_len = usize::from(old_reserved) * 512;
    let offset = usize::from(reserved) * 512;
    if first_len > original.len() || offset < first_len || offset >= original.len() {
        return Err(invalid(
            "EFIESP reserved-sector placement exceeds partition",
        ));
    }
    let mut first = original[..first_len].to_vec();
    first[14..16].copy_from_slice(&reserved.to_le_bytes());
    let second_len = original.len() - offset;
    let second = patched
        .get(first_len..first_len + second_len)
        .ok_or_else(|| invalid("EFIESP second-view slice exceeds image"))?
        .to_vec();
    Ok((
        vec![
            region("EFIESP-prefix", start, first)?,
            region("EFIESP-second-view", start + u64::from(reserved), second)?,
        ],
        reserved,
    ))
}

/// Verify the reference ZIP again and bind this phase to the exact boot plan.
/// Results remain local and cannot admit hardware writes. In particular, using
/// reference EFIESP bytes does NOT establish preservation of the installed one.
pub fn build<R: Read + Seek, F: FnMut(&str, u64, u64) -> bool>(
    package: &mut R,
    primary: &[u8],
    boot: &programmer_plan::Plan,
    mut progress: F,
) -> Result<Plan> {
    let report = boot.report();
    let layout_report = &report.layout;
    let mut check = |stage, done, total| {
        if progress(stage, done, total) {
            Ok(())
        } else {
            Err(ImageError::Cancelled)
        }
    };
    check("Verify finish-stage inputs", 0, 0)?;
    let verified = live_plan::verify(
        package,
        primary,
        layout_report.recorded_capacity_sectors,
        &layout_report.saved_primary_sha256,
        &layout_report.package_sha256,
        |d, t| progress("Verify finish-stage package", d, t),
    )?;
    if verified.report.candidate_primary_sha256 != layout_report.candidate_primary_sha256
        || verified.report.source_ffu_sha256 != layout_report.source_ffu_sha256
        || verified
            .candidate
            .prepared
            .partition("IS_UNLOCKED_SBL3")
            .is_err()
    {
        return Err(invalid(
            "Finish stages require the same source/layout and engineering-SBL3 boot plan",
        ));
    }
    let (nv_primary, nv) = variable_layout(&verified.candidate.bytes)?;
    let candidate = layout::parse(&nv_primary)?;
    let p = candidate.partition("EFIESP")?;
    let (_, size) = p.byte_range()?;
    let mut load = |path: &str| {
        read_image(
            package,
            live_plan::member(&verified.files, path)?,
            &mut progress,
        )
    };
    let original = load("original/EFIESP.img")?;
    let patched = load("prepared/EFIESP.img")?;
    if size != original.len() as u64 || original.len() != patched.len() {
        return Err(invalid(
            "Reference EFIESP length differs from saved installed partition capacity",
        ));
    }
    if !progress("Compose UEFI variable and EFIESP stages", 0, size) {
        return Err(ImageError::Cancelled);
    }
    let original_reserved = u16le(&original, 14)?;
    let (esp, reserved) = dual_efiesp(p.first_sector, &original, &patched, original_reserved)?;
    let nv = vec![nv, region("GPT-primary", 0, nv_primary.clone())?];
    let result = Report {
        schema:1,kind:"wpi-spec-a-finish-reference-plan",phone_contacted:false,
        source_ffu_sha256: layout_report.source_ffu_sha256.clone(),
        package_sha256: layout_report.package_sha256.clone(),
        saved_primary_sha256: layout_report.saved_primary_sha256.clone(),
        expected_boot_primary_sha256: layout_report.candidate_primary_sha256.clone(),
        nv_primary_sha256: super::hash(&nv_primary),
        original_efiesp_sha256: super::hash(&original),
        prepared_efiesp_sha256: super::hash(&patched),
        enlarged_reserved_sectors: reserved,
        nv_stage: nv.iter().map(transfer).collect(), efiesp_stage: esp.iter().map(transfer).collect(),
        original_nv_partition_retained: true, unrelated_partition_entries_preserved: true,
        installed_originals_captured: false, data_preservation_validated: false, phone_writes_enabled: false,
        blockers: vec!["Reference EFIESP bytes are not the installed original; capture and compare before writes.",
            "Native emergency/programmer and later-stage integration and hardware recovery validation remain required.",
            "Engineering SBL3 requires mass-storage capture, a second EFIESP pass and verified return to Windows."],
    };
    if !progress("Finish local UEFI/EFIESP composition", size, size) {
        return Err(ImageError::Cancelled);
    }
    Ok(Plan {
        nv,
        esp,
        primary: nv_primary,
        original_reserved,
        report: result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn large_efiesp_reader_uses_bounded_chunks_pinned_hashes_and_cancellation() {
        struct Audit {
            io: Cursor<Vec<u8>>,
            max_read: usize,
        }
        impl Read for Audit {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.max_read = self.max_read.max(b.len());
                self.io.read(b)
            }
        }
        impl Seek for Audit {
            fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
                self.io.seek(p)
            }
        }
        let mut source = Audit {
            io: Cursor::new(vec![42; 33 * 1024 * 1024]),
            max_read: 0,
        };
        let mut file = super::super::archive::FileRecord {
            path: "synthetic/EFIESP".into(),
            size: 33 * 1024 * 1024,
            sha256: super::super::hash(source.io.get_ref()),
            crc32: 0,
            data_offset: 0,
        };
        let result = read_image(&mut source, &file, &mut |_, _, _| true).unwrap();
        assert_eq!(&result, source.io.get_ref());
        assert!(source.max_read <= crate::COPY_BUFFER);
        assert!(matches!(
            read_image(&mut source, &file, &mut |_, _, _| false),
            Err(ImageError::Cancelled)
        ));
        file.size = MAX_ESP + 1;
        assert!(read_image(&mut source, &file, &mut |_, _, _| true).is_err());
        file.size = 512;
        file.sha256 = "0".repeat(64);
        assert!(read_image(&mut source, &file, &mut |_, _, _| true).is_err());
    }
    fn primary() -> Vec<u8> {
        let mut source = Cursor::new(include_bytes!(
            "../../../../tests/fixtures/synthetic-spec-a-package.ffu"
        ));
        let ffu = crate::ffu::FfuMetadata::open(&mut source).unwrap();
        let mut bytes = ffu.read_disk(&mut source, 0, layout::PRIMARY_SIZE).unwrap();
        // Synthetic extended disk and deliberately non-reference EFIESP offset.
        bytes[544..552].copy_from_slice(&0x10000u64.to_le_bytes());
        bytes[560..568].copy_from_slice(&0xffdfu64.to_le_bytes());
        let mut header = bytes[512..604].to_vec();
        header[16..20].fill(0);
        bytes[528..532].copy_from_slice(&crc32fast::hash(&header).to_le_bytes());
        let mut gpt = layout::parse(&bytes).unwrap();
        let esp = gpt
            .partitions
            .iter_mut()
            .find(|p| p.name == "EFIESP")
            .unwrap();
        esp.first_sector = 0x4000;
        esp.last_sector = 0x5fff;
        let mut nv = esp.clone();
        nv.name = "UEFI_BS_NV".into();
        nv.first_sector = 0x6000;
        nv.last_sector = 0x61ff;
        nv.guid = uuid::Uuid::from_bytes([0x91; 16]);
        nv.type_guid = uuid::Uuid::from_bytes([0x92; 16]);
        gpt.partitions.push(nv);
        layout::encode(&bytes, &gpt.partitions).unwrap()
    }
    fn image() -> Vec<u8> {
        let mut image = Cursor::new(vec![0; 4 * 1024 * 1024]);
        fatfs::format_volume(&mut image, fatfs::FormatVolumeOptions::new()).unwrap();
        image.set_position(0);
        let fs = fatfs::FileSystem::new(&mut image, fatfs::FsOptions::new()).unwrap();
        let root = fs.root_dir();
        let windows = root.create_dir("Windows").unwrap();
        let system = windows.create_dir("System32").unwrap();
        let boot = system.create_dir("Boot").unwrap();
        boot.create_file("mobilestartup.efi")
            .unwrap()
            .write_all(b"abcdefgh")
            .unwrap();
        let efi = root.create_dir("efi").unwrap();
        let ms = efi.create_dir("Microsoft").unwrap();
        let boot2 = ms.create_dir("Boot").unwrap();
        boot2
            .create_file("BCD")
            .unwrap()
            .write_all(include_bytes!(
                "../../../../tests/fixtures/spec-a/bcd.synthetic.hive"
            ))
            .unwrap();
        root.create_file("keep.txt")
            .unwrap()
            .write_all(b"installed-only file")
            .unwrap();
        drop((root, windows, system, boot, efi, ms, boot2));
        fs.unmount().unwrap();
        image.into_inner()
    }
    fn catalog() -> crate::patch::PatchCatalog {
        crate::patch::PatchCatalog::parse(&format!(r#"<PatchDefinitions><PatchDefinition Name="SecureBootHack-V1.1-EFIESP"><TargetVersions><TargetVersion Description="synthetic"><TargetFiles><TargetFile Path="{}" HashOriginal="{}" HashPatched="{}"><Patches><Patch Address="0x2" OriginalBytes="6364" PatchedBytes="5859" /></Patches><Obsolete /></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>"#,
            efiesp::PATH,crate::patch::sha1(b"abcdefgh"),crate::patch::sha1(b"abXYefgh"))).unwrap()
    }
    #[test]
    fn variable_layout_keeps_original_and_rejects_collisions_or_unreviewed_geometry() {
        let before = primary();
        let old = layout::parse(&before).unwrap();
        let (bytes, payload) = variable_layout(&before).unwrap();
        let new = layout::parse(&bytes).unwrap();
        let original = old.partition("UEFI_BS_NV").unwrap();
        let backup = new.partition("BACKUP_BS_NV").unwrap();
        let active = new.partition("UEFI_BS_NV").unwrap();
        assert_eq!(
            (backup.first_sector, backup.last_sector),
            (original.first_sector, original.last_sector)
        );
        assert_ne!(backup.guid, original.guid);
        assert_eq!(
            (active.guid, active.type_guid),
            (original.guid, original.type_guid)
        );
        assert_eq!((active.first_sector, active.last_sector), (0x6200, 0x63ff));
        assert_eq!(payload.bytes.len(), 262144);
        assert_eq!(super::super::hash(&payload.bytes), NV_SHA);
        for part in old.partitions.iter().filter(|p| p.name != "UEFI_BS_NV") {
            assert_eq!(
                serde_json::to_value(part).unwrap(),
                serde_json::to_value(new.partition(&part.name).unwrap()).unwrap()
            );
        }
        assert!(variable_layout(&bytes).is_err());
        let mut parts = old.partitions;
        let mut obstruction = parts[0].clone();
        obstruction.name = "Data".into();
        obstruction.guid = uuid::Uuid::from_bytes([0x93; 16]);
        obstruction.first_sector = 0x6200;
        obstruction.last_sector = 0x62ff;
        parts.push(obstruction);
        assert!(variable_layout(&layout::encode(&before, &parts).unwrap()).is_err());
        let p = parts.iter_mut().find(|p| p.name == "UEFI_BS_NV").unwrap();
        p.last_sector -= 1;
        assert!(variable_layout(&layout::encode(&before, &parts).unwrap()).is_err());
        for n in [0, 511, 1024, 17407] {
            assert!(variable_layout(&before[..n]).is_err());
        }
    }
    #[test]
    fn dual_view_matches_upstream_slices_and_rejects_malformed_lengths_and_offsets() {
        let original = image();
        let mut patched = original.clone();
        patched[1024] = 77;
        let old = u16le(&original, 14).unwrap();
        let (regions, reserved) = dual_efiesp(0x4000, &original, &patched, old).unwrap();
        assert_eq!(
            reserved,
            u16::try_from(original.len() / 1024 - usize::from(old) + 1).unwrap()
        );
        assert_eq!(regions[0].bytes.len(), usize::from(old) * 512);
        assert_eq!(u16le(&regions[0].bytes, 14).unwrap(), reserved);
        assert_eq!(regions[1].start, 0x4000 + u32::from(reserved));
        assert_eq!(
            regions[1].bytes,
            &patched[usize::from(old) * 512
                ..usize::from(old) * 512 + original.len() - usize::from(reserved) * 512]
        );
        assert_eq!(u16le(&original, 14).unwrap(), old);
        assert!(dual_efiesp(u64::from(u32::MAX), &original, &patched, old).is_err());
        for n in [0, 511, 512, 1023, original.len() - 1] {
            assert!(dual_efiesp(0, &original[..n], &patched, old).is_err());
        }
        let mut bad = patched.clone();
        bad[12] = 0;
        assert!(dual_efiesp(0, &original, &bad, old).is_err());
        assert!(dual_efiesp(0, &original, &patched, u16::MAX).is_err());
    }
    fn plan() -> (Plan, Vec<u8>) {
        let (primary, nv) = variable_layout(&primary()).unwrap();
        let original = image();
        let old = u16le(&original, 14).unwrap();
        let mut patched = Cursor::new(Vec::new());
        efiesp::assemble_with_catalog(
            &mut Cursor::new(&original),
            &mut patched,
            b"abcdefgh",
            |_, _| true,
            &catalog(),
        )
        .unwrap();
        let (esp, reserved) = dual_efiesp(0x4000, &original, &patched.into_inner(), old).unwrap();
        let mut captured = original;
        for r in &esp {
            let at = (r.start - 0x4000) as usize * 512;
            captured[at..at + r.bytes.len()].copy_from_slice(&r.bytes);
        }
        let report = Report {
            schema: 1,
            kind: "synthetic-private-test-context",
            phone_contacted: false,
            source_ffu_sha256: String::new(),
            package_sha256: String::new(),
            saved_primary_sha256: String::new(),
            expected_boot_primary_sha256: String::new(),
            nv_primary_sha256: super::super::hash(&primary),
            original_efiesp_sha256: String::new(),
            prepared_efiesp_sha256: String::new(),
            enlarged_reserved_sectors: reserved,
            nv_stage: vec![],
            efiesp_stage: vec![],
            original_nv_partition_retained: true,
            unrelated_partition_entries_preserved: true,
            installed_originals_captured: false,
            data_preservation_validated: false,
            phone_writes_enabled: false,
            blockers: vec![],
        };
        (
            Plan {
                nv: vec![nv],
                esp,
                primary,
                original_reserved: old,
                report,
            },
            captured,
        )
    }
    #[test]
    fn installed_capture_reconstruction_preserves_files_and_refuses_changed_captures_or_cancel() {
        let (plan, capture) = plan();
        let digest = super::super::hash(&capture);
        let final_plan = plan
            .second_pass(
                &plan.primary,
                &capture,
                &digest,
                b"abcdefgh",
                |_, _| true,
                &catalog(),
            )
            .unwrap();
        assert!(final_plan.assembly.preserved_other_files);
        assert!(!final_plan.assembly.phone_writes_enabled);
        assert_eq!(final_plan.captured_sha256, digest);
        assert_eq!(final_plan.regions.len(), 2);
        assert!(plan
            .second_pass(
                &plan.primary,
                &capture,
                &"0".repeat(64),
                b"abcdefgh",
                |_, _| true,
                &catalog()
            )
            .is_err());
        let mut changed = capture.clone();
        changed[0] ^= 1;
        assert!(plan
            .second_pass(
                &plan.primary,
                &changed,
                &super::super::hash(&changed),
                b"abcdefgh",
                |_, _| true,
                &catalog()
            )
            .is_err());
        let mut wrong = plan.primary.clone();
        wrong[440] ^= 1;
        assert!(plan
            .second_pass(
                &wrong,
                &capture,
                &digest,
                b"abcdefgh",
                |_, _| true,
                &catalog()
            )
            .is_err());
        assert!(matches!(
            plan.second_pass(
                &plan.primary,
                &capture,
                &digest,
                b"abcdefgh",
                |_, _| false,
                &catalog()
            ),
            Err(ImageError::Cancelled)
        ));
    }
}
