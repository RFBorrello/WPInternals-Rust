//! Streaming offline Spec A reference packages. No transport or execution API.
pub use super::archive::FileRecord;
use super::{archive::Archive, efiesp, layout, Import};
use crate::{
    ffu::{FfuMetadata, ReadSegment},
    gpt::Gpt,
    invalid,
    patch::PatchCatalog,
    ImageError, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom, Write},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Placement {
    pub path: String,
    pub reference_start_sector: u64,
    pub byte_length: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    pub kind: String,
    pub upstream_revision: String,
    pub source_platform: String,
    pub source_ffu_size: u64,
    pub source_ffu_sha256: String,
    pub source_chunk_integrity: String,
    pub source_gpt: Gpt,
    pub prepared_gpt: Gpt,
    pub normalized_backup_pairs: Vec<String>,
    pub external_sbl3: bool,
    pub files: Vec<FileRecord>,
    pub prepared: Vec<Placement>,
    pub restore: Vec<Placement>,
    pub originals_are_installed_backup: bool,
    pub backup_gpt_captured: bool,
    pub phone_writes_enabled: bool,
    pub execution_blockers: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub size: u64,
    pub resulting_sha256: String,
    pub manifest_sha256: String,
    pub integrity_verified: bool,
    pub phone_writes_enabled: bool,
    pub manifest: Manifest,
}
// Seekable logical partition view. Only bounded slices of the source FFU are
// read. Unlike metadata probes this deliberately permits a complete image copy.
struct View<'a, R> {
    source: &'a mut R,
    segments: Vec<ReadSegment>,
    size: u64,
    at: u64,
}
impl<'a, R: Read + Seek> View<'a, R> {
    fn new(source: &'a mut R, ffu: &FfuMetadata, start: u64, size: u64) -> Result<Self> {
        Ok(Self {
            source,
            segments: ffu.segments(start, size)?,
            size,
            at: 0,
        })
    }
}
impl<R: Read + Seek> Read for View<'_, R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.size || b.is_empty() {
            return Ok(0);
        }
        let i = self
            .segments
            .partition_point(|s| s.output_offset + s.length <= self.at);
        let s = self
            .segments
            .get(i)
            .ok_or_else(|| std::io::Error::other("missing FFU segment"))?;
        let within = self.at - s.output_offset;
        let n = b.len().min((s.length - within).min(65536) as usize);
        if let Some(offset) = s.file_offset {
            self.source.seek(SeekFrom::Start(offset + within))?;
            self.source.read_exact(&mut b[..n])?;
        } else {
            b[..n].fill(0);
        }
        self.at += n as u64;
        Ok(n)
    }
}
impl<R> Seek for View<'_, R> {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        let at = match p {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(n) => self.at as i128 + n as i128,
            SeekFrom::End(n) => self.size as i128 + n as i128,
        };
        if at < 0 || at > self.size as i128 {
            return Err(std::io::Error::other("partition seek out of bounds"));
        }
        self.at = at as u64;
        Ok(self.at)
    }
}
fn boundary<F: FnMut(&str, u64, u64) -> bool>(
    f: &mut F,
    stage: &str,
    done: u64,
    total: u64,
) -> Result<()> {
    if f(stage, done, total) {
        Ok(())
    } else {
        Err(ImageError::Cancelled)
    }
}
/// Creates and re-reads a complete candidate ZIP in new scratch output. Images
/// are derived from a stock FFU; they are not installed-device backups or a
/// validated flash plan. Any error requires the caller to discard both outputs.
pub fn build<
    R: Read + Seek,
    S: Read + Write + Seek,
    W: Read + Write + Seek,
    F: FnMut(&str, u64, u64) -> bool,
>(
    source: &mut R,
    external: Option<Import<'_>>,
    loaders: &[Import<'_>],
    donor_boot: &[u8],
    scratch: &mut S,
    output: &mut W,
    progress: F,
) -> Result<Report> {
    build_with_catalog(
        source,
        external,
        loaders,
        donor_boot,
        scratch,
        output,
        progress,
        &PatchCatalog::bundled()?,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn build_with_catalog<
    R: Read + Seek,
    S: Read + Write + Seek,
    W: Read + Write + Seek,
    F: FnMut(&str, u64, u64) -> bool,
>(
    source: &mut R,
    external: Option<Import<'_>>,
    loaders: &[Import<'_>],
    donor_boot: &[u8],
    scratch: &mut S,
    output: &mut W,
    mut progress: F,
    catalog: &PatchCatalog,
) -> Result<Report> {
    boundary(&mut progress, "Validate imports", 0, 0)?;
    if output.seek(SeekFrom::End(0))? != 0
        || scratch.seek(SeekFrom::End(0))? != 0
        || loaders.len() > super::MAX_LOADERS
    {
        return Err(invalid(
            "package requires empty distinct scratch files and at most 32 loaders",
        ));
    }
    let ffu = FfuMetadata::open(source)?;
    if ffu.total_size > 16 * 1024 * 1024 * 1024 {
        return Err(invalid("package source FFU exceeds 16 GiB"));
    }
    let primary = ffu.read_disk(source, 0, layout::PRIMARY_SIZE)?;
    let gpt = layout::prepare(&primary, external.is_some())?;
    let mut originals = BTreeMap::new();
    for name in layout::BOOT {
        let (start, len) = gpt.original.partition(name)?.byte_range()?;
        if len > super::MAX_BOOT_IMAGE as u64 {
            return Err(invalid("boot partition exceeds 4 MiB"));
        }
        originals.insert(name, ffu.read_disk(source, start, len as usize)?);
    }
    let first = &originals["SBL1"];
    let first_image = super::parse(first, 0x2800)?;
    let first_target = gpt.prepared.partition("SBL1")?.byte_range()?.1;
    if first_image.image_offset + first_image.image_size > first_target as usize
        || first_target + 512 != first.len() as u64
    {
        return Err(invalid(
            "SBL1 payload would remove signed image bytes or target geometry differs",
        ));
    }
    let second = super::patch_boot(&originals["SBL2"], true)?;
    let extra = super::sbl1::generate(first, &second)?;
    let third_source = external
        .as_ref()
        .map(|v| v.bytes)
        .unwrap_or(&originals["SBL3"]);
    let third_image = super::parse(third_source, 0)?;
    if third_image.root_certificate_sha256 != first_image.root_certificate_sha256 {
        return Err(invalid(
            "SBL3 and stock SBL1 root certificate fingerprints differ",
        ));
    }
    let third = super::patch_boot(third_source, false)?;
    let (uefi, uefi_report) = super::uefi::rebuild(&originals["UEFI"])?;
    let mut transformed = vec![
        ("SBL1", first[..first_target as usize].to_vec()),
        ("HACK", extra),
        ("SBL2", second),
        ("SBL3", third),
        ("UEFI", uefi),
    ];
    for name in ["TZ", "RPM", "WINSECAPP"] {
        transformed.push((name, originals[name].clone()));
    }
    for (name, bytes) in &transformed {
        if bytes.len() as u64 > gpt.prepared.partition(name)?.byte_range()?.1 {
            return Err(invalid(format!(
                "{name} payload exceeds prepared partition"
            )));
        }
    }
    let marker: Vec<_> = "QHSUSB_ARMPRG"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut decoded_loaders = Vec::new();
    for loader in loaders {
        let bytes = super::decode_loader(loader.bytes)?;
        let image = super::parse(&bytes, 0)?;
        if image.root_certificate_sha256 != first_image.root_certificate_sha256
            || !bytes[image.image_offset..image.image_offset + image.code_size]
                .windows(marker.len())
                .any(|v| v == marker)
        {
            return Err(invalid(
                "imported loader lacks a matching root fingerprint or V1 marker",
            ));
        }
        decoded_loaders.push(bytes);
    }
    // Establish a complete source identity; neither chunk integrity nor this
    // fingerprint authenticates OEM trust, firmware applicability or a loader.
    let mut chunk_cancelled = false;
    ffu.verify_hashes(source, |done, total| {
        let keep = progress(
            "Verify stock FFU chunks",
            done * ffu.chunk_size as u64,
            total * ffu.chunk_size as u64,
        );
        chunk_cancelled |= !keep;
        keep
    })?;
    if chunk_cancelled {
        return Err(ImageError::Cancelled);
    }
    boundary(&mut progress, "Fingerprint stock FFU", 0, ffu.total_size)?;
    source.seek(SeekFrom::Start(0))?;
    let source_hash =
        crate::stream::copy_hashed(source, &mut std::io::sink(), ffu.total_size, |d, t| {
            progress("Fingerprint stock FFU", d, t)
        })?;
    let (esp_start, esp_len) = gpt.original.partition("EFIESP")?.byte_range()?;
    if esp_len > 128 * 1024 * 1024
        || gpt.prepared.partition("EFIESP")?.byte_range()? != (esp_start, esp_len)
    {
        return Err(invalid("unsupported EFIESP package geometry"));
    }
    boundary(&mut progress, "Assemble EFIESP", 0, esp_len)?;
    let esp_report = efiesp::assemble_with_catalog(
        &mut View::new(source, &ffu, esp_start, esp_len)?,
        scratch,
        donor_boot,
        |d, t| progress("Assemble EFIESP", d, t),
        catalog,
    )?;
    let mut archive = Archive::new(output);
    let mut restore = vec![Placement {
        path: "original/GPT-primary.bin".into(),
        reference_start_sector: 0,
        byte_length: primary.len() as u64,
    }];
    archive.bytes("original/GPT-primary.bin", &primary)?;
    // Capture all affected stock boot partitions, including low backup ranges
    // when upstream normalization swaps them with their active counterpart.
    let mut original_names: Vec<String> = layout::BOOT.iter().map(|n| n.to_string()).collect();
    original_names.extend(gpt.swapped.iter().map(|n| format!("BACKUP_{n}")));
    original_names.push("EFIESP".into());
    for name in &original_names {
        let (start, len) = gpt.original.partition(name)?.byte_range()?;
        if len > 128 * 1024 * 1024 {
            return Err(invalid("preserved partition exceeds package entry bound"));
        }
        let path = format!("original/{name}.img");
        archive.add(&path, len, |entry| {
            ffu.extract(source, entry, start, len, |d, t| {
                progress("Preserve FFU originals", d, t)
            })
        })?;
        restore.push(Placement {
            path,
            reference_start_sector: start / 512,
            byte_length: len,
        });
    }
    let mut prepared = vec![Placement {
        path: "prepared/GPT-primary.bin".into(),
        reference_start_sector: 0,
        byte_length: gpt.bytes.len() as u64,
    }];
    archive.bytes("prepared/GPT-primary.bin", &gpt.bytes)?;
    for (name, bytes) in &transformed {
        boundary(
            &mut progress,
            "Archive prepared boot images",
            0,
            bytes.len() as u64,
        )?;
        let path = format!("prepared/{name}.img");
        archive.bytes(&path, bytes)?;
        prepared.push(Placement {
            path,
            reference_start_sector: gpt.prepared.partition(name)?.first_sector,
            byte_length: bytes.len() as u64,
        });
    }
    scratch.seek(SeekFrom::Start(0))?;
    archive.add("prepared/EFIESP.img", esp_len, |entry| {
        crate::stream::copy_hashed(scratch, entry, esp_len, |d, t| {
            progress("Archive assembled EFIESP", d, t)
        })
        .map(|_| ())
    })?;
    prepared.push(Placement {
        path: "prepared/EFIESP.img".into(),
        reference_start_sector: esp_start / 512,
        byte_length: esp_len,
    });
    if let Some(ref external) = external {
        archive.bytes("imports/SBL3.bin", external.bytes)?;
    }
    for (i, (original, decoded)) in loaders.iter().zip(&decoded_loaders).enumerate() {
        archive.bytes(
            &format!("imports/loader-{:02}.source", i + 1),
            original.bytes,
        )?;
        archive.bytes(&format!("imports/loader-{:02}.mbn", i + 1), decoded)?;
    }
    archive.bytes(
        "reports/uefi.json",
        &serde_json::to_vec_pretty(&uefi_report).map_err(|e| invalid(e.to_string()))?,
    )?;
    archive.bytes(
        "reports/efiesp.json",
        &serde_json::to_vec_pretty(&esp_report).map_err(|e| invalid(e.to_string()))?,
    )?;
    archive.bytes("README.txt",b"OFFLINE REFERENCE PACKAGE. NOT AUTHORIZED FOR DEVICE WRITES.\nOriginals come from the selected stock FFU, not the installed phone.\nSignature-invalidated images and reference GPT coordinates require independent review and live preflight.\nSee manifest.json for recovery coverage and missing requirements.\n")?;
    let manifest=Manifest{schema:1,kind:"wpi-spec-a-offline-reference".into(),upstream_revision:super::UPSTREAM.into(),
        source_platform:ffu.platform_id.clone(),source_ffu_size:ffu.total_size,source_ffu_sha256:source_hash,source_chunk_integrity:"passed".into(),
        source_gpt:gpt.original,prepared_gpt:gpt.prepared,normalized_backup_pairs:gpt.swapped,external_sbl3:external.is_some(),files:archive.files(),prepared,restore,
        originals_are_installed_backup:false,backup_gpt_captured:false,phone_writes_enabled:false,
        execution_blockers:vec!["Reference coordinates come from the FFU, not a fresh live GPT; backup GPT is not captured.".into(),
            "Installed originals, device RRKH/security state, applicability and recovery are unvalidated.".into(),
            "Boot signatures are invalidated by patches; imported loader/SBL3 engineering status and donor suitability are unverified.".into(),
            "No native or browser unlock executor is implemented; this manifest is not a flash plan.".into()]};
    let encoded = serde_json::to_vec_pretty(&manifest).map_err(|e| invalid(e.to_string()))?;
    let manifest_hash = super::hash(&encoded);
    archive.bytes("manifest.json", &encoded)?;
    let finished = archive.finish()?;
    boundary(&mut progress, "Verify package output", 0, finished.size)?;
    let sha = finished.verify(output, |d, t| progress("Verify package output", d, t))?;
    Ok(Report {
        size: finished.size,
        resulting_sha256: sha,
        manifest_sha256: manifest_hash,
        integrity_verified: true,
        phone_writes_enabled: false,
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    const SOURCE: &[u8] = include_bytes!("../../../../tests/fixtures/synthetic-spec-a-package.ffu");
    fn catalog() -> PatchCatalog {
        PatchCatalog::parse(&format!(r#"<PatchDefinitions><PatchDefinition Name="SecureBootHack-V1.1-EFIESP"><TargetVersions><TargetVersion Description="synthetic"><TargetFiles><TargetFile Path="{}" HashOriginal="{}" HashPatched="{}"><Patches><Patch Address="0x2" OriginalBytes="6364" PatchedBytes="5859" /></Patches><Obsolete /></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>"#,efiesp::PATH,crate::patch::sha1(b"abcdefgh"),crate::patch::sha1(b"abXYefgh"))).unwrap()
    }
    #[test]
    fn complete_package_binds_originals_transform_hashes_and_restore_coordinates() {
        let mut source = Cursor::new(SOURCE);
        let mut scratch = Cursor::new(Vec::new());
        let mut output = Cursor::new(Vec::new());
        let report = build_with_catalog(
            &mut source,
            None,
            &[],
            b"abcdefgh",
            &mut scratch,
            &mut output,
            |_, _, _| true,
            &catalog(),
        )
        .unwrap();
        assert!(report.integrity_verified && !report.phone_writes_enabled);
        assert!(
            !report.manifest.originals_are_installed_backup && !report.manifest.backup_gpt_captured
        );
        assert_eq!(
            report.resulting_sha256,
            super::super::hash(output.get_ref())
        );
        assert_eq!(
            report.manifest.source_ffu_sha256,
            super::super::hash(SOURCE)
        );
        assert_eq!(report.manifest.restore.len(), 9);
        let manifest = report
            .manifest
            .files
            .iter()
            .map(|f| (f.path.as_str(), f))
            .collect::<BTreeMap<_, _>>();
        for f in &report.manifest.files {
            let start = f.data_offset as usize;
            assert_eq!(
                super::super::hash(&output.get_ref()[start..start + f.size as usize]),
                f.sha256
            );
        }
        let old = manifest["original/SBL1.img"];
        let new = manifest["prepared/SBL1.img"];
        assert_eq!(old.size, new.size + 512);
        let gpt = manifest["prepared/GPT-primary.bin"];
        let original = manifest["original/GPT-primary.bin"];
        let get = |f: &FileRecord| {
            &output.get_ref()[f.data_offset as usize..(f.data_offset + f.size) as usize]
        };
        assert_eq!(
            layout::restore(get(gpt), get(original), false).unwrap(),
            get(original)
        );
        assert_eq!(&output.get_ref()[..4], b"PK\x03\x04");
    }
    #[test]
    fn corrupt_source_and_unrecognized_donor_cannot_complete_a_package() {
        let mut bad = SOURCE.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        let result = build_with_catalog(
            &mut Cursor::new(bad),
            None,
            &[],
            b"abcdefgh",
            &mut Cursor::new(Vec::new()),
            &mut Cursor::new(Vec::new()),
            |_, _, _| true,
            &catalog(),
        );
        assert!(result.unwrap_err().to_string().contains("FFU hash"));
        assert!(build_with_catalog(
            &mut Cursor::new(SOURCE),
            None,
            &[],
            b"unknown",
            &mut Cursor::new(Vec::new()),
            &mut Cursor::new(Vec::new()),
            |_, _, _| true,
            &catalog()
        )
        .is_err());
    }
    #[test]
    fn backup_normalization_cannot_place_a_larger_payload_in_a_smaller_target() {
        let mut bytes = SOURCE.to_vec();
        let f = FfuMetadata::open(&mut Cursor::new(SOURCE)).unwrap();
        let at = f.header_size as usize;
        let entry = &mut bytes[at + 1024 + 8 * 128..at + 1024 + 9 * 128];
        entry[..16].fill(99);
        entry[16..32].fill(100);
        entry[32..40].copy_from_slice(&0xf0u64.to_le_bytes());
        entry[40..48].copy_from_slice(&0xf7u64.to_le_bytes());
        let name: Vec<_> = "BACKUP_TZ"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        entry[56..56 + name.len()].copy_from_slice(&name);
        let crc = crc32fast::hash(&bytes[at + 1024..at + layout::PRIMARY_SIZE]);
        bytes[at + 600..at + 604].copy_from_slice(&crc.to_le_bytes());
        bytes[at + 528..at + 532].fill(0);
        let crc = crc32fast::hash(&bytes[at + 512..at + 604]);
        bytes[at + 528..at + 532].copy_from_slice(&crc.to_le_bytes());
        let result = build_with_catalog(
            &mut Cursor::new(bytes),
            None,
            &[],
            b"abcdefgh",
            &mut Cursor::new(Vec::new()),
            &mut Cursor::new(Vec::new()),
            |_, _, _| true,
            &catalog(),
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("TZ payload exceeds"));
    }
    #[test]
    fn cancellation_at_the_final_chunk_verification_boundary_is_not_lost() {
        let result = build_with_catalog(
            &mut Cursor::new(SOURCE),
            None,
            &[],
            b"abcdefgh",
            &mut Cursor::new(Vec::new()),
            &mut Cursor::new(Vec::new()),
            |stage, done, total| stage != "Verify stock FFU chunks" || done != total,
            &catalog(),
        );
        assert!(matches!(result, Err(ImageError::Cancelled)));
    }
    #[test]
    fn cancellation_during_source_copy_or_output_verification_never_reports_success() {
        for stop in [
            "Verify stock FFU chunks",
            "Fingerprint stock FFU",
            "Preserve FFU originals",
            "Archive assembled EFIESP",
            "Verify package output",
        ] {
            let mut seen = false;
            let result = build_with_catalog(
                &mut Cursor::new(SOURCE),
                None,
                &[],
                b"abcdefgh",
                &mut Cursor::new(Vec::new()),
                &mut Cursor::new(Vec::new()),
                |stage, _, _| {
                    if stage == stop {
                        seen = true;
                        false
                    } else {
                        true
                    }
                },
                &catalog(),
            );
            assert!(seen, "{stop}");
            assert!(matches!(result, Err(ImageError::Cancelled)), "{stop}");
        }
    }
    #[test]
    fn external_sbl3_and_programmers_are_preserved_without_granting_device_access() {
        let third = include_bytes!("../../../../tests/fixtures/spec-a/sbl3.bin");
        let loader = include_bytes!("../../../../tests/fixtures/spec-a/loader.hex");
        let make = || {
            build_with_catalog(
                &mut Cursor::new(SOURCE),
                Some(Import {
                    name: "SBL3",
                    bytes: third,
                }),
                &[Import {
                    name: "loader",
                    bytes: loader,
                }],
                b"abcdefgh",
                &mut Cursor::new(Vec::new()),
                &mut Cursor::new(Vec::new()),
                |_, _, _| true,
                &catalog(),
            )
        };
        let report = make().unwrap();
        assert!(report.manifest.external_sbl3);
        assert_eq!(
            report
                .manifest
                .prepared_gpt
                .partition("IS_UNLOCKED_SBL3")
                .unwrap()
                .first_sector,
            64
        );
        assert!(report
            .manifest
            .files
            .iter()
            .any(|f| f.path == "imports/loader-01.mbn"));
        assert_eq!(report.resulting_sha256, make().unwrap().resulting_sha256);
        let mut invalid = third.to_vec();
        invalid[40 + 20] ^= 1;
        assert!(build_with_catalog(
            &mut Cursor::new(SOURCE),
            Some(Import {
                name: "bad",
                bytes: &invalid
            }),
            &[],
            b"abcdefgh",
            &mut Cursor::new(Vec::new()),
            &mut Cursor::new(Vec::new()),
            |_, _, _| true,
            &catalog()
        )
        .is_err());
    }
}
