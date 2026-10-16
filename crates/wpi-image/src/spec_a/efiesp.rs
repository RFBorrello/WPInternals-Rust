//! Bounded EFIESP file/catalog checks and assembly into a separate local copy.
use crate::{ffu::FfuMetadata, filesystem, gpt::Gpt, invalid, patch::PatchCatalog, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom, Write},
};
pub const PATH: &str = "Windows/System32/Boot/mobilestartup.efi";
const DEFINITION: &str = "SecureBootHack-V1.1-EFIESP";
pub const BCD_PATH: &str = "efi/Microsoft/Boot/BCD";
const MAX_IMAGE: u64 = 128 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub path: String,
    pub size: Option<usize>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub status: String,
    pub catalog_target_descriptions: Vec<String>,
    pub prepared_copy_sha256: Option<String>,
    pub bcd_present: bool,
    pub bcd_sha256: Option<String>,
    pub bcd_editing_implemented: bool,
}
pub fn assess(bytes: Option<&[u8]>, bcd: Option<&[u8]>) -> Result<Report> {
    assess_with_catalog(bytes, bcd, &PatchCatalog::bundled()?)
}
fn assess_with_catalog(
    bytes: Option<&[u8]>,
    bcd: Option<&[u8]>,
    catalog: &PatchCatalog,
) -> Result<Report> {
    if bytes.is_some_and(|v| v.len() > 4 * 1024 * 1024)
        || bcd.is_some_and(|v| v.len() > 1024 * 1024)
    {
        return Err(invalid(
            "EFIESP boot target exceeds 4 MiB or BCD exceeds 1 MiB",
        ));
    }
    let mut report = Report {
        path: PATH.into(),
        size: bytes.map(<[u8]>::len),
        sha256: bytes.map(|v| hex::encode(Sha256::digest(v))),
        sha1: bytes.map(crate::patch::sha1),
        status: "missing".into(),
        catalog_target_descriptions: Vec::new(),
        prepared_copy_sha256: None,
        bcd_present: bcd.is_some(),
        bcd_sha256: bcd.map(|v| hex::encode(Sha256::digest(v))),
        bcd_editing_implemented: true,
    };
    let Some(bytes) = bytes else {
        return Ok(report);
    };
    let definition = catalog
        .definitions
        .iter()
        .find(|v| v.name == DEFINITION)
        .ok_or_else(|| invalid("missing pinned EFIESP definition"))?;
    let hash = crate::patch::sha1(bytes);
    for version in &definition.versions.versions {
        if version.files.files.len() != 1
            || crate::patch::safe_relative_path(&version.files.files[0].path)?.to_lowercase()
                != PATH.to_lowercase()
        {
            return Err(invalid("unsupported EFIESP patch-catalog target set"));
        }
        let target = &version.files.files[0];
        if target.hash_original.eq_ignore_ascii_case(&hash)
            || target.hash_patched.eq_ignore_ascii_case(&hash)
            || target
                .obsolete
                .files
                .iter()
                .any(|v| v.hash_patched.eq_ignore_ascii_case(&hash))
        {
            report
                .catalog_target_descriptions
                .push(version.description.clone());
        }
    }
    if report.catalog_target_descriptions.is_empty() {
        report.status = "unsupported_donor_required".into();
        return Ok(report);
    }
    // The existing patch engine verifies all expected bytes and resulting hash
    // on an ephemeral copy. No modified file or partition is written/exported.
    let (_, patched) = catalog.prepare(DEFINITION, false, |path| {
        if !path.eq_ignore_ascii_case(PATH) {
            return Err(invalid("unexpected EFIESP target path"));
        }
        Ok(bytes.to_vec())
    })?;
    if patched.len() != 1 {
        return Err(invalid("ambiguous EFIESP patch result"));
    }
    report.status = if patched[0].bytes == bytes {
        "already_patched_supported"
    } else {
        "original_supported"
    }
    .into();
    report.prepared_copy_sha256 = Some(hex::encode(Sha256::digest(&patched[0].bytes)));
    Ok(report)
}
pub fn inspect<R: Read + Seek>(reader: &mut R, ffu: &FfuMetadata, gpt: &Gpt) -> Result<Report> {
    crate::partition::with_partition(
        "EFIESP",
        reader,
        ffu,
        gpt,
        |_, _| true,
        |partition| {
            let boot = filesystem::read_small_fat_file(partition, PATH, 4 * 1024 * 1024)?;
            let bcd =
                filesystem::read_small_fat_file(partition, "efi/Microsoft/Boot/BCD", 1024 * 1024)?;
            Ok(Some(assess(boot.as_deref(), bcd.as_deref())?))
        },
    )?
    .ok_or_else(|| invalid("EFIESP partition is missing"))
}
pub fn boot_from_ffu<R: Read + Seek>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
) -> Result<Vec<u8>> {
    crate::partition::with_partition(
        "EFIESP",
        reader,
        ffu,
        gpt,
        |_, _| true,
        |partition| filesystem::read_small_fat_file(partition, PATH, 4 * 1024 * 1024),
    )?
    .ok_or_else(|| invalid("donor boot file missing"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblyReport {
    pub original_sha256: String,
    pub resulting_sha256: String,
    pub size: u64,
    pub boot_sha256: String,
    pub bcd: super::bcd::Report,
    pub preserved_other_files: bool,
    pub phone_writes_enabled: bool,
}
// Bound every filesystem call, including malformed allocation chains. Underlying
// files may be ordinary files or browser scratch-file callbacks, never devices.
struct Bounded<'a, T> {
    io: &'a mut T,
    len: u64,
    calls: usize,
    bytes: u64,
}
impl<T> Bounded<'_, T> {
    fn tick(&mut self, n: usize) -> std::io::Result<()> {
        self.calls += 1;
        self.bytes += n as u64;
        if self.calls > 262144 || self.bytes > MAX_IMAGE * 8 {
            return Err(std::io::Error::other("FAT I/O budget exceeded"));
        }
        Ok(())
    }
}
impl<T: Seek> Seek for Bounded<'_, T> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.tick(0)?;
        let at = self.io.seek(pos)?;
        if at > self.len {
            return Err(std::io::Error::other("FAT seek exceeds image"));
        }
        Ok(at)
    }
}
impl<T: Read + Seek> Read for Bounded<'_, T> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.tick(b.len())?;
        let left = self.len.saturating_sub(self.io.stream_position()?);
        let n = b.len().min(left as usize);
        self.io.read(&mut b[..n])
    }
}
impl<T: Write + Seek> Write for Bounded<'_, T> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.tick(b.len())?;
        if b.len() as u64 > self.len.saturating_sub(self.io.stream_position()?) {
            return Err(std::io::Error::other("FAT write exceeds image"));
        }
        self.io.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}
struct ReadOnly<'a, T>(&'a mut T);
impl<T: Read> Read for ReadOnly<'_, T> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}
impl<T: Seek> Seek for ReadOnly<'_, T> {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(p)
    }
}
impl<T> Write for ReadOnly<'_, T> {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("source is read only"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn inventory<R: Read + Seek>(reader: &mut R, size: u64) -> Result<BTreeMap<String, String>> {
    fn walk<T: fatfs::ReadWriteSeek>(
        dir: fatfs::Dir<'_, T>,
        prefix: &str,
        out: &mut BTreeMap<String, String>,
        depth: usize,
        budget: &mut u64,
    ) -> Result<()> {
        if depth > 16 {
            return Err(invalid("FAT directory depth exceeds limit"));
        }
        for entry in dir.iter() {
            let entry = entry?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            if out.len() >= 4096 {
                return Err(invalid("FAT entry count exceeds limit"));
            }
            let path = format!("{prefix}{}", name.to_lowercase());
            crate::patch::safe_relative_path(&path)?;
            if out.contains_key(&path) {
                return Err(invalid("duplicate FAT path"));
            }
            if entry.is_dir() {
                out.insert(path.clone(), "directory".into());
                walk(entry.to_dir(), &format!("{path}/"), out, depth + 1, budget)?;
            } else {
                let mut file = entry.to_file();
                let mut hash = Sha256::new();
                let mut buf = [0; 65536];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    *budget += n as u64;
                    if *budget > MAX_IMAGE {
                        return Err(invalid("FAT inventory byte budget exceeded"));
                    }
                    hash.update(&buf[..n]);
                }
                out.insert(path, hex::encode(hash.finalize()));
            }
        }
        Ok(())
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut read_only = ReadOnly(reader);
    let fs = fatfs::FileSystem::new(
        Bounded {
            io: &mut read_only,
            len: size,
            calls: 0,
            bytes: 0,
        },
        fatfs::FsOptions::new(),
    )?;
    let mut out = BTreeMap::new();
    walk(fs.root_dir(), "", &mut out, 0, &mut 0)?;
    fs.unmount()?;
    Ok(out)
}
/// Copies a bounded extracted FAT image in chunks, replacing the boot file with
/// a verified catalog-patched donor and editing BCD. Destination must be a new
/// empty scratch file. Caller publishes it only after successful verification.
pub fn assemble<R: Read + Seek, W: Read + Write + Seek, F: FnMut(u64, u64) -> bool>(
    source: &mut R,
    destination: &mut W,
    donor_boot: &[u8],
    progress: F,
) -> Result<AssemblyReport> {
    assemble_with_catalog(
        source,
        destination,
        donor_boot,
        progress,
        &PatchCatalog::bundled()?,
    )
}
pub(super) fn assemble_with_catalog<
    R: Read + Seek,
    W: Read + Write + Seek,
    F: FnMut(u64, u64) -> bool,
>(
    source: &mut R,
    destination: &mut W,
    donor_boot: &[u8],
    progress: F,
    catalog: &PatchCatalog,
) -> Result<AssemblyReport> {
    let size = source.seek(SeekFrom::End(0))?;
    if size == 0 || size > MAX_IMAGE || destination.seek(SeekFrom::End(0))? != 0 {
        return Err(invalid(
            "EFIESP requires a bounded image and an empty separate destination",
        ));
    }
    let info = filesystem::inspect(source)?;
    if !info.kind.starts_with("FAT")
        || info.total_sectors * u64::from(info.bytes_per_sector) != size
    {
        return Err(invalid(
            "EFIESP geometry must exactly fill its partition image",
        ));
    }
    let mut expected = inventory(source, size)?;
    if !expected.contains_key(&PATH.to_lowercase()) {
        return Err(invalid("stock boot file missing"));
    }
    let mut bounded = Bounded {
        io: source,
        len: size,
        calls: 0,
        bytes: 0,
    };
    let bcd = filesystem::read_small_fat_file(&mut bounded, BCD_PATH, 1024 * 1024)?
        .ok_or_else(|| invalid("stock BCD missing"))?;
    let (bcd, bcd_report) = super::bcd::patch(&bcd)?;
    if donor_boot.len() > 4 * 1024 * 1024 {
        return Err(invalid("donor boot exceeds 4 MiB"));
    }
    let (_, patched) = catalog.prepare(DEFINITION, false, |p| {
        if !p.eq_ignore_ascii_case(PATH) {
            return Err(invalid("unexpected catalog path"));
        }
        Ok(donor_boot.to_vec())
    })?;
    if patched.len() != 1 {
        return Err(invalid("expected one donor boot target"));
    }
    let boot = &patched[0].bytes;
    let boot_hash = hex::encode(Sha256::digest(boot));
    expected.insert(PATH.to_lowercase(), boot_hash.clone());
    expected.insert(BCD_PATH.to_lowercase(), bcd_report.resulting_sha256.clone());
    bounded.seek(SeekFrom::Start(0))?;
    destination.seek(SeekFrom::Start(0))?;
    let original_sha256 = crate::stream::copy_hashed(&mut bounded, destination, size, progress)?;
    destination.seek(SeekFrom::Start(0))?;
    let fs = fatfs::FileSystem::new(
        Bounded {
            io: &mut *destination,
            len: size,
            calls: 0,
            bytes: 0,
        },
        fatfs::FsOptions::new(),
    )?;
    for (path, data) in [(PATH, boot.as_slice()), (BCD_PATH, bcd.as_slice())] {
        let mut file = fs.root_dir().open_file(path)?;
        file.seek(SeekFrom::Start(0))?;
        file.truncate()?;
        file.write_all(data)?;
        file.flush()?;
    }
    fs.unmount()?;
    if destination.seek(SeekFrom::End(0))? != size || inventory(destination, size)? != expected {
        return Err(invalid(
            "EFIESP verification failed: unrelated files or target data changed",
        ));
    }
    destination.seek(SeekFrom::Start(0))?;
    let resulting_sha256 =
        crate::stream::copy_hashed(destination, &mut std::io::sink(), size, |_, _| true)?;
    Ok(AssemblyReport {
        original_sha256,
        resulting_sha256,
        size,
        boot_sha256: boot_hash,
        bcd: bcd_report,
        preserved_other_files: true,
        phone_writes_enabled: false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        use std::io::Cursor;
        let mut disk = Cursor::new(vec![0; 4 * 1024 * 1024]);
        fatfs::format_volume(&mut disk, fatfs::FormatVolumeOptions::new()).unwrap();
        disk.set_position(0);
        let fs = fatfs::FileSystem::new(&mut disk, fatfs::FsOptions::new()).unwrap();
        let root = fs.root_dir();
        let windows = root.create_dir("Windows").unwrap();
        let system = windows.create_dir("System32").unwrap();
        let boot = system.create_dir("Boot").unwrap();
        boot.create_file("mobilestartup.efi")
            .unwrap()
            .write_all(b"old boot")
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
        root.create_file("preserve.txt")
            .unwrap()
            .write_all(b"untouched other file")
            .unwrap();
        drop((boot2, ms, efi, boot, system, windows, root));
        fs.unmount().unwrap();
        disk.into_inner()
    }
    fn catalog(original: &[u8], patched: &[u8]) -> PatchCatalog {
        PatchCatalog::parse(&format!(r#"<PatchDefinitions><PatchDefinition Name="{DEFINITION}"><TargetVersions><TargetVersion Description="synthetic"><TargetFiles><TargetFile Path="{PATH}" HashOriginal="{}" HashPatched="{}"><Patches><Patch Address="0x2" OriginalBytes="6364" PatchedBytes="5859" /></Patches><Obsolete /></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>"#,crate::patch::sha1(original),crate::patch::sha1(patched))).unwrap()
    }
    #[test]
    fn assembly_reallocates_larger_boot_preserves_other_files_and_source() {
        use std::io::Cursor;
        let original = fixture();
        let mut donor = b"abcdefgh".to_vec();
        donor.resize(4096, 42);
        let mut patched = donor.clone();
        patched[2..4].copy_from_slice(b"XY");
        let mut source = Cursor::new(original.clone());
        let mut output = Cursor::new(Vec::new());
        let report = assemble_with_catalog(
            &mut source,
            &mut output,
            &donor,
            |_, _| true,
            &catalog(&donor, &patched),
        )
        .unwrap();
        assert_eq!(source.into_inner(), original);
        assert_eq!(output.get_ref().len(), original.len());
        assert_eq!(
            filesystem::read_small_fat_file(&mut output, PATH, 8192)
                .unwrap()
                .unwrap(),
            patched
        );
        assert_eq!(
            filesystem::read_small_fat_file(&mut output, "preserve.txt", 100)
                .unwrap()
                .unwrap(),
            b"untouched other file"
        );
        assert_eq!(report.bcd.created_elements, 2);
        assert!(report.preserved_other_files && !report.phone_writes_enabled);
    }
    #[test]
    fn cancellation_unsupported_donor_nonempty_output_and_bad_bcd_never_succeed() {
        use std::io::Cursor;
        let original = fixture();
        let donor = b"abcdefgh";
        let cat = catalog(donor, b"abXYefgh");
        let mut output = Cursor::new(Vec::new());
        let result = assemble_with_catalog(
            &mut Cursor::new(&original),
            &mut output,
            donor,
            |_, _| false,
            &cat,
        );
        assert!(matches!(result, Err(crate::ImageError::Cancelled)));
        assert!(output.get_ref().is_empty());
        assert!(assemble_with_catalog(
            &mut Cursor::new(&original),
            &mut output,
            b"unrecognized",
            |_, _| true,
            &cat
        )
        .is_err());
        output.write_all(b"existing").unwrap();
        assert!(assemble_with_catalog(
            &mut Cursor::new(&original),
            &mut output,
            donor,
            |_, _| true,
            &cat
        )
        .is_err());
        let mut bad = Cursor::new(original);
        {
            let fs = fatfs::FileSystem::new(&mut bad, fatfs::FsOptions::new()).unwrap();
            fs.root_dir()
                .open_file(BCD_PATH)
                .unwrap()
                .write_all(b"BAD!")
                .unwrap();
            fs.unmount().unwrap();
        }
        assert!(assemble_with_catalog(
            &mut bad,
            &mut Cursor::new(Vec::new()),
            donor,
            |_, _| true,
            &cat
        )
        .is_err());
    }
    #[test]
    fn catalog_match_requires_expected_bytes_and_result_hash_without_mutating_original() {
        let original = b"abcdefgh";
        let patched = b"abXYefgh";
        let xml = format!(
            r#"<PatchDefinitions><PatchDefinition Name="{DEFINITION}"><TargetVersions><TargetVersion Description="synthetic"><TargetFiles><TargetFile Path="{PATH}" HashOriginal="{}" HashPatched="{}"><Patches><Patch Address="0x2" OriginalBytes="6364" PatchedBytes="5859" /></Patches><Obsolete /></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>"#,
            crate::patch::sha1(original),
            crate::patch::sha1(patched)
        );
        let catalog = PatchCatalog::parse(&xml).unwrap();
        let report = assess_with_catalog(Some(original), None, &catalog).unwrap();
        assert_eq!(report.status, "original_supported");
        assert_eq!(
            report.prepared_copy_sha256,
            Some(hex::encode(Sha256::digest(patched)))
        );
        assert_eq!(original, b"abcdefgh");
        assert_eq!(
            assess_with_catalog(Some(patched), None, &catalog)
                .unwrap()
                .status,
            "already_patched_supported"
        );
        let wrong =
            PatchCatalog::parse(&xml.replace("OriginalBytes=\"6364\"", "OriginalBytes=\"ffff\""))
                .unwrap();
        assert!(assess_with_catalog(Some(original), None, &wrong).is_err());
    }
}
