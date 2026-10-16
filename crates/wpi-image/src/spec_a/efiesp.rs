//! Bounded EFIESP file/catalog applicability. No BCD edits or FAT writes.
use crate::{ffu::FfuMetadata, filesystem, gpt::Gpt, invalid, patch::PatchCatalog, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
pub const PATH: &str = "Windows/System32/Boot/mobilestartup.efi";
const DEFINITION: &str = "SecureBootHack-V1.1-EFIESP";
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
        bcd_editing_implemented: false,
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

#[cfg(test)]
mod tests {
    use super::*;
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
