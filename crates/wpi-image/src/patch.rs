//! Hash-pinned, reversible file patching using the upstream 2.9.2 catalog.
//! Copyright (c) 2018 Rene Lergner. See THIRD_PARTY_NOTICES.md.
use crate::{invalid, slice, ImageError, Result, MAX_METADATA};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "PatchDefinitions")]
pub struct PatchCatalog {
    #[serde(rename = "PatchDefinition", default)]
    pub definitions: Vec<PatchDefinition>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct PatchDefinition {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "TargetVersions")]
    pub versions: TargetVersions,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TargetVersions {
    #[serde(rename = "TargetVersion", default)]
    pub versions: Vec<TargetVersion>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TargetVersion {
    #[serde(rename = "@Description")]
    pub description: String,
    #[serde(rename = "TargetFiles")]
    pub files: TargetFiles,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TargetFiles {
    #[serde(rename = "TargetFile", default)]
    pub files: Vec<TargetFile>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TargetFile {
    #[serde(rename = "@Path")]
    pub path: String,
    #[serde(rename = "@HashOriginal")]
    pub hash_original: String,
    #[serde(rename = "@HashPatched")]
    pub hash_patched: String,
    #[serde(rename = "Patches")]
    pub patches: Patches,
    #[serde(rename = "Obsolete", default)]
    pub obsolete: TargetFiles,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Patches {
    #[serde(rename = "Patch", default)]
    pub patches: Vec<BytePatch>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct BytePatch {
    #[serde(rename = "@Address")]
    pub address: String,
    #[serde(rename = "@OriginalBytes")]
    pub original: String,
    #[serde(rename = "@PatchedBytes")]
    pub patched: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct PatchSummary {
    pub name: String,
    pub versions: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct PatchedFile {
    pub path: String,
    pub bytes: Vec<u8>,
    pub original_sha1: String,
    pub resulting_sha1: String,
}

pub fn sha1(bytes: &[u8]) -> String {
    hex::encode_upper(Sha1::digest(bytes))
}
pub fn safe_relative_path(path: &str) -> Result<String> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty()
        || normalized
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.contains(':') || p.contains('\0'))
    {
        return Err(invalid(
            "patch path must be a relative file path without traversal",
        ));
    }
    Ok(normalized)
}
impl PatchCatalog {
    pub fn parse(xml: &str) -> Result<Self> {
        if xml.len() > MAX_METADATA {
            return Err(invalid("patch catalog exceeds metadata limit"));
        }
        let catalog: Self =
            quick_xml::de::from_str(xml).map_err(|e| invalid(format!("patch XML: {e}")))?;
        for definition in &catalog.definitions {
            if definition.versions.versions.is_empty() {
                return Err(invalid("empty patch definition"));
            }
            for version in &definition.versions.versions {
                if version.files.files.is_empty() {
                    return Err(invalid("empty target version"));
                }
                for file in &version.files.files {
                    validate_file(file)?;
                }
            }
        }
        Ok(catalog)
    }
    pub fn bundled() -> Result<Self> {
        Self::parse(include_str!(
            "../../../resources/upstream/PatchDefinitions.xml"
        ))
    }
    pub fn summaries(&self) -> Vec<PatchSummary> {
        self.definitions
            .iter()
            .map(|d| PatchSummary {
                name: d.name.clone(),
                versions: d
                    .versions
                    .versions
                    .iter()
                    .map(|v| v.description.clone())
                    .collect(),
            })
            .collect()
    }
    /// Loads and validates every file before returning any modified bytes.
    /// Callers must write the results to new artifacts, never over the source.
    pub fn prepare<F: FnMut(&str) -> Result<Vec<u8>>>(
        &self,
        name: &str,
        reverse: bool,
        mut load: F,
    ) -> Result<(String, Vec<PatchedFile>)> {
        let definition = self
            .definitions
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| invalid("unknown patch definition"))?;
        let mut cache = BTreeMap::new();
        let mut total = 0usize;
        for version in &definition.versions.versions {
            let mut matching = true;
            for target in &version.files.files {
                let path = safe_relative_path(&target.path)?;
                if !cache.contains_key(&path) {
                    let data = load(&path)?;
                    if data.len() > MAX_METADATA {
                        return Err(invalid("patch target exceeds 32 MiB"));
                    }
                    total = total
                        .checked_add(data.len())
                        .ok_or_else(|| invalid("patch memory overflow"))?;
                    if total > MAX_METADATA * 4 {
                        return Err(invalid("patch targets exceed 128 MiB"));
                    }
                    cache.insert(path.clone(), data);
                }
                let hash = sha1(&cache[&path]);
                if hash != target.hash_original.to_uppercase()
                    && hash != target.hash_patched.to_uppercase()
                    && !target
                        .obsolete
                        .files
                        .iter()
                        .any(|o| o.hash_patched.eq_ignore_ascii_case(&hash))
                {
                    matching = false;
                    break;
                }
            }
            if !matching {
                continue;
            }
            let mut output = Vec::new();
            for target in &version.files.files {
                let path = safe_relative_path(&target.path)?;
                let mut bytes = cache[&path].clone();
                let before = sha1(&bytes);
                if before != target.hash_original.to_uppercase()
                    && before != target.hash_patched.to_uppercase()
                {
                    let obsolete = target
                        .obsolete
                        .files
                        .iter()
                        .find(|o| o.hash_patched.eq_ignore_ascii_case(&before))
                        .ok_or_else(|| invalid("obsolete patch mismatch"))?;
                    apply(&mut bytes, obsolete, true)?;
                }
                let desired = if reverse {
                    &target.hash_original
                } else {
                    &target.hash_patched
                };
                if !sha1(&bytes).eq_ignore_ascii_case(desired) {
                    apply(&mut bytes, target, reverse)?;
                }
                let after = sha1(&bytes);
                if !after.eq_ignore_ascii_case(desired) {
                    return Err(invalid("patched file hash does not match catalog"));
                }
                output.push(PatchedFile {
                    path,
                    bytes,
                    original_sha1: before,
                    resulting_sha1: after,
                });
            }
            return Ok((version.description.clone(), output));
        }
        Err(ImageError::Unsupported(
            "no catalog version matches every target file hash".into(),
        ))
    }
}
fn decode(p: &BytePatch) -> Result<(usize, Vec<u8>, Vec<u8>)> {
    let address = p
        .address
        .strip_prefix("0x")
        .or_else(|| p.address.strip_prefix("0X"))
        .ok_or_else(|| invalid("patch address must be hex"))?;
    let offset =
        usize::from_str_radix(address, 16).map_err(|_| invalid("invalid patch address"))?;
    let original = hex::decode(&p.original).map_err(|_| invalid("invalid original patch bytes"))?;
    let patched =
        hex::decode(&p.patched).map_err(|_| invalid("invalid replacement patch bytes"))?;
    if original.is_empty() || original.len() != patched.len() {
        return Err(invalid("patches must preserve file length"));
    }
    Ok((offset, original, patched))
}
fn validate_file(file: &TargetFile) -> Result<()> {
    safe_relative_path(&file.path)?;
    for hash in [&file.hash_original, &file.hash_patched] {
        if hex::decode(hash)
            .map_err(|_| invalid("invalid SHA-1"))?
            .len()
            != 20
        {
            return Err(invalid("invalid SHA-1 length"));
        }
    }
    let mut ranges = Vec::new();
    for patch in &file.patches.patches {
        let (offset, bytes, _) = decode(patch)?;
        ranges.push((
            offset,
            offset
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("patch offset overflow"))?,
        ));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|r| r[0].1 > r[1].0) {
        return Err(invalid("overlapping byte patches"));
    }
    for obsolete in &file.obsolete.files {
        validate_file(obsolete)?;
    }
    Ok(())
}
fn apply(bytes: &mut [u8], file: &TargetFile, reverse: bool) -> Result<()> {
    let expected = if reverse {
        &file.hash_patched
    } else {
        &file.hash_original
    };
    if !sha1(bytes).eq_ignore_ascii_case(expected) {
        return Err(invalid("source file hash mismatch"));
    }
    // Check all preconditions before mutation.
    for patch in &file.patches.patches {
        let (offset, original, patched) = decode(patch)?;
        let source = if reverse { &patched } else { &original };
        if slice(bytes, offset, source.len())? != source {
            return Err(invalid("patch original bytes mismatch"));
        }
    }
    for patch in &file.patches.patches {
        let (offset, original, patched) = decode(patch)?;
        let replacement = if reverse { original } else { patched };
        bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
    }
    Ok(())
}
