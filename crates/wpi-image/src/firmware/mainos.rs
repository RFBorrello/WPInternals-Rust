//! Read-only Nokia package metadata fallback. No hive mounting or string search.
use super::{components, VersionEvidence};
use crate::{ffu::FfuMetadata, filesystem, gpt::Gpt, invalid, Result};
use std::io::{Read, Seek, SeekFrom};

pub const REG_PATH: &str =
    "Windows/Packages/RegistryFiles/Nokia.DeviceInfo.PhoneFirmwareRevision.reg";
pub const DSM_PATH: &str =
    "Windows/Packages/DsmFiles/Nokia.DeviceInfo.PhoneFirmwareRevision.dsm.xml";
pub const TARGET_PATH: &str = "Windows/Packages/RegistryFiles/OEMSettings.reg";
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetingInfo {
    pub hardware_variant: String,
    pub manufacturer_model: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub source: String,
}
const LIMIT: usize = 64 * 1024;
const REG_KEY: &str = "HKEY_LOCAL_MACHINE\\SYSTEM\\Platform\\DeviceTargetingInfo";

fn with_mainos<R: Read + Seek, F: FnMut(u64, u64) -> bool, T>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    progress: F,
    action: impl FnOnce(&mut crate::partition::Partition<'_, R, F>) -> Result<Option<T>>,
) -> Result<Option<T>> {
    crate::partition::with_partition("MainOS", reader, ffu, gpt, progress, |partition| {
        let mut boot = [0; 512];
        partition.read_exact(&mut boot)?;
        if &boot[3..11] != b"NTFS    " {
            return Ok(None);
        }
        let info = filesystem::inspect_boot_sector(&boot)?;
        let length = partition.seek(SeekFrom::End(0))?;
        if info
            .total_sectors
            .checked_mul(u64::from(info.bytes_per_sector))
            .is_none_or(|n| n > length)
        {
            return Err(invalid("MainOS NTFS volume exceeds partition bounds"));
        }
        partition.seek(SeekFrom::Start(0))?;
        action(partition)
    })
}
pub fn read<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    progress: F,
) -> Result<Option<VersionEvidence>> {
    with_mainos(reader, ffu, gpt, progress, |partition| {
        let reg = filesystem::read_small_ntfs_file(partition, REG_PATH, LIMIT)?;
        let dsm = filesystem::read_small_ntfs_file(partition, DSM_PATH, LIMIT)?;
        package(reg.as_deref(), dsm.as_deref())
    })
}
pub fn read_targeting<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    progress: F,
) -> Result<Option<TargetingInfo>> {
    with_mainos(reader, ffu, gpt, progress, |partition| {
        filesystem::read_small_ntfs_file(partition, TARGET_PATH, LIMIT)?
            .as_deref()
            .map(targeting)
            .transpose()
    })
}

fn unpack(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > LIMIT {
        return Err(invalid("package metadata exceeds 64 KiB"));
    }
    if !bytes.starts_with(&[0x1f, 0x8b]) {
        return Ok(bytes.to_vec());
    }
    let mut decoder = flate2::bufread::GzDecoder::new(bytes);
    let mut output = Vec::new();
    decoder
        .by_ref()
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut output)?;
    if output.len() > LIMIT {
        return Err(invalid("expanded package metadata exceeds 64 KiB"));
    }
    if !decoder.into_inner().is_empty() {
        return Err(invalid(
            "trailing data or multiple gzip members in package metadata",
        ));
    }
    Ok(output)
}
fn registry_values(
    bytes: &[u8],
    allowed: &[&str],
) -> Result<std::collections::BTreeMap<String, String>> {
    let bytes = unpack(bytes)?;
    let text = if let Some(body) = bytes.strip_prefix(&[0xff, 0xfe]) {
        if body.len() % 2 != 0 {
            return Err(invalid("odd UTF-16 registry metadata length"));
        }
        String::from_utf16(
            &body
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_le_bytes)
                .collect::<Vec<_>>(),
        )
        .map_err(|_| invalid("invalid UTF-16 registry metadata"))?
    } else {
        std::str::from_utf8(&bytes)
            .map_err(|_| invalid("registry metadata encoding is unsupported"))?
            .trim_start_matches('\u{feff}')
            .to_owned()
    };
    let mut lines = text.lines();
    if lines.next().map(str::trim_end) != Some("Windows Registry Editor Version 5.00") {
        return Err(invalid("unsupported registry package header"));
    }
    let mut active = false;
    let mut values = std::collections::BTreeMap::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let key = line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .ok_or_else(|| invalid("malformed registry section"))?;
            if key
                .strip_prefix('-')
                .is_some_and(|s| s.eq_ignore_ascii_case(REG_KEY))
            {
                return Err(invalid("firmware registry package deletes its target key"));
            }
            active = key.eq_ignore_ascii_case(REG_KEY);
        } else if active {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("malformed registry assignment"))?;
            let Some(name) = name
                .trim()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
            else {
                continue;
            };
            let Some(key) = allowed.iter().find(|key| name.eq_ignore_ascii_case(key)) else {
                continue;
            };
            let value = value
                .trim()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or_else(|| invalid("Targeting metadata must be a string"))?;
            if value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                || value.contains(['"', '\\'])
                || values.insert((*key).to_owned(), value.to_owned()).is_some()
            {
                return Err(invalid("invalid or duplicate targeting metadata"));
            }
        }
    }
    Ok(values)
}
fn registry_version(bytes: &[u8]) -> Result<String> {
    let mut values = registry_values(bytes, &["PhoneFirmwareRevision"])?;
    let version = values.remove("PhoneFirmwareRevision").ok_or_else(|| {
        invalid("registry package has no DeviceTargetingInfo PhoneFirmwareRevision")
    })?;
    if components(&version).is_none() {
        return Err(invalid("Invalid PhoneFirmwareRevision components"));
    }
    Ok(version)
}
pub fn targeting(bytes: &[u8]) -> Result<TargetingInfo> {
    let mut values = registry_values(
        bytes,
        &[
            "PhoneHardwareVariant",
            "PhoneManufacturerModelName",
            "PhoneManufacturer",
            "PhoneModelName",
        ],
    )?;
    let variant = values
        .remove("PhoneHardwareVariant")
        .ok_or_else(|| invalid("OEMSettings has no DeviceTargetingInfo PhoneHardwareVariant"))?;
    let digits = variant
        .strip_prefix("RM-")
        .ok_or_else(|| invalid("Unsupported hardware-variant format"))?;
    if !(3..=4).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("Unsupported hardware-variant format"));
    }
    let model = values.remove("PhoneManufacturerModelName");
    if model.as_ref().is_some_and(|m| {
        !m.strip_prefix(&variant)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('_'))
    }) {
        return Err(invalid(
            "Hardware variant and manufacturer model contradict each other",
        ));
    }
    Ok(TargetingInfo {
        hardware_variant: variant,
        manufacturer_model: model,
        manufacturer: values.remove("PhoneManufacturer"),
        model_name: values.remove("PhoneModelName"),
        source: format!("MainOS/{TARGET_PATH}: {REG_KEY}"),
    })
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Package {
    identity: Identity,
    partition: String,
    is_removal: String,
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Identity {
    owner: String,
    component: String,
    sub_component: String,
    version: DsmVersion,
}
#[derive(serde::Deserialize)]
struct DsmVersion {
    #[serde(rename = "@Major")]
    major: u32,
    #[serde(rename = "@Minor")]
    minor: u32,
    #[serde(rename = "@QFE")]
    qfe: u32,
    #[serde(rename = "@Build")]
    build: u32,
}
fn dsm_version(bytes: &[u8]) -> Result<[u32; 4]> {
    use quick_xml::events::Event;
    let bytes = unpack(bytes)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("DSM metadata is not UTF-8"))?;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut depth: usize = 0;
    let mut nodes = 0;
    let mut roots = 0;
    loop {
        let event = reader.read_event().map_err(|e| invalid(e.to_string()))?;
        match &event {
            Event::DocType(_) => return Err(invalid("DSM DTD is forbidden")),
            Event::Start(e) | Event::Empty(e) => {
                nodes += 1;
                if depth == 0 {
                    roots += 1;
                    let namespace = e
                        .try_get_attribute("xmlns")
                        .map_err(|e| invalid(e.to_string()))?;
                    if roots != 1
                        || e.name().as_ref() != b"Package"
                        || namespace.as_ref().map(|a| a.value.as_ref())
                            != Some(
                                b"http://schemas.microsoft.com/embedded/2004/10/ImageUpdate"
                                    .as_slice(),
                            )
                    {
                        return Err(invalid("unsupported DSM package root or namespace"));
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        match event {
            Event::Start(_) => depth += 1,
            Event::End(_) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid("DSM closing element without opening element"))?;
            }
            _ => {}
        }
        if nodes > 4096 || depth > 16 {
            return Err(invalid("DSM metadata node or depth limit exceeded"));
        }
    }
    if roots != 1 || depth != 0 {
        return Err(invalid("truncated DSM package"));
    }
    let package: Package = quick_xml::de::from_str(text).map_err(|e| invalid(e.to_string()))?;
    let id = package.identity;
    if id.owner != "Nokia"
        || id.component != "DeviceInfo"
        || id.sub_component != "PhoneFirmwareRevision"
        || package.partition != "MainOS"
        || package.is_removal != "false"
    {
        return Err(invalid(
            "DSM does not identify the supported MainOS firmware revision package",
        ));
    }
    Ok([
        id.version.major,
        id.version.minor,
        id.version.qfe,
        id.version.build,
    ])
}
/// Require both the registry value and its package identity/version. Leading
/// zeroes may differ in DSM numeric attributes; retain the registry display form.
pub fn package(reg: Option<&[u8]>, dsm: Option<&[u8]>) -> Result<Option<VersionEvidence>> {
    if reg.is_none() && dsm.is_none() {
        return Ok(None);
    }
    let reg =
        reg.ok_or_else(|| invalid("firmware revision package is missing its registry file"))?;
    let dsm = dsm.ok_or_else(|| invalid("firmware revision package is missing its DSM file"))?;
    let version = registry_version(reg)?;
    if components(&version) != Some(dsm_version(dsm)?) {
        return Err(invalid(
            "registry and DSM firmware revisions contradict each other",
        ));
    }
    Ok(Some(VersionEvidence {
        version,
        sources: vec![
            format!("MainOS/{REG_PATH}: {REG_KEY}\\PhoneFirmwareRevision"),
            format!("MainOS/{DSM_PATH}: Identity/Version"),
        ],
    }))
}
