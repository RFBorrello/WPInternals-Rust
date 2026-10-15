//! Read-only Nokia package metadata fallback. No hive mounting or string search.
use super::{components, VersionEvidence};
use crate::{ffu::FfuMetadata, filesystem, gpt::Gpt, invalid, ImageError, Result, SECTOR_SIZE};
use std::io::{self, Read, Seek, SeekFrom};

pub const REG_PATH: &str =
    "Windows/Packages/RegistryFiles/Nokia.DeviceInfo.PhoneFirmwareRevision.reg";
pub const DSM_PATH: &str =
    "Windows/Packages/DsmFiles/Nokia.DeviceInfo.PhoneFirmwareRevision.dsm.xml";
const LIMIT: usize = 64 * 1024;
const IO_BUDGET: u64 = 16 * 1024 * 1024;
const REG_KEY: &str = "HKEY_LOCAL_MACHINE\\SYSTEM\\Platform\\DeviceTargetingInfo";

/// A partition-relative view of sparse FFU mappings. All host reads are bounded;
/// corrupt NTFS cannot seek outside the partition or consume unbounded I/O.
struct Partition<'a, R, F> {
    reader: &'a mut R,
    ffu: &'a FfuMetadata,
    start: u64,
    length: u64,
    position: u64,
    cache_at: u64,
    cache: Vec<u8>,
    fetched: u64,
    calls: u32,
    progress: F,
    cancelled: bool,
}
impl<R: Read + Seek, F: FnMut(u64, u64) -> bool> Read for Partition<'_, R, F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !(self.progress)(self.fetched, IO_BUDGET) {
            self.cancelled = true;
            return Err(io::Error::other("Operation cancelled"));
        }
        self.calls += 1;
        if self.calls > 65536 {
            return Err(io::Error::other(
                "MainOS metadata read-call budget exceeded",
            ));
        }
        let n = buffer
            .len()
            .min((self.length - self.position).min(LIMIT as u64) as usize);
        if n == 0 {
            return Ok(0);
        }
        if self.position < self.cache_at || self.position >= self.cache_at + self.cache.len() as u64
        {
            self.cache_at = self.position / LIMIT as u64 * LIMIT as u64;
            let count = (self.length - self.cache_at).min(LIMIT as u64) as usize;
            if self.fetched + count as u64 > IO_BUDGET {
                return Err(io::Error::other("MainOS metadata I/O exceeds 16 MiB"));
            }
            self.fetched += count as u64;
            self.cache = self
                .ffu
                .read_disk(self.reader, self.start + self.cache_at, count)
                .map_err(io::Error::other)?;
        }
        let at = (self.position - self.cache_at) as usize;
        let n = n.min(self.cache.len() - at);
        buffer[..n].copy_from_slice(&self.cache[at..at + n]);
        self.position += n as u64;
        Ok(n)
    }
}
impl<R, F> Seek for Partition<'_, R, F> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::End(p) => i128::from(self.length) + i128::from(p),
            SeekFrom::Current(p) => i128::from(self.position) + i128::from(p),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::other("MainOS seek outside partition bounds"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

pub fn read<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    progress: F,
) -> Result<Option<VersionEvidence>> {
    let partitions: Vec<_> = gpt
        .partitions
        .iter()
        .filter(|p| p.name == "MainOS")
        .collect();
    if partitions.is_empty() {
        return Ok(None);
    }
    if partitions.len() != 1 {
        return Err(invalid("Ambiguous MainOS partition"));
    }
    let p = partitions[0];
    let start = p
        .first_sector
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| invalid("MainOS offset overflow"))?;
    let length = p
        .last_sector
        .checked_sub(p.first_sector)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(SECTOR_SIZE))
        .ok_or_else(|| invalid("MainOS length overflow"))?;
    start
        .checked_add(length)
        .ok_or_else(|| invalid("MainOS extent overflow"))?;
    let mut partition = Partition {
        reader,
        ffu,
        start,
        length,
        position: 0,
        cache_at: 0,
        cache: vec![],
        fetched: 0,
        calls: 0,
        progress,
        cancelled: false,
    };
    let result = (|| {
        let mut boot = [0; 512];
        partition.read_exact(&mut boot)?;
        // Other filesystem families have no supported fallback profile yet.
        if &boot[3..11] != b"NTFS    " {
            return Ok(None);
        }
        let info = filesystem::inspect_boot_sector(&boot)?;
        if info
            .total_sectors
            .checked_mul(u64::from(info.bytes_per_sector))
            .is_none_or(|n| n > length)
        {
            return Err(invalid("MainOS NTFS volume exceeds partition bounds"));
        }
        let reg = filesystem::read_small_ntfs_file(&mut partition, REG_PATH, LIMIT)?;
        let dsm = filesystem::read_small_ntfs_file(&mut partition, DSM_PATH, LIMIT)?;
        package(reg.as_deref(), dsm.as_deref())
    })();
    if partition.cancelled {
        return Err(ImageError::Cancelled);
    }
    result
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
fn registry_version(bytes: &[u8]) -> Result<String> {
    let bytes = unpack(bytes)?;
    let text = if let Some(body) = bytes.strip_prefix(&[0xff, 0xfe]) {
        if body.len() % 2 != 0 {
            return Err(invalid("odd UTF-16 registry metadata length"));
        }
        String::from_utf16(
            &body
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
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
    if lines.next() != Some("Windows Registry Editor Version 5.00") {
        return Err(invalid("unsupported registry package header"));
    }
    let mut active = false;
    let mut version = None;
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
            if !name
                .trim()
                .eq_ignore_ascii_case("\"PhoneFirmwareRevision\"")
            {
                continue;
            }
            let value = value
                .trim()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or_else(|| invalid("PhoneFirmwareRevision must be a string"))?;
            if components(value).is_none() || version.is_some() {
                return Err(invalid("invalid or duplicate PhoneFirmwareRevision"));
            }
            version = Some(value.to_owned());
        }
    }
    version
        .ok_or_else(|| invalid("registry package has no DeviceTargetingInfo PhoneFirmwareRevision"))
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
