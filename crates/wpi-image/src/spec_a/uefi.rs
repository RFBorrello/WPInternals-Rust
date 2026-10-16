//! Bounded read-only FV/FFS/LZMA inspection and patch previews from upstream
//! UEFI.cs (2.9.2), copyright (c) 2018 Rene Lergner, MIT. No rebuild/export.
use crate::{invalid, slice, u32le, u64le, ImageError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Write};
const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_DICT: u32 = 32 * 1024 * 1024;
const LZMA_GUID: [u8; 16] = [
    0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf,
];
fn word(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, at, 2)?.try_into().unwrap()))
}
fn size24(b: &[u8], at: usize) -> Result<usize> {
    let v = slice(b, at, 3)?;
    let n = v[0] as usize | ((v[1] as usize) << 8) | ((v[2] as usize) << 16);
    if n == 0xffffff {
        return Err(ImageError::Unsupported(
            "extended FFS/section sizes are unsupported".into(),
        ));
    }
    Ok(n)
}
fn align(n: usize, bound: usize) -> Result<usize> {
    n.checked_add(bound - 1)
        .map(|v| v & !(bound - 1))
        .ok_or_else(|| invalid("UEFI alignment overflow"))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub label: String,
    /// Offset within the decompressed EFI executable, never the compressed FFU.
    pub offset: usize,
    pub expected: String,
    pub replacement: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfiReport {
    pub name: String,
    pub guid: String,
    pub size: usize,
    pub sha256: String,
    pub pe_checksum_offset: usize,
    pub patches: Vec<Patch>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub partition_sha256: String,
    pub outer_volume_size: usize,
    pub compressed_size: usize,
    pub decompressed_size: usize,
    pub decompressed_sha256: String,
    pub file_count: usize,
    pub targets: Vec<EfiReport>,
    pub rebuilt_image: bool,
}
struct Volume<'a> {
    bytes: &'a [u8],
    header: usize,
    padding: u8,
}
fn volume(bytes: &[u8]) -> Result<Volume<'_>> {
    slice(bytes, 0, 64)?;
    if slice(bytes, 40, 4)? != b"_FVH" || bytes[55] != 2 {
        return Err(invalid("unsupported firmware volume signature/revision"));
    }
    let size = u64le(bytes, 32)?;
    if size > MAX_OUTPUT as u64 || size < 64 {
        return Err(invalid("firmware volume size outside supported bounds"));
    }
    let bytes = slice(bytes, 0, size as usize)?;
    let header = word(bytes, 48)? as usize;
    if !(64..=4096).contains(&header) || !header.is_multiple_of(8) {
        return Err(invalid("invalid firmware volume header length"));
    }
    let header_bytes = slice(bytes, 0, header)?;
    if header_bytes.chunks_exact(2).fold(0u16, |a, v| {
        a.wrapping_add(u16::from_le_bytes([v[0], v[1]]))
    }) != 0
    {
        return Err(invalid("firmware volume header checksum mismatch"));
    }
    let guid = &bytes[16..32];
    if guid
        != [
            0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3,
            0x2d, 0xd3,
        ]
        && guid
            != [
                0xd9, 0x54, 0x93, 0x7a, 0x68, 0x04, 0x4a, 0x44, 0x81, 0xce, 0x0b, 0xf6, 0x17, 0xd8,
                0x90, 0xdf,
            ]
    {
        return Err(ImageError::Unsupported(
            "unknown firmware filesystem GUID".into(),
        ));
    }
    if word(bytes, 52)? != 0 {
        return Err(ImageError::Unsupported(
            "extended FV headers are unsupported".into(),
        ));
    }
    let mut blocks = 0u64;
    let mut terminated = false;
    for entry in header_bytes[56..].chunks_exact(8) {
        let count = u32le(entry, 0)?;
        let length = u32le(entry, 4)?;
        if count == 0 && length == 0 {
            terminated = true;
            break;
        }
        if count == 0 || length == 0 {
            return Err(invalid("invalid FV block map"));
        }
        blocks = blocks
            .checked_add(count as u64 * length as u64)
            .ok_or_else(|| invalid("FV block map overflow"))?;
    }
    if !terminated || blocks != size {
        return Err(invalid("FV block map size mismatch"));
    }
    Ok(Volume {
        bytes,
        header,
        padding: if u32le(bytes, 44)? & 0x800 != 0 {
            255
        } else {
            0
        },
    })
}
struct File<'a> {
    bytes: &'a [u8],
    kind: u8,
    guid: uuid::Uuid,
}
fn files<'a>(fv: &Volume<'a>) -> Result<Vec<File<'a>>> {
    let mut at = fv.header;
    let mut result = Vec::new();
    while at < fv.bytes.len() {
        let remaining = &fv.bytes[at..];
        if remaining.iter().all(|v| *v == fv.padding) {
            break;
        }
        let header = slice(fv.bytes, at, 24)?;
        let size = size24(header, 20)?;
        if size < 24 {
            return Err(invalid("FFS file is smaller than its header"));
        }
        let data = slice(fv.bytes, at, size)?;
        if header[19] & 1 != 0 {
            return Err(ImageError::Unsupported(
                "large FFS file header is unsupported".into(),
            ));
        }
        let sum = header[..23]
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 17)
            .fold(0u8, |a, (_, v)| a.wrapping_add(*v));
        if sum != 0 {
            return Err(invalid("FFS header checksum mismatch"));
        }
        if header[19] & 0x40 != 0 {
            if data[24..]
                .iter()
                .fold(header[17], |a, v| a.wrapping_add(*v))
                != 0
            {
                return Err(invalid("FFS data checksum mismatch"));
            }
        } else if header[17] != 0xaa && header[17] != 0x55 {
            return Err(invalid("FFS fixed checksum is invalid"));
        }
        let state = if fv.padding == 255 {
            !header[23]
        } else {
            header[23]
        };
        if state != 7 {
            return Err(ImageError::Unsupported(
                "FFS file is not in the supported data-valid state".into(),
            ));
        }
        if result.len() >= 512 {
            return Err(invalid("FV exceeds 512 files"));
        }
        let guid = uuid::Uuid::from_bytes_le(header[..16].try_into().unwrap());
        if result.iter().any(|f: &File<'_>| f.guid == guid) {
            return Err(invalid("duplicate FFS file GUID"));
        }
        result.push(File {
            bytes: data,
            kind: header[18],
            guid,
        });
        let next = align(at + size - fv.header, 8)? + fv.header;
        let end = next.min(fv.bytes.len());
        if fv.bytes[at + size..end]
            .iter()
            .any(|v| *v != fv.padding && *v != 0)
        {
            return Err(invalid("invalid FFS alignment padding"));
        }
        at = next;
    }
    Ok(result)
}
struct Section<'a> {
    bytes: &'a [u8],
    kind: u8,
}
fn sections(bytes: &[u8]) -> Result<Vec<Section<'_>>> {
    let mut at = 0;
    let mut result = Vec::new();
    while at < bytes.len() {
        let header = slice(bytes, at, 4)?;
        let size = size24(header, 0)?;
        if size < 4 {
            return Err(invalid("EFI section is smaller than header"));
        }
        if result.len() >= 2048 {
            return Err(invalid("section count limit exceeded"));
        }
        result.push(Section {
            bytes: slice(bytes, at, size)?,
            kind: header[3],
        });
        let next = align(at + size, 4)?;
        if bytes[at + size..next.min(bytes.len())]
            .iter()
            .any(|v| *v != 0 && *v != 255)
        {
            return Err(invalid("invalid EFI section alignment padding"));
        }
        at = next;
    }
    Ok(result)
}
struct LimitedOutput {
    bytes: Vec<u8>,
    size: usize,
}
impl Write for LimitedOutput {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() > self.size - self.bytes.len() {
            return Err(std::io::Error::other(
                "LZMA output exceeds declared bounded size",
            ));
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    slice(bytes, 0, 13)?;
    let property = bytes[0];
    if property >= 225 || property % 9 + (property / 9) % 5 > 4 {
        return Err(ImageError::Unsupported(
            "LZMA properties exceed supported model limit".into(),
        ));
    }
    let dict = u32le(bytes, 1)?;
    let size = u64le(bytes, 5)?;
    if !(4096..=MAX_DICT).contains(&dict) || size == 0 || size > MAX_OUTPUT as u64 {
        return Err(invalid("LZMA dictionary or output exceeds limits"));
    }
    let mut output = LimitedOutput {
        bytes: Vec::new(),
        size: size as usize,
    };
    let options = lzma_rs::decompress::Options {
        memlimit: Some(MAX_DICT as usize),
        ..Default::default()
    };
    lzma_rs::lzma_decompress_with_options(&mut Cursor::new(bytes), &mut output, &options)
        .map_err(|e| invalid(format!("LZMA decompression failed: {e}")))?;
    if output.bytes.len() != size as usize {
        return Err(invalid("truncated LZMA output"));
    }
    Ok(output.bytes)
}
fn preview(name: &str, guid: uuid::Uuid, bytes: &[u8]) -> Result<EfiReport> {
    if slice(bytes, 0, 2)? != b"MZ" {
        return Err(invalid("EFI executable lacks DOS signature"));
    }
    let pe = u32le(bytes, 0x3c)? as usize;
    if slice(bytes, pe, 4)? != b"PE\0\0" {
        return Err(invalid("EFI executable lacks PE signature"));
    }
    if word(bytes, pe + 4)? != 0x1c2 && word(bytes, pe + 4)? != 0x1c4 {
        return Err(ImageError::Unsupported(
            "EFI executable is not ARM32".into(),
        ));
    }
    let optional = word(bytes, pe + 20)? as usize;
    if optional < 68 || word(bytes, pe + 24)? != 0x10b {
        return Err(invalid("invalid PE32 optional header"));
    }
    slice(bytes, pe + 24, optional)?;
    let section_count = word(bytes, pe + 6)? as usize;
    if !(1..=96).contains(&section_count) {
        return Err(invalid("invalid PE section count"));
    }
    let section_table = slice(bytes, pe + 24 + optional, section_count * 40)?;
    let mut executable = Vec::new();
    for section in section_table.chunks_exact(40) {
        let size = u32le(section, 16)? as usize;
        let at = u32le(section, 20)? as usize;
        if size > 0 {
            slice(bytes, at, size)?;
            if at < pe + 24 + optional + section_count * 40 {
                return Err(invalid("PE section overlaps headers"));
            }
        }
        if size > 0 && u32le(section, 36)? & 0x20000000 != 0 {
            executable.push((at, at + size));
        }
    }
    let checksum = pe + 0x58;
    slice(bytes, checksum, 4)?;
    let patterns: Vec<(&str, &str, &str, usize, &str)> = if name == "SecurityDxe" {
        vec![(
            "SecurityDxe authentication",
            "f0412de90000b0e128d04de20000a0e1000000132000a0e3",
            "00000000ffff000000000000ffff00000000ff0000ff0000",
            0,
            "0000a0e31eff2fe1",
        )]
    } else {
        vec![
            (
                "SecurityServicesDxe policy 1",
                "100000e5800010e30000000a",
                "00ffff0000ff0000ffffff00",
                11,
                "ea",
            ),
            (
                "SecurityServicesDxe policy 2",
                "110000e5400010e30000000a",
                "00ffff0000ff0000ffffff00",
                11,
                "ea",
            ),
        ]
    };
    let mut patches = vec![Patch {
        label: "PE checksum clear".into(),
        offset: checksum,
        expected: hex::encode(slice(bytes, checksum, 4)?),
        replacement: "00000000".into(),
    }];
    for (label, pattern, mask, skip, replacement) in patterns {
        let pattern = hex::decode(pattern).unwrap();
        let mask = hex::decode(mask).unwrap();
        let pattern_at = super::sbl1::unique(bytes, &pattern, &mask)?;
        if pattern_at % 4 != 0
            || !executable
                .iter()
                .any(|(start, end)| pattern_at >= *start && pattern_at + pattern.len() <= *end)
        {
            return Err(invalid(
                "UEFI patch pattern is outside aligned executable code",
            ));
        }
        let at = pattern_at + skip;
        let length = replacement.len() / 2;
        if at < pe + 24 + optional {
            return Err(invalid("UEFI patch pattern is inside PE headers"));
        }
        patches.push(Patch {
            label: label.into(),
            offset: at,
            expected: hex::encode(slice(bytes, at, length)?),
            replacement: replacement.into(),
        });
    }
    Ok(EfiReport {
        name: name.into(),
        guid: guid.to_string(),
        size: bytes.len(),
        sha256: hex::encode(Sha256::digest(bytes)),
        pe_checksum_offset: checksum,
        patches,
    })
}
pub fn inspect(bytes: &[u8]) -> Result<Report> {
    let image = super::parse(bytes, 0)?;
    let fv = volume(slice(bytes, image.image_offset, image.code_size)?)?;
    let outer = files(&fv)?;
    let candidates: Vec<_> = outer.iter().filter(|f| f.kind == 11).collect();
    if candidates.len() != 1 {
        return Err(invalid("expected one FV image file"));
    }
    let list = sections(&candidates[0].bytes[24..])?;
    let candidates: Vec<_> = list.iter().filter(|s| s.kind == 2).collect();
    if candidates.len() != 1 {
        return Err(invalid("expected one GUID-defined compression section"));
    }
    let section = candidates[0].bytes;
    if slice(section, 4, 16)? != LZMA_GUID {
        return Err(ImageError::Unsupported(
            "GUID-defined section is not LZMA".into(),
        ));
    }
    let data_at = word(section, 20)? as usize;
    if data_at < 24 || word(section, 22)? != 1 {
        return Err(invalid("unsupported LZMA section header/attributes"));
    }
    let compressed = slice(
        section,
        data_at,
        section
            .len()
            .checked_sub(data_at)
            .ok_or_else(|| invalid("invalid compression data offset"))?,
    )?;
    let decompressed = decompress(compressed)?;
    let inner_sections = sections(&decompressed)?;
    let candidates: Vec<_> = inner_sections.iter().filter(|s| s.kind == 0x17).collect();
    if candidates.len() != 1 {
        return Err(invalid("expected one decompressed FV section"));
    }
    let inner = volume(&candidates[0].bytes[4..])?;
    let inner_files = files(&inner)?;
    let mut targets = Vec::new();
    for name in ["SecurityDxe", "SecurityServicesDxe"] {
        let mut found = None;
        for file in inner_files.iter().filter(|f| f.kind != 0xf0) {
            let sections = sections(&file.bytes[24..])?;
            let descriptions: Vec<_> = sections.iter().filter(|s| s.kind == 0x15).collect();
            if descriptions.len() > 1 {
                return Err(invalid("ambiguous EFI UI description"));
            }
            let Some(description) = descriptions.first() else {
                continue;
            };
            let text = &description.bytes[4..];
            if text.len() > 512 || text.len() % 2 != 0 {
                return Err(invalid("invalid EFI name length"));
            }
            let units: Vec<_> = text
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect();
            let text =
                String::from_utf16(&units).map_err(|_| invalid("invalid EFI name encoding"))?;
            if !text
                .trim_end_matches(['\0', ' '])
                .eq_ignore_ascii_case(name)
            {
                continue;
            }
            if found.is_some() {
                return Err(invalid("duplicate target EFI name"));
            }
            let binaries: Vec<_> = sections.iter().filter(|s| s.kind == 0x10).collect();
            if binaries.len() != 1 {
                return Err(invalid("expected one target PE32 section"));
            }
            found = Some(preview(name, file.guid, &binaries[0].bytes[4..])?);
        }
        targets.push(found.ok_or_else(|| invalid(format!("missing {name} EFI target")))?);
    }
    Ok(Report {
        partition_sha256: hex::encode(Sha256::digest(bytes)),
        outer_volume_size: fv.bytes.len(),
        compressed_size: compressed.len(),
        decompressed_size: decompressed.len(),
        decompressed_sha256: hex::encode(Sha256::digest(&decompressed)),
        file_count: inner_files.len(),
        targets,
        rebuilt_image: false,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    const DXE: &[u8] =
        include_bytes!("../../../../tests/fixtures/spec-a/SecurityDxe.synthetic.efi");
    #[test]
    fn ffs_duplicate_guids_invalid_states_and_payload_checksums_are_rejected() {
        let original = include_bytes!("../../../../tests/fixtures/spec-a/uefi.decompressed.bin");
        let mut bytes = original[4..].to_vec();
        let first = 72;
        let second = align(first + size24(&bytes, first + 20).unwrap(), 8).unwrap();
        let guid = bytes[first..first + 16].to_vec();
        bytes[second..second + 16].copy_from_slice(&guid);
        fn checksum(bytes: &mut [u8], at: usize) {
            bytes[at + 16] = 0;
            bytes[at + 16] = 0u8.wrapping_sub(
                bytes[at..at + 23]
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != 17)
                    .fold(0u8, |a, (_, b)| a.wrapping_add(*b)),
            );
        }
        checksum(&mut bytes, second);
        assert!(files(&volume(&bytes).unwrap()).is_err());
        bytes = original[4..].to_vec();
        bytes[first + 23] = 0xff;
        assert!(files(&volume(&bytes).unwrap()).is_err());
        bytes = original[4..].to_vec();
        bytes[first + 19] |= 0x40;
        checksum(&mut bytes, first);
        let size = size24(&bytes, first + 20).unwrap();
        bytes[first + 17] = 0u8.wrapping_sub(
            bytes[first + 24..first + size]
                .iter()
                .fold(0u8, |a, b| a.wrapping_add(*b)),
        );
        assert!(files(&volume(&bytes).unwrap()).is_ok());
        bytes[first + 24] ^= 1;
        assert!(files(&volume(&bytes).unwrap()).is_err());
    }
    #[test]
    fn pe_checks_reject_non_code_ambiguous_patterns_and_oversized_headers() {
        let guid = uuid::Uuid::nil();
        assert!(preview("SecurityDxe", guid, DXE).is_ok());
        let mut resource = DXE.to_vec();
        resource[128 + 24 + 224 + 36..128 + 24 + 224 + 40].copy_from_slice(&0u32.to_le_bytes());
        assert!(preview("SecurityDxe", guid, &resource).is_err());
        let mut duplicate = DXE.to_vec();
        duplicate[640..664].copy_from_slice(&DXE[576..600]);
        assert!(preview("SecurityDxe", guid, &duplicate).is_err());
        for (at, word) in [(60, u32::MAX), (128 + 24 + 224 + 20, u32::MAX)] {
            let mut bad = DXE.to_vec();
            bad[at..at + 4].copy_from_slice(&word.to_le_bytes());
            assert!(preview("SecurityDxe", guid, &bad).is_err());
        }
    }
    #[test]
    fn section_zero_lengths_and_extended_sizes_cannot_loop_or_escape_bounds() {
        assert!(sections(&[0, 0, 0, 0x17]).is_err());
        assert!(sections(&[255, 255, 255, 0x17]).is_err());
        assert!(sections(&[8, 0, 0, 0x17, 0]).is_err());
        let mut output = LimitedOutput {
            bytes: vec![],
            size: 2,
        };
        output.write_all(&[1, 2]).unwrap();
        assert!(output.write_all(&[3]).is_err());
        assert_eq!(output.bytes, [1, 2]);
    }
    #[test]
    fn lzma_rejects_unknown_output_size_oversized_models_and_truncated_stream() {
        let mut data = vec![0x5d, 0, 0, 0x10, 0];
        data.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decompress(&data).is_err());
        data[5..13].copy_from_slice(&1024u64.to_le_bytes());
        assert!(decompress(&data).is_err());
        data[0] = 224;
        assert!(decompress(&data).is_err());
    }
}
