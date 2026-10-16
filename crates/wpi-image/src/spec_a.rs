//! Read-only Spec A preparation, derived from WPInternals 2.9.2
//! (d8fd0aa516b16dc094df0422a3adc525af005c29), QualcommPartition, SBL2,
//! SBL3 and QualcommLoader. Copyright (c) 2018 Rene Lergner, MIT;
//! see resources/upstream/LICENSE. No payload generation or device commands.
use crate::{ffu::FfuMetadata, gpt::Gpt, invalid, slice, u32le, ImageError, Result};
use der::Decode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
use x509_cert::Certificate;
pub mod efiesp;
pub mod sbl1;
pub mod uefi;

pub const MAX_BOOT_IMAGE: usize = 4 * 1024 * 1024;
pub const MAX_LOADER_FILE: usize = 512 * 1024;
pub const MAX_LOADERS: usize = 32;
pub const UPSTREAM: &str = "d8fd0aa516b16dc094df0422a3adc525af005c29";
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualcommImage {
    pub header_kind: String,
    pub header_offset: usize,
    pub image_offset: usize,
    pub image_address: u32,
    pub image_size: usize,
    pub code_size: usize,
    pub signature_offset: usize,
    pub signature_size: usize,
    pub certificates_offset: usize,
    pub certificates_size: usize,
    pub certificate_sha256: Vec<String>,
    /// Hash of the last DER certificate, as upstream uses for RRKH comparison.
    /// This is not a verified signature, trusted root, or phone RRKH reading.
    pub root_certificate_sha256: String,
}

/// Only the raw short v3 and long MBN profiles used by the Spec A workflow.
/// ELF programmers require a separate validated profile; do not truncate ELF64
/// offsets or guess that every binary contains an MBN header.
pub fn parse(bytes: &[u8], offset: usize) -> Result<QualcommImage> {
    if bytes.len() > MAX_BOOT_IMAGE {
        return Err(invalid("boot image exceeds 4 MiB"));
    }
    let prefix = slice(bytes, offset, 20)?;
    if prefix.starts_with(b"\x7fELF") {
        return Err(ImageError::Unsupported(
            "ELF programmer profile is not implemented".into(),
        ));
    }
    let long = prefix[..8] == [0xd1, 0xdc, 0x4b, 0x84, 0x34, 0x10, 0xd7, 0x73]
        && prefix[12..20].iter().all(|b| *b == 0xff);
    if !long && u32le(bytes, offset + 4)? != 3 {
        return Err(invalid("not a supported short v3 or long Qualcomm header"));
    }
    let header_offset = offset + if long { 20 } else { 8 };
    slice(bytes, header_offset, 32)?;
    let source = u32le(bytes, header_offset)? as usize;
    let minimum = offset + if long { 0x50 } else { 0x28 };
    slice(bytes, offset, minimum - offset)?;
    let image_offset = if source == 0 { minimum } else { source };
    if image_offset < minimum {
        return Err(invalid("MBN payload overlaps its header"));
    }
    let image_address = u32le(bytes, header_offset + 4)?;
    let image_size = u32le(bytes, header_offset + 8)? as usize;
    let code_size = u32le(bytes, header_offset + 12)? as usize;
    let signature_address = u32le(bytes, header_offset + 16)?;
    let signature_size = u32le(bytes, header_offset + 20)? as usize;
    let certificates_address = u32le(bytes, header_offset + 24)?;
    let certificates_size = u32le(bytes, header_offset + 28)? as usize;
    if code_size == 0 || signature_size == 0 || certificates_size == 0 || certificates_size > 32768
    {
        return Err(invalid(
            "empty code/signature/chain or chain exceeds 32 KiB",
        ));
    }
    let sig_relative = signature_address
        .checked_sub(image_address)
        .ok_or_else(|| invalid("signature address precedes image"))?
        as usize;
    let cert_relative = certificates_address
        .checked_sub(image_address)
        .ok_or_else(|| invalid("certificate address precedes image"))?
        as usize;
    let total = code_size
        .checked_add(signature_size)
        .and_then(|v| v.checked_add(certificates_size))
        .ok_or_else(|| invalid("MBN sizes overflow"))?;
    if sig_relative != code_size
        || cert_relative != code_size + signature_size
        || image_size != total
    {
        return Err(invalid(
            "unsupported noncontiguous MBN code/signature/certificate geometry",
        ));
    }
    // Bounds-check the complete payload before calculating subordinate offsets.
    slice(bytes, image_offset, image_size)?;
    image_address
        .checked_add(image_size as u32)
        .ok_or_else(|| invalid("MBN address range overflows 32 bits"))?;
    let signature_offset = image_offset + sig_relative;
    let certificates_offset = image_offset + cert_relative;
    let chain = slice(bytes, certificates_offset, certificates_size)?;
    let mut certificate_sha256 = Vec::new();
    let mut at = 0;
    while at < chain.len() {
        // Qualcomm reserves a fixed chain region; accept only uniform padding.
        if chain[at..].iter().all(|b| *b == 0xff) || chain[at..].iter().all(|b| *b == 0) {
            break;
        }
        if certificate_sha256.len() == 8 {
            return Err(invalid("MBN certificate chain exceeds eight certificates"));
        }
        if slice(chain, at, 4)?[..2] != [0x30, 0x82] {
            return Err(invalid("unsupported or malformed MBN DER certificate"));
        }
        let length = usize::from(u16::from_be_bytes([chain[at + 2], chain[at + 3]])) + 4;
        let der = slice(chain, at, length)?;
        Certificate::from_der(der).map_err(|_| invalid("invalid MBN X.509 certificate"))?;
        certificate_sha256.push(hash(der));
        at += length;
    }
    let root_certificate_sha256 = certificate_sha256
        .last()
        .cloned()
        .ok_or_else(|| invalid("MBN has no DER certificates"))?;
    Ok(QualcommImage {
        header_kind: if long { "long" } else { "short_v3" }.into(),
        header_offset,
        image_offset,
        image_address,
        image_size,
        code_size,
        signature_offset,
        signature_size,
        certificates_offset,
        certificates_size,
        certificate_sha256,
        root_certificate_sha256,
    })
}

/// Strict Intel HEX import. Upstream concatenates data without checking addresses
/// or checksums. Preserve its valid contiguous profile, rejecting gaps, overlaps,
/// bad checksums, missing EOF, and unsupported records instead of fabricating data.
pub fn decode_loader(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_LOADER_FILE {
        return Err(invalid("loader import exceeds 512 KiB"));
    }
    if !bytes.starts_with(b":") {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("HEX is not UTF-8 ASCII"))?;
    let mut output = Vec::new();
    let mut base = 0u64;
    let mut next = None;
    let mut eof = false;
    for line in text.lines() {
        if eof {
            return Err(invalid("records after HEX EOF"));
        }
        if line.len() > 521 || !line.starts_with(':') {
            return Err(invalid("invalid HEX record"));
        }
        let record = hex::decode(&line[1..]).map_err(|_| invalid("invalid HEX digits"))?;
        if record.len() < 5
            || record.len() != record[0] as usize + 5
            || record.iter().fold(0u8, |s, b| s.wrapping_add(*b)) != 0
        {
            return Err(invalid("HEX length or checksum mismatch"));
        }
        let address = u16::from_be_bytes([record[1], record[2]]) as u64;
        let data = &record[4..record.len() - 1];
        match (record[3], data.len(), address) {
            (0, n, _) if n > 0 => {
                let start = base + address;
                let end = start + n as u64;
                if end > 0x1_0000_0000 || next.is_some_and(|v| v != start) {
                    return Err(invalid(
                        "HEX data is noncontiguous or exceeds address space",
                    ));
                }
                if output.len() + n > 256 * 1024 {
                    return Err(invalid("decoded HEX exceeds 256 KiB"));
                }
                output.extend_from_slice(data);
                next = Some(end);
            }
            (1, 0, 0) => eof = true,
            (2, 2, 0) => base = u16::from_be_bytes(data.try_into().unwrap()) as u64 * 16,
            (4, 2, 0) => base = u16::from_be_bytes(data.try_into().unwrap()) as u64 * 65536,
            (3 | 5, 4, 0) => {} // Start-address metadata; no execution here.
            _ => return Err(invalid("unsupported HEX record or geometry")),
        }
    }
    if !eof || output.is_empty() {
        return Err(invalid("HEX has no data or EOF"));
    }
    Ok(output)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPreview {
    pub status: String,
    pub match_count: usize,
    pub offset: Option<usize>,
    pub expected: String,
    pub replacement: String,
}
/// Preview only. Search the parsed code region, never headers or certificates;
/// require exactly one occurrence before displaying an applicable patch offset.
pub fn patch_preview(bytes: &[u8], image: &QualcommImage, sbl2: bool) -> Result<PatchPreview> {
    let (pattern, skip): (&[u8], usize) = if sbl2 {
        (
            &[
                0, 0, 0, 0xe3, 1, 0x0e, 0x42, 0xe3, 0x28, 0, 0xd0, 0xe5, 0x1e, 0xff, 0x2f, 0xe1,
            ],
            8,
        )
    } else {
        (
            &[
                4, 0, 0x9f, 0xe5, 0x28, 0, 0xd0, 0xe5, 0x1e, 0xff, 0x2f, 0xe1,
            ],
            4,
        )
    };
    let code = slice(bytes, image.image_offset, image.code_size)?;
    let mut matches = code
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, v)| {
            if sbl2 {
                v[3..] == pattern[3..]
            } else {
                *v == pattern
            }
        })
        .map(|(i, _)| image.image_offset + i + skip);
    let first = matches.next();
    let count = usize::from(first.is_some()) + matches.count();
    Ok(PatchPreview {
        status: match count {
            0 => "missing",
            1 => "unique",
            _ => "ambiguous",
        }
        .into(),
        match_count: count,
        offset: if count == 1 { first } else { None },
        expected: "2800d0e5".into(),
        replacement: "0000a0e3".into(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootReport {
    pub name: String,
    pub size: usize,
    pub sha256: String,
    pub image: Option<QualcommImage>,
    pub patch: Option<PatchPreview>,
    pub error: Option<String>,
}
fn boot(name: &str, bytes: &[u8], offset: usize, patch: Option<bool>) -> BootReport {
    let mut report = BootReport {
        name: name.into(),
        size: bytes.len(),
        sha256: hash(bytes),
        image: None,
        patch: None,
        error: None,
    };
    match parse(bytes, offset) {
        Ok(image) => {
            if let Some(sbl2) = patch {
                match patch_preview(bytes, &image, sbl2) {
                    Ok(p) => report.patch = Some(p),
                    Err(e) => report.error = Some(e.to_string()),
                }
            }
            report.image = Some(image);
        }
        Err(error) => report.error = Some(error.to_string()),
    }
    report
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderReport {
    pub name: String,
    pub input_sha256: String,
    pub decoded: Option<BootReport>,
    pub v1_marker_present: bool,
    pub matches_stock_sbl1_root: bool,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preparation {
    pub upstream_revision: String,
    pub platform_id: String,
    pub stock: Vec<BootReport>,
    pub external_sbl3: Option<BootReport>,
    pub external_sbl3_fits: Option<bool>,
    pub loaders: Vec<LoaderReport>,
    #[serde(default)]
    pub sbl1_prerequisites: Option<sbl1::Prerequisites>,
    #[serde(default)]
    pub sbl1_error: Option<String>,
    #[serde(default)]
    pub uefi: Option<uefi::Report>,
    #[serde(default)]
    pub uefi_error: Option<String>,
    #[serde(default)]
    pub efiesp: Option<efiesp::Report>,
    #[serde(default)]
    pub efiesp_error: Option<String>,
    #[serde(default)]
    pub donor_efiesp: Option<efiesp::Report>,
    #[serde(default)]
    pub donor_error: Option<String>,
    pub phone_writes_enabled: bool,
    pub blockers: Vec<String>,
}
pub struct Import<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

pub fn prepare<R: Read + Seek>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    sbl3: Option<Import<'_>>,
    loaders: &[Import<'_>],
) -> Result<Preparation> {
    if loaders.len() > MAX_LOADERS {
        return Err(invalid("at most 32 loader imports are allowed"));
    }
    if sbl3
        .as_ref()
        .is_some_and(|v| v.bytes.len() > MAX_BOOT_IMAGE)
    {
        return Err(invalid(
            "external SBL3 exceeds 4 MiB; import an extracted raw partition",
        ));
    }
    if loaders.iter().any(|v| v.bytes.len() > MAX_LOADER_FILE) {
        return Err(invalid("loader import exceeds 512 KiB"));
    }
    let mut stock = Vec::new();
    let mut sbl1_prerequisites = None;
    let mut sbl1_error = None;
    for (name, offset, patch) in [
        ("SBL1", 0x2800, None),
        ("SBL2", 0, Some(true)),
        ("SBL3", 0, Some(false)),
    ] {
        let partition = gpt.partition(name)?;
        let (start, size) = partition.byte_range()?;
        if size > MAX_BOOT_IMAGE as u64 {
            return Err(invalid(format!("{name} partition exceeds 4 MiB")));
        }
        let bytes = ffu.read_disk(reader, start, size as usize)?;
        let report = boot(name, &bytes, offset, patch);
        if name == "SBL1" {
            match report
                .image
                .as_ref()
                .ok_or_else(|| invalid("SBL1 header did not parse"))
                .and_then(|image| sbl1::inspect(&bytes, image))
            {
                Ok(v) => sbl1_prerequisites = Some(v),
                Err(e) => sbl1_error = Some(e.to_string()),
            }
        }
        stock.push(report);
    }
    let uefi_result = (|| {
        let (start, size) = gpt.partition("UEFI")?.byte_range()?;
        if size > MAX_BOOT_IMAGE as u64 {
            return Err(invalid("UEFI partition exceeds 4 MiB"));
        }
        uefi::inspect(&ffu.read_disk(reader, start, size as usize)?)
    })();
    let (uefi, uefi_error) = match uefi_result {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let (efiesp, efiesp_error) = match efiesp::inspect(reader, ffu, gpt) {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    };
    let stock_root = stock[0]
        .image
        .as_ref()
        .map(|v| v.root_certificate_sha256.as_str());
    let external_sbl3 = sbl3.map(|v| boot(v.name, v.bytes, 0, Some(false)));
    let external_sbl3_fits = external_sbl3.as_ref().map(|v| v.size <= stock[2].size);
    let mut reports = Vec::new();
    let marker: Vec<_> = "QHSUSB_ARMPRG"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    for input in loaders {
        let mut report = LoaderReport {
            name: input.name.into(),
            input_sha256: hash(input.bytes),
            decoded: None,
            v1_marker_present: false,
            matches_stock_sbl1_root: false,
            error: None,
        };
        match decode_loader(input.bytes) {
            Ok(bytes) => {
                let decoded = boot(input.name, &bytes, 0, None);
                if let Some(image) = &decoded.image {
                    report.matches_stock_sbl1_root =
                        stock_root == Some(image.root_certificate_sha256.as_str());
                    let code = slice(&bytes, image.image_offset, image.code_size)?;
                    report.v1_marker_present = code.windows(marker.len()).any(|v| v == marker);
                }
                report.decoded = Some(decoded);
            }
            Err(e) => report.error = Some(e.to_string()),
        }
        reports.push(report);
    }
    let mut blockers=vec![
        "FFU chunk integrity, OEM authenticity and firmware applicability require the separate Recovery preparation checks.".into(),
        "Phone RRKH and Flash security/application state have not been read in this offline check.".into(),
        "Live GPT, recoverable installed originals, and interruption recovery are not validated.".into(),
        "SBL1 payload generation, UEFI rebuild, EFIESP donor replacement and BCD editing are not implemented by this check.".into(),
        "Certificate fingerprints and code patterns do not establish signature trust, engineering status, hardware compatibility or mass-storage support.".into(),
        "Spec A unlock executor and hardware validation are incomplete; this report never authorizes phone writes.".into(),
    ];
    if sbl1_prerequisites.is_none() {
        blockers.push(
            "SBL1 prerequisite inspection failed; review its error before further preparation."
                .into(),
        );
    }
    if uefi.is_none() {
        blockers.push("UEFI inspection or unique patch matching failed; review its error.".into());
    }
    if efiesp
        .as_ref()
        .is_none_or(|v| v.prepared_copy_sha256.is_none())
    {
        blockers.push("EFIESP boot target is missing, unsupported, or unreadable; a separately validated donor may be required.".into());
    }
    if stock
        .iter()
        .any(|v| v.error.is_some() || v.patch.as_ref().is_some_and(|p| p.status != "unique"))
    {
        blockers.push("A stock boot image failed parsing or unique patch matching.".into());
    }
    if external_sbl3.is_none() {
        blockers.push("No external engineering SBL3 was imported; stock SBL3 is not evidence of engineering mass-storage support.".into());
    }
    if external_sbl3
        .as_ref()
        .is_some_and(|v| v.error.is_some() || v.patch.as_ref().is_none_or(|p| p.status != "unique"))
        || external_sbl3_fits == Some(false)
    {
        blockers.push("External SBL3 failed parsing, unique patch matching or the stock partition size limit.".into());
    }
    if !reports
        .iter()
        .any(|v| v.v1_marker_present && v.matches_stock_sbl1_root)
    {
        blockers.push(
            "No parsed V1 loader has the same certificate-root fingerprint as stock SBL1.".into(),
        );
    }
    Ok(Preparation {
        upstream_revision: UPSTREAM.into(),
        platform_id: ffu.platform_id.clone(),
        stock,
        external_sbl3,
        external_sbl3_fits,
        loaders: reports,
        sbl1_prerequisites,
        sbl1_error,
        uefi,
        uefi_error,
        efiesp,
        efiesp_error,
        donor_efiesp: None,
        donor_error: None,
        phone_writes_enabled: false,
        blockers,
    })
}
/// A donor's boot-file match is not permission to install its files on a phone.
pub fn assess_donor<R: Read + Seek>(
    report: &mut Preparation,
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
) {
    report
        .blockers
        .retain(|v| !v.starts_with("Imported donor "));
    report.donor_efiesp = None;
    report.donor_error = None;
    match efiesp::inspect(reader, ffu, gpt) {
        Ok(v) => report.donor_efiesp = Some(v),
        Err(e) => report.donor_error = Some(e.to_string()),
    }
    if report
        .donor_efiesp
        .as_ref()
        .is_some_and(|v| v.prepared_copy_sha256.is_some())
    {
        report.blockers.retain(|v|v!="EFIESP boot target is missing, unsupported, or unreadable; a separately validated donor may be required.");
        report.blockers.push("Imported donor boot bytes match the pinned patch catalog, but replacement, BCD edits and cross-version/device compatibility remain unvalidated.".into());
    } else {
        if report
            .efiesp
            .as_ref()
            .is_none_or(|v| v.prepared_copy_sha256.is_none())
            && !report
                .blockers
                .iter()
                .any(|v| v.starts_with("EFIESP boot target is missing"))
        {
            report.blockers.push("EFIESP boot target is missing, unsupported, or unreadable; a separately validated donor may be required.".into());
        }
        report.blockers.push("Imported donor has no supported EFIESP patch result; inspect its error or boot-file status.".into());
    }
    report.phone_writes_enabled = false;
}
