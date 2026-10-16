//! Offline prerequisites/payload from upstream SBL1.GenerateExtraSector (2.9.2).
//! Copyright (c) 2018 Rene Lergner, MIT. No device I/O.
use super::QualcommImage;
use crate::{invalid, slice, u32le, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prerequisites {
    pub loader_table_offset: usize,
    pub loader_table_size: usize,
    pub security_function_offset: usize,
    pub shared_memory_address: u32,
    pub security_flag_address: u32,
    pub return_function_offset: usize,
    pub return_address: u32,
    pub payload_generated: bool,
}
pub(super) fn unique(bytes: &[u8], pattern: &[u8], mask: &[u8]) -> Result<usize> {
    if pattern.is_empty() || pattern.len() != mask.len() {
        return Err(invalid("invalid pattern definition"));
    }
    let mut matches = bytes
        .windows(pattern.len())
        .enumerate()
        .filter(|(_, v)| {
            v.iter()
                .zip(pattern)
                .zip(mask)
                .all(|((a, b), m)| *m == 0xff || a == b)
        })
        .map(|(i, _)| i);
    let first = matches
        .next()
        .ok_or_else(|| invalid("required code pattern is missing"))?;
    if matches.next().is_some() {
        return Err(invalid("required code pattern is ambiguous"));
    }
    Ok(first)
}
pub fn inspect(bytes: &[u8], image: &QualcommImage) -> Result<Prerequisites> {
    let code = slice(bytes, image.image_offset, image.code_size)?;
    let table = hex::decode(
        "15000000000000001b0000000000000005000000010000000100000000000000000000000000000000000000",
    )
    .unwrap();
    let loader = unique(code, &table, &vec![0; table.len()])?;
    slice(code, loader, 0x50)?;
    let security = hex::decode("04009fe52800d0e51eff2fe100000000").unwrap();
    let security_mask = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255];
    let security_at = unique(code, &security, &security_mask)?;
    let shared_memory_address = u32le(code, security_at + 12)?;
    if shared_memory_address == 0 || shared_memory_address % 4 != 0 {
        return Err(invalid("invalid SBL1 shared-memory address"));
    }
    let security_flag_address = shared_memory_address
        .checked_add(0x28)
        .ok_or_else(|| invalid("SBL1 security address overflow"))?;
    let return_pattern = hex::decode("0100a0e30000a0e11cd08de2f04fbde81eff2fe1").unwrap();
    let return_mask = [
        0, 255, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let return_at = unique(code, &return_pattern, &return_mask)?;
    let return_address = image
        .image_address
        .checked_add(return_at as u32)
        .ok_or_else(|| invalid("SBL1 return address overflow"))?;
    Ok(Prerequisites {
        loader_table_offset: image.image_offset + loader,
        loader_table_size: 0x50,
        security_function_offset: image.image_offset + security_at,
        shared_memory_address,
        security_flag_address,
        return_function_offset: image.image_offset + return_at,
        return_address,
        payload_generated: false,
    })
}

/// Builds the pinned 512-byte extra sector on an owned copy. The caller must
/// validate the SBL1/GPT footprint before including this in an offline package.
pub fn generate(bytes: &[u8], sbl2: &[u8]) -> Result<Vec<u8>> {
    let image = super::parse(bytes, 0x2800)?;
    let second = super::parse(sbl2, 0)?;
    if second.header_kind != "short_v3" || second.image_offset != 40 {
        return Err(invalid("payload requires the short v3 SBL2 header"));
    }
    let p = inspect(bytes, &image)?;
    let template = hex::decode("16000000030000002800000028bd0200d8010000d8010000000000000000000000000000000000000000a0e33c109fe50000c1e538009fe538109fe5000081e534109fe5000081e530009fe520109fe52c309fe5002090e5002081e5040080e2041081e2030050e1f9ffffba14f09fe5000000000010020090bf0200d0bf0200a0bd0200a0be020000000000").unwrap();
    let mut sector = vec![0; 512];
    sector[..template.len()].copy_from_slice(&template);
    sector[..12].copy_from_slice(slice(sbl2, 0, 12)?);
    sector[0x70..0x74].copy_from_slice(&p.security_flag_address.to_le_bytes());
    sector[0x88..0x8c].copy_from_slice(&p.return_address.to_le_bytes());
    let table = slice(bytes, p.loader_table_offset, p.loader_table_size)?;
    sector[0xa0..0xf0].copy_from_slice(table);
    sector[0xd0..0xd4].fill(0);
    sector[0xf0..0x140].copy_from_slice(table);
    sector[0x11c..0x120].fill(0);
    sector[0x128..0x12c].copy_from_slice(&0x210f0u32.to_le_bytes());
    sector[0x190..0x1a0].fill(0x74);
    sector[0x1fc..].copy_from_slice(&0x2bd28u32.to_le_bytes());
    Ok(sector)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn inputs() -> (Vec<u8>, Vec<u8>) {
        let mut r = std::io::Cursor::new(
            include_bytes!("../../../../tests/fixtures/synthetic-spec-a-package.ffu").as_slice(),
        );
        let f = crate::ffu::FfuMetadata::open(&mut r).unwrap();
        let g = f.gpt(&mut r).unwrap();
        let mut get = |name: &str| {
            let (start, len) = g.partition(name).unwrap().byte_range().unwrap();
            f.read_disk(&mut r, start, len as usize).unwrap()
        };
        (get("SBL1"), get("SBL2"))
    }
    #[test]
    fn sector_header_addresses_tables_guids_and_instruction_patch_match_reference() {
        let (first, second) = inputs();
        let second = super::super::patch_boot(&second, true).unwrap();
        let image = super::super::parse(&first, 0x2800).unwrap();
        let p = inspect(&first, &image).unwrap();
        let out = generate(&first, &second).unwrap();
        assert_eq!(out.len(), 512);
        assert_eq!(&out[..12], &second[..12]);
        assert_eq!(u32le(&out, 0x70).unwrap(), p.security_flag_address);
        assert_eq!(u32le(&out, 0x88).unwrap(), p.return_address);
        let mut table = first[p.loader_table_offset..p.loader_table_offset + 80].to_vec();
        table[0x30..0x34].fill(0);
        assert_eq!(&out[0xa0..0xf0], table);
        assert_eq!(u32le(&out, 0x11c).unwrap(), 0);
        assert_eq!(u32le(&out, 0x128).unwrap(), 0x210f0);
        assert_eq!(&out[0x190..0x1a0], &[0x74; 16]);
        assert_eq!(u32le(&out, 508).unwrap(), 0x2bd28);
        assert_eq!(&second[64..68], &[0, 0, 0xa0, 0xe3]);
    }
    #[test]
    fn missing_patterns_wrong_headers_and_repeated_patches_are_rejected() {
        let (first, second) = inputs();
        assert!(generate(&first, &second[..39]).is_err());
        let mut missing = first.clone();
        let p = inspect(&first, &super::super::parse(&first, 0x2800).unwrap()).unwrap();
        missing[p.loader_table_offset] ^= 1;
        assert!(generate(&missing, &second).is_err());
        let patched = super::super::patch_boot(&second, true).unwrap();
        assert!(super::super::patch_boot(&patched, true).is_err());
        let mut bad = second;
        bad[64] ^= 1;
        assert!(super::super::patch_boot(&bad, true).is_err());
    }
}
