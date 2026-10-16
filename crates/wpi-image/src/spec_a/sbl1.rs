//! Read-only prerequisites from upstream SBL1.GenerateExtraSector (2.9.2).
//! Copyright (c) 2018 Rene Lergner, MIT. No payload is generated.
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
