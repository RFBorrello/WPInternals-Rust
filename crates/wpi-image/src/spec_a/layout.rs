//! Offline primary GPT transform from WPInternals 2.9.2 GPT.InsertHack,
//! RestoreBackupPartitions and Spec A unlock workflow. Rene Lergner, MIT.
use crate::{
    gpt::{Gpt, Partition},
    invalid, slice, u32le, u64le, Result,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub const BOOT: [&str; 7] = ["SBL1", "SBL2", "SBL3", "UEFI", "TZ", "RPM", "WINSECAPP"];
pub const PRIMARY_SIZE: usize = 34 * 512;
pub struct Layout {
    pub bytes: Vec<u8>,
    pub original: Gpt,
    pub prepared: Gpt,
    pub swapped: Vec<String>,
}
fn parse(bytes: &[u8]) -> Result<Gpt> {
    if bytes.len() != PRIMARY_SIZE
        || u32le(bytes, 512 + 12)? != 92
        || u64le(bytes, 512 + 24)? != 1
        || u64le(bytes, 512 + 72)? != 2
        || u32le(bytes, 512 + 80)? != 128
        || u32le(bytes, 512 + 84)? != 128
    {
        return Err(invalid(
            "Spec A package requires primary GPT at sectors 0–33, 128 entries of 128 bytes",
        ));
    }
    let gpt = Gpt::from_parts(&bytes[512..1024], &bytes[1024..], None)?;
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for (i, p) in gpt.partitions.iter().enumerate() {
        if p.name.is_empty()
            || !p.name.is_ascii()
            || !names.insert(p.name.to_ascii_uppercase())
            || p.guid.is_nil()
            || !ids.insert(p.guid)
            || p.type_guid.is_nil()
            || slice(bytes, 1024 + i * 128, 16)?.iter().all(|b| *b == 0)
        {
            return Err(invalid(
                "GPT requires packed, uniquely named/identified source partitions",
            ));
        }
    }
    if bytes[1024 + gpt.partitions.len() * 128..]
        .iter()
        .any(|b| *b != 0)
    {
        return Err(invalid("opaque unused GPT entries are unsupported"));
    }
    Ok(gpt)
}
fn encode(original: &[u8], parts: &[Partition]) -> Result<Vec<u8>> {
    if parts.len() > 128 {
        return Err(invalid("GPT has insufficient entry capacity"));
    }
    let mut bytes = original.to_vec();
    bytes[1024..].fill(0);
    for (i, p) in parts.iter().enumerate() {
        let entry = &mut bytes[1024 + i * 128..1024 + (i + 1) * 128];
        entry[..16].copy_from_slice(&p.type_guid.to_bytes_le());
        entry[16..32].copy_from_slice(&p.guid.to_bytes_le());
        entry[32..40].copy_from_slice(&p.first_sector.to_le_bytes());
        entry[40..48].copy_from_slice(&p.last_sector.to_le_bytes());
        entry[48..56].copy_from_slice(&p.attributes.to_le_bytes());
        let units: Vec<_> = p.name.encode_utf16().collect();
        if units.len() > 36 {
            return Err(invalid("GPT name exceeds 36 UTF-16 units"));
        }
        for (j, c) in units.iter().enumerate() {
            entry[56 + j * 2..58 + j * 2].copy_from_slice(&c.to_le_bytes());
        }
    }
    let crc = crc32fast::hash(&bytes[1024..]);
    bytes[600..604].copy_from_slice(&crc.to_le_bytes());
    bytes[528..532].fill(0);
    let crc = crc32fast::hash(&bytes[512..604]);
    bytes[528..532].copy_from_slice(&crc.to_le_bytes());
    parse(&bytes)?;
    Ok(bytes)
}
/// An exact unmodified stock layout is required; no guessing at prior unlocks.
/// Deterministic marker GUIDs replace upstream randomness for reproducible ZIPs.
pub fn prepare(bytes: &[u8], external_sbl3: bool) -> Result<Layout> {
    let original = parse(bytes)?;
    for name in ["HACK", "IS_UNLOCKED", "IS_UNLOCKED_SBL3"] {
        if original
            .partitions
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case(name))
        {
            return Err(invalid(
                "already modified GPT is unsupported for stock package generation",
            ));
        }
    }
    let mut parts = original.partitions.clone();
    let mut swapped = Vec::new();
    for name in BOOT {
        let i = parts
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| invalid(format!("missing {name}")))?;
        if let Some(j) = parts
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(&format!("BACKUP_{name}")))
        {
            if parts[i].first_sector > parts[j].first_sector {
                let active = (parts[i].first_sector, parts[i].last_sector);
                parts[i].first_sector = parts[j].first_sector;
                parts[i].last_sector = parts[j].last_sector;
                parts[j].first_sector = active.0;
                parts[j].last_sector = active.1;
                swapped.push(name.to_string());
            }
        }
        if parts[i].last_sector >= 0xf400 {
            return Err(invalid(
                "normalized boot partition exceeds upstream V1 programmer limit",
            ));
        }
    }
    let first = parts
        .iter()
        .position(|p| p.name.eq_ignore_ascii_case("SBL1"))
        .unwrap();
    let second = parts
        .iter()
        .position(|p| p.name.eq_ignore_ascii_case("SBL2"))
        .unwrap();
    if parts[first].last_sector <= parts[first].first_sector {
        return Err(invalid("SBL1 cannot spare a sector"));
    }
    let mut hack = parts[second].clone();
    hack.name = "HACK".into();
    hack.first_sector = parts[first].last_sector;
    hack.last_sector = hack.first_sector;
    parts[first].last_sector -= 1;
    parts[second].type_guid = uuid::Uuid::from_bytes([0x74; 16]);
    parts[second].guid = parts[second].type_guid;
    parts.push(hack);
    if external_sbl3 {
        let guid = |label: &[u8]| {
            let mut hash = Sha256::new();
            hash.update(bytes);
            hash.update(label);
            let mut raw: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
            raw[6] = (raw[6] & 15) | 0x40;
            raw[8] = (raw[8] & 63) | 0x80;
            uuid::Uuid::from_bytes(raw)
        };
        parts.push(Partition {
            name: "IS_UNLOCKED_SBL3".into(),
            type_guid: guid(b"SpecA marker type"),
            guid: guid(b"SpecA marker id"),
            first_sector: 0x40,
            last_sector: 0x40,
            attributes: 0,
        });
    }
    let prepared_bytes = encode(bytes, &parts)?;
    let prepared = parse(&prepared_bytes)?; // CRCs, duplicates, bounds and overlaps, including marker.
    Ok(Layout {
        bytes: prepared_bytes,
        original,
        prepared,
        swapped,
    })
}
/// Restore only the exact layout represented by this source-based package.
/// This checks local bytes; it never reads a device or authorizes restoration.
pub fn restore(prepared: &[u8], original: &[u8], external_sbl3: bool) -> Result<Vec<u8>> {
    if prepare(original, external_sbl3)?.bytes != prepared {
        return Err(invalid(
            "prepared GPT does not match the preserved original",
        ));
    }
    Ok(original.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original() -> Vec<u8> {
        let mut r = std::io::Cursor::new(
            include_bytes!("../../../../tests/fixtures/synthetic-spec-a-package.ffu").as_slice(),
        );
        let f = crate::ffu::FfuMetadata::open(&mut r).unwrap();
        f.read_disk(&mut r, 0, PRIMARY_SIZE).unwrap()
    }
    #[test]
    fn roundtrip_changes_only_named_entries_and_restores_exact_source() {
        let source = original();
        let l = prepare(&source, true).unwrap();
        assert_eq!(restore(&l.bytes, &source, true).unwrap(), source);
        let old = l.original.partition("SBL2").unwrap();
        let hack = l.prepared.partition("HACK").unwrap();
        assert_eq!(
            (hack.guid, hack.type_guid, hack.attributes),
            (old.guid, old.type_guid, old.attributes)
        );
        assert_eq!(
            hack.first_sector,
            l.original.partition("SBL1").unwrap().last_sector
        );
        assert_eq!(
            l.prepared.partition("SBL1").unwrap().last_sector + 1,
            hack.first_sector
        );
        assert_eq!(
            l.prepared.partition("SBL2").unwrap().guid,
            uuid::Uuid::from_bytes([0x74; 16])
        );
        for p in &l.original.partitions {
            if !["SBL1", "SBL2"].contains(&p.name.as_str()) {
                assert_eq!(
                    serde_json::to_value(p).unwrap(),
                    serde_json::to_value(l.prepared.partition(&p.name).unwrap()).unwrap()
                );
            }
        }
        assert_eq!(prepare(&source, true).unwrap().bytes, l.bytes);
        assert!(prepare(&l.bytes, true).is_err());
        let mut bad = l.bytes;
        bad[1024] ^= 1;
        assert!(restore(&bad, &source, true).is_err());
    }
    #[test]
    fn backup_normalization_swaps_bounds_without_losing_identity() {
        let mut source = original();
        let mut parts = parse(&source).unwrap().partitions;
        source[544..552].copy_from_slice(&0x2301u64.to_le_bytes());
        source[560..568].copy_from_slice(&0x2300u64.to_le_bytes());
        let mut backup = parts[0].clone();
        backup.name = "BACKUP_SBL1".into();
        backup.guid = uuid::Uuid::from_u128(999);
        parts[0].first_sector = 0x2240;
        parts[0].last_sector = 0x227f;
        parts.push(backup);
        let source = encode(&source, &parts).unwrap();
        let l = prepare(&source, false).unwrap();
        assert_eq!(l.swapped, ["SBL1"]);
        assert_eq!(l.prepared.partition("SBL1").unwrap().first_sector, 0x100);
        assert_eq!(
            l.prepared.partition("BACKUP_SBL1").unwrap().first_sector,
            0x2240
        );
        assert_eq!(
            l.prepared.partition("BACKUP_SBL1").unwrap().guid,
            uuid::Uuid::from_u128(999)
        );
    }
    #[test]
    fn occupied_marker_capacity_duplicates_and_bad_geometry_fail_closed() {
        let source = original();
        let gpt = parse(&source).unwrap();
        let mut occupied = gpt.partitions.clone();
        occupied[4].first_sector = 64;
        occupied[4].last_sector = 64;
        assert!(prepare(&encode(&source, &occupied).unwrap(), true).is_err());
        let mut full = gpt.partitions.clone();
        for i in 0..119 {
            full.push(Partition {
                name: format!("FILL{i}"),
                guid: uuid::Uuid::from_u128(1000 + i),
                type_guid: uuid::Uuid::from_u128(2),
                first_sector: 80 + i as u64,
                last_sector: 80 + i as u64,
                attributes: 0,
            });
        }
        assert!(prepare(&encode(&source, &full).unwrap(), true).is_err());
        let mut duplicate = gpt.partitions.clone();
        duplicate[1].guid = duplicate[0].guid;
        assert!(encode(&source, &duplicate).is_err());
        let mut crc = source.clone();
        crc[528] ^= 1;
        assert!(prepare(&crc, false).is_err());
        let mut bad = source;
        bad[592..596].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(prepare(&bad, false).is_err());
    }
}
