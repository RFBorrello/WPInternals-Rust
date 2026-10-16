//! Narrow offline REGF/BCD editor. Format/reference: DiscUtils commit
//! 59d7cadab839c6d8dfcf52f8be5efe6d2ced190f, MIT, Kenneth Bell (2008-2011)
//! and Quamotion (2014). See resources/licenses/DiscUtils-MIT.
//! Only the two pinned NoCodeIntegrity elements are changed; no host registry API.
use crate::{invalid, slice, u32le, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub const OBJECTS: [&str; 2] = [
    "{01de5a27-8705-40db-bad6-96fa5187d4a6}",
    "{7619dcc9-fafe-11d9-b411-000476eba25f}",
];
const LIMIT: usize = 1024 * 1024;
const NONE: u32 = u32::MAX;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub original_sha256: String,
    pub resulting_sha256: String,
    pub size: usize,
    pub created_elements: usize,
    pub changed_values: usize,
    pub preserved_other_entries: bool,
}
#[derive(Clone)]
struct Cell {
    at: usize,
    size: usize,
    allocated: bool,
}
struct Hive {
    bytes: Vec<u8>,
    cells: BTreeMap<u32, Cell>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Value {
    kind: u32,
    bytes: Vec<u8>,
}
type Snapshot = BTreeMap<String, BTreeMap<String, Value>>;
fn word(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, at, 2)?.try_into().unwrap()))
}
fn put(b: &mut [u8], at: usize, n: u32) -> Result<()> {
    slice(b, at, 4)?;
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
    Ok(())
}
fn checksum(b: &[u8]) -> Result<u32> {
    let mut sum = 0;
    for i in (0..508).step_by(4) {
        sum ^= u32le(b, i)?;
    }
    Ok(match sum {
        0 => 1,
        u32::MAX => u32::MAX - 1,
        _ => sum,
    })
}
fn cells(bytes: &[u8]) -> Result<BTreeMap<u32, Cell>> {
    if bytes.len() < 8192
        || bytes.len() > LIMIT
        || !bytes.len().is_multiple_of(4096)
        || slice(bytes, 0, 4)? != b"regf"
    {
        return Err(invalid("BCD requires a bounded REGF hive"));
    }
    if u32le(bytes, 4)? != u32le(bytes, 8)? {
        return Err(invalid("dirty registry hive requires log replay"));
    }
    if u32le(bytes, 20)? != 1
        || !(3..=5).contains(&u32le(bytes, 24)?)
        || u32le(bytes, 28)? != 0
        || u32le(bytes, 32)? != 1
    {
        return Err(invalid("unsupported registry hive version/type/format"));
    }
    if checksum(bytes)? != u32le(bytes, 508)? || u32le(bytes, 40)? as usize != bytes.len() - 4096 {
        return Err(invalid("REGF checksum or bin length mismatch"));
    }
    let mut result = BTreeMap::new();
    let mut bin = 4096;
    while bin < bytes.len() {
        if slice(bytes, bin, 4)? != b"hbin" || u32le(bytes, bin + 4)? as usize != bin - 4096 {
            return Err(invalid("invalid HBIN identity"));
        }
        let size = u32le(bytes, bin + 8)? as usize;
        if size < 4096 || !size.is_multiple_of(4096) {
            return Err(invalid("invalid HBIN size"));
        }
        slice(bytes, bin, size)?;
        let mut at = bin + 32;
        while at < bin + size {
            let signed = u32le(bytes, at)? as i32;
            let length = signed.unsigned_abs() as usize;
            if length < 8 || !length.is_multiple_of(8) || at + length > bin + size {
                return Err(invalid("invalid registry cell extent"));
            }
            result.insert(
                (at - 4096) as u32,
                Cell {
                    at: at + 4,
                    size: length - 4,
                    allocated: signed < 0,
                },
            );
            at += length;
            if result.len() > 65536 {
                return Err(invalid("registry cell limit exceeded"));
            }
        }
        bin += size;
    }
    Ok(result)
}
impl Hive {
    fn open(bytes: Vec<u8>) -> Result<Self> {
        let cells = cells(&bytes)?;
        Ok(Self { bytes, cells })
    }
    fn cell(&self, id: u32) -> Result<&Cell> {
        self.cells
            .get(&id)
            .filter(|c| c.allocated)
            .ok_or_else(|| invalid("registry reference is not an allocated cell"))
    }
    fn data(&self, id: u32) -> Result<&[u8]> {
        let c = self.cell(id)?;
        slice(&self.bytes, c.at, c.size)
    }
    fn key(&self, id: u32) -> Result<&[u8]> {
        let b = self.data(id)?;
        if slice(b, 0, 2)? != b"nk" || word(b, 2)? & 0x10 != 0 || u32le(b, 24)? != 0 {
            return Err(invalid("unsupported registry key/link/volatile subkeys"));
        }
        slice(b, 0, 76)?;
        Ok(b)
    }
    fn text(b: &[u8], compressed: bool) -> Result<String> {
        let text = if compressed {
            if !b.is_ascii() {
                return Err(invalid("non-ASCII compressed registry names unsupported"));
            }
            String::from_utf8(b.to_vec()).unwrap()
        } else {
            if !b.len().is_multiple_of(2) {
                return Err(invalid("invalid registry Unicode name"));
            }
            String::from_utf16(
                &b.chunks_exact(2)
                    .map(|v| u16::from_le_bytes([v[0], v[1]]))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| invalid("invalid registry Unicode name"))?
        };
        if text.contains(['\0', '\\', '/']) || !text.is_ascii() {
            return Err(invalid("unsupported registry name"));
        }
        Ok(text.to_ascii_lowercase())
    }
    fn name(&self, id: u32) -> Result<String> {
        let b = self.key(id)?;
        Self::text(slice(b, 76, word(b, 72)? as usize)?, word(b, 2)? & 32 != 0)
    }
    fn index(&self, id: u32, seen: &mut BTreeSet<u32>, depth: usize) -> Result<Vec<u32>> {
        if depth > 8 || !seen.insert(id) || seen.len() > 4096 {
            return Err(invalid("cyclic or oversized subkey index"));
        }
        let b = self.data(id)?;
        let count = word(b, 2)? as usize;
        if count > 4096 {
            return Err(invalid("subkey index count exceeds limit"));
        }
        let mut out = Vec::new();
        let typ = slice(b, 0, 2)?;
        if typ != b"lh" && typ != b"lf" && typ != b"li" && typ != b"ri" {
            return Err(invalid("unknown registry subkey index"));
        }
        for i in 0..count {
            let child = u32le(b, 4 + i * if typ == b"lh" || typ == b"lf" { 8 } else { 4 })?;
            if typ == b"ri" {
                out.extend(self.index(child, seen, depth + 1)?);
            } else {
                let name = self.name(child)?;
                if typ == b"lh" {
                    let hash = name
                        .to_ascii_uppercase()
                        .bytes()
                        .fold(0u32, |a, v| a.wrapping_mul(37).wrapping_add(v as u32));
                    if hash != u32le(b, 8 + i * 8)? {
                        return Err(invalid("registry LH hash mismatch"));
                    }
                }
                if typ == b"lf" {
                    let hint = u32le(b, 8 + i * 8)?.to_le_bytes();
                    let mut expected = [0u8; 4];
                    for (a, v) in expected.iter_mut().zip(name.bytes()) {
                        *a = v.to_ascii_uppercase();
                    }
                    if hint.map(|v| v.to_ascii_uppercase()) != expected {
                        return Err(invalid("registry LF hint mismatch"));
                    }
                }
                out.push(child);
            }
            if out.len() > 4096 {
                return Err(invalid("too many registry subkeys"));
            }
        }
        Ok(out)
    }
    fn children(&self, id: u32) -> Result<Vec<u32>> {
        let b = self.key(id)?;
        let count = u32le(b, 20)? as usize;
        if count > 4096 {
            return Err(invalid("too many registry subkeys"));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        let ids = self.index(u32le(b, 28)?, &mut BTreeSet::new(), 0)?;
        if ids.len() != count {
            return Err(invalid("registry subkey count mismatch"));
        }
        let mut names = BTreeSet::new();
        for child in &ids {
            if u32le(self.key(*child)?, 16)? != id || !names.insert(self.name(*child)?) {
                return Err(invalid("registry parent mismatch or duplicate child name"));
            }
        }
        Ok(ids)
    }
    fn path(&self, path: &str) -> Result<u32> {
        let mut id = u32le(&self.bytes, 36)?;
        for name in path.split('/').filter(|v| !v.is_empty()) {
            id = self
                .children(id)?
                .into_iter()
                .find(|v| self.name(*v).is_ok_and(|n| n.eq_ignore_ascii_case(name)))
                .ok_or_else(|| invalid(format!("BCD key missing: {name}")))?;
        }
        Ok(id)
    }
    fn values(&self, id: u32) -> Result<Vec<(String, u32, Value)>> {
        let key = self.key(id)?;
        let count = u32le(key, 36)? as usize;
        if count > 8192 {
            return Err(invalid("registry value count exceeds limit"));
        }
        let mut result = Vec::new();
        let mut names = BTreeSet::new();
        for i in 0..count {
            let index = u32le(self.data(u32le(key, 40)?)?, i * 4)?;
            let b = self.data(index)?;
            if slice(b, 0, 2)? != b"vk" {
                return Err(invalid("invalid registry value cell"));
            }
            let name = Self::text(slice(b, 20, word(b, 2)? as usize)?, word(b, 16)? & 1 != 0)?;
            if !names.insert(name.clone()) {
                return Err(invalid("duplicate registry value name"));
            }
            let raw = u32le(b, 4)?;
            let length = (raw & 0x7fffffff) as usize;
            if length > 256 * 1024 {
                return Err(invalid("registry value data exceeds limit"));
            }
            let data = if raw & 0x80000000 != 0 {
                if length > 4 {
                    return Err(invalid("invalid inline registry value"));
                }
                slice(b, 8, length)?
            } else if length == 0 {
                &[]
            } else {
                slice(self.data(u32le(b, 8)?)?, 0, length)?
            };
            result.push((
                name,
                index,
                Value {
                    kind: u32le(b, 12)?,
                    bytes: data.to_vec(),
                },
            ));
        }
        Ok(result)
    }
    fn snapshot(&self) -> Result<Snapshot> {
        fn walk(
            h: &Hive,
            id: u32,
            path: String,
            seen: &mut BTreeSet<u32>,
            out: &mut Snapshot,
            depth: usize,
            total: &mut usize,
        ) -> Result<()> {
            if depth > 32 || !seen.insert(id) || seen.len() > 4096 {
                return Err(invalid("registry key cycle/depth/count exceeded"));
            }
            let values = h.values(id)?;
            for (_, _, v) in &values {
                *total += v.bytes.len();
                if *total > LIMIT {
                    return Err(invalid("registry data budget exceeded"));
                }
            }
            out.insert(
                path.clone(),
                values.into_iter().map(|(n, _, v)| (n, v)).collect(),
            );
            for child in h.children(id)? {
                let name = h.name(child)?;
                walk(
                    h,
                    child,
                    if path.is_empty() {
                        name
                    } else {
                        format!("{path}/{name}")
                    },
                    seen,
                    out,
                    depth + 1,
                    total,
                )?;
            }
            Ok(())
        }
        let mut out = BTreeMap::new();
        walk(
            self,
            u32le(&self.bytes, 36)?,
            String::new(),
            &mut BTreeSet::new(),
            &mut out,
            0,
            &mut 0,
        )?;
        Ok(out)
    }
    fn allocate(&mut self, data: &[u8]) -> Result<u32> {
        let need = (data.len() + 4 + 7) & !7;
        let (&id, cell) = self
            .cells
            .iter()
            .find(|(_, c)| !c.allocated && c.size + 4 >= need)
            .ok_or_else(|| {
                invalid("BCD has insufficient free cells; hive growth is unsupported")
            })?;
        let at = cell.at - 4;
        let available = cell.size + 4;
        let length = if available - need >= 8 {
            need
        } else {
            available
        };
        self.bytes[at..at + length].fill(0);
        put(&mut self.bytes, at, (-(length as i32)) as u32)?;
        self.bytes[at + 4..at + 4 + data.len()].copy_from_slice(data);
        self.cells.remove(&id);
        self.cells.insert(
            id,
            Cell {
                at: at + 4,
                size: length - 4,
                allocated: true,
            },
        );
        if length < available {
            put(&mut self.bytes, at + length, (available - length) as u32)?;
            self.cells.insert(
                id + length as u32,
                Cell {
                    at: at + length + 4,
                    size: available - length - 4,
                    allocated: false,
                },
            );
        }
        Ok(id)
    }
    fn set(&mut self, id: u32, offset: usize, value: u32) -> Result<()> {
        let at = self.cell(id)?.at;
        put(&mut self.bytes, at + offset, value)
    }
    fn add_element(&mut self, parent: u32) -> Result<u32> {
        let key = self.key(parent)?;
        let security = u32le(key, 44)?;
        let timestamp = slice(key, 4, 8)?.to_vec();
        let sk = self.data(security)?;
        if slice(sk, 0, 2)? != b"sk" {
            return Err(invalid("invalid inherited registry security cell"));
        }
        slice(sk, 20, u32le(sk, 16)? as usize)?;
        let refs = u32le(sk, 12)?
            .checked_add(1)
            .ok_or_else(|| invalid("security reference count overflow"))?;
        let mut nk = vec![0; 84];
        nk[..2].copy_from_slice(b"nk");
        nk[2..4].copy_from_slice(&32u16.to_le_bytes());
        nk[4..12].copy_from_slice(&timestamp);
        put(&mut nk, 16, parent)?;
        for at in [28, 32, 40, 48] {
            put(&mut nk, at, NONE)?;
        }
        put(&mut nk, 44, security)?;
        nk[72..74].copy_from_slice(&8u16.to_le_bytes());
        nk[76..84].copy_from_slice(b"16000048");
        let child = self.allocate(&nk)?;
        self.set(security, 12, refs)?;
        let mut children = self.children(parent)?;
        children.push(child);
        children.sort_by_key(|id| self.name(*id).unwrap_or_default());
        let mut list = Vec::from(b"lh".as_slice());
        list.extend_from_slice(&(children.len() as u16).to_le_bytes());
        for id in &children {
            list.extend_from_slice(&id.to_le_bytes());
            list.extend_from_slice(
                &self
                    .name(*id)?
                    .to_ascii_uppercase()
                    .bytes()
                    .fold(0u32, |a, b| a.wrapping_mul(37).wrapping_add(b as u32))
                    .to_le_bytes(),
            );
        }
        let index = self.allocate(&list)?;
        self.set(parent, 28, index)?;
        self.set(parent, 20, children.len() as u32)?;
        let maximum = u32le(self.key(parent)?, 52)?.max(16);
        self.set(parent, 52, maximum)?;
        Ok(child)
    }
    fn boolean(&mut self, id: u32) -> Result<bool> {
        let values = self.values(id)?;
        if let Some((_, index, value)) = values.iter().find(|(n, _, _)| n == "element") {
            if value.kind != 3 || value.bytes.len() != 1 || value.bytes[0] > 1 {
                return Err(invalid(
                    "NoCodeIntegrity must be a one-byte REG_BINARY boolean",
                ));
            }
            let b = self.data(*index)?;
            if u32le(b, 4)? & 0x80000000 != 0 {
                let at = self.cell(*index)?.at + 8;
                self.bytes[at] = 1;
            } else {
                let at = self.cell(u32le(b, 8)?)?.at;
                self.bytes[at] = 1;
            }
            return Ok(value.bytes[0] == 0);
        }
        let mut vk = vec![0; 27];
        vk[..2].copy_from_slice(b"vk");
        vk[2..4].copy_from_slice(&7u16.to_le_bytes());
        put(&mut vk, 4, 0x80000001)?;
        put(&mut vk, 8, 1)?;
        put(&mut vk, 12, 3)?;
        vk[16..18].copy_from_slice(&1u16.to_le_bytes());
        vk[20..].copy_from_slice(b"Element");
        let value = self.allocate(&vk)?;
        let mut list = Vec::new();
        for (_, index, _) in &values {
            list.extend_from_slice(&index.to_le_bytes());
        }
        list.extend_from_slice(&value.to_le_bytes());
        let list = self.allocate(&list)?;
        self.set(id, 36, values.len() as u32 + 1)?;
        self.set(id, 40, list)?;
        let max = u32le(self.key(id)?, 60)?.max(14);
        self.set(id, 60, max)?;
        let max = u32le(self.key(id)?, 64)?.max(1);
        self.set(id, 64, max)?;
        Ok(true)
    }
}
/// Returns a new hive, fully re-parsed and compared with an expected semantic
/// snapshot. Unsupported/dirty inputs fail without changing caller bytes.
pub fn patch(bytes: &[u8]) -> Result<(Vec<u8>, Report)> {
    let mut hive = Hive::open(bytes.to_vec())?;
    let before = hive.snapshot()?;
    let mut expected = before.clone();
    let mut created = 0;
    let mut changed = 0;
    for object in OBJECTS {
        let parent_path = format!("objects/{object}/elements");
        let parent = hive.path(&parent_path)?;
        let element = hive
            .children(parent)?
            .into_iter()
            .find(|id| hive.name(*id).is_ok_and(|n| n == "16000048"));
        let element = if let Some(id) = element {
            id
        } else {
            created += 1;
            hive.add_element(parent)?
        };
        if hive.boolean(element)? {
            changed += 1;
        }
        expected
            .entry(format!("{parent_path}/16000048"))
            .or_default()
            .insert(
                "element".into(),
                Value {
                    kind: 3,
                    bytes: vec![1],
                },
            );
    }
    if changed > 0 || created > 0 {
        let sequence = u32le(&hive.bytes, 4)?
            .checked_add(1)
            .ok_or_else(|| invalid("registry sequence overflow"))?;
        put(&mut hive.bytes, 4, sequence)?;
        put(&mut hive.bytes, 8, sequence)?;
        let crc = checksum(&hive.bytes)?;
        put(&mut hive.bytes, 508, crc)?;
    }
    let after = Hive::open(hive.bytes.clone())?;
    if after.snapshot()? != expected {
        return Err(invalid("BCD edit changed unrelated registry entries"));
    }
    let report = Report {
        original_sha256: hex::encode(Sha256::digest(bytes)),
        resulting_sha256: hex::encode(Sha256::digest(&hive.bytes)),
        size: hive.bytes.len(),
        created_elements: created,
        changed_values: changed,
        preserved_other_entries: true,
    };
    Ok((hive.bytes, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/spec-a/bcd.synthetic.hive");
    fn reseal(bytes: &mut [u8]) {
        let sum = checksum(bytes).unwrap();
        put(bytes, 508, sum).unwrap();
    }
    #[test]
    fn creates_only_two_elements_preserves_source_and_is_idempotent() {
        let before = Hive::open(FIXTURE.to_vec()).unwrap().snapshot().unwrap();
        let (bytes, report) = patch(FIXTURE).unwrap();
        assert_eq!((report.created_elements, report.changed_values), (2, 2));
        assert_eq!(bytes.len(), FIXTURE.len());
        let after = Hive::open(bytes.clone()).unwrap().snapshot().unwrap();
        for (path, values) in before {
            assert_eq!(after[&path], values);
        }
        assert_eq!(after.len(), 10);
        let (again, report) = patch(&bytes).unwrap();
        assert_eq!(again, bytes);
        assert_eq!((report.created_elements, report.changed_values), (0, 0));
    }
    #[test]
    fn updates_existing_booleans_and_rejects_other_types() {
        let (bytes, _) = patch(FIXTURE).unwrap();
        let mut hive = Hive::open(bytes).unwrap();
        let id = hive
            .path(&format!("Objects/{}/Elements/16000048", OBJECTS[0]))
            .unwrap();
        let index = hive.values(id).unwrap()[0].1;
        hive.set(index, 8, 0).unwrap();
        let (fixed, report) = patch(&hive.bytes).unwrap();
        assert_eq!((report.created_elements, report.changed_values), (0, 1));
        assert_eq!(
            Hive::open(fixed).unwrap().values(id).unwrap()[0].2.bytes,
            [1]
        );
        hive.set(index, 12, 4).unwrap();
        assert!(patch(&hive.bytes).is_err());
    }
    #[test]
    fn dirty_truncated_oversized_and_bad_cells_are_rejected() {
        for n in [0, 8191, FIXTURE.len() - 1] {
            assert!(patch(&FIXTURE[..n]).is_err());
        }
        let mut dirty = FIXTURE.to_vec();
        put(&mut dirty, 4, 2).unwrap();
        reseal(&mut dirty);
        assert!(patch(&dirty).is_err());
        for size in [0, 4, 0x80000000, 32768] {
            let mut bad = FIXTURE.to_vec();
            put(&mut bad, 4128, size).unwrap();
            assert!(patch(&bad).is_err());
        }
        let mut huge = vec![0; LIMIT + 4096];
        huge[..FIXTURE.len()].copy_from_slice(FIXTURE);
        assert!(patch(&huge).is_err());
    }
    #[test]
    fn cycles_bad_parent_hashes_and_exhausted_free_space_fail_closed() {
        let mut hive = Hive::open(FIXTURE.to_vec()).unwrap();
        let root = u32le(&hive.bytes, 36).unwrap();
        let index = u32le(hive.key(root).unwrap(), 28).unwrap();
        hive.set(index, 4, root).unwrap();
        assert!(patch(&hive.bytes).is_err());
        let mut hive = Hive::open(FIXTURE.to_vec()).unwrap();
        hive.set(index, 8, 123).unwrap();
        assert!(patch(&hive.bytes).is_err());
        let mut hive = Hive::open(FIXTURE.to_vec()).unwrap();
        let free: Vec<_> = hive
            .cells
            .values()
            .filter(|c| !c.allocated)
            .cloned()
            .collect();
        for c in free {
            put(&mut hive.bytes, c.at - 4, (-((c.size + 4) as i32)) as u32).unwrap();
        }
        assert!(patch(&hive.bytes)
            .unwrap_err()
            .to_string()
            .contains("free cells"));
    }
}
