//! GPT inspection with CRC checks, UTF-16 names and bounded partition ranges.
use crate::{invalid, read_at, slice, u32le, u64le, Result, MAX_METADATA, SECTOR_SIZE};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub name: String,
    pub type_guid: Uuid,
    pub guid: Uuid,
    pub first_sector: u64,
    pub last_sector: u64,
    #[serde(with = "decimal_u64")]
    pub attributes: u64,
}
// Attribute bits often use bit 63; JSON numbers would lose precision in JavaScript.
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        value: &u64,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}
impl Partition {
    pub fn byte_range(&self) -> Result<(u64, u64)> {
        let count = self
            .last_sector
            .checked_sub(self.first_sector)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| invalid("invalid partition range"))?;
        Ok((
            self.first_sector
                .checked_mul(SECTOR_SIZE)
                .ok_or_else(|| invalid("partition offset overflow"))?,
            count
                .checked_mul(SECTOR_SIZE)
                .ok_or_else(|| invalid("partition size overflow"))?,
        ))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gpt {
    pub disk_guid: Uuid,
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_sector: u64,
    pub last_usable_sector: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    pub partitions: Vec<Partition>,
}
impl Gpt {
    pub fn from_parts(header: &[u8], entries: &[u8], disk_size: Option<u64>) -> Result<Self> {
        if slice(header, 0, 8)? != b"EFI PART" {
            return Err(invalid("missing GPT EFI PART signature"));
        }
        if u32le(header, 8)? != 0x10000 {
            return Err(invalid("unsupported GPT revision"));
        }
        let size = u32le(header, 12)? as usize;
        if !(92..=512).contains(&size) {
            return Err(invalid("invalid GPT header size"));
        }
        let mut checked = slice(header, 0, size)?.to_vec();
        checked[16..20].fill(0);
        if crc32fast::hash(&checked) != u32le(header, 16)? {
            return Err(invalid("GPT header CRC mismatch"));
        }
        let count = u32le(header, 80)?;
        let entry_size = u32le(header, 84)?;
        if count == 0 || entry_size < 128 || entry_size % 128 != 0 {
            return Err(invalid("invalid GPT entry geometry"));
        }
        let table_size = (count as usize)
            .checked_mul(entry_size as usize)
            .ok_or_else(|| invalid("GPT entries overflow"))?;
        if table_size > MAX_METADATA {
            return Err(invalid("GPT table exceeds limit"));
        }
        let entries = slice(entries, 0, table_size)?;
        if crc32fast::hash(entries) != u32le(header, 88)? {
            return Err(invalid("GPT table CRC mismatch"));
        }
        let first = u64le(header, 40)?;
        let last = u64le(header, 48)?;
        let current_lba = u64le(header, 24)?;
        let backup_lba = u64le(header, 32)?;
        if first > last
            || current_lba == backup_lba
            || (first..=last).contains(&current_lba)
            || (first..=last).contains(&backup_lba)
        {
            return Err(invalid("invalid GPT usable range"));
        }
        if let Some(bytes) = disk_size {
            let sectors = bytes / SECTOR_SIZE;
            if last >= sectors || current_lba >= sectors || backup_lba >= sectors {
                return Err(invalid("GPT exceeds disk size"));
            }
        }
        let mut partitions = Vec::new();
        for entry in entries.chunks_exact(entry_size as usize) {
            if entry[..16].iter().all(|b| *b == 0) {
                continue;
            }
            let first_sector = u64le(entry, 32)?;
            let last_sector = u64le(entry, 40)?;
            if first_sector > last_sector || first_sector < first || last_sector > last {
                return Err(invalid("partition exceeds usable GPT range"));
            }
            let units: Vec<u16> = slice(entry, 56, 72)?
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .take_while(|u| *u != 0)
                .collect();
            let name =
                String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16 GPT name"))?;
            partitions.push(Partition {
                name,
                type_guid: Uuid::from_bytes_le(entry[..16].try_into().unwrap()),
                guid: Uuid::from_bytes_le(entry[16..32].try_into().unwrap()),
                first_sector,
                last_sector,
                attributes: u64le(entry, 48)?,
            });
        }
        let mut sorted: Vec<_> = partitions.iter().collect();
        sorted.sort_by_key(|p| p.first_sector);
        if sorted
            .windows(2)
            .any(|pair| pair[0].last_sector >= pair[1].first_sector)
        {
            return Err(invalid("overlapping GPT partitions"));
        }
        Ok(Self {
            disk_guid: Uuid::from_bytes_le(slice(header, 56, 16)?.try_into().unwrap()),
            current_lba,
            backup_lba,
            first_usable_sector: first,
            last_usable_sector: last,
            entry_count: count,
            entry_size,
            partitions,
        })
    }
    /// Accepts either a full disk image or a GPT.bin starting at the primary header.
    pub fn read<R: Read + Seek>(reader: &mut R, disk_size: u64) -> Result<Self> {
        let prefix = read_at(reader, 0, 512)?;
        let (header, header_start) = if prefix.starts_with(b"EFI PART") {
            (prefix, 0u64)
        } else {
            (read_at(reader, 512, 512)?, 512u64)
        };
        let table_lba = u64le(&header, 72)?;
        let table_size = (u32le(&header, 80)? as usize)
            .checked_mul(u32le(&header, 84)? as usize)
            .ok_or_else(|| invalid("table overflow"))?;
        let offset = table_lba
            .checked_mul(SECTOR_SIZE)
            .and_then(|n| n.checked_sub(if header_start == 0 { SECTOR_SIZE } else { 0 }))
            .ok_or_else(|| invalid("invalid GPT table location"))?;
        let entries = read_at(reader, offset, table_size)?;
        // A small GPT.bin is not the complete disk; the CRC/range checks still apply.
        let declared = u64le(&header, 32)?
            .checked_add(1)
            .and_then(|n| n.checked_mul(SECTOR_SIZE))
            .ok_or_else(|| invalid("GPT disk geometry overflow"))?;
        Self::from_parts(
            &header,
            &entries,
            if disk_size >= declared {
                Some(disk_size)
            } else {
                None
            },
        )
    }
    pub fn partition(&self, name: &str) -> Result<&Partition> {
        let matches: Vec<_> = self
            .partitions
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(name))
            .collect();
        match matches.as_slice() {
            [p] => Ok(p),
            [] => Err(invalid(format!("partition {name} not found"))),
            _ => Err(invalid("ambiguous partition name")),
        }
    }
    pub fn to_xml(&self) -> String {
        fn escape(s: &str) -> String {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&apos;")
        }
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Partitions>\n");
        for p in &self.partitions {
            xml.push_str(&format!("  <Partition Name=\"{}\" FirstSector=\"{}\" LastSector=\"{}\" PartitionTypeGuid=\"{}\" PartitionGuid=\"{}\" Attributes=\"{}\" />\n", escape(&p.name), p.first_sector, p.last_sector, p.type_guid, p.guid, p.attributes));
        }
        xml.push_str("</Partitions>\n");
        xml
    }
}
