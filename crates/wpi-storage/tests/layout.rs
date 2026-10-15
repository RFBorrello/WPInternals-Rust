use wpi_core::backup::{Geometry, ReadOnlySource};
use wpi_image::{ImageError, Result};
use wpi_storage::layout;
struct Source {
    bytes: Vec<u8>,
    reads: usize,
    max: usize,
    fail_at: Option<usize>,
}
impl ReadOnlySource for Source {
    fn geometry(&self) -> Geometry {
        Geometry {
            size: self.bytes.len() as u64,
            sector_size: 512,
        }
    }
    fn validate(&mut self) -> Result<()> {
        Ok(())
    }
    fn read_at(&mut self, offset: u64, b: &mut [u8]) -> Result<()> {
        self.reads += 1;
        self.max = self.max.max(b.len());
        if self.fail_at == Some(self.reads) {
            return Err(ImageError::Invalid("disconnected".into()));
        }
        b.copy_from_slice(
            self.bytes
                .get(offset as usize..offset as usize + b.len())
                .ok_or_else(|| ImageError::Invalid("out of bounds".into()))?,
        );
        Ok(())
    }
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn crc(b: &[u8]) -> u32 {
    crc32fast::hash(b)
}
fn header(current: u64, backup: u64, table: u64, entries: &[u8]) -> Vec<u8> {
    let mut h = vec![0; 512];
    h[..8].copy_from_slice(b"EFI PART");
    put32(&mut h, 8, 0x10000);
    put32(&mut h, 12, 92);
    put64(&mut h, 24, current);
    put64(&mut h, 32, backup);
    put64(&mut h, 40, 34);
    put64(&mut h, 48, 62);
    h[56..72].fill(0x55);
    put64(&mut h, 72, table);
    put32(&mut h, 80, 128);
    put32(&mut h, 84, 128);
    put32(&mut h, 88, crc(entries));
    let sum = crc(&h[..92]);
    put32(&mut h, 16, sum);
    h
}
fn fixture(names: [&str; 3]) -> Source {
    let mut e = vec![0; 128 * 128];
    for (i, (name, first, last)) in names
        .into_iter()
        .zip([(34, 39), (40, 49), (50, 62)])
        .enumerate()
        .map(|(i, (n, (a, b)))| (i, (n, a, b)))
    {
        let p = &mut e[i * 128..(i + 1) * 128];
        p[..16].fill(1);
        p[16..32].fill((i + 1) as u8);
        put64(p, 32, first);
        put64(p, 40, last);
        for (n, c) in name.encode_utf16().enumerate() {
            p[56 + n * 2..58 + n * 2].copy_from_slice(&c.to_le_bytes());
        }
    }
    let mut bytes = vec![0; 96 * 512];
    bytes[512..1024].copy_from_slice(&header(1, 95, 2, &e));
    bytes[95 * 512..].copy_from_slice(&header(95, 1, 63, &e));
    bytes[1024..1024 + e.len()].copy_from_slice(&e);
    bytes[63 * 512..95 * 512].copy_from_slice(&e);
    Source {
        bytes,
        reads: 0,
        max: 0,
        fail_at: None,
    }
}
#[test]
fn paired_gpt_and_required_partition_ranges_are_bounded_and_fingerprinted() {
    let mut s = fixture(["EFIESP", "MainOS", "Data"]);
    let original = s.bytes.clone();
    let r = layout::inspect(&mut s).unwrap();
    assert_eq!(s.reads, 4);
    assert!(s.max <= 1024 * 1024);
    assert_eq!(layout::range(&r, None).unwrap(), (0, 96));
    assert_eq!(layout::range(&r, Some("MainOS")).unwrap(), (40, 10));
    assert_eq!(r.gpt_sha256.len(), 64);
    assert!(!r.hardware_validated);
    assert!(!r.device_identity_authenticated);
    assert_eq!(s.bytes, original);
}
#[test]
fn corrupt_or_inconsistent_backup_gpt_is_not_accepted() {
    for at in [512 + 16, 1024 + 60, 95 * 512 + 16, 63 * 512 + 60] {
        let mut s = fixture(["EFIESP", "MainOS", "Data"]);
        s.bytes[at] ^= 1;
        assert!(layout::inspect(&mut s).is_err());
    }
    let mut s = fixture(["EFIESP", "MainOS", "Data"]);
    let secondary = &mut s.bytes[95 * 512..];
    secondary[56] ^= 1;
    put32(secondary, 16, 0);
    let sum = crc(&secondary[..92]);
    put32(secondary, 16, sum);
    assert!(layout::inspect(&mut s).is_err());
}
#[test]
fn overflow_missing_and_ambiguous_partition_metadata_fail_closed() {
    for names in [
        ["EFIESP", "MainOS", "Other"],
        ["EFIESP", "MainOS", "MainOS"],
        ["EFIESP", "MainOS", ""],
    ] {
        assert!(layout::inspect(&mut fixture(names)).is_err());
    }
    for (at, value) in [(72, u64::MAX), (80, u64::MAX)] {
        let mut s = fixture(["EFIESP", "MainOS", "Data"]);
        put64(&mut s.bytes, 512 + at, value);
        assert!(layout::inspect(&mut s).is_err());
        assert_eq!(s.reads, 1);
    }
}
#[test]
fn read_errors_stop_gpt_inspection_without_retry() {
    for n in 1..=4 {
        let mut s = fixture(["EFIESP", "MainOS", "Data"]);
        s.fail_at = Some(n);
        assert!(layout::inspect(&mut s).is_err());
        assert_eq!(s.reads, n);
    }
}
