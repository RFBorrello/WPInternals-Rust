use sha2::{Digest, Sha256};
use std::io::Cursor;
use wpi_image::{
    ffu::FfuMetadata,
    gpt::Gpt,
    recovery_audit::{self, parse_manifest},
    ImageError,
};
const CHUNK: usize = 32768;
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn crc_header(h: &mut [u8]) {
    h[16..20].fill(0);
    let crc = crc32fast::hash(&h[..92]);
    put32(h, 16, crc);
}
fn crc_primary(b: &mut [u8]) {
    let crc = crc32fast::hash(&b[1024..17408]);
    put32(b, 600, crc);
    crc_header(&mut b[512..1024]);
}
fn rehash(b: &mut [u8]) {
    for i in 1..6 {
        let h = Sha256::digest(&b[i * CHUNK..(i + 1) * CHUNK]);
        b[32 + (i - 1) * 32..32 + i * 32].copy_from_slice(&h);
    }
}
fn fixture() -> (Vec<u8>, Vec<u8>) {
    let mut input = Cursor::new(
        include_bytes!("../../../tests/fixtures/synthetic-spec-a-package.ffu").as_slice(),
    );
    let f = FfuMetadata::open(&mut input).unwrap();
    let mut p = f.read_disk(&mut input, 0, 17408).unwrap();
    put64(&mut p, 544, 0x3fff);
    put64(&mut p, 560, 0x3fde);
    let at = 1024 + 8 * 128;
    p[at..at + 16].fill(0x55);
    p[at + 16..at + 32].fill(0x66);
    put64(&mut p, at + 32, 0x2400);
    put64(&mut p, at + 40, 0x3fde);
    for (i, c) in "Data".encode_utf16().enumerate() {
        p[at + 56 + i * 2..at + 58 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    crc_primary(&mut p);
    let g = Gpt::read(&mut Cursor::new(&p), p.len() as u64).unwrap();
    let mut manifest=String::from("[FullFlash]\r\nDescription without a property delimiter\r\n[Store]\r\nSectorSize=512\r\nMinSectorCount=16384\r\n");
    for part in &g.partitions {
        manifest.push_str(&format!(
            "[Partition]\r\nName={}\r\nPrimary={}\r\n",
            part.name, part.name
        ));
        if part.name == "Data" {
            manifest.push_str("UseAllSpace=true\r\n");
        } else {
            manifest.push_str(&format!(
                "TotalSectors={}\r\nRequiredToFlash=True\r\n",
                part.last_sector - part.first_sector + 1
            ));
        }
    }
    let mut b = vec![0u8; CHUNK * 6];
    put32(&mut b, 0, 32);
    b[4..16].copy_from_slice(b"SignedImage ");
    put32(&mut b, 16, 32);
    put32(&mut b, 20, 0x800c);
    put32(&mut b, 28, 5 * 32);
    put32(&mut b, CHUNK, 24);
    b[CHUNK + 4..CHUNK + 16].copy_from_slice(b"ImageFlash  ");
    put32(&mut b, CHUNK + 16, manifest.len() as u32);
    put32(&mut b, CHUNK + 20, 32);
    b[CHUNK + 24..CHUNK + 24 + manifest.len()].copy_from_slice(manifest.as_bytes());
    let store = 2 * CHUNK;
    b[store + 4] = 1;
    b[store + 12..store + 30].copy_from_slice(b"SYNTHETIC.RECOVERY");
    put32(&mut b, store + 204, CHUNK as u32);
    put32(&mut b, store + 208, 3);
    put32(&mut b, store + 212, 56);
    for (i, n) in [2, 1, 0, 0, 2, 0, 1, 1, 0, 0, 1, 1, 2, 0]
        .into_iter()
        .enumerate()
    {
        put32(&mut b, store + 248 + i * 4, n);
    }
    b[4 * CHUNK..4 * CHUNK + p.len()].copy_from_slice(&p);
    b[6 * CHUNK - 33 * 512..6 * CHUNK - 512].copy_from_slice(&p[1024..]);
    b[6 * CHUNK - 512..].copy_from_slice(&p[512..1024]);
    let h = &mut b[6 * CHUNK - 512..];
    put64(h, 24, 0x3fff);
    put64(h, 32, 1);
    put64(h, 72, 0x3fdf);
    crc_header(h);
    rehash(&mut b);
    put64(&mut p, 544, 0x7fff);
    put64(&mut p, 560, 0x7fde);
    put64(&mut p, at + 40, 0x7fde);
    crc_primary(&mut p);
    (b, p)
}
fn audit(b: &[u8], p: &[u8]) -> wpi_image::Result<recovery_audit::Report> {
    recovery_audit::analyze(
        &mut Cursor::new(b),
        p,
        0x8000,
        &hash(p),
        &hash(b),
        |_, _, _| true,
    )
}
#[test]
fn ini_handles_phone_line_endings_and_rejects_ambiguous_or_oversized_layouts() {
    let valid="[FullFlash]\r\r\nDescription text\r\r\n[Store]\r\r\nSectorSize=512\r\r\nMinSectorCount=1000\r\r\n[Partition]\r\r\nName=Data\r\r\nUseAllSpace=TrUe";
    let m = parse_manifest(valid).unwrap();
    assert_eq!(m.minimum_sector_count, 1000);
    assert!(m.partitions[0].use_all_space);
    for text in [
        valid.replace("SectorSize=512", "SectorSize=4096"),
        valid.replace("1000", "18446744073709551616"),
        valid.replace("TrUe", "yes"),
        valid.replace("TrUe", "false"),
        format!("{valid}\nName=other"),
        format!("{valid}\n[Store]\nSectorSize=512"),
        format!("{valid}\n[Partition]\nName=data\nTotalSectors=1"),
        format!("{valid}\n[Partition]\nName=other\nUseAllSpace=true"),
        format!("{valid}\n[Unknown]\nName=x"),
        format!("{valid}\nPrimary=Other"),
        format!("{valid}\nTotalSectors=1\nUsedSectors=2"),
        "x".repeat(128 * 1024 + 1),
        format!("{valid}\n{}", "x".repeat(4097)),
        format!("{valid}\0"),
    ] {
        assert!(parse_manifest(&text).is_err());
    }
}
#[test]
fn minimum_size_expansion_and_source_backup_are_reported_without_recovery_authority() {
    let (b, p) = fixture();
    let original = p.clone();
    let r = audit(&b, &p).unwrap();
    assert_eq!(p, original);
    assert!(
        r.chunk_integrity_verified
            && r.capacity_meets_manifest_minimum
            && r.template_capacity_equals_manifest_minimum
    );
    assert_eq!(r.expanding_partitions, ["Data"]);
    assert_eq!(r.partitions_with_changed_ranges, ["Data"]);
    assert_eq!(r.end_relative_payloads.len(), 2);
    assert_eq!(r.end_relative_payloads[0].all_zero, Some(true));
    let backup = r.end_relative_payloads[1].backup_template.as_ref().unwrap();
    assert_eq!(backup.current_lba, 0x3fff);
    assert!(backup.matches_source_primary_entries && backup.header_and_table_crc_valid);
    assert!(
        !r.device_layout_expansion_validated
            && !r.recovery_validated
            && !r.phone_contacted
            && !r.phone_writes_enabled
    );
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("66666666-6666-6666-6666-666666666666"));
}
#[test]
fn contradictory_template_or_manifest_cannot_be_hidden_by_valid_ffu_chunk_hashes() {
    let (b, p) = fixture();
    let mut wrong = b.clone();
    let h = &mut wrong[6 * CHUNK - 512..];
    put64(h, 32, 2);
    crc_header(h);
    rehash(&mut wrong);
    assert!(audit(&wrong, &p).is_err());
    let mut wrong = b.clone();
    wrong[6 * CHUNK - 33 * 512] ^= 1;
    rehash(&mut wrong);
    assert!(audit(&wrong, &p).is_err());
    let mut wrong = b.clone();
    let text = std::str::from_utf8(&wrong[CHUNK + 24..CHUNK + 2000]).unwrap();
    let at = text.find("TotalSectors=64").unwrap() + CHUNK + 24 + 13;
    wrong[at] = b'5';
    rehash(&mut wrong);
    assert!(audit(&wrong, &p).is_err());
    let mut wrong = b.clone();
    wrong[4 * CHUNK + 600] ^= 1;
    rehash(&mut wrong);
    assert!(audit(&wrong, &p).is_err());
}
#[test]
fn source_attribute_difference_is_reported_without_normalization_or_recovery_grants() {
    let (mut b, p) = fixture();
    let at = 6 * CHUNK - 33 * 512;
    put64(&mut b, at + 48, 1u64 << 63);
    let crc = crc32fast::hash(&b[at..6 * CHUNK - 512]);
    put32(&mut b, 6 * CHUNK - 512 + 88, crc);
    crc_header(&mut b[6 * CHUNK - 512..]);
    rehash(&mut b);
    let r = audit(&b, &p).unwrap();
    let backup = r.end_relative_payloads[1].backup_template.as_ref().unwrap();
    assert!(!backup.matches_source_primary_entries && backup.header_and_table_crc_valid);
    assert_eq!(backup.attribute_differences.len(), 1);
    assert_eq!(
        backup.attribute_differences[0].backup_attributes,
        "0x8000000000000000"
    );
    assert!(!r.recovery_validated && !r.phone_writes_enabled);
    assert!(r
        .execution_blockers
        .iter()
        .any(|s| s.contains("differing partition attributes")));
    // A valid-CRC change to an identity/range is still rejected.
    b[at + 16] ^= 1;
    let crc = crc32fast::hash(&b[at..6 * CHUNK - 512]);
    put32(&mut b, 6 * CHUNK - 512 + 88, crc);
    crc_header(&mut b[6 * CHUNK - 512..]);
    rehash(&mut b);
    assert!(audit(&b, &p).is_err());
}
#[test]
fn corruption_pins_capacity_and_each_cancellation_boundary_fail_closed() {
    let (b, p) = fixture();
    let mut bad = b.clone();
    bad[4 * CHUNK + 20000] ^= 1;
    assert!(audit(&bad, &p).is_err());
    for (primary_hash, ffu_hash) in [(hash(&p), "0".repeat(64)), ("0".repeat(64), hash(&b))] {
        assert!(recovery_audit::analyze(
            &mut Cursor::new(&b),
            &p,
            0x8000,
            &primary_hash,
            &ffu_hash,
            |_, _, _| true
        )
        .is_err());
    }
    assert!(recovery_audit::analyze(
        &mut Cursor::new(&b),
        &p,
        u64::MAX,
        &hash(&p),
        &hash(&b),
        |_, _, _| true
    )
    .is_err());
    for stage in [
        "Verify FFU chunks",
        "Fingerprint FFU",
        "Complete offline recovery audit",
    ] {
        for only_final in [false, true] {
            let r = recovery_audit::analyze(
                &mut Cursor::new(&b),
                &p,
                0x8000,
                &hash(&p),
                &hash(&b),
                |s, d, t| s != stage || (only_final && d != t),
            );
            assert!(
                matches!(r, Err(ImageError::Cancelled)),
                "{stage}/{only_final}"
            );
        }
    }
    for n in [0, 17407] {
        assert!(audit(&b, &p[..n]).is_err());
    }
}
