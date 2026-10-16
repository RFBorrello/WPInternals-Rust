use std::io::Cursor;
use wpi_image::{
    ffu::FfuMetadata,
    spec_a::{self, Import},
    ImageError,
};
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic-spec-a.ffu");
const SBL3: &[u8] = include_bytes!("../../../tests/fixtures/spec-a/sbl3.bin");
const LOADER: &[u8] = include_bytes!("../../../tests/fixtures/spec-a/loader.mbn");
const HEX: &[u8] = include_bytes!("../../../tests/fixtures/spec-a/loader.hex");
fn prepare(sbl3: Option<Import<'_>>, loaders: &[Import<'_>]) -> spec_a::Preparation {
    let mut reader = Cursor::new(FFU);
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    let gpt = ffu.gpt(&mut reader).unwrap();
    ffu.verify_hashes(&mut reader, |_, _| true).unwrap();
    spec_a::prepare(&mut reader, &ffu, &gpt, sbl3, loaders).unwrap()
}
#[test]
fn reference_short_long_headers_hex_and_patch_locations() {
    let report = prepare(
        Some(Import {
            name: "raw.bin",
            bytes: SBL3,
        }),
        &[Import {
            name: "loader.hex",
            bytes: HEX,
        }],
    );
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/spec-a/reference.json"
    ))
    .unwrap();
    for stock in &report.stock {
        assert!(stock.error.is_none());
        assert_eq!(
            stock.image.as_ref().unwrap().root_certificate_sha256,
            expected["root_certificate_sha256"].as_str().unwrap()
        );
    }
    assert_eq!(
        report.stock[0].image.as_ref().unwrap().header_offset,
        0x2800 + 20
    );
    assert_eq!(
        report.stock[1].patch.as_ref().unwrap().offset,
        Some(expected["sbl2_patch_offset"].as_u64().unwrap() as usize)
    );
    assert_eq!(
        report.stock[2].patch.as_ref().unwrap().offset,
        Some(expected["sbl3_patch_offset"].as_u64().unwrap() as usize)
    );
    assert_eq!(
        report.loaders[0].decoded.as_ref().unwrap().sha256,
        expected["loader_decoded_sha256"].as_str().unwrap()
    );
    assert!(report.loaders[0].v1_marker_present && report.loaders[0].matches_stock_sbl1_root);
    assert_eq!(spec_a::decode_loader(HEX).unwrap(), LOADER);
    assert_eq!(report.external_sbl3_fits, Some(true));
    assert!(!report.phone_writes_enabled);
    assert!(!report.blockers.is_empty());
}
#[test]
fn malformed_headers_offsets_and_certificate_regions_fail_closed() {
    for length in [0, 4, 19, 39, SBL3.len() - 1] {
        assert!(spec_a::parse(&SBL3[..length], 0).is_err());
    }
    assert!(spec_a::parse(SBL3, usize::MAX).is_err());
    for (at, value) in [
        (4, 4),
        (8, u32::MAX),
        (12, u32::MAX),
        (16, u32::MAX),
        (20, 0),
        (24, 1),
        (28, u32::MAX),
        (32, 0),
        (36, 0),
        (36, u32::MAX),
    ] {
        let mut bad = SBL3.to_vec();
        bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(spec_a::parse(&bad, 0).is_err(), "field {at}");
    }
    let image = spec_a::parse(SBL3, 0).unwrap();
    for relative in [0, 2, 10] {
        let mut bad = SBL3.to_vec();
        bad[image.certificates_offset + relative] ^= 255;
        assert!(spec_a::parse(&bad, 0).is_err());
    }
    let mut bad = SBL3.to_vec();
    *bad.last_mut().unwrap() = 7;
    assert!(spec_a::parse(&bad, 0).is_err());
    assert!(spec_a::parse(&vec![0; spec_a::MAX_BOOT_IMAGE + 1], 0).is_err());
    assert!(matches!(
        spec_a::parse(b"\x7fELF\x02\x01\x01\0abcdefghijklmnop", 0),
        Err(ImageError::Unsupported(_))
    ));
}
#[test]
fn patch_patterns_require_unique_code_matches_and_preserve_originals() {
    let original = SBL3.to_vec();
    let image = spec_a::parse(&original, 0).unwrap();
    let mut duplicate = original.clone();
    duplicate[image.image_offset + 64..image.image_offset + 76]
        .copy_from_slice(&original[image.image_offset + 16..image.image_offset + 28]);
    let result = spec_a::patch_preview(&duplicate, &image, false).unwrap();
    assert_eq!(result.status, "ambiguous");
    assert!(result.offset.is_none());
    let mut missing = original.clone();
    missing[image.image_offset..image.image_offset + image.code_size].fill(0);
    // Matching bytes outside code must never authorize a preview.
    missing.extend_from_slice(&original[image.image_offset + 16..image.image_offset + 28]);
    assert_eq!(
        spec_a::patch_preview(&missing, &image, false)
            .unwrap()
            .status,
        "missing"
    );
    assert_eq!(original, SBL3);
    assert_eq!(
        spec_a::patch_preview(&original, &image, false)
            .unwrap()
            .expected,
        "2800d0e5"
    );
}
fn record(kind: u8, address: u16, data: &[u8]) -> String {
    let mut r = vec![data.len() as u8, (address >> 8) as u8, address as u8, kind];
    r.extend_from_slice(data);
    r.push(0u8.wrapping_sub(r.iter().fold(0u8, |a, b| a.wrapping_add(*b))));
    format!(":{}\n", hex::encode(r))
}
#[test]
fn intel_hex_checksums_continuity_record_types_and_eof_are_enforced() {
    let eof = record(1, 0, &[]);
    let valid = record(4, 0, &[0x2a, 0]) + &record(0, 0, &[1, 2]) + &record(0, 2, &[3]) + &eof;
    assert_eq!(
        spec_a::decode_loader(valid.as_bytes()).unwrap(),
        vec![1, 2, 3]
    );
    for bad in [
        valid.replace("0102", "0103"),
        record(0, 0, &[1]),
        record(0, 0, &[1]) + &record(0, 2, &[2]) + &eof,
        record(0, 0, &[1]) + &record(0, 0, &[2]) + &eof,
        record(6, 0, &[1]) + &eof,
        valid.clone() + &eof,
        eof.clone(),
        ":0100000001\n".into(),
        record(4, 1, &[0, 0]) + &eof,
    ] {
        assert!(spec_a::decode_loader(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(spec_a::decode_loader(&vec![b':'; spec_a::MAX_LOADER_FILE + 1]).is_err());
    let overflow = record(4, 0, &[255, 255]) + &record(0, 65535, &[1, 2]) + &eof;
    assert!(spec_a::decode_loader(overflow.as_bytes()).is_err());
}
#[test]
fn absent_invalid_and_oversized_imports_do_not_enable_unlocking() {
    let missing = prepare(None, &[]);
    assert!(missing.blockers.iter().any(|v| v.contains("No external")));
    assert!(missing.blockers.iter().any(|v| v.contains("No parsed V1")));
    let invalid = prepare(
        Some(Import {
            name: "engineering.bin",
            bytes: b"fake",
        }),
        &[Import {
            name: "loader",
            bytes: b"fake",
        }],
    );
    assert!(invalid.external_sbl3.unwrap().error.is_some());
    assert!(invalid.loaders[0].decoded.as_ref().unwrap().error.is_some());
    assert!(!invalid.phone_writes_enabled);
    let mut big = SBL3.to_vec();
    big.resize(8193, 0);
    let big = prepare(
        Some(Import {
            name: "too-big.bin",
            bytes: &big,
        }),
        &[],
    );
    assert_eq!(big.external_sbl3_fits, Some(false));
    assert!(!big.phone_writes_enabled);
    let mut reader = Cursor::new(FFU);
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    let gpt = ffu.gpt(&mut reader).unwrap();
    let many: Vec<_> = (0..33)
        .map(|_| Import {
            name: "loader",
            bytes: LOADER,
        })
        .collect();
    assert!(spec_a::prepare(&mut reader, &ffu, &gpt, None, &many).is_err());
    let huge = vec![0; spec_a::MAX_BOOT_IMAGE + 1];
    assert!(spec_a::prepare(
        &mut reader,
        &ffu,
        &gpt,
        Some(Import {
            name: "huge",
            bytes: &huge
        }),
        &[]
    )
    .is_err());
}
#[test]
fn different_root_and_missing_marker_cannot_be_candidate_loaders() {
    let mut wrong = LOADER.to_vec();
    let image = spec_a::parse(&wrong, 0).unwrap();
    // Certificate signature bytes remain DER-valid but change the fingerprint.
    let cert_len = 4 + u16::from_be_bytes([
        wrong[image.certificates_offset + 2],
        wrong[image.certificates_offset + 3],
    ]) as usize;
    wrong[image.certificates_offset + cert_len - 1] ^= 1;
    let report = prepare(
        None,
        &[
            Import {
                name: "wrong.mbn",
                bytes: &wrong,
            },
            Import {
                name: "sbl3.bin",
                bytes: SBL3,
            },
        ],
    );
    assert!(report.loaders[0].v1_marker_present);
    assert!(!report.loaders[0].matches_stock_sbl1_root);
    assert!(report.loaders[1].matches_stock_sbl1_root);
    assert!(!report.loaders[1].v1_marker_present);
    assert!(!report.phone_writes_enabled);
}
