use wpi_image::spec_a::{self, efiesp, sbl1, uefi};
const SBL1: &[u8] = include_bytes!("../../../tests/fixtures/spec-a/sbl1.synthetic.bin");
const UEFI: &[u8] = include_bytes!("../../../tests/fixtures/spec-a/uefi.synthetic.bin");
#[test]
fn synthetic_sbl1_prerequisites_match_reference_without_payload_generation() {
    let image = spec_a::parse(SBL1, 0x2800).unwrap();
    let report = sbl1::inspect(SBL1, &image).unwrap();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/spec-a/offline-reference.json"
    ))
    .unwrap();
    assert_eq!(
        report.loader_table_offset as u64,
        reference["sbl1_loader_table_offset"].as_u64().unwrap()
    );
    assert_eq!(
        report.security_flag_address as u64,
        reference["sbl1_security_flag_address"].as_u64().unwrap()
    );
    assert_eq!(
        report.return_address as u64,
        reference["sbl1_return_address"].as_u64().unwrap()
    );
    assert!(!report.payload_generated);
}
#[test]
fn sbl1_rejects_missing_ambiguous_truncated_and_overflowing_prerequisites() {
    let image = spec_a::parse(SBL1, 0x2800).unwrap();
    let mut missing = SBL1.to_vec();
    missing[image.image_offset + 64] = 0;
    assert!(sbl1::inspect(&missing, &image).is_err());
    let mut duplicate = SBL1.to_vec();
    duplicate[image.image_offset + 256..image.image_offset + 276]
        .copy_from_slice(&SBL1[image.image_offset + 64..image.image_offset + 84]);
    assert!(sbl1::inspect(&duplicate, &image).is_err());
    let mut overflow = SBL1.to_vec();
    overflow[image.image_offset + 28..image.image_offset + 32]
        .copy_from_slice(&0xfffffffcu32.to_le_bytes());
    assert!(sbl1::inspect(&overflow, &image).is_err());
    let mut truncated = image.clone();
    truncated.code_size = 128 + 44;
    assert!(sbl1::inspect(SBL1, &truncated).is_err());
    assert_eq!(
        SBL1,
        include_bytes!("../../../tests/fixtures/spec-a/sbl1.synthetic.bin")
    );
}
#[test]
fn compressed_uefi_checksum_targets_and_patch_previews_match_reference() {
    let report = uefi::inspect(UEFI).unwrap();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/spec-a/offline-reference.json"
    ))
    .unwrap();
    assert_eq!(
        report.decompressed_sha256,
        reference["decompressed_sha256"].as_str().unwrap()
    );
    assert_eq!(report.file_count, 2);
    assert!(!report.rebuilt_image);
    for (target, expected) in report
        .targets
        .iter()
        .zip(reference["targets"].as_array().unwrap())
    {
        assert_eq!(target.name, expected["name"].as_str().unwrap());
        assert_eq!(target.sha256, expected["sha256"].as_str().unwrap());
        let offsets: Vec<_> = target
            .patches
            .iter()
            .filter(|p| p.label != "PE checksum clear")
            .map(|p| p.offset as u64)
            .collect();
        assert_eq!(
            offsets,
            expected["code_patch_offsets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap())
                .collect::<Vec<_>>()
        );
    }
}
#[test]
fn malformed_uefi_headers_compression_limits_and_truncation_fail_closed() {
    for n in [0, 20, 39, 80, UEFI.len() - 1] {
        assert!(uefi::inspect(&UEFI[..n]).is_err());
    }
    for at in [40 + 50, 40 + 72 + 16, 40 + 72 + 24 + 4, 40 + 72 + 24 + 24] {
        let mut bad = UEFI.to_vec();
        bad[at] ^= 255;
        assert!(uefi::inspect(&bad).is_err(), "offset {at}");
    }
    let compressed = 40 + 72 + 24 + 24;
    for (at, length) in [(compressed + 1, 4), (compressed + 5, 8)] {
        let mut bad = UEFI.to_vec();
        bad[at..at + length].fill(255);
        assert!(uefi::inspect(&bad).is_err());
    }
    assert!(uefi::inspect(&vec![0; spec_a::MAX_BOOT_IMAGE + 1]).is_err());
}
#[test]
fn missing_and_unknown_efiesp_targets_remain_unsupported() {
    let missing = efiesp::assess(None, Some(b"synthetic hive bytes")).unwrap();
    assert_eq!(missing.status, "missing");
    assert!(missing.bcd_present);
    assert!(!missing.bcd_editing_implemented);
    let unsupported = efiesp::assess(Some(b"unsupported boot file"), None).unwrap();
    assert_eq!(unsupported.status, "unsupported_donor_required");
    assert!(unsupported.prepared_copy_sha256.is_none());
    assert!(!unsupported.bcd_present);
    assert!(efiesp::assess(Some(&vec![0; 4 * 1024 * 1024 + 1]), None).is_err());
}
#[test]
fn donor_reassessment_discards_stale_claims_and_never_preserves_a_write_grant() {
    use std::io::Cursor;
    use wpi_image::ffu::FfuMetadata;
    let mut reader = Cursor::new(
        include_bytes!("../../../tests/fixtures/synthetic-spec-a-offline.ffu").as_slice(),
    );
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    let gpt = ffu.gpt(&mut reader).unwrap();
    ffu.verify_hashes(&mut reader, |_, _| true).unwrap();
    let mut report = spec_a::prepare(&mut reader, &ffu, &gpt, None, &[]).unwrap();
    assert!(report.sbl1_prerequisites.is_some() && report.uefi.is_some());
    assert_eq!(
        report.efiesp.as_ref().unwrap().status,
        "unsupported_donor_required"
    );
    report.phone_writes_enabled = true;
    report
        .blockers
        .push("Imported donor boot bytes match stale evidence".into());
    for _ in 0..2 {
        spec_a::assess_donor(&mut report, &mut reader, &ffu, &gpt);
    }
    assert!(!report.phone_writes_enabled);
    assert!(!report.blockers.iter().any(|v| v.contains("stale evidence")));
    assert_eq!(
        report
            .blockers
            .iter()
            .filter(|v| v.starts_with("Imported donor "))
            .count(),
        1
    );
    assert_eq!(
        report.donor_efiesp.as_ref().unwrap().status,
        "unsupported_donor_required"
    );
}
