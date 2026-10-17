use std::io::Cursor;
use wpi_image::{ffu::FfuMetadata, gpt::Gpt, patch::PatchCatalog, ImageError};
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic.ffu");
const RAW: &[u8] = include_bytes!("../../../tests/fixtures/synthetic.img");
const GPT: &[u8] = include_bytes!("../../../tests/fixtures/gpt.bin");

#[test]
fn high_gpt_attribute_bits_round_trip_without_javascript_precision_loss() {
    let mut gpt = Gpt::read(&mut Cursor::new(GPT), GPT.len() as u64).unwrap();
    gpt.partitions[0].attributes = u64::MAX;
    let json = serde_json::to_string(&gpt).unwrap();
    assert!(json.contains("\"attributes\":\"18446744073709551615\""));
    let restored: Gpt = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.partitions[0].attributes, u64::MAX);
    assert!(restored
        .to_xml()
        .contains("Attributes=\"18446744073709551615\""));
}

#[test]
fn reference_ffu_layout_and_partition_extraction() {
    let mut input = Cursor::new(FFU);
    let ffu = FfuMetadata::open(&mut input).unwrap();
    assert_eq!(ffu.platform_id, "SYNTHETIC.LUMIA.TEST");
    assert_eq!(ffu.chunk_size, 4096);
    assert_eq!(ffu.header_size, 12288);
    assert_eq!(ffu.payload_size, 24576);
    ffu.verify_hashes(&mut input, |_, _| true).unwrap();
    let gpt = ffu.gpt(&mut input).unwrap();
    assert_eq!(gpt.partitions.len(), 2);
    let (start, size) = gpt.partition("efiesp").unwrap().byte_range().unwrap();
    let mut output = Vec::new();
    ffu.extract(&mut input, &mut output, start, size, |_, _| true)
        .unwrap();
    assert_eq!(output, vec![0xab; 2048]);
}
#[test]
fn gpt_crc_checked_for_disk_and_header_only_input() {
    let full = Gpt::read(&mut Cursor::new(RAW), RAW.len() as u64).unwrap();
    let table = Gpt::read(&mut Cursor::new(GPT), GPT.len() as u64).unwrap();
    assert_eq!(full.disk_guid, table.disk_guid);
    assert!(full.to_xml().contains("Name=\"EFIESP\""));
    let mut corrupted = GPT.to_vec();
    corrupted[92 + 512] ^= 1;
    assert!(Gpt::read(&mut Cursor::new(&corrupted), corrupted.len() as u64).is_err());
    let mut corrupted = GPT.to_vec();
    corrupted[40] ^= 1;
    assert!(Gpt::read(&mut Cursor::new(&corrupted), corrupted.len() as u64).is_err());
}
#[test]
fn truncated_and_oversized_headers_fail_without_allocation() {
    for size in [0, 4, 16, 31, 4096, 8192, FFU.len() - 1] {
        assert!(FfuMetadata::open(&mut Cursor::new(&FFU[..size])).is_err());
    }
    let mut large = FFU.to_vec();
    large[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(FfuMetadata::open(&mut Cursor::new(large)).is_err());
    let mut large = FFU.to_vec();
    large[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(FfuMetadata::open(&mut Cursor::new(large)).is_err());
    // Image chunk size is KiB, unlike the store's byte-sized block field.
    // Reject both inconsistent values and overflow during KiB conversion.
    for image_chunk_kib in [4096u32, u32::MAX] {
        let mut invalid_image = FFU.to_vec();
        invalid_image[4096 + 20..4096 + 24].copy_from_slice(&image_chunk_kib.to_le_bytes());
        assert!(FfuMetadata::open(&mut Cursor::new(invalid_image)).is_err());
    }
}
#[test]
fn chunk_verification_honors_cancellation_at_every_boundary_including_completion() {
    let ffu = FfuMetadata::open(&mut Cursor::new(FFU)).unwrap();
    let count = (ffu.total_size - ffu.security_size) / u64::from(ffu.chunk_size);
    for stop in 0..=count {
        let mut reader = Cursor::new(FFU);
        let mut seen = Vec::new();
        let result = ffu.verify_hashes(&mut reader, |done, total| {
            assert_eq!(total, count);
            seen.push(done);
            done != stop
        });
        assert!(
            matches!(result, Err(ImageError::Cancelled)),
            "boundary {stop}"
        );
        assert_eq!(seen, (0..=stop).collect::<Vec<_>>());
        assert_eq!(
            reader.position(),
            ffu.security_size + stop * u64::from(ffu.chunk_size)
        );
    }
}
#[test]
fn payload_tampering_is_detected_and_cancellation_is_bounded() {
    let mut corrupted = FFU.to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut reader = Cursor::new(corrupted);
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    assert!(ffu.verify_hashes(&mut reader, |_, _| true).is_err());
    let mut output = Vec::new();
    assert!(matches!(
        ffu.extract(&mut reader, &mut output, 34 * 512, 2048, |_, _| false),
        Err(ImageError::Cancelled)
    ));
    assert!(output.is_empty());
    assert!(ffu.segments(u64::MAX, 512).is_err());
}
#[test]
fn sparse_intervals_and_last_descriptor_precedence() {
    use wpi_image::ffu::Mapping;
    let mut ffu = FfuMetadata::open(&mut Cursor::new(FFU)).unwrap();
    ffu.mappings = vec![
        Mapping {
            disk_access: 0,
            disk_chunk: 0,
            chunk_count: 1,
            payload_chunk: 0,
        },
        Mapping {
            disk_access: 0,
            disk_chunk: 2,
            chunk_count: 1,
            payload_chunk: 2,
        },
        Mapping {
            disk_access: 0,
            disk_chunk: 0,
            chunk_count: 1,
            payload_chunk: 3,
        },
    ];
    let segments = ffu.segments(0, 3 * 4096).unwrap();
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].file_offset, Some(ffu.header_size + 3 * 4096));
    assert_eq!(segments[1].file_offset, None);
}
#[test]
fn upstream_patch_catalog_is_parseable_and_paths_are_safe() {
    let catalog = PatchCatalog::bundled().unwrap();
    assert!(catalog
        .definitions
        .iter()
        .any(|d| d.name == "RootAccess-MainOS"));
    for path in [
        "../secret",
        "C:\\Windows\\secret",
        "/absolute",
        "folder/../file",
        "folder\\..\\file",
    ] {
        assert!(wpi_image::patch::safe_relative_path(path).is_err());
    }
}
#[test]
fn patch_apply_reverse_and_preconditions() {
    let original = b"abcdefgh";
    let patched = b"abXYefgh";
    let xml = format!("<PatchDefinitions><PatchDefinition Name=\"test\"><TargetVersions><TargetVersion Description=\"fixture\"><TargetFiles><TargetFile Path=\"kernel.bin\" HashOriginal=\"{}\" HashPatched=\"{}\"><Patches><Patch Address=\"0x2\" OriginalBytes=\"6364\" PatchedBytes=\"5859\"/></Patches></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>", wpi_image::patch::sha1(original), wpi_image::patch::sha1(patched));
    let catalog = PatchCatalog::parse(&xml).unwrap();
    let (_, files) = catalog
        .prepare("test", false, |_| Ok(original.to_vec()))
        .unwrap();
    assert_eq!(files[0].bytes, patched);
    let (_, files) = catalog
        .prepare("test", true, |_| Ok(patched.to_vec()))
        .unwrap();
    assert_eq!(files[0].bytes, original);
    assert!(catalog
        .prepare("test", false, |_| Ok(b"different".to_vec()))
        .is_err());
    let bad_xml = xml.replace("OriginalBytes=\"6364\"", "OriginalBytes=\"6162\"");
    assert!(PatchCatalog::parse(&bad_xml)
        .unwrap()
        .prepare("test", false, |_| Ok(original.to_vec()))
        .is_err());
}
