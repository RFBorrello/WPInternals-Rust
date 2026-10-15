use std::io::Cursor;
use wpi_image::{
    ffu::{FfuMetadata, Mapping},
    firmware,
    gpt::Gpt,
};
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic.ffu");
#[test]
fn version_scanning_rejects_ambiguity_unterminated_values_and_non_numeric_components() {
    assert_eq!(
        firmware::scan_version(b"SWVERSION=3051.50009.1424.0002\r\n")
            .unwrap()
            .as_deref(),
        Some("3051.50009.1424.0002")
    );
    for bytes in [
        b"SWVERSION=1.2.3.4\0SWVERSION=1.2.3.5\0".as_slice(),
        b"SWVERSION=1.2.3.4",
        b"SWVERSION=1.2.x.4\0",
        b"SWVERSION=4294967296.2.3.4\0",
        b"SWVERSION=\0",
    ] {
        assert!(firmware::scan_version(bytes).is_err());
    }
    assert_eq!(
        firmware::scan_version(b"no version in this partition").unwrap(),
        None
    );
}
fn image() -> (FfuMetadata, Gpt) {
    let mut input = Cursor::new(FFU);
    let mut ffu = FfuMetadata::open(&mut input).unwrap();
    let mut gpt = ffu.gpt(&mut input).unwrap();
    ffu.header_size = 0;
    ffu.chunk_size = 4096;
    ffu.mappings = vec![Mapping {
        disk_access: 0,
        disk_chunk: 0,
        chunk_count: 32,
        payload_chunk: 0,
    }];
    gpt.partitions.truncate(1);
    let p = &mut gpt.partitions[0];
    p.name = "PLAT".into();
    p.first_sector = 0;
    p.last_sector = 255;
    (ffu, gpt)
}
#[test]
fn plat_scan_spans_chunk_boundaries_and_cancels_before_reading() {
    let (ffu, gpt) = image();
    let mut bytes = vec![0; 128 * 1024];
    let v = b"SWVERSION=1.2.3.4\0";
    bytes[64 * 1024 - 5..64 * 1024 - 5 + v.len()].copy_from_slice(v);
    assert_eq!(
        firmware::read_version(&mut Cursor::new(&bytes), &ffu, &gpt, |_, _| true)
            .unwrap()
            .as_deref(),
        Some("1.2.3.4")
    );
    assert!(matches!(
        firmware::read_version(&mut Cursor::new(&bytes), &ffu, &gpt, |_, _| false),
        Err(wpi_image::ImageError::Cancelled)
    ));
    let mut large = gpt;
    large.partitions[0].last_sector = u64::MAX;
    assert!(firmware::read_version(&mut Cursor::new(&bytes), &ffu, &large, |_, _| true).is_err());
}

fn reg(value: &str) -> Vec<u8> {
    format!("Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\Platform\\DeviceTargetingInfo]\r\n\"PhoneFirmwareRevision\"=\"{value}\"\r\n").into_bytes()
}
fn dsm(build: &str) -> Vec<u8> {
    format!("<Package xmlns=\"http://schemas.microsoft.com/embedded/2004/10/ImageUpdate\"><Identity><Owner>Nokia</Owner><Component>DeviceInfo</Component><SubComponent>PhoneFirmwareRevision</SubComponent><Version Major=\"1\" Minor=\"2\" QFE=\"3\" Build=\"{build}\" /></Identity><Partition>MainOS</Partition><IsRemoval>false</IsRemoval></Package>").into_bytes()
}
#[test]
fn package_versions_require_corroboration_and_preserve_registry_zeroes() {
    use firmware::mainos::package;
    let observed = package(Some(&reg("1.2.3.0004")), Some(&dsm("4")))
        .unwrap()
        .unwrap();
    assert_eq!(observed.version, "1.2.3.0004");
    assert_eq!(observed.sources.len(), 2);
    assert!(observed
        .sources
        .iter()
        .all(|s| s.starts_with("MainOS/Windows/Packages/")));
    assert_eq!(package(None, None).unwrap(), None);
    assert!(package(Some(&reg("1.2.3.4")), None).is_err());
    assert!(package(None, Some(&dsm("4"))).is_err());
    assert!(package(Some(&reg("1.2.3.4")), Some(&dsm("5"))).is_err());
    assert!(package(Some(&reg("1.2.3.4")), Some(&dsm("4294967296"))).is_err());
    for bad in [
        "1.2.x.4",
        "1.2.3.4294967296",
        "1.2.3.4\"\n\"PhoneFirmwareRevision\"=\"1.2.3.4",
        "1.2.3.4\"\n\"PhoneFirmwareRevision\"=\"1.2.3.5",
    ] {
        assert!(package(Some(&reg(bad)), Some(&dsm("4"))).is_err());
    }
    let wrong = String::from_utf8(reg("1.2.3.4"))
        .unwrap()
        .replace("DeviceTargetingInfo", "WrongKey");
    assert!(package(Some(wrong.as_bytes()), Some(&dsm("4"))).is_err());
    let wrong = String::from_utf8(dsm("4"))
        .unwrap()
        .replace("Nokia", "Other");
    assert!(package(Some(&reg("1.2.3.4")), Some(wrong.as_bytes())).is_err());
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}
#[test]
fn package_decoding_checks_gzip_crc_trailing_bytes_expansion_utf16_and_xml_limits() {
    use firmware::mainos::package;
    let text = String::from_utf8(reg("1.2.3.0004")).unwrap();
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    let compressed = gzip(&utf16);
    assert_eq!(
        package(Some(&compressed), Some(&gzip(&dsm("4"))))
            .unwrap()
            .unwrap()
            .version,
        "1.2.3.0004"
    );
    let mut corrupt = compressed.clone();
    let n = corrupt.len();
    corrupt[n - 8] ^= 1;
    let mut trailing = compressed.clone();
    trailing.push(0);
    let mut multiple = compressed.clone();
    multiple.extend(&compressed);
    for bad in [
        corrupt,
        trailing,
        multiple,
        compressed[..compressed.len() - 1].to_vec(),
        gzip(&vec![b'x'; 65537]),
        vec![b'x'; 65537],
        vec![0xff, 0xfe, 1],
        vec![0xff, 0xfe, 0, 0xd8],
    ] {
        assert!(package(Some(&bad), Some(&dsm("4"))).is_err());
    }
    let valid = String::from_utf8(dsm("4")).unwrap();
    for bad in [
        format!("<!DOCTYPE Package [<!ENTITY x 'y'>]>{valid}"),
        format!("{valid}{valid}"),
        valid.replace(
            "</Package>",
            &format!("{}{}</Package>", "<x>".repeat(20), "</x>".repeat(20)),
        ),
        valid.replace("ImageUpdate", "WrongNamespace"),
        valid.replace("</Package>", ""),
    ] {
        assert!(package(Some(&reg("1.2.3.4")), Some(bad.as_bytes())).is_err());
    }
}
#[test]
fn mainos_sparse_ffu_uses_bounded_ntfs_lookup_and_rejects_bad_geometry_or_disconnect() {
    let bytes = include_bytes!("../../../tests/fixtures/synthetic-mainos.ffu");
    let mut input = Cursor::new(bytes);
    let ffu = FfuMetadata::open(&mut input).unwrap();
    let gpt = ffu.gpt(&mut input).unwrap();
    ffu.verify_hashes(&mut input, |_, _| true).unwrap();
    let mut fetched = 0;
    let observed = firmware::inspect(&mut input, &ffu, &gpt, |done, _| {
        fetched = fetched.max(done);
        true
    })
    .unwrap()
    .unwrap();
    assert_eq!(observed.version, "1.2.3.0004");
    assert!(fetched <= 16 * 1024 * 1024);
    assert!(matches!(
        firmware::inspect(&mut input, &ffu, &gpt, |_, _| false),
        Err(wpi_image::ImageError::Cancelled)
    ));
    let mut small = gpt.clone();
    small.partitions[0].last_sector = small.partitions[0].first_sector + 1;
    assert!(firmware::inspect(&mut input, &ffu, &small, |_, _| true).is_err());
    let mut dup = gpt.clone();
    dup.partitions.push(dup.partitions[0].clone());
    assert!(firmware::inspect(&mut input, &ffu, &dup, |_, _| true).is_err());
    let mut truncated = Cursor::new(&bytes[..bytes.len() / 2]);
    assert!(firmware::inspect(&mut truncated, &ffu, &gpt, |_, _| true).is_err());
}
