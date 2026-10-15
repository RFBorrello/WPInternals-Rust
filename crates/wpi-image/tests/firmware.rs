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
