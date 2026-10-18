use wpi_protocol::flash;
#[test]
fn wire_layout_and_address_limits_match_upstream_flash_sectors() {
    let payload = vec![0xa7; 1024];
    let wire = flash::sectors_v1(0x12345678, &payload, 42).unwrap();
    assert_eq!(&wire[..4], b"NOKF");
    assert_eq!(&wire[11..15], &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(&wire[15..19], &[0, 0, 0, 2]);
    assert_eq!(wire[19], 42);
    assert!(wire[4..11]
        .iter()
        .chain(wire[20..64].iter())
        .all(|b| *b == 0));
    assert_eq!(&wire[64..], payload);
    assert!(flash::sectors_v1(u32::MAX, &payload, 0).is_err());
    assert!(flash::sectors_v1(u32::MAX, &payload[..512], 0).is_ok());
    for n in [0, 1, 511, 513, 2 * 1024 * 1024 + 512] {
        assert!(flash::sectors_v1(0, &vec![0; n], 0).is_err());
    }
    assert!(flash::sectors_v1(0, &payload, 101).is_err());
}
#[test]
fn raw_status_is_strict_and_never_accepts_an_empty_or_ambiguous_reply() {
    assert!(flash::sectors_v1_status(b"NOKF\0\0\0\0").is_ok());
    for reply in [
        b"".as_slice(),
        b"NOKF\0\0\0",
        b"NOKF\0\0\0\x01",
        b"NOKF\0\0\0\0X",
        b"NOKU\0\0\0\0",
    ] {
        assert!(flash::sectors_v1_status(reply).is_err());
    }
}
