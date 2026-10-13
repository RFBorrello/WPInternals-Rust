use wpi_protocol::{
    flash, qualcomm,
    replay::{Exchange, ReplayTransport},
    MessageTransport,
};

#[test]
fn normal_queries_are_read_only_and_response_ids_are_checked() {
    use wpi_protocol::normal;
    assert!(normal::request(0, "SwitchToFlashApp").is_err());
    assert!(normal::request(0, "ReadManufacturerModelName").is_ok());
    let response = br#"{"jsonrpc":"2.0","id":0,"result":{"ManufacturerModelName":"RM-875_eu"}}"#;
    assert_eq!(
        normal::parse(response, 0, "ManufacturerModelName").unwrap(),
        "RM-875_eu"
    );
    assert!(normal::parse(response, 1, "ManufacturerModelName").is_err());
}
#[test]
fn nokv_replay_and_subblock_bounds() {
    let response = [
        b'N', b'O', b'K', b'V', 0, 2, 2, 0, 1, 0, 1, 5, 0, 4, b'T', b'E', b'S', b'T',
    ];
    let mut replay = ReplayTransport::new(vec![Exchange {
        request: b"NOKV".to_vec(),
        response: response.to_vec(),
        error: None,
    }]);
    let info = flash::read_info(&mut replay).unwrap();
    assert_eq!(info.platform_id.as_deref(), Some("TEST"));
    assert!(replay.finished());
    for size in 0..response.len() {
        assert!(flash::parse_info(&response[..size]).is_err());
    }
    let mut response = response;
    response[13] = 250;
    assert!(flash::parse_info(&response).is_err());
}
#[test]
fn disconnect_and_unexpected_request_do_not_retry() {
    let mut replay = ReplayTransport::new(vec![Exchange {
        request: b"NOKV".to_vec(),
        response: vec![],
        error: Some("disconnected".into()),
    }]);
    assert!(flash::read_info(&mut replay).is_err());
    assert!(replay.finished());
    let mut replay = ReplayTransport::new(vec![Exchange {
        request: b"NOKV".to_vec(),
        response: vec![0; 65537],
        error: None,
    }]);
    assert!(replay.exchange(b"NOKV", 65536).is_err());
}
#[test]
fn hdlc_reference_crc_escape_and_corruption() {
    assert_eq!(qualcomm::crc16(b"123456789"), 0x906e);
    let payload = [0x01, 0x7e, 0x7d, 0xff];
    let frame = qualcomm::encode_hdlc(&payload).unwrap();
    assert_eq!(qualcomm::decode_hdlc(&frame).unwrap(), payload);
    for size in 0..frame.len() {
        assert!(qualcomm::decode_hdlc(&frame[..size]).is_err());
    }
    let mut corrupted = frame;
    corrupted[1] ^= 1;
    assert!(qualcomm::decode_hdlc(&corrupted).is_err());
}
#[test]
fn stock_flash_builders_never_set_security_skip_options() {
    let header = flash::ffu_header_v1(&[1, 2, 3]).unwrap();
    assert_eq!(&header[..6], b"NOKXFS");
    assert_eq!(&header[6..8], &[0, 1]);
    assert_eq!(header[28], 0);
    assert_eq!(&header[32..], &[1, 2, 3]);
    let payload = flash::ffu_payload_v1(&[4, 5], 50).unwrap();
    assert_eq!(payload[24], 0);
    assert_eq!(payload[8], 50);
    assert!(flash::ffu_payload_v1(&[4, 5], 101).is_err());
}
