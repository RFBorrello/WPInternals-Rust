use wpi_protocol::{
    qualcomm::{encode_hdlc, v1},
    replay::Exchange,
};

fn fixture() -> serde_json::Value {
    serde_json::from_slice(include_bytes!(
        "../../../tests/fixtures/spec-a-programmer-v1.json"
    ))
    .unwrap()
}

#[test]
fn commands_and_framed_replies_match_independent_pinned_reference() {
    let fixture = fixture();
    let exchanges: Vec<Exchange> = serde_json::from_value(fixture["exchanges"].clone()).unwrap();
    assert_eq!(v1::hello(), exchanges[0].request);
    assert_eq!(v1::SECURITY_MODE_ZERO, exchanges[1].request);
    assert_eq!(v1::OPEN_BOOT_PARTITION, exchanges[2].request);
    assert_eq!(v1::CLOSE_PARTITION, exchanges[7].request);
    assert_eq!(v1::REBOOT, exchanges[8].request);
    for (i, exchange) in exchanges.iter().enumerate() {
        let ack = match i {
            0 => v1::Ack::Hello,
            1 => v1::Ack::SecurityMode,
            2 => v1::Ack::Open,
            7 => v1::Ack::Close,
            8 => v1::Ack::Reboot,
            _ => {
                let start = u32::from_le_bytes(exchange.request[1..5].try_into().unwrap());
                assert_eq!(
                    v1::write(start, &exchange.request[5..]).unwrap(),
                    exchange.request
                );
                v1::Ack::Write(start)
            }
        };
        v1::check_ack(&exchange.response, ack).unwrap();
    }
    // Upstream prefix matching allows bounded metadata after the ACK.
    v1::check_ack(&encode_hdlc(&[0x02, 0x7e, 0x7d]).unwrap(), v1::Ack::Hello).unwrap();
}

#[test]
fn byte_address_and_payload_limits_are_checked_without_wrapping() {
    assert!(v1::write(0, &[]).is_err());
    assert!(v1::write(0, &vec![0; 1025]).is_err());
    assert!(v1::write(u32::MAX, &[1, 2]).is_err());
    assert_eq!(
        v1::write(u32::MAX, &[0x7e]).unwrap(),
        [7, 255, 255, 255, 255, 0x7e]
    );
    assert!(v1::write(u32::MAX - 1023, &vec![0; 1024]).is_ok());
    // Byte addresses, not sector addresses; payload escapes remain unframed.
    assert_eq!(
        v1::write(0x12345678, &[0x7e, 0x7d]).unwrap(),
        [7, 0x78, 0x56, 0x34, 0x12, 0x7e, 0x7d]
    );
}

#[test]
fn acknowledgements_require_valid_complete_frames_and_exact_address_echoes() {
    let frame = encode_hdlc(&[8, 0x7e, 0x7d, 0, 0]).unwrap();
    let address = 0x7d7e;
    v1::check_ack(&frame, v1::Ack::Write(address)).unwrap();
    assert!(v1::check_ack(&frame, v1::Ack::Write(address + 1)).is_err());
    assert!(v1::check_ack(&frame, v1::Ack::Open).is_err());
    assert!(v1::check_ack(&encode_hdlc(&[8]).unwrap(), v1::Ack::Write(0)).is_err());
    for end in 0..frame.len() {
        assert!(v1::check_ack(&frame[..end], v1::Ack::Write(address)).is_err());
    }
    for bit in 0..8 {
        let mut corrupt = frame.clone();
        corrupt[1] ^= 1 << bit;
        assert!(v1::check_ack(&corrupt, v1::Ack::Write(address)).is_err());
    }
    let mut trailing = frame.clone();
    trailing.extend_from_slice(&frame);
    assert!(v1::check_ack(&trailing, v1::Ack::Write(address)).is_err());
    let huge = encode_hdlc(&vec![2; v1::MAX_REPLY_FRAME]).unwrap();
    assert!(v1::check_ack(&huge, v1::Ack::Hello).is_err());
}
