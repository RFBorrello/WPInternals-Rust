use wpi_protocol::{
    preflight::RootKeyHash,
    qualcomm::{decode_hdlc, dload, encode_hdlc},
    replay::{FramedExchange, FramedReplayTransport},
    MessageTransport,
};

#[test]
fn memory_upload_matches_independent_pinned_csharp_array_overload_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../tests/fixtures/spec-a-dload.json"))
            .unwrap();
    let exchanges: Vec<wpi_protocol::replay::Exchange> =
        serde_json::from_value(fixture["exchanges"].clone()).unwrap();
    let bytes = include_bytes!("../../../tests/fixtures/spec-a/loader.mbn");
    assert_eq!(dload::alive().unwrap(), exchanges[0].request);
    assert_eq!(dload::root_key().unwrap(), exchanges[1].request);
    dload::parse_root(&exchanges[1].response).unwrap();
    for (index, chunk) in bytes.chunks(256).enumerate() {
        let exchange = &exchanges[index + 2];
        assert_eq!(
            dload::memory(dload::LOADER_ADDRESS + (index * 256) as u32, chunk).unwrap(),
            exchange.request
        );
        dload::check_ack(&exchange.response).unwrap();
    }
    assert_eq!(
        dload::start(dload::LOADER_ADDRESS).unwrap(),
        exchanges.last().unwrap().request
    );
}

#[test]
fn dload_addresses_lengths_and_short_tail_are_big_endian_and_framed() {
    assert_eq!(decode_hdlc(&dload::alive().unwrap()).unwrap(), [6]);
    assert_eq!(decode_hdlc(&dload::root_key().unwrap()).unwrap(), [0x18]);
    assert_eq!(
        decode_hdlc(&dload::start(0x2a000000).unwrap()).unwrap(),
        [5, 0x2a, 0, 0, 0]
    );
    assert_eq!(
        decode_hdlc(&dload::memory(0x12345678, &[0x7e, 0x7d, 1]).unwrap()).unwrap(),
        [0xf, 0x12, 0x34, 0x56, 0x78, 0, 3, 0x7e, 0x7d, 1]
    );
    assert!(dload::memory(0, &[]).is_err());
    assert!(dload::memory(0, &[0; 257]).is_err());
    assert!(dload::memory(u32::MAX, &[1, 2]).is_err());
    assert!(dload::memory(u32::MAX, &[1]).is_ok());
    let full = decode_hdlc(&dload::memory(0x2a000000, &[0; 256]).unwrap()).unwrap();
    assert_eq!(&full[5..7], &[1, 0]);
}
#[test]
fn root_reply_is_exact_nonblank_and_never_confused_with_an_ack() {
    let mut reply = vec![0x18, 1, 0];
    reply.extend_from_slice(&[7; 32]);
    assert_eq!(
        dload::parse_root(&encode_hdlc(&reply).unwrap()).unwrap(),
        RootKeyHash::parse(&[7; 32]).unwrap()
    );
    for length in 0..35 {
        assert!(dload::parse_root(&encode_hdlc(&reply[..length.max(1)]).unwrap()).is_err());
    }
    for value in [0, 255] {
        reply[3..].fill(value);
        assert!(dload::parse_root(&encode_hdlc(&reply).unwrap()).is_err());
    }
    assert!(dload::parse_root(&encode_hdlc(&[2]).unwrap()).is_err());
    assert!(dload::check_ack(&encode_hdlc(&[0xe]).unwrap()).is_err());
}
#[test]
fn every_frame_split_and_one_byte_reads_preserve_escapes_and_checksum() {
    let frame = encode_hdlc(&[2, 0x7e, 0x7d, 0xff]).unwrap();
    for split in 1..frame.len() {
        let mut decoder = dload::ReplyDecoder::default();
        assert!(decoder.push(&frame[..split]).unwrap().is_none());
        assert_eq!(decoder.push(&frame[split..]).unwrap().unwrap(), frame);
        assert!(decoder.push(&frame).is_err());
    }
    let mut decoder = dload::ReplyDecoder::default();
    for (i, byte) in frame.iter().enumerate() {
        assert_eq!(
            decoder.push(&[*byte]).unwrap().is_some(),
            i + 1 == frame.len()
        );
    }
}
#[test]
fn malformed_or_surplus_fragment_streams_stop_and_poison_the_decoder() {
    let frame = encode_hdlc(&[2]).unwrap();
    let mut bad_crc = frame.clone();
    bad_crc[2] ^= 1;
    for bad in [
        vec![],
        vec![0],
        bad_crc,
        [frame.as_slice(), &[0]].concat(),
        [frame.as_slice(), frame.as_slice()].concat(),
        vec![0x7e; 8193],
    ] {
        let mut decoder = dload::ReplyDecoder::default();
        assert!(decoder.push(&bad).is_err());
        assert!(decoder.push(&frame).is_err());
    }
    for fragments in [
        vec![frame[..2].to_vec()],
        vec![frame.clone(), frame.clone()],
        vec![vec![]],
    ] {
        let mut transport = FramedReplayTransport::new(vec![FramedExchange {
            request: vec![1],
            fragments,
            error: None,
        }]);
        assert!(transport.exchange(&[1], 8192).is_err());
        assert!(transport.finished());
    }
}
