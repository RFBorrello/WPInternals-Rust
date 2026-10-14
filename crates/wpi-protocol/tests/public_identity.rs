use wpi_protocol::{
    identity,
    replay::{Exchange, ReplayTransport},
};

fn normal(id: u32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"PublicId":(1..=20).collect::<Vec<u8>>()}})).unwrap()
}
fn terminal(nodes: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut r = vec![0; 32];
    r[..6].copy_from_slice(b"NOKXFT");
    r[24..28].copy_from_slice(&0x10000u32.to_le_bytes());
    for (number, payload) in nodes {
        r.extend_from_slice(&number.to_le_bytes());
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(payload);
    }
    let length = r.len();
    r[20..24].copy_from_slice(&((length - 24) as u32).to_be_bytes());
    r[28..32].copy_from_slice(&((length - 32) as u32).to_le_bytes());
    r
}
fn good_terminal() -> Vec<u8> {
    terminal(&[(3, (1..=20).collect()), (7, vec![0xa5; 32])])
}

#[test]
fn identity_query_bytes_match_pinned_upstream_and_do_not_extend_generic_allowlist() {
    assert!(wpi_protocol::normal::request(3, "ReadPublicId").is_err());
    let value: serde_json::Value = serde_json::from_slice(&identity::normal_request(3)).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"ReadPublicId","params":{"MessageVersion":0}})
    );
    let request = identity::flash_request();
    assert_eq!(request.len(), 172);
    // Independently transcribed from NokiaFlashModel.GetTerminalResponse in 2.9.2.
    assert_eq!(
        &request[..36],
        &[
            0x4e, 0x4f, 0x4b, 0x58, 0x46, 0x54, 0, 1, 0, 0, 0, 0x18, 0, 0, 0, 0x9c, 0, 0, 0, 0, 1,
            0, 16, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64
        ]
    );
    assert!(request[36..].iter().all(|b| *b == 0));
}
#[test]
fn same_public_id_can_correlate_modes_without_exposing_bytes_in_debug() {
    let a = identity::parse_normal(&normal(3), 3).unwrap();
    let b = identity::parse_flash(&good_terminal()).unwrap();
    assert_eq!(a, b);
    assert_eq!(format!("{a:?}"), "PublicId([redacted])");
    let mut r = good_terminal();
    r[40] = 0xa5;
    assert_ne!(a, identity::parse_flash(&r).unwrap());
}
#[test]
fn normal_ids_reject_wrong_requests_types_blank_values_and_oversized_inputs() {
    for field in [
        serde_json::json!(null),
        serde_json::json!("private"),
        serde_json::json!([1, 2]),
        serde_json::json!(vec![0; 20]),
    ] {
        let r = serde_json::to_vec(
            &serde_json::json!({"jsonrpc":"2.0","id":3,"result":{"PublicId":field}}),
        )
        .unwrap();
        assert!(identity::parse_normal(&r, 3).is_err());
    }
    for bad in [
        serde_json::json!(-1),
        serde_json::json!(256),
        serde_json::json!(1.5),
        serde_json::json!(true),
    ] {
        let mut array = vec![serde_json::json!(1); 20];
        array[7] = bad;
        let r = serde_json::to_vec(
            &serde_json::json!({"jsonrpc":"2.0","id":3,"result":{"PublicId":array}}),
        )
        .unwrap();
        assert!(identity::parse_normal(&r, 3).is_err());
    }
    assert!(identity::parse_normal(&normal(3), 4).is_err());
    assert!(identity::parse_normal(&vec![b' '; 65537], 3).is_err());
    assert!(identity::parse_normal(b"{\"error\":\"sensitive\"}", 3).is_err());
}
#[test]
fn terminal_ids_reject_truncation_oversized_lengths_duplicate_nodes_and_bad_status() {
    let r = good_terminal();
    for length in 0..r.len() {
        assert!(identity::parse_flash(&r[..length]).is_err());
    }
    for offset in [20, 24, 28, 36] {
        let mut r = r.clone();
        r[offset..offset + 4].fill(255);
        assert!(identity::parse_flash(&r).is_err());
    }
    for nodes in [
        vec![(7, vec![1; 32])],
        vec![(3, vec![0; 20])],
        vec![(3, vec![255; 20])],
        vec![(3, vec![1; 19])],
        vec![(3, vec![1; 20]), (3, vec![1; 20])],
    ] {
        assert!(identity::parse_flash(&terminal(&nodes)).is_err());
    }
    let many = (100..=356).map(|n| (n, Vec::new())).collect::<Vec<_>>();
    assert!(identity::parse_flash(&terminal(&many)).is_err());
    let mut status = r.clone();
    status[7] = 1;
    assert!(identity::parse_flash(&status).is_err());
    let mut signature = r;
    signature[0] = b'X';
    assert!(identity::parse_flash(&signature).is_err());
    assert!(identity::parse_flash(&vec![0; 65537]).is_err());
    assert!(identity::parse_flash(b"NOKU").is_err());
}
#[test]
fn identity_transport_failures_never_repeat_the_query() {
    let mut replay = ReplayTransport::new(vec![Exchange {
        request: identity::normal_request(3),
        response: vec![],
        error: Some("disconnected".into()),
    }]);
    assert!(identity::read_normal(&mut replay, 3).is_err());
    assert!(replay.finished());
    let mut replay = ReplayTransport::new(vec![Exchange {
        request: identity::flash_request(),
        response: good_terminal(),
        error: None,
    }]);
    assert_eq!(
        identity::read_flash(&mut replay).unwrap(),
        identity::parse_normal(&normal(3), 3).unwrap()
    );
    assert!(replay.finished());
}
