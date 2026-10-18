use super::*;
pub(crate) const CHUNK: usize = 0x20000;
pub(crate) const LOADER: &[u8] = include_bytes!("../../../../tests/fixtures/spec-a/loader.mbn");
pub(crate) fn sha(bytes: &[u8]) -> String {
    wpi_image::stream::sha256(&mut Cursor::new(bytes)).unwrap()
}
pub(crate) fn hash_bytes(bytes: &[u8]) -> Vec<u8> {
    sha(bytes)
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) fn root_bytes() -> Vec<u8> {
    hash_bytes(include_bytes!(
        "../../../../tests/fixtures/image-issuer/root.der"
    ))
}
pub(crate) fn root() -> RootKeyHash {
    RootKeyHash::parse(&root_bytes()).unwrap()
}
pub(crate) fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
pub(crate) fn rehash(bytes: &mut [u8]) {
    for index in 0..4 {
        let digest = hash_bytes(&bytes[(index + 1) * CHUNK..(index + 2) * CHUNK]);
        bytes[32 + index * 32..64 + index * 32].copy_from_slice(&digest);
    }
}
pub(crate) fn ffu() -> Vec<u8> {
    let basic = include_bytes!("../../../../tests/fixtures/synthetic.ffu");
    let mut bytes = vec![0; CHUNK * 5];
    bytes[..32].copy_from_slice(&basic[..32]);
    put(&mut bytes, 16, 128);
    put(&mut bytes, 28, 128);
    bytes[CHUNK..CHUNK + 4096].copy_from_slice(&basic[4096..8192]);
    put(&mut bytes, CHUNK + 20, 128);
    bytes[CHUNK * 2..CHUNK * 2 + 248].copy_from_slice(&basic[8192..8192 + 248]);
    put(&mut bytes, CHUNK * 2 + 204, CHUNK as u32);
    put(&mut bytes, CHUNK * 2 + 208, 2);
    put(&mut bytes, CHUNK * 2 + 212, 40);
    for (i, value) in [2, 1, 0, 0, 2, 0, 1, 1, 0, 0].iter().enumerate() {
        put(&mut bytes, CHUNK * 2 + 248 + i * 4, *value);
    }
    bytes[CHUNK * 4..CHUNK * 4 + 24576].copy_from_slice(&basic[12288..]);
    rehash(&mut bytes);
    bytes
}
pub(crate) fn terminal(value: u8) -> Vec<u8> {
    let mut r = vec![0; 60];
    r[..6].copy_from_slice(b"NOKXFT");
    r[20..24].copy_from_slice(&36u32.to_be_bytes());
    r[24..28].copy_from_slice(&0x10000u32.to_le_bytes());
    r[28..32].copy_from_slice(&28u32.to_le_bytes());
    r[32..36].copy_from_slice(&3u32.to_le_bytes());
    r[36..40].copy_from_slice(&20u32.to_le_bytes());
    r[40..].fill(value);
    r
}
pub(crate) fn binding() -> Binding {
    Binding {
        public_id: identity::parse_flash(&terminal(42)).unwrap(),
        physical_port: "synthetic-port-1".into(),
    }
}
pub(crate) fn parameter(bytes: &[u8]) -> Vec<u8> {
    let mut r = vec![0; 17];
    r[..6].copy_from_slice(b"NOKXFR");
    r[16] = bytes.len() as u8;
    r.extend_from_slice(bytes);
    r
}
pub(crate) fn plain(request: Vec<u8>, response: Vec<u8>) -> Exchange {
    Exchange {
        request,
        response,
        error: None,
    }
}
pub(crate) fn framed(request: Vec<u8>, response: &[u8]) -> FramedExchange {
    FramedExchange {
        request,
        fragments: encode_hdlc(response)
            .unwrap()
            .chunks(1)
            .map(|b| b.to_vec())
            .collect(),
        error: None,
    }
}
pub(crate) fn arrivals(endpoint: Endpoint) -> Vec<TimedObservation> {
    vec![
        TimedObservation {
            elapsed_ms: 10,
            observation: Observation::Disconnected,
        },
        TimedObservation {
            elapsed_ms: 20,
            observation: Observation::Connected {
                endpoint,
                physical_port: "synthetic-port-1".into(),
                candidates: 1,
            },
        },
    ]
}
pub(crate) fn transcripts(
    bytes: &[u8],
) -> (Vec<Exchange>, Vec<FramedExchange>, Vec<FramedExchange>) {
    let mut info = b"NOKV\0\x02\x01\x12\x02\x02\x03".to_vec();
    let platform = b"SYNTHETIC.LUMIA.TEST";
    info.extend_from_slice(&[5, 0, platform.len() as u8]);
    info.extend_from_slice(platform);
    info.extend_from_slice(&[15, 0, 8, 3, 1, 1, 1, 0, 0, 1, 1]);
    info.extend_from_slice(&[0x10, 0, 3, 1, 0, 1]);
    let mut flash = vec![
        plain(b"NOKV".to_vec(), info.clone()),
        plain(identity::flash_request(), terminal(42)),
        plain(
            flash::parameter_request("RRKH").unwrap(),
            parameter(&root_bytes()),
        ),
        plain(
            flash::parameter_request("SS").unwrap(),
            parameter(&[0, 1, 1, 1, 0, 0, 1, 1]),
        ),
        plain(b"NOKV".to_vec(), info),
        plain(identity::flash_request(), terminal(42)),
        plain(
            flash::ffu_header_v1(&bytes[..CHUNK * 3]).unwrap(),
            b"NOKXFS\0\0".to_vec(),
        ),
        plain(
            flash::ffu_payload_v1(&vec![0; CHUNK], 0).unwrap(),
            b"NOKXFS\0\0".to_vec(),
        ),
        plain(b"NOKR".to_vec(), vec![]),
    ];
    flash.push(plain(b"UNSUBMITTED".to_vec(), vec![]));
    let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../tests/fixtures/spec-a-dload.json"
    ))
    .unwrap();
    let expected: Vec<Exchange> = serde_json::from_value(vectors["exchanges"].clone()).unwrap();
    let mut download: Vec<_> = expected
        .into_iter()
        .map(|e| FramedExchange {
            request: e.request,
            fragments: e.response.chunks(1).map(|b| b.to_vec()).collect(),
            error: e.error,
        })
        .collect();
    download.push(framed(b"UNSUBMITTED".to_vec(), &[2]));
    let programmer = vec![
        framed(v1::hello(), &[2]),
        framed(b"UNSUBMITTED".to_vec(), &[2]),
    ];
    (flash, download, programmer)
}
pub(crate) fn scenario(
    flash: Vec<Exchange>,
    download: Vec<FramedExchange>,
    programmer: Vec<FramedExchange>,
) -> Scenario {
    Scenario {
        source_port: "synthetic-port-1".into(),
        source_candidates: 1,
        flash: ReplayTransport::new(flash),
        download: FramedReplayTransport::new(download),
        programmer: FramedReplayTransport::new(programmer),
        download_arrivals: arrivals(Endpoint::Download),
        programmer_arrivals: arrivals(Endpoint::Programmer),
    }
}
pub(crate) fn prepare(bytes: &[u8]) -> (EntryPlan, Loader) {
    (
        EntryPlan::read(&mut Cursor::new(bytes), &sha(bytes), |_, _| true).unwrap(),
        Loader::prepare(LOADER, &sha(LOADER), &root()).unwrap(),
    )
}
pub(crate) fn remaining(
    scenario: &mut Scenario,
    f: &[Exchange],
    d: &[FramedExchange],
    p: &[FramedExchange],
) {
    for step in f {
        assert_eq!(
            scenario.flash.exchange(&step.request, 65536).unwrap(),
            step.response
        );
    }
    assert!(scenario.flash.finished());
    for (transport, steps) in [(&mut scenario.download, d), (&mut scenario.programmer, p)] {
        for step in steps {
            let response: Vec<_> = step.fragments.iter().flatten().copied().collect();
            assert_eq!(transport.exchange(&step.request, 8192).unwrap(), response);
        }
        assert!(transport.finished());
    }
}
