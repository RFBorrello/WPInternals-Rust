use std::io::Cursor;
use wpi_core::boot_gpt;
use wpi_protocol::{
    replay::{Exchange, ReplayTransport},
    MessageTransport,
};

fn primary() -> Vec<u8> {
    let mut f = Cursor::new(include_bytes!(
        "../../../tests/fixtures/synthetic-spec-a-package.ffu"
    ));
    let meta = wpi_image::ffu::FfuMetadata::open(&mut f).unwrap();
    let mut b = meta.read_disk(&mut f, 0, 34 * 512).unwrap();
    b[560..568].copy_from_slice(&(0x2228u64 - 34).to_le_bytes());
    b[528..532].fill(0);
    let mut c = !0u32;
    for v in &b[512..604] {
        c ^= u32::from(*v);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 == 1 { 0xedb88320 } else { 0 };
        }
    }
    b[528..532].copy_from_slice(&(!c).to_le_bytes());
    b
}
fn nokv() -> Vec<u8> {
    let mut r = b"NOKV\0\x01\x01\x01\x01\x10\x01".to_vec();
    r.extend_from_slice(&[1, 0, 4]);
    r.extend_from_slice(&2363392u32.to_be_bytes());
    r
}
fn exchanges() -> Vec<Exchange> {
    let mut response = b"NOKT\0\0\0\0".to_vec();
    response.extend(primary());
    [
        (b"NOKV".to_vec(), nokv()),
        (b"NOKT".to_vec(), response.clone()),
        (b"NOKT".to_vec(), response),
        (b"NOKV".to_vec(), nokv()),
    ]
    .into_iter()
    .map(|(request, response)| Exchange {
        request,
        response,
        error: None,
    })
    .collect()
}
fn read(e: Vec<Exchange>) -> boot_gpt::Capture {
    let mut t = ReplayTransport::new(e);
    let c = boot_gpt::read(&mut t, 0x2228, |_| true).unwrap();
    assert!(t.finished());
    c
}
#[test]
fn read_only_boot_profile_and_consistent_primary_produce_no_execution_grants() {
    let c = read(exchanges());
    let sha = wpi_image::stream::sha256(&mut Cursor::new(primary())).unwrap();
    let report = c.report(&sha);
    assert_eq!(report.sha256, sha);
    assert_eq!(report.bytes, 34 * 512);
    assert_eq!(report.partition_count, 8);
    assert!(report.reference_primary_identical);
    assert!(
        !report.primary_gpt_preserved
            && !report.backup_gpt_captured
            && !report.installed_partitions_preserved
            && !report.phone_writes_enabled
    );
    assert!(
        !c.report("different-source-digest")
            .reference_primary_identical
    );
}
struct Counted {
    t: ReplayTransport,
    calls: usize,
}
impl MessageTransport for Counted {
    fn exchange(&mut self, r: &[u8], n: usize) -> wpi_protocol::Result<Vec<u8>> {
        self.calls += 1;
        self.t.exchange(r, n)
    }
}
#[test]
fn query_failures_partial_transfers_and_all_cancellation_boundaries_never_retry() {
    for i in 0..4 {
        for error in ["disconnected", "timed out", "partial transfer"] {
            let mut e = exchanges();
            e[i].error = Some(error.into());
            let mut t = Counted {
                t: ReplayTransport::new(e),
                calls: 0,
            };
            assert!(boot_gpt::read(&mut t, 0x2228, |_| true).is_err());
            assert_eq!(t.calls, i + 1);
        }
    }
    for i in 0..5 {
        let mut t = Counted {
            t: ReplayTransport::new(exchanges()),
            calls: 0,
        };
        let mut n = 0;
        assert!(boot_gpt::read(&mut t, 0x2228, |_| {
            let yes = n != i;
            n += 1;
            yes
        })
        .is_err());
        assert_eq!(t.calls, i.min(4));
    }
}
#[test]
fn invalid_profiles_bounds_crc_oversized_geometry_and_changed_data_stop_immediately() {
    for (index, at) in [
        (0, 5),
        (0, 7),
        (0, 9),
        (1, 8 + 528),
        (1, 8 + 592),
        (2, 8 + 1000),
        (3, 7),
    ] {
        let mut e = exchanges();
        e[index].response[at] ^= 1;
        let mut t = Counted {
            t: ReplayTransport::new(e),
            calls: 0,
        };
        assert!(
            boot_gpt::read(&mut t, 0x2228, |_| true).is_err(),
            "{index}:{at}"
        );
        assert_eq!(t.calls, index + 1);
    }
    for sectors in [0, 34, 0x2227, 0x2229, u32::MAX] {
        let mut t = Counted {
            t: ReplayTransport::new(exchanges()),
            calls: 0,
        };
        assert!(boot_gpt::read(&mut t, sectors, |_| true).is_err());
        assert!(t.calls <= 2);
    }
    for len in [0, 7, 8, 17415, 17417] {
        let mut e = exchanges();
        e[1].response.resize(len, 0);
        let mut t = Counted {
            t: ReplayTransport::new(e),
            calls: 0,
        };
        assert!(boot_gpt::read(&mut t, 0x2228, |_| true).is_err());
        assert_eq!(t.calls, 2);
    }
}
#[test]
fn atomic_preservation_verifies_bytes_and_never_overwrites_existing_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("primary.bin");
    boot_gpt::check_destination(&file).unwrap();
    assert!(!file.exists());
    let report = read(exchanges()).save(&file, "source-sha").unwrap();
    assert!(report.primary_gpt_preserved);
    assert!(!report.reference_primary_identical);
    assert_eq!(std::fs::read(&file).unwrap(), primary());
    assert!(read(exchanges()).save(&file, "source-sha").is_err());
    assert!(boot_gpt::check_destination(&file).is_err());
    assert!(boot_gpt::check_destination(&dir.path().join("absent/new.bin")).is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
