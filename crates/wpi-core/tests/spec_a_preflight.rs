use std::io::Cursor;
use wpi_core::spec_a_preflight::{self, Reference};
use wpi_protocol::{
    preflight,
    replay::{Exchange, ReplayTransport},
};
use wpi_types::PreparationStatus;
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic-spec-a-package.ffu");
const LOCKED: &str = include_str!("../../../tests/fixtures/spec-a-preflight-locked.json");
const PRIMARY: &str = include_str!("../../../tests/fixtures/spec-a-preflight-primary.json");

fn exchanges(s: &str) -> Vec<Exchange> {
    #[derive(serde::Deserialize)]
    struct Scenario {
        exchanges: Vec<Exchange>,
    }
    serde_json::from_str::<Scenario>(s).unwrap().exchanges
}
fn capture(r: &Reference, e: Vec<Exchange>) -> preflight::Capture {
    let mut transport = ReplayTransport::new(e);
    let c = preflight::capture(&mut transport, r.root(), r.platform(), true, |_| true).unwrap();
    assert!(transport.finished());
    c
}
#[test]
fn passing_synthetic_comparisons_cannot_authorize_writes_or_claim_backups() {
    let r = Reference::read(&mut Cursor::new(FFU)).unwrap();
    for (fixture, status) in [
        (LOCKED, PreparationStatus::Missing),
        (PRIMARY, PreparationStatus::Passed),
    ] {
        let report = spec_a_preflight::assess(&r, capture(&r, exchanges(fixture)), true).unwrap();
        assert_eq!(report.source_kind, "replay_only");
        assert_eq!(
            report
                .checks
                .iter()
                .find(|c| c.key == "live_gpt")
                .unwrap()
                .status,
            status
        );
        assert_eq!(report.observed_primary_sha256.is_some(), fixture == PRIMARY);
        let json = serde_json::to_value(report).unwrap();
        for field in [
            "public_id_bytes_exported",
            "identity_authenticated",
            "normal_session_correlated",
            "mode_changes_sent",
            "installed_originals_preserved",
            "backup_gpt_captured",
            "recovery_authorized",
            "phone_writes_enabled",
        ] {
            assert_eq!(json[field], false, "{field}");
        }
        assert_eq!(json["reference"]["full_ffu_integrity_checked"], false);
        assert_eq!(json["reference"]["oem_signer_trusted"], false);
        assert!(json.get("public_id").is_none() && json.get("serial").is_none());
    }
}
fn update_crcs(primary: &mut [u8]) {
    // Use the image crate's CRC dependency through a tiny standalone implementation
    // to check corruptions independently of its GPT encoder.
    fn crc(b: &[u8]) -> u32 {
        let mut c = !0u32;
        for v in b {
            c ^= u32::from(*v);
            for _ in 0..8 {
                c = (c >> 1) ^ if c & 1 == 1 { 0xedb88320 } else { 0 };
            }
        }
        !c
    }
    let c = crc(&primary[1024..]);
    primary[600..604].copy_from_slice(&c.to_le_bytes());
    primary[528..532].fill(0);
    let c = crc(&primary[512..604]);
    primary[528..532].copy_from_slice(&c.to_le_bytes());
}
#[test]
fn layout_mismatches_fail_and_malformed_or_oversized_gpt_is_rejected() {
    let r = Reference::read(&mut Cursor::new(FFU)).unwrap();
    // Attribute and disk GUID differences have valid CRCs, but cannot inherit
    // coordinates/identity from a reference image.
    for at in [512 + 56, 1024 + 48] {
        let mut e = exchanges(PRIMARY);
        e[4].response[8 + at] ^= 1;
        update_crcs(&mut e[4].response[8..]);
        let report = spec_a_preflight::assess(&r, capture(&r, e), true).unwrap();
        assert_eq!(
            report
                .checks
                .iter()
                .find(|c| c.key == "live_gpt")
                .unwrap()
                .status,
            PreparationStatus::Failed
        );
        assert!(!report.phone_writes_enabled);
    }
    for at in [512 + 16, 1024 + 32] {
        let mut e = exchanges(PRIMARY);
        e[4].response[8 + at] ^= 1;
        assert!(spec_a_preflight::assess(&r, capture(&r, e), true).is_err());
    }
    let mut e = exchanges(PRIMARY);
    // Two valid copies of a tiny reported eMMC capacity; live GPT lies beyond it.
    for i in [0, 5] {
        e[i].response[10] += 1;
        e[i].response.extend_from_slice(&[3, 0, 4, 0, 0, 0, 40]);
    }
    assert!(spec_a_preflight::assess(&r, capture(&r, e), true).is_err());
}
#[test]
fn reference_is_bounded_and_observed_evidence_is_bound_to_its_source() {
    let r = Reference::read(&mut Cursor::new(FFU)).unwrap();
    assert!(Reference::read(&mut Cursor::new(&FFU[..128])).is_err());
    let mut bytes = FFU.to_vec();
    // Change the source platform in the FFU store header; metadata parses but a
    // capture made for the old source cannot be relabeled as this reference.
    let at = bytes
        .windows(r.platform().len())
        .position(|w| w == r.platform().as_bytes())
        .unwrap();
    bytes[at] = b'X';
    let other = Reference::read(&mut Cursor::new(bytes)).unwrap();
    assert!(spec_a_preflight::assess(&other, capture(&r, exchanges(LOCKED)), true).is_err());
}
