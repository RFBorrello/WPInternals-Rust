use std::io::{Cursor, Read, Seek, SeekFrom};
use wpi_image::{
    catalog::{self, image_issuer, Status},
    ffu::FfuMetadata,
    ImageError,
};
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic-image-issuer.ffu");
const WRONG: &[u8] = include_bytes!("../../../tests/fixtures/synthetic-wrong-issuer.ffu");
const PK: &[u8] = include_bytes!("../../../tests/fixtures/image-issuer/production.bin");
const AT: u64 = 1_790_000_000;

#[test]
fn image_local_pk_completes_signatures_without_conferring_oem_trust() {
    let mut reader = Cursor::new(FFU);
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    let gpt = ffu.gpt(&mut reader).unwrap();
    ffu.verify_hashes(&mut reader, |_, _| true).unwrap();
    assert_eq!(
        catalog::inspect_at(&mut reader, &ffu, Some(AT))
            .unwrap()
            .signer_assessment
            .unwrap()
            .chain_signatures
            .status,
        Status::Missing
    );
    let report = catalog::inspect_with_image_issuer(&mut reader, &ffu, &gpt, Some(AT)).unwrap();
    assert_eq!(report.signature.status, Status::Valid);
    let evidence = report.issuer_evidence.unwrap();
    assert_eq!(evidence.source, image_issuer::SOURCE);
    assert_eq!(evidence.check.status, Status::Valid);
    let signer = report.signer_assessment.unwrap();
    assert_eq!(
        signer.chain_signatures.status,
        Status::Valid,
        "{}",
        signer.chain_signatures.message
    );
    assert_eq!(signer.chain_certificate_sha256.len(), 2);
    assert_eq!(
        signer.chain_certificate_sha256[1],
        evidence.certificate_sha256.unwrap()
    );
    assert_eq!(signer.trust_anchor.status, Status::Unverified);
    assert_eq!(signer.revocation.status, Status::Unverified);
    assert_eq!(report.signer_trust.status, Status::Unverified);
}

#[test]
fn same_subject_wrong_key_cannot_complete_a_chain() {
    let mut reader = Cursor::new(WRONG);
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    let gpt = ffu.gpt(&mut reader).unwrap();
    let report = catalog::inspect_with_image_issuer(&mut reader, &ffu, &gpt, Some(AT)).unwrap();
    assert_eq!(report.signature.status, Status::Valid);
    assert_eq!(
        report.signer_assessment.unwrap().chain_signatures.status,
        Status::Invalid
    );
    assert_eq!(report.signer_trust.status, Status::Invalid);
}

#[test]
fn provisioning_structure_rejects_truncation_overflow_wrong_types_and_extra_entries() {
    assert!(image_issuer::certificate(PK).is_ok());
    for n in 0..PK.len() {
        assert!(
            image_issuer::certificate(&PK[..n]).is_err(),
            "accepted truncation {n}"
        );
    }
    let payload = 16 + u32::from_le_bytes(PK[16..20].try_into().unwrap()) as usize;
    for (at, value) in [
        (16, u32::MAX),
        (payload + 16, u32::MAX),
        (payload + 20, 1),
        (payload + 24, 0),
        (payload + 24, u32::MAX),
    ] {
        let mut bad = PK.to_vec();
        bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert!(image_issuer::certificate(&bad).is_err());
    }
    for at in [20, 22, 24, payload] {
        let mut bad = PK.to_vec();
        bad[at] ^= 1;
        assert!(image_issuer::certificate(&bad).is_err());
    }
    let mut bad = PK.to_vec();
    bad.push(0);
    assert!(image_issuer::certificate(&bad).is_err());
    assert!(image_issuer::certificate(&vec![0; 16 * 1024 + 1]).is_err());
}

#[test]
fn optional_lookup_handles_absence_and_never_ignores_ambiguous_or_short_partitions() {
    let mut reader = Cursor::new(FFU);
    let ffu = FfuMetadata::open(&mut reader).unwrap();
    let gpt = ffu.gpt(&mut reader).unwrap();
    let mut missing = gpt.clone();
    missing.partitions.clear();
    assert!(
        catalog::inspect_with_image_issuer(&mut reader, &ffu, &missing, Some(AT))
            .unwrap()
            .issuer_evidence
            .is_none()
    );
    let mut dup = gpt.clone();
    dup.partitions.push(dup.partitions[0].clone());
    let r = catalog::inspect_with_image_issuer(&mut reader, &ffu, &dup, Some(AT)).unwrap();
    assert_eq!(r.issuer_evidence.unwrap().check.status, Status::Invalid);
    assert_eq!(
        r.signer_assessment.unwrap().chain_signatures.status,
        Status::Missing
    );
    let mut small = gpt;
    small.partitions[0].last_sector = small.partitions[0].first_sector + 1;
    assert_eq!(
        catalog::inspect_with_image_issuer(&mut reader, &ffu, &small, Some(AT))
            .unwrap()
            .issuer_evidence
            .unwrap()
            .check
            .status,
        Status::Invalid
    );
}

#[test]
fn image_issuer_reads_are_bounded_and_disconnections_cannot_produce_success() {
    struct Limited {
        bytes: Cursor<&'static [u8]>,
        max: usize,
        fail: bool,
    }
    impl Read for Limited {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.max = self.max.max(b.len());
            assert!(b.len() <= 64 * 1024);
            if self.fail && self.bytes.position() > 512 * 1024 {
                return Err(std::io::Error::other("disconnected"));
            }
            self.bytes.read(b)
        }
    }
    impl Seek for Limited {
        fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(p)
        }
    }
    let mut r = Limited {
        bytes: Cursor::new(FFU),
        max: 0,
        fail: false,
    };
    let ffu = FfuMetadata::open(&mut r).unwrap();
    let gpt = ffu.gpt(&mut r).unwrap();
    assert_eq!(
        catalog::inspect_with_image_issuer(&mut r, &ffu, &gpt, Some(AT))
            .unwrap()
            .signer_assessment
            .unwrap()
            .chain_signatures
            .status,
        Status::Valid
    );
    r.fail = true;
    let result = catalog::inspect_with_image_issuer(&mut r, &ffu, &gpt, Some(AT));
    match result {
        Ok(report) => assert_ne!(
            report.signer_assessment.unwrap().chain_signatures.status,
            Status::Valid
        ),
        Err(ImageError::Io(_)) => {}
        Err(error) => panic!("unexpected error {error}"),
    }
}
