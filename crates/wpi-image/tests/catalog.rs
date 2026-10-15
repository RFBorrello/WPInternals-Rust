use wpi_image::catalog::{verify, Status};
const TABLE: &[u8] = include_bytes!("../../../tests/fixtures/catalog/hash-table.bin");
const PKCS7: &[u8] = include_bytes!("../../../tests/fixtures/catalog/pkcs7-sha1.der");
const CMS: &[u8] = include_bytes!("../../../tests/fixtures/catalog/cms-sha256.der");
#[test]
fn verifies_both_encodings_and_binds_the_table_without_trusting_embedded_certificates() {
    for (catalog, hash) in [(PKCS7, "sha1"), (CMS, "sha256")] {
        let r = verify(catalog, TABLE);
        assert_eq!(r.signature.status, Status::Valid, "{}", r.signature.message);
        assert_eq!(
            r.hash_table_binding.status,
            Status::Valid,
            "{}",
            r.hash_table_binding.message
        );
        assert_eq!(r.membership_hash_algorithm.as_deref(), Some(hash));
        assert_eq!(r.signer_trust.status, Status::Unverified);
    }
}
#[test]
fn changed_table_signed_content_and_rsa_signature_are_distinct_failures() {
    let mut table = TABLE.to_vec();
    table[0] ^= 1;
    let r = verify(PKCS7, &table);
    assert_eq!(r.signature.status, Status::Valid);
    assert_eq!(r.hash_table_binding.status, Status::Invalid);
    for content in [false, true] {
        let mut bytes = PKCS7.to_vec();
        let i = if content {
            bytes
                .windows(8)
                .position(|b| b == [b'H', 0, b'a', 0, b's', 0, b'h', 0])
                .unwrap()
        } else {
            bytes.len() - 1
        };
        bytes[i] ^= 1;
        let r = verify(&bytes, TABLE);
        assert_eq!(r.signature.status, Status::Invalid);
        assert_ne!(r.hash_table_binding.status, Status::Valid);
    }
}
#[test]
fn ambiguous_attributes_unrelated_members_truncation_and_oversize_are_not_verified() {
    let r = verify(
        include_bytes!("../../../tests/fixtures/catalog/duplicate-digest.der"),
        TABLE,
    );
    assert_eq!(r.signature.status, Status::Invalid);
    let r = verify(
        include_bytes!("../../../tests/fixtures/catalog/wrong-member.der"),
        TABLE,
    );
    assert_eq!(r.signature.status, Status::Valid);
    assert_eq!(r.hash_table_binding.status, Status::Unsupported);
    for n in [1, 4, 32, PKCS7.len() - 1] {
        assert_eq!(verify(&PKCS7[..n], TABLE).signature.status, Status::Invalid);
    }
    assert_eq!(
        verify(&vec![0; 1024 * 1024 + 1], TABLE).signature.status,
        Status::Invalid
    );
    assert_eq!(verify(&[], TABLE).signature.status, Status::Missing);
    assert_eq!(
        verify(&[0x30, 0x80, 0, 0], TABLE).signature.status,
        Status::Invalid
    );
    let mut unsupported = PKCS7.to_vec();
    let rsa_oid = [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
    let at = unsupported
        .windows(rsa_oid.len())
        .rposition(|b| b == rsa_oid)
        .unwrap();
    unsupported[at + rsa_oid.len() - 1] = 7; // RSA-OAEP cannot be treated as PKCS#1 signing.
    assert_eq!(
        verify(&unsupported, TABLE).signature.status,
        Status::Unsupported
    );
    let mut nested = vec![0x30, 0];
    for _ in 0..25 {
        let mut next = vec![0x30, nested.len() as u8];
        next.extend(nested);
        nested = next;
    }
    assert!(verify(&nested, TABLE).signature.message.contains("nesting"));
}

#[test]
fn complete_synthetic_chain_passes_mathematics_and_signing_profile_without_becoming_trusted() {
    let report = wpi_image::catalog::verify_at(
        include_bytes!("../../../tests/fixtures/signer-policy/chain.der"),
        TABLE,
        Some(1767225600),
    );
    assert_eq!(report.signature.status, Status::Valid);
    let signer = report.signer_assessment.unwrap();
    assert_eq!(signer.validity.status, Status::Valid);
    assert_eq!(signer.key_usage.status, Status::Valid);
    assert_eq!(signer.extended_key_usage.status, Status::Valid);
    assert_eq!(
        signer.chain_signatures.status,
        Status::Valid,
        "{}",
        signer.chain_signatures.message
    );
    assert_eq!(signer.chain_certificate_sha256.len(), 3);
    assert_eq!(signer.trust_anchor.status, Status::Unverified);
    assert_eq!(signer.revocation.status, Status::Unverified);
    assert_eq!(report.signer_trust.status, Status::Unverified);
}
#[test]
fn certificate_policy_and_chain_failures_are_distinct_from_valid_catalog_signatures() {
    for (bytes, invalid_trust, chain_status) in [
        (
            include_bytes!("../../../tests/fixtures/signer-policy/missing-issuer.der").as_slice(),
            false,
            Status::Missing,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/ambiguous-issuer.der").as_slice(),
            true,
            Status::Invalid,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/bad-chain-signature.der")
                .as_slice(),
            true,
            Status::Invalid,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/non-ca-issuer.der").as_slice(),
            true,
            Status::Invalid,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/wrong-key-usage.der").as_slice(),
            true,
            Status::Valid,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/wrong-eku.der").as_slice(),
            true,
            Status::Valid,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/expired.der").as_slice(),
            true,
            Status::Invalid,
        ),
        (
            include_bytes!("../../../tests/fixtures/signer-policy/unknown-critical.der").as_slice(),
            false,
            Status::Unsupported,
        ),
    ] {
        let report = wpi_image::catalog::verify_at(bytes, TABLE, Some(1767225600));
        assert_eq!(
            report.signature.status,
            Status::Valid,
            "{}",
            report.signature.message
        );
        let signer = report.signer_assessment.unwrap();
        assert_eq!(
            signer.chain_signatures.status, chain_status,
            "{}",
            signer.chain_signatures.message
        );
        assert_eq!(
            report.signer_trust.status,
            if invalid_trust {
                Status::Invalid
            } else {
                Status::Unverified
            }
        );
    }
}
#[test]
fn certificate_dates_require_an_explicit_time_and_do_not_trust_cms_signing_time() {
    let bytes = include_bytes!("../../../tests/fixtures/signer-policy/chain.der");
    assert_eq!(
        verify(bytes, TABLE)
            .signer_assessment
            .unwrap()
            .validity
            .status,
        Status::Unverified
    );
    for at in [1, 2524608000] {
        let report = wpi_image::catalog::verify_at(bytes, TABLE, Some(at));
        assert_eq!(report.signature.status, Status::Valid);
        assert_eq!(
            report.signer_assessment.unwrap().validity.status,
            Status::Invalid
        );
        assert_eq!(report.signer_trust.status, Status::Invalid);
    }
}
