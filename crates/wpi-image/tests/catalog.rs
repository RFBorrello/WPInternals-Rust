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
