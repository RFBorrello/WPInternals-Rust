use sha2::{Digest, Sha256};
use std::io::Cursor;
use wpi_image::{ffu::FfuMetadata, integrity::FfuVerifier};
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic-mainos.ffu");
fn headers(bytes: &[u8]) -> (&[u8], FfuMetadata) {
    let metadata = FfuMetadata::open(&mut Cursor::new(bytes)).unwrap();
    (&bytes[..metadata.header_size as usize], metadata)
}
#[test]
fn streaming_matches_native_chunk_checks_and_independent_whole_file_digest_at_arbitrary_boundaries()
{
    for bytes in [
        FFU,
        include_bytes!("../../../tests/fixtures/synthetic-signed.ffu").as_slice(),
    ] {
        let (header, metadata) = headers(bytes);
        metadata
            .verify_hashes(&mut Cursor::new(bytes), |_, _| true)
            .unwrap();
        for batch in [1, 17, 4095, 4096, 65537, 1024 * 1024] {
            let mut verifier = FfuVerifier::new(header, bytes.len() as u64).unwrap();
            verifier.update(&[]).unwrap();
            for part in bytes.chunks(batch) {
                verifier.update(part).unwrap();
            }
            let result = verifier.finish().unwrap();
            assert_eq!(result.sha256, hex::encode(Sha256::digest(bytes)));
            assert_eq!(
                result.chunk_count,
                (bytes.len() as u64 - metadata.security_size) / u64::from(metadata.chunk_size)
            );
            assert_eq!(result.first_mismatch, None);
        }
    }
}
#[test]
fn corrupted_payload_keeps_a_complete_fingerprint_but_fails_chunk_integrity() {
    let (header, metadata) = headers(FFU);
    let mut corrupt = FFU.to_vec();
    corrupt[metadata.header_size as usize + 500_000] ^= 1;
    assert!(metadata
        .verify_hashes(&mut Cursor::new(&corrupt), |_, _| true)
        .is_err());
    let mut verifier = FfuVerifier::new(header, FFU.len() as u64).unwrap();
    for part in corrupt.chunks(9001) {
        verifier.update(part).unwrap();
    }
    let result = verifier.finish().unwrap();
    assert!(result.first_mismatch.is_some());
    assert_eq!(result.sha256, hex::encode(Sha256::digest(&corrupt)));
    assert_ne!(result.sha256, hex::encode(Sha256::digest(FFU)));
}
#[test]
fn incomplete_oversized_extra_and_changed_header_input_cannot_publish_a_complete_result() {
    let (header, _) = headers(FFU);
    let mut partial = FfuVerifier::new(header, FFU.len() as u64).unwrap();
    partial.update(&FFU[..100]).unwrap();
    assert!(partial.finish().is_err());
    let mut oversized = FfuVerifier::new(header, FFU.len() as u64).unwrap();
    assert!(oversized.update(&vec![0; 1024 * 1024 + 1]).is_err());
    assert!(oversized.update(&[]).is_err());
    assert!(oversized.finish().is_err());
    let mut extra = FfuVerifier::new(header, FFU.len() as u64).unwrap();
    for part in FFU.chunks(1024 * 1024) {
        extra.update(part).unwrap();
    }
    assert!(extra.update(&[0]).is_err());
    assert!(extra.finish().is_err());
    let mut changed = FfuVerifier::new(header, FFU.len() as u64).unwrap();
    let mut prefix = FFU[..100].to_vec();
    prefix[40] ^= 1;
    assert!(changed.update(&prefix).is_err());
    assert!(changed.finish().is_err());
    assert!(FfuVerifier::new(&header[..header.len() - 1], FFU.len() as u64).is_err());
    assert!(FfuVerifier::new(FFU, FFU.len() as u64).is_err());
    assert!(FfuVerifier::new(header, FFU.len() as u64 + 1).is_err());
}
#[test]
fn unsupported_algorithm_or_wrong_hash_table_length_is_rejected_before_streaming() {
    let (header, _) = headers(FFU);
    let mut bad = header.to_vec();
    bad[20..24].copy_from_slice(&0x8004u32.to_le_bytes());
    assert!(FfuVerifier::new(&bad, FFU.len() as u64).is_err());
    let mut bad = header.to_vec();
    let count = u32::from_le_bytes(bad[28..32].try_into().unwrap());
    bad[28..32].copy_from_slice(&(count - 32).to_le_bytes());
    assert!(FfuVerifier::new(&bad, FFU.len() as u64).is_err());
}

#[test]
fn files_larger_than_four_gib_are_described_without_allocating_their_payload() {
    let (_, old) = headers(FFU);
    let chunk = 1024 * 1024;
    let payload_chunks = 4097u32;
    let mut header = vec![0; chunk * 3];
    header[..32].copy_from_slice(&FFU[..32]);
    header[16..20].copy_from_slice(&1024u32.to_le_bytes());
    header[28..32].copy_from_slice(&((payload_chunks + 2) * 32).to_le_bytes());
    header[chunk..chunk + old.image_size as usize].copy_from_slice(
        &FFU[old.security_size as usize..(old.security_size + old.image_size) as usize],
    );
    header[chunk + 20..chunk + 24].copy_from_slice(&1024u32.to_le_bytes());
    let store = (old.security_size + old.image_size) as usize;
    header[2 * chunk..2 * chunk + old.store_size as usize]
        .copy_from_slice(&FFU[store..store + old.store_size as usize]);
    header[2 * chunk + 204..2 * chunk + 208].copy_from_slice(&(chunk as u32).to_le_bytes());
    header[2 * chunk + 252..2 * chunk + 256].copy_from_slice(&payload_chunks.to_le_bytes());
    let total = (u64::from(payload_chunks) + 3) * chunk as u64;
    let mut verifier = FfuVerifier::new(&header, total).unwrap();
    assert!(verifier.metadata().total_size > u64::from(u32::MAX));
    for block in header.chunks(chunk) {
        verifier.update(block).unwrap();
    }
    assert!(verifier.finish().is_err()); // No payload was supplied or fingerprint published.
}
