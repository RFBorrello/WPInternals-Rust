//! Image-local issuer candidates, never independent trust anchors. The narrow
//! profile reads the production PK provisioning file, not arbitrary DER matches.
use super::{bound_der, malformed, unsupported};
use crate::{ffu::FfuMetadata, filesystem, gpt::Gpt, invalid, slice, u32le, Result};
use der::Decode;
use std::io::{Read, Seek};
use x509_cert::Certificate;

pub const PATH: &str = "Nokia/Security/Nokia_Production_PK.bin";
pub const SOURCE: &str = "EFIESP/Nokia/Security/Nokia_Production_PK.bin";
const LIMIT: usize = 16 * 1024;
const PKCS7_GUID: &[u8] = &[
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
];
const X509_GUID: &[u8] = &[
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];

pub(crate) fn read<R: Read + Seek, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    ffu: &FfuMetadata,
    gpt: &Gpt,
    progress: F,
) -> Result<Option<Vec<u8>>> {
    crate::partition::with_partition("EFIESP", reader, ffu, gpt, progress, |partition| {
        filesystem::read_small_fat_file(partition, PATH, LIMIT)
    })
}

/// Decode EFI_VARIABLE_AUTHENTICATION_2 followed by exactly one X.509 signature
/// list entry. Authentication bytes are structurally bounded, not authenticated;
/// neither this file nor its name proves enrollment in any phone's PK variable.
pub fn certificate(bytes: &[u8]) -> Result<Certificate> {
    if bytes.len() > LIMIT {
        return Err(invalid("PK provisioning file exceeds 16 KiB"));
    }
    // EFI_TIME (16), WIN_CERTIFICATE_UEFI_GUID (24 + bounded PKCS#7).
    let auth_len = u32le(bytes, 16)? as usize;
    if auth_len < 24
        || slice(bytes, 20, 4)? != [0x00, 0x02, 0xf1, 0x0e]
        || slice(bytes, 24, 16)? != PKCS7_GUID
    {
        return Err(unsupported(
            "Unsupported authenticated-variable certificate header",
        ));
    }
    let payload_at = 16usize
        .checked_add(auth_len)
        .ok_or_else(|| invalid("PK authentication length overflow"))?;
    let auth = slice(bytes, 40, auth_len - 24)?;
    bound_der(auth, 0, &mut 0)?;
    let content = cms::content_info::ContentInfo::from_der(auth).map_err(malformed)?;
    if content.content_type != super::oid(super::SIGNED_DATA) {
        return Err(unsupported(
            "PK authentication wrapper is not CMS SignedData",
        ));
    }
    let _: cms::signed_data::SignedData = content.content.decode_as().map_err(malformed)?;
    let list = bytes
        .get(payload_at..)
        .ok_or_else(|| invalid("Truncated PK signature list"))?;
    if slice(list, 0, 16)? != X509_GUID {
        return Err(unsupported("PK signature list is not X.509"));
    }
    let list_len = u32le(list, 16)? as usize;
    let header_len = u32le(list, 20)? as usize;
    let sig_len = u32le(list, 24)? as usize;
    if list_len != list.len()
        || header_len != 0
        || sig_len < 17
        || sig_len.checked_add(28) != Some(list_len)
    {
        return Err(invalid(
            "PK profile requires exactly one complete X.509 signature-list entry",
        ));
    }
    let der = slice(list, 44, sig_len - 16)?;
    bound_der(der, 0, &mut 0)?;
    Certificate::from_der(der).map_err(malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_propagates_from_the_bounded_partition_reader() {
        let mut reader = std::io::Cursor::new(
            include_bytes!("../../../../tests/fixtures/synthetic-image-issuer.ffu").as_slice(),
        );
        let ffu = FfuMetadata::open(&mut reader).unwrap();
        let gpt = ffu.gpt(&mut reader).unwrap();
        assert!(matches!(
            read(&mut reader, &ffu, &gpt, |_, _| false),
            Err(crate::ImageError::Cancelled)
        ));
    }
}
