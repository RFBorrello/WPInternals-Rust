//! Offline legacy FFU catalog verification. Embedded certificates are never trust anchors.
//! CMS/PKCS#7: RFC 5652 §§5.2.1, 5.4. Windows CTL/CAT member semantics: see
//! docs/firmware-validation.md. RSA here is public-key verification only.
use crate::{ffu::FfuMetadata, invalid, read_at, ImageError, Result};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use der::{
    asn1::{ObjectIdentifier, OctetString, Uint},
    Any, Decode, Encode, Sequence, Tag, Tagged,
};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
use x509_cert::{attr::Attributes, spki::AlgorithmIdentifierOwned, time::Time};

const MAX_CATALOG: usize = 1024 * 1024;
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const CTL: &str = "1.3.6.1.4.1.311.10.1";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA1: &str = "1.3.14.3.2.26";
const RSA: &str = "1.2.840.113549.1.1.1";
const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}
fn unsupported(s: &str) -> ImageError {
    ImageError::Unsupported(s.into())
}
fn malformed(e: impl std::fmt::Display) -> ImageError {
    invalid(format!("Malformed signing catalog: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Valid,
    Invalid,
    Unsupported,
    Missing,
    Unverified,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub status: Status,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogReport {
    pub signature: Check,
    pub hash_table_binding: Check,
    pub signer_trust: Check,
    pub signer_subject: Option<String>,
    pub signer_certificate_sha256: Option<String>,
    pub catalog_sha256: String,
    pub membership_hash_algorithm: Option<String>,
}
fn result_check(result: Result<()>, success: &str) -> Check {
    match result {
        Ok(()) => Check {
            status: Status::Valid,
            message: success.into(),
        },
        Err(ImageError::Unsupported(s)) => Check {
            status: Status::Unsupported,
            message: s,
        },
        Err(e) => Check {
            status: Status::Invalid,
            message: e.to_string(),
        },
    }
}
pub fn inspect<R: Read + Seek>(reader: &mut R, ffu: &FfuMetadata) -> Result<CatalogReport> {
    if ffu.catalog_size as usize > MAX_CATALOG {
        return Err(invalid("Signing catalog exceeds 1 MiB"));
    }
    let start = ffu
        .hash_table_offset
        .checked_sub(ffu.catalog_size as u64)
        .ok_or_else(|| invalid("Catalog offset underflow"))?;
    if start < 32
        || ffu
            .hash_table_offset
            .checked_add(ffu.hash_table_size as u64)
            .is_none_or(|end| end > ffu.security_size)
    {
        return Err(invalid("Catalog/hash table exceed the FFU security region"));
    }
    let catalog = read_at(reader, start, ffu.catalog_size as usize)?;
    let hashes = read_at(reader, ffu.hash_table_offset, ffu.hash_table_size as usize)?;
    Ok(verify(&catalog, &hashes))
}
pub fn verify(catalog: &[u8], hashes: &[u8]) -> CatalogReport {
    let mut report = CatalogReport {
        signature:Check {status:Status::Missing,message:"No signing catalog is present.".into()},
        hash_table_binding:Check {status:Status::Unverified,message:"Hash-table binding requires a valid catalog signature.".into()},
        signer_trust:Check {status:Status::Unverified,message:"An embedded certificate is not a trust anchor. OEM chain, device root-key binding, certificate policy/time and revocation have not been validated.".into()},
        signer_subject:None, signer_certificate_sha256:None,
        catalog_sha256:hex::encode(Sha256::digest(catalog)),membership_hash_algorithm:None,
    };
    if catalog.is_empty() {
        return report;
    }
    let signed = verify_signature(catalog);
    let (content, certificate) = match signed {
        Ok(s) => s,
        Err(e) => {
            report.signature = result_check(Err(e), "");
            return report;
        }
    };
    report.signature=result_check(Ok(()),"RSA/SHA-256 catalog signature and signed attributes verified. This does not establish signer trust or device acceptance.");
    report.signer_subject = Some(certificate.tbs_certificate.subject.to_string());
    report.signer_certificate_sha256 = certificate
        .to_der()
        .ok()
        .map(|c| hex::encode(Sha256::digest(c)));
    let bound = bind_table(&content, hashes);
    match bound {
        Ok(algorithm) => {
            report.hash_table_binding = result_check(
                Ok(()),
                if algorithm == "sha1" {
                    "Signed catalog member matches the FFU hash table using legacy SHA-1. Legacy collision resistance is not a modern authenticity guarantee."
                } else {
                    "Signed catalog SHA-256 member matches the FFU hash table."
                },
            );
            report.membership_hash_algorithm = Some(algorithm.into());
        }
        Err(e) => report.hash_table_binding = result_check(Err(e), ""),
    }
    report
}
pub fn unavailable(error: ImageError) -> CatalogReport {
    let mut report = verify(&[], &[]);
    report.signature = result_check(Err(error), "");
    report
}

// Reject deep/huge ASN.1 before allocating CMS/X.509 structures. DER primitives,
// canonical lengths and ordering are then decoded by RustCrypto's DER library.
fn bound_der(bytes: &[u8], depth: usize, nodes: &mut usize) -> Result<()> {
    if depth > 24 {
        return Err(invalid("Catalog ASN.1 nesting exceeds 24"));
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        *nodes += 1;
        if *nodes > 4096 {
            return Err(invalid("Catalog ASN.1 node count exceeds 4096"));
        }
        if rest.len() < 2 || rest[0] & 31 == 31 {
            return Err(invalid("Unsupported or truncated catalog ASN.1 tag"));
        }
        let tag = rest[0];
        let mut header = 2;
        let mut len = rest[1] as usize;
        if len & 128 != 0 {
            let count = len & 127;
            if count == 0 || count > 4 || rest.len() < 2 + count || rest[2] == 0 {
                return Err(invalid("Invalid catalog DER length"));
            }
            len = 0;
            for b in &rest[2..2 + count] {
                len = len
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(*b as usize))
                    .ok_or_else(|| invalid("DER length overflow"))?;
            }
            if len < 128 {
                return Err(invalid("Noncanonical catalog DER length"));
            }
            header += count;
        }
        let end = header
            .checked_add(len)
            .ok_or_else(|| invalid("DER length overflow"))?;
        let value = rest
            .get(header..end)
            .ok_or_else(|| invalid("Truncated catalog DER value"))?;
        if tag & 32 != 0 {
            bound_der(value, depth + 1, nodes)?;
        }
        rest = &rest[end..];
    }
    Ok(())
}
fn null_or_absent(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_none_or(|p| p.tag() == Tag::Null && p.value().is_empty())
}
fn attribute<'a>(attrs: &'a Attributes, id: &str) -> Result<&'a Any> {
    let matches: Vec<_> = attrs.iter().filter(|a| a.oid == oid(id)).collect();
    if matches.len() != 1 || matches[0].values.len() != 1 {
        return Err(invalid(
            "Required signed attribute missing, duplicated or ambiguous",
        ));
    }
    Ok(matches[0].values.iter().next().unwrap())
}
fn verify_signature(catalog: &[u8]) -> Result<(Vec<u8>, x509_cert::Certificate)> {
    if catalog.len() > MAX_CATALOG {
        return Err(invalid("Signing catalog exceeds 1 MiB"));
    }
    bound_der(catalog, 0, &mut 0)?;
    let outer = ContentInfo::from_der(catalog).map_err(malformed)?;
    if outer.content_type != oid(SIGNED_DATA) {
        return Err(unsupported("Catalog is not CMS/PKCS#7 SignedData"));
    }
    let signed: SignedData = outer.content.decode_as().map_err(malformed)?;
    if signed.encap_content_info.econtent_type != oid(CTL) {
        return Err(unsupported(
            "Only Windows CTL signing catalogs are supported",
        ));
    }
    if signed.signer_infos.0.len() != 1 {
        return Err(unsupported("Exactly one catalog signer is required"));
    }
    if signed.digest_algorithms.len() != 1
        || !signed
            .digest_algorithms
            .iter()
            .all(|a| a.oid == oid(SHA256) && null_or_absent(a))
    {
        return Err(unsupported(
            "Only SHA-256 catalog signature digests are supported",
        ));
    }
    let signer = signed.signer_infos.0.iter().next().unwrap();
    if signer.digest_alg.oid != oid(SHA256)
        || !null_or_absent(&signer.digest_alg)
        || signer.signature_algorithm.oid != oid(RSA)
        || !null_or_absent(&signer.signature_algorithm)
    {
        return Err(unsupported(
            "Only RSA PKCS#1 v1.5 / SHA-256 catalog signatures are supported",
        ));
    }
    let encapsulated = signed
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| invalid("Detached catalog content is not accepted"))?;
    let content = match encapsulated.tag() {
        Tag::OctetString => encapsulated.value().to_vec(),
        Tag::Sequence => encapsulated.to_der().map_err(malformed)?,
        _ => return Err(unsupported("Unsupported catalog content encoding")),
    };
    let digest_content = if encapsulated.tag() == Tag::Sequence {
        encapsulated.value()
    } else {
        &content
    };
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| invalid("Signed catalog attributes are required"))?;
    if attrs.len() > 32 {
        return Err(invalid("Too many signed catalog attributes"));
    }
    let content_type: ObjectIdentifier = attribute(attrs, CONTENT_TYPE)?
        .decode_as()
        .map_err(malformed)?;
    if content_type != oid(CTL) {
        return Err(invalid("Signed content-type contradicts CTL content"));
    }
    let digest: OctetString = attribute(attrs, MESSAGE_DIGEST)?
        .decode_as()
        .map_err(malformed)?;
    if digest.as_bytes() != Sha256::digest(digest_content).as_slice() {
        return Err(invalid("Catalog signed-content digest mismatch"));
    }
    let certs = signed
        .certificates
        .as_ref()
        .ok_or_else(|| invalid("Signer certificate missing"))?;
    if certs.0.len() > 16 {
        return Err(invalid("Too many catalog certificates"));
    }
    let sid = match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(s) => s,
        _ => {
            return Err(unsupported(
                "Only issuer-and-serial signer IDs are supported",
            ))
        }
    };
    let matching: Vec<_> = certs
        .0
        .iter()
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c)
                if c.tbs_certificate.issuer == sid.issuer
                    && c.tbs_certificate.serial_number == sid.serial_number =>
            {
                Some(c)
            }
            _ => None,
        })
        .collect();
    if matching.len() != 1 {
        return Err(invalid("Signer certificate missing or ambiguous"));
    }
    let certificate = matching[0];
    let key = RsaPublicKey::from_public_key_der(
        &certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(malformed)?,
    )
    .map_err(malformed)?;
    if !(2048..=4096).contains(&key.n().bits()) {
        return Err(unsupported("Catalog RSA modulus must be 2048–4096 bits"));
    }
    let attributes = attrs.to_der().map_err(malformed)?;
    key.verify(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(&attributes),
        signer.signature.as_bytes(),
    )
    .map_err(|_| invalid("Catalog RSA signature mismatch"))?;
    Ok((content, certificate.clone()))
}

#[derive(Sequence)]
struct Ctl {
    version: Option<Uint>,
    usage: Vec<ObjectIdentifier>,
    list_id: Option<OctetString>,
    sequence: Option<Uint>,
    this_update: Time,
    next_update: Option<Time>,
    algorithm: AlgorithmIdentifierOwned,
    entries: Option<Vec<CtlEntry>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Any>,
}
#[derive(Sequence)]
struct CtlEntry {
    subject: OctetString,
    attributes: Attributes,
}
#[derive(Sequence)]
struct Indirect {
    data: IndirectType,
    digest: DigestInfo,
}
#[derive(Sequence)]
struct IndirectType {
    kind: ObjectIdentifier,
    value: Option<Any>,
}
#[derive(Sequence)]
struct DigestInfo {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}
fn bind_table(content: &[u8], hashes: &[u8]) -> Result<&'static str> {
    let ctl = Ctl::from_der(content).map_err(malformed)?;
    if ctl.usage != [oid("1.3.6.1.4.1.311.12.1.1")]
        || ctl.algorithm.oid != oid("1.3.6.1.4.1.311.12.1.2")
        || !null_or_absent(&ctl.algorithm)
    {
        return Err(unsupported(
            "Unsupported CTL catalog usage/subject algorithm",
        ));
    }
    let entries = ctl
        .entries
        .ok_or_else(|| invalid("Catalog has no members"))?;
    if entries.len() != 1 {
        return Err(unsupported(
            "Only a single HashTable.blob catalog member is supported",
        ));
    }
    let expected: Vec<u8> = "HashTable.blob\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    if entries[0].subject.as_bytes() != expected {
        return Err(unsupported("Catalog member is not HashTable.blob"));
    }
    let indirect: Indirect = attribute(&entries[0].attributes, INDIRECT_DATA)?
        .decode_as()
        .map_err(malformed)?;
    if indirect.data.kind != oid("1.3.6.1.4.1.311.2.1.25")
        || !null_or_absent(&indirect.digest.algorithm)
    {
        return Err(unsupported(
            "Unsupported catalog indirect-data type/parameters",
        ));
    }
    let (name, digest) = match indirect.digest.algorithm.oid {
        id if id == oid(SHA1) => ("sha1", sha1::Sha1::digest(hashes).to_vec()),
        id if id == oid(SHA256) => ("sha256", Sha256::digest(hashes).to_vec()),
        _ => return Err(unsupported("Unsupported catalog member hash algorithm")),
    };
    if indirect.digest.digest.as_bytes() != digest {
        return Err(invalid(
            "Signed catalog member does not match the FFU hash table",
        ));
    }
    Ok(name)
}
