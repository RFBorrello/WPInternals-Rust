//! Limited offline certificate assessment, based on RFC 5280. This is not a
//! complete PKIX/OEM policy engine. No embedded root or name is trusted.
use super::{malformed, null_or_absent, oid, result_check, unsupported, Check, Status};
use crate::{invalid, Result};
use der::{Decode, Encode};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_cert::{
    ext::pkix::{
        name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
        SubjectKeyIdentifier,
    },
    Certificate,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerAssessment {
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub checked_at_unix_seconds: Option<u64>,
    pub validity: Check,
    pub key_usage: Check,
    pub extended_key_usage: Check,
    pub extensions: Check,
    pub chain_signatures: Check,
    pub chain_certificate_sha256: Vec<String>,
    pub trust_anchor: Check,
    pub revocation: Check,
}
fn check(status: Status, message: impl Into<String>) -> Check {
    Check {
        status,
        message: message.into(),
    }
}
fn fingerprint(c: &Certificate) -> Result<String> {
    Ok(hex::encode(Sha256::digest(c.to_der().map_err(malformed)?)))
}
fn extension<T: for<'a> Decode<'a>>(c: &Certificate, id: &str) -> Result<Option<T>> {
    let extensions: Vec<_> = c
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id == oid(id))
        .collect();
    if extensions.len() > 1 {
        return Err(invalid("Duplicate certificate extension"));
    }
    extensions
        .first()
        .map(|e| T::from_der(e.extn_value.as_bytes()).map_err(malformed))
        .transpose()
}
fn extensions(c: &Certificate) -> Result<()> {
    let all = c.tbs_certificate.extensions.as_deref().unwrap_or(&[]);
    if all.len() > 32 {
        return Err(invalid("Certificate exceeds 32 extensions"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in all {
        if !seen.insert(e.extn_id) {
            return Err(invalid("Duplicate certificate extension"));
        }
        match e.extn_id.to_string().as_str() {
            "2.5.29.15" => {
                KeyUsage::from_der(e.extn_value.as_bytes()).map_err(malformed)?;
            }
            "2.5.29.37" => {
                ExtendedKeyUsage::from_der(e.extn_value.as_bytes()).map_err(malformed)?;
            }
            "2.5.29.19" => {
                BasicConstraints::from_der(e.extn_value.as_bytes()).map_err(malformed)?;
            }
            "2.5.29.14" => {
                SubjectKeyIdentifier::from_der(e.extn_value.as_bytes()).map_err(malformed)?;
            }
            "2.5.29.35" => {
                AuthorityKeyIdentifier::from_der(e.extn_value.as_bytes()).map_err(malformed)?;
            }
            _ if e.critical => {
                return Err(unsupported(
                    "Certificate has an unprocessed critical extension",
                ))
            }
            _ => {}
        }
    }
    Ok(())
}
fn validity(c: &Certificate, at: Option<u64>) -> Check {
    let before = c
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let after = c
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    if before > after {
        return check(Status::Invalid, "Certificate validity interval is reversed");
    }
    let period = format!(
        "Certificate validity is {} through {}.",
        c.tbs_certificate.validity.not_before, c.tbs_certificate.validity.not_after
    );
    match at {
        Some(t) if t < before || t > after => check(Status::Invalid, "Certificate is outside its validity interval at the supplied local time; no historical timestamp policy is implemented"),
        Some(_) => check(Status::Valid, format!("{period} Includes the supplied local time. The clock is not authenticated; signing-time validation is not implemented.")),
        None => check(Status::Unverified, "No explicit reference time was supplied for certificate-date checking"),
    }
}
fn verify_link(child: &Certificate, issuer: &Certificate) -> Result<()> {
    if child.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Err(invalid("Certificate issuer name mismatch"));
    }
    if child.signature_algorithm != child.tbs_certificate.signature {
        return Err(invalid("Certificate signature algorithms disagree"));
    }
    if child.signature_algorithm.oid != oid("1.2.840.113549.1.1.11")
        || !null_or_absent(&child.signature_algorithm)
    {
        return Err(unsupported(
            "Only RSA/SHA-256 certificate signatures are supported",
        ));
    }
    if let Some(aki) = extension::<AuthorityKeyIdentifier>(child, "2.5.29.35")? {
        if let (Some(aki), Some(ski)) = (
            aki.key_identifier,
            extension::<SubjectKeyIdentifier>(issuer, "2.5.29.14")?,
        ) {
            if aki != ski.0 {
                return Err(invalid(
                    "Certificate authority/subject key identifiers disagree",
                ));
            }
        }
        match (aki.authority_cert_issuer, aki.authority_cert_serial_number) {
            (None, None) => {}
            (Some(names), Some(serial)) => {
                // authorityCertIssuer names the issuer OF the candidate issuer.
                // Support only one exact directoryName; never ignore constraints.
                if names.len() != 1 {
                    return Err(unsupported(
                        "Only a single authority directoryName is supported",
                    ));
                }
                match &names[0] {
                    GeneralName::DirectoryName(name) if name == &issuer.tbs_certificate.issuer => {}
                    GeneralName::DirectoryName(_) => {
                        return Err(invalid("Authority certificate issuer name mismatch"))
                    }
                    _ => {
                        return Err(unsupported(
                            "Authority certificate issuer name type is unsupported",
                        ))
                    }
                }
                if serial != issuer.tbs_certificate.serial_number {
                    return Err(invalid("Authority certificate serial number mismatch"));
                }
            }
            _ => return Err(invalid("Authority issuer and serial must appear together")),
        }
    }
    let key = RsaPublicKey::from_public_key_der(
        &issuer
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(malformed)?,
    )
    .map_err(malformed)?;
    if !(2048..=4096).contains(&key.n().bits()) {
        return Err(unsupported(
            "Certificate RSA modulus must be 2048–4096 bits",
        ));
    }
    let signature = child
        .signature
        .as_bytes()
        .ok_or_else(|| invalid("Certificate signature has unused bits"))?;
    key.verify(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(child.tbs_certificate.to_der().map_err(malformed)?),
        signature,
    )
    .map_err(|_| invalid("Certificate issuer signature mismatch"))
}
fn chain(
    leaf: &Certificate,
    certificates: &[Certificate],
    at: Option<u64>,
    fingerprints: &mut Vec<String>,
) -> Result<Check> {
    let mut current = leaf;
    for depth in 0..8 {
        let hash = fingerprint(current)?;
        if fingerprints.contains(&hash) {
            return Err(invalid("Certificate chain cycle"));
        }
        fingerprints.push(hash);
        extensions(current)?;
        if validity(current, at).status == Status::Invalid {
            return Err(invalid(
                "Certificate chain contains an out-of-time certificate",
            ));
        }
        if current.tbs_certificate.issuer == current.tbs_certificate.subject {
            verify_link(current, current)?;
            return Ok(check(Status::Valid, "Certificate signatures reach a self-signed certificate. This proves internal consistency only; the root is not trusted and full PKIX/OEM policy is not implemented."));
        }
        let issuers: Vec<_> = certificates
            .iter()
            .filter(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer)
            .collect();
        if issuers.is_empty() {
            return Ok(check(Status::Missing, format!("Issuer certificate is missing: {}. No automatic certificate download is performed.", current.tbs_certificate.issuer)));
        }
        if issuers.len() != 1 {
            return Err(invalid("Certificate chain has ambiguous issuers"));
        }
        let issuer = issuers[0];
        extensions(issuer)?;
        let ca = extension::<BasicConstraints>(issuer, "2.5.29.19")?
            .ok_or_else(|| unsupported("Issuer has no basic-constraints extension"))?;
        if !ca.ca {
            return Err(invalid("Issuer certificate is not a CA"));
        }
        if ca
            .path_len_constraint
            .is_some_and(|limit| depth > usize::from(limit))
        {
            return Err(invalid(
                "Certificate chain exceeds the CA path-length constraint",
            ));
        }
        let usage = extension::<KeyUsage>(issuer, "2.5.29.15")?
            .ok_or_else(|| unsupported("Issuer has no explicit key usage"))?;
        if !usage.key_cert_sign() {
            return Err(invalid("Issuer key usage forbids certificate signing"));
        }
        verify_link(current, issuer)?;
        current = issuer;
    }
    Err(unsupported("Certificate chain exceeds eight certificates"))
}
pub(super) fn assess(
    leaf: &Certificate,
    certificates: &[Certificate],
    at: Option<u64>,
) -> SignerAssessment {
    let mut hashes = Vec::new();
    let chain_check = match chain(leaf, certificates, at, &mut hashes) {
        Ok(check) => check,
        Err(error) => result_check(Err(error), ""),
    };
    let usage = (|| {
        if extension::<BasicConstraints>(leaf, "2.5.29.19")?.is_some_and(|c| c.ca) {
            return Err(invalid(
                "Catalog signer is a CA rather than an end-entity signing certificate",
            ));
        }
        match extension::<KeyUsage>(leaf, "2.5.29.15")? {
            Some(u) if !u.digital_signature() => {
                Err(invalid("Signer key usage forbids digital signatures"))
            }
            Some(_) => Ok(check(
                Status::Valid,
                "Signer key usage permits digital signatures",
            )),
            None => Ok(check(
                Status::Unverified,
                "Signer has no explicit digital-signature key usage",
            )),
        }
    })();
    let eku = match extension::<ExtendedKeyUsage>(leaf, "2.5.29.37") {
        Ok(Some(eku)) if eku.0.contains(&oid("1.3.6.1.5.5.7.3.3")) => check(Status::Valid, "Signer EKU includes code signing. Device-specific OEM policy OIDs have not been validated."),
        Ok(Some(_)) => check(Status::Invalid, "Signer EKU does not permit code signing"),
        Ok(None) => check(Status::Unverified, "Signer has no explicit code-signing EKU"),
        Err(e) => result_check(Err(e), ""),
    };
    SignerAssessment {
        issuer: leaf.tbs_certificate.issuer.to_string(), not_before: leaf.tbs_certificate.validity.not_before.to_string(), not_after: leaf.tbs_certificate.validity.not_after.to_string(), checked_at_unix_seconds: at,
        validity: validity(leaf, at), key_usage: usage.unwrap_or_else(|e| result_check(Err(e), "")), extended_key_usage: eku,
        extensions: result_check(extensions(leaf), "No duplicate or unprocessed critical signer extensions in the supported profile"), chain_signatures: chain_check, chain_certificate_sha256: hashes,
        trust_anchor: check(Status::Unverified, "No independently authenticated OEM trust anchor is configured. An embedded/self-signed root or a matching Nokia subject name is not a trust anchor."),
        revocation: check(Status::Unverified, "No authenticated, current offline revocation evidence is available. No network revocation lookup is performed."),
    }
}
impl SignerAssessment {
    pub fn overall(&self) -> Check {
        if [
            &self.validity,
            &self.key_usage,
            &self.extended_key_usage,
            &self.extensions,
            &self.chain_signatures,
        ]
        .iter()
        .any(|c| c.status == Status::Invalid)
        {
            check(Status::Invalid, "Signer certificate assessment failed. Mathematical catalog signature verification alone cannot override certificate-policy or chain failures.")
        } else {
            check(Status::Unverified, format!("OEM trust is unverified. {} Full OEM policy, device trust binding and revocation remain unvalidated.", self.chain_signatures.message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_authority_identifier_checks_issuer_name_serial_and_key() {
        let root = Certificate::from_der(include_bytes!(
            "../../../../tests/fixtures/image-issuer/root.der"
        ))
        .unwrap();
        verify_link(&root, &root).unwrap();
        let mut wrong = root.clone();
        wrong.tbs_certificate.serial_number =
            x509_cert::serial_number::SerialNumber::new(&[1]).unwrap();
        assert!(verify_link(&root, &wrong)
            .unwrap_err()
            .to_string()
            .contains("serial number mismatch"));
        let mut wrong = root.clone();
        wrong.tbs_certificate.issuer = "CN=Different issuer".parse().unwrap();
        assert!(verify_link(&root, &wrong)
            .unwrap_err()
            .to_string()
            .contains("issuer name mismatch"));
        for names in [
            None,
            Some(vec![]),
            Some(vec![
                GeneralName::DirectoryName(
                    root.tbs_certificate.issuer.clone()
                );
                2
            ]),
        ] {
            let mut child = root.clone();
            let mut aki = extension::<AuthorityKeyIdentifier>(&child, "2.5.29.35")
                .unwrap()
                .unwrap();
            aki.authority_cert_issuer = names;
            let ext = child
                .tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.extn_id == oid("2.5.29.35"))
                .unwrap();
            ext.extn_value = der::asn1::OctetString::new(aki.to_der().unwrap()).unwrap();
            assert!(verify_link(&child, &root).is_err());
        }
    }
}
