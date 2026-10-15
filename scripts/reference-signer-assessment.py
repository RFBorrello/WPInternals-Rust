"""Independent offline cryptography check of a supplied catalog's certificates.

Usage: python scripts/reference-signer-assessment.py catalog.der
This records certificate facts/signature links, not OEM trust. No network or keys.
"""
import argparse, datetime, hashlib, json, warnings
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID
from cryptography.x509 import ExtensionNotFound
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('catalog')
args = parser.parse_args()
with open(args.catalog, 'rb') as stream:
    data = stream.read(1048577)
if len(data) > 1048576:
    raise ValueError('catalog exceeds 1 MiB')
with warnings.catch_warnings():
    warnings.simplefilter('ignore', UserWarning)  # Legacy PKCS#7 CTL sequence wrapper.
    certificates = load_der_pkcs7_certificates(data)
if not 1 <= len(certificates) <= 16:
    raise ValueError('unsupported certificate count')
if len(certificates) == 1:
    signer = certificates[0]
else:
    # Multi-cert reference fixtures deliberately identify their signer this way.
    candidates = [c for c in certificates if any(a.value == 'WPI synthetic catalog signer' for a in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME))]
    if len(candidates) != 1:
        raise ValueError('reference requires a unique synthetic signer or a single-cert real catalog')
    signer = candidates[0]
def extension(cert, oid):
    try: return cert.extensions.get_extension_for_oid(oid).value
    except ExtensionNotFound: return None
def fingerprint(c): return hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()
links, seen, chain_state = [], set(), 'unsupported'
current = signer
for _ in range(8):
    identity = fingerprint(current)
    if identity in seen:
        chain_state = 'cycle'; break
    seen.add(identity)
    issuers = [c for c in certificates if c.subject == current.issuer]
    if not issuers:
        chain_state = 'missing_issuer'; break
    if len(issuers) != 1:
        chain_state = 'ambiguous_issuer'; break
    issuer = issuers[0]
    try: current.verify_directly_issued_by(issuer)
    except Exception:
        chain_state = 'invalid_signature'; break
    links.append({'child_sha256':identity, 'issuer_sha256':fingerprint(issuer)})
    if current.subject == current.issuer:
        chain_state = 'internally_consistent'; break
    current = issuer
usage = extension(signer, ExtensionOID.KEY_USAGE)
eku = extension(signer, ExtensionOID.EXTENDED_KEY_USAGE)
print(json.dumps({
    'certificate_count':len(certificates), 'signer_sha256':fingerprint(signer),
    'subject':signer.subject.rfc4514_string(), 'issuer':signer.issuer.rfc4514_string(),
    'not_before':signer.not_valid_before_utc.isoformat(), 'not_after':signer.not_valid_after_utc.isoformat(),
    'digital_signature_usage':None if usage is None else usage.digital_signature,
    'code_signing_eku':None if eku is None else ExtendedKeyUsageOID.CODE_SIGNING in eku,
    'certificate_signature_links':links,'chain_state':chain_state,
    'oem_trust_established':False,'revocation_checked':False,
},indent=2))
