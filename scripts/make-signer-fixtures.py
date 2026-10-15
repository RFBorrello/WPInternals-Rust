"""Generate disposable synthetic CMS certificate-policy fixtures, never OEM data.

Requires cryptography; no private keys are saved. Regeneration changes these
public fixtures. DER helpers follow make-catalog-fixtures.py / RFC 5652.
"""
from pathlib import Path
import datetime, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier

out = Path(__file__).resolve().parents[1] / 'tests/fixtures/signer-policy'
out.mkdir(exist_ok=True)
from synthetic_der import tlv, seq, setof, oid, integer, octets, alg, attr

def key(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def name(value): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
def date(year): return datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc)
root_key, issuer_key, signer_key = key(), key(), key()
root_name, issuer_name, signer_name = [name('WPI synthetic ' + n) for n in ('root UNTRUSTED', 'issuer', 'catalog signer')]
def cert(subject, public_key, issuer, private_key, serial, ca=False, digital=True, eku=None, extra=None, expired=False, path=None):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key.public_key()).serial_number(serial)
        .not_valid_before(date(2010 if expired else 2020)).not_valid_after(date(2011 if expired else 2040))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path), True)
        .add_extension(x509.KeyUsage(digital, False, not digital, False, False, ca, ca, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), False))
    if eku is not None: builder = builder.add_extension(x509.ExtendedKeyUsage([eku]), False)
    if extra is not None: builder = builder.add_extension(extra, True)
    return builder.sign(private_key, hashes.SHA256())
root = cert(root_name, root_key, root_name, root_key, 1, ca=True, path=1)
issuer = cert(issuer_name, issuer_key, root_name, root_key, 2, ca=True, path=0)
def leaf(**kwargs): return cert(signer_name, signer_key, issuer_name, issuer_key, 3, eku=kwargs.pop('eku', ExtendedKeyUsageOID.CODE_SIGNING), **kwargs)
table = bytes(range(256)); SHA256 = '2.16.840.1.101.3.4.2.1'; CTL = '1.3.6.1.4.1.311.10.1'
def cms(signer, pool, membership_table=table):
    indirect = seq(seq(oid('1.3.6.1.4.1.311.2.1.25'),tlv(0xa2,tlv(0x80,b''))),seq(alg(SHA256),octets(hashlib.sha256(membership_table).digest())))
    entries = seq(seq(octets('HashTable.blob\0'.encode('utf-16le')), setof(attr('1.3.6.1.4.1.311.2.1.4', indirect))))
    content = seq(seq(oid('1.3.6.1.4.1.311.12.1.1')) + octets(bytes(16)) + tlv(0x17,b'260101000000Z') + alg('1.3.6.1.4.1.311.12.1.2') + entries)
    attrs = [attr('1.2.840.113549.1.9.3',oid(CTL)),attr('1.2.840.113549.1.9.4',octets(hashlib.sha256(content).digest()))]
    signature = signer_key.sign(setof(*attrs), padding.PKCS1v15(), hashes.SHA256())
    info = seq(integer(1),seq(issuer_name.public_bytes(),integer(signer.serial_number)),alg(SHA256),tlv(0xa0,b''.join(sorted(attrs))),alg('1.2.840.113549.1.1.1'),octets(signature))
    encoded = [c if isinstance(c,bytes) else c.public_bytes(serialization.Encoding.DER) for c in pool]
    return seq(oid('1.2.840.113549.1.7.2'),tlv(0xa0,seq(integer(1),setof(alg(SHA256)),seq(oid(CTL),tlv(0xa0,octets(content))),tlv(0xa0,b''.join(sorted(encoded))),setof(info))))
good = leaf()
bad_signature = bytearray(issuer.public_bytes(serialization.Encoding.DER)); bad_signature[-1] ^= 1
ambiguous = cert(issuer_name, key(), root_name, root_key, 5, ca=True)
non_ca = cert(issuer_name, issuer_key, root_name, root_key, 6)
for filename, signer, pool in [
    ('chain', good, [good, issuer, root]),
    ('missing-issuer', good, [good]),
    ('ambiguous-issuer', good, [good, issuer, ambiguous, root]),
    ('bad-chain-signature', good, [good, bytes(bad_signature), root]),
    ('non-ca-issuer', good, [good, non_ca, root]),
    ('wrong-key-usage', leaf(digital=False), None),
    ('wrong-eku', leaf(eku=ExtendedKeyUsageOID.SERVER_AUTH), None),
    ('expired', leaf(expired=True), None),
    ('unknown-critical', leaf(extra=x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'\x05\x00')), None),
]:
    (out/(filename+'.der')).write_bytes(cms(signer, pool or [signer,issuer,root]))
import struct
base = bytearray((out.parent/'synthetic.ffu').read_bytes())
header, chunk, size = struct.unpack_from('<I',base,0)[0], struct.unpack_from('<I',base,16)[0]*1024, struct.unpack_from('<I',base,28)[0]
hash_table_bytes = bytes(base[header:header+size])
for filename, signer in [('synthetic-chain.ffu',good),('synthetic-bad-signer.ffu',leaf(eku=ExtendedKeyUsageOID.SERVER_AUTH))]:
    catalog = cms(signer,[signer,issuer,root],hash_table_bytes)
    assert header + len(catalog) + size <= chunk
    ffu = base.copy()
    struct.pack_into('<I',ffu,24,len(catalog))
    ffu[header:chunk] = catalog + hash_table_bytes + bytes(chunk-header-len(catalog)-size)
    (out.parent/filename).write_bytes(ffu)
print('Generated synthetic certificate-chain/policy fixtures; private keys discarded.')
