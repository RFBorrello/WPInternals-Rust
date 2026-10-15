"""Generate synthetic public CMS/PKCS#7 fixtures; no OEM bytes or private keys saved.

Requires cryptography. Fixtures are stable test inputs once committed; regenerating
intentionally creates a new test key. The embedded self-signed cert is NOT trusted.
DER, PKCS#7 sequence hashing, and CMS octet hashing follow RFC 5652 5.2.1/5.4.
"""
from pathlib import Path
import datetime, hashlib, struct
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
OUT = ROOT / 'catalog'
OUT.mkdir(exist_ok=True)
def tlv(tag, value):
    n=len(value)
    length=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([tag])+length+value
def seq(*v): return tlv(0x30,b''.join(v))
def setof(*v): return tlv(0x31,b''.join(sorted(v)))
def oid(s):
    parts=list(map(int,s.split('.'))); out=bytearray([parts[0]*40+parts[1]])
    for n in parts[2:]:
        encoded=[n&127]; n>>=7
        while n: encoded.insert(0,128|(n&127)); n>>=7
        out.extend(encoded)
    return tlv(6,bytes(out))
def integer(n):
    b=n.to_bytes(max(1,(n.bit_length()+7)//8),'big')
    return tlv(2,(b'\0' if b[0]&128 else b'')+b)
def octets(v): return tlv(4,v)
def alg(o): return seq(oid(o),tlv(5,b''))
def attr(o,v): return seq(oid(o),setof(v))
SHA256='2.16.840.1.101.3.4.2.1'; SHA1='1.3.14.3.2.26'; CTL='1.3.6.1.4.1.311.10.1'
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'WPI synthetic fixture — untrusted')])
cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(17)
      .not_valid_before(datetime.datetime(2020,1,1,tzinfo=datetime.timezone.utc))
      .not_valid_after(datetime.datetime(2030,1,1,tzinfo=datetime.timezone.utc))
      .sign(key,hashes.SHA256()))
def catalog(table, cms=False, member_algo=SHA1, duplicate_md=False, member='HashTable.blob'):
    digest=hashlib.sha1(table).digest() if member_algo==SHA1 else hashlib.sha256(table).digest()
    indirect=seq(seq(oid('1.3.6.1.4.1.311.2.1.25'),tlv(0xa2,tlv(0x80,b''))),seq(alg(member_algo),octets(digest)))
    entries=seq(seq(octets((member+'\0').encode('utf-16le')),setof(attr('1.3.6.1.4.1.311.2.1.4',indirect))))
    body=seq(oid('1.3.6.1.4.1.311.12.1.1'))+octets(bytes(16))+tlv(0x17,b'240101000000Z')+alg('1.3.6.1.4.1.311.12.1.2')+entries
    content=seq(body)
    md=attr('1.2.840.113549.1.9.4',octets(hashlib.sha256(content if cms else body).digest()))
    attrs=[attr('1.2.840.113549.1.9.3',oid(CTL)),md]
    if duplicate_md: attrs.append(md)
    encoded_attrs=setof(*attrs)
    signature=key.sign(encoded_attrs,padding.PKCS1v15(),hashes.SHA256())
    signer=seq(integer(1),seq(name.public_bytes(),integer(cert.serial_number)),alg(SHA256),tlv(0xa0,b''.join(sorted(attrs))),alg('1.2.840.113549.1.1.1'),octets(signature))
    data=seq(integer(1),setof(alg(SHA256)),seq(oid(CTL),tlv(0xa0,octets(content) if cms else content)),tlv(0xa0,cert.public_bytes(serialization.Encoding.DER)),setof(signer))
    return seq(oid('1.2.840.113549.1.7.2'),tlv(0xa0,data))
table=bytes(range(256))
(OUT/'hash-table.bin').write_bytes(table)
for filename,kwargs in [('pkcs7-sha1.der',{}),('cms-sha256.der',{'cms':True,'member_algo':SHA256}),('duplicate-digest.der',{'duplicate_md':True}),('wrong-member.der',{'member':'unrelated.bin'})]:
    (OUT/filename).write_bytes(catalog(table,**kwargs))
ffu=bytearray((ROOT/'synthetic.ffu').read_bytes())
header,chunk,catsize,tablesize=struct.unpack_from('<I',ffu,0)[0],struct.unpack_from('<I',ffu,16)[0]*1024,struct.unpack_from('<I',ffu,24)[0],struct.unpack_from('<I',ffu,28)[0]
original_table=bytes(ffu[header+catsize:header+catsize+tablesize])
signed=catalog(original_table)
old_security=((header+catsize+tablesize+chunk-1)//chunk)*chunk
assert header+len(signed)+tablesize<=old_security
struct.pack_into('<I',ffu,24,len(signed))
ffu[header:old_security]=signed+original_table+bytes(old_security-header-len(signed)-tablesize)
(ROOT/'synthetic-signed.ffu').write_bytes(ffu)
print('Generated synthetic fixtures; private key discarded.')
