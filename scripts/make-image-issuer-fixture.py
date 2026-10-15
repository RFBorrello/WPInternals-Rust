"""Disposable catalog + FAT/FFU PK provisioning fixtures; no OEM data/keys.

The root uses the complete authority directoryName/serial form found in the local
image. A second same-name root has the wrong key. Private keys are discarded.
"""
from pathlib import Path
import datetime, hashlib, struct, uuid, zlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from synthetic_der import tlv, seq, setof, oid, integer, octets, alg, attr

out = Path(__file__).resolve().parents[1] / 'tests/fixtures'
folder = out / 'image-issuer'
folder.mkdir(exist_ok=True)
SHA256 = '2.16.840.1.101.3.4.2.1'
CTL = '1.3.6.1.4.1.311.10.1'
pk_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'WPI synthetic PK UNTRUSTED')])
leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'WPI synthetic catalog signer')])
key, wrong_key, leaf_key = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]

def cert(subject, public_key, issuer_key, serial, ca):
    ski = x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key())
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(pk_name)
        .public_key(public_key.public_key()).serial_number(serial)
        .not_valid_before(datetime.datetime(2020,1,1,tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040,1,1,tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=ca,path_length=None),True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,ca,ca,None,None),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key.public_key()),False)
        .add_extension(x509.AuthorityKeyIdentifier(ski.digest,[x509.DirectoryName(pk_name)],666),False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),False)
        .sign(issuer_key,hashes.SHA256()))

root, wrong, leaf = cert(pk_name,key,key,666,True),cert(pk_name,wrong_key,wrong_key,666,True),cert(leaf_name,leaf_key,key,777,False)
def der(c): return c.public_bytes(serialization.Encoding.DER)
def pk_file(c):
    # Structural auth wrapper with a CMS ContentInfo, not a valid variable update.
    auth = seq(oid('1.2.840.113549.1.7.2'),tlv(0xa0,seq(integer(1),setof(),seq(oid('1.2.840.113549.1.7.1')),setof())))
    header = bytes(16)+struct.pack('<IHH',24+len(auth),0x200,0xef1)+uuid.UUID('4aafd29d-68df-49ee-8aa9-347d375665a7').bytes_le+auth
    entry = bytes(16)+der(c)
    return header+uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le+struct.pack('<III',28+len(entry),0,len(entry))+entry
for name,c in [('production',root),('wrong-key',wrong)]:
    (folder/(name+'.bin')).write_bytes(pk_file(c))
(folder/'root.der').write_bytes(der(root))

def catalog(table):
    indirect = seq(seq(oid('1.3.6.1.4.1.311.2.1.25'),tlv(0xa2,tlv(0x80,b''))),seq(alg(SHA256),octets(hashlib.sha256(table).digest())))
    entries = seq(seq(octets('HashTable.blob\0'.encode('utf-16le')),setof(attr('1.3.6.1.4.1.311.2.1.4',indirect))))
    content = seq(seq(oid('1.3.6.1.4.1.311.12.1.1'))+octets(bytes(16))+tlv(0x17,b'260101000000Z')+alg('1.3.6.1.4.1.311.12.1.2')+entries)
    attrs=[attr('1.2.840.113549.1.9.3',oid(CTL)),attr('1.2.840.113549.1.9.4',octets(hashlib.sha256(content).digest()))]
    sig=leaf_key.sign(setof(*attrs),padding.PKCS1v15(),hashes.SHA256())
    signer=seq(integer(1),seq(pk_name.public_bytes(),integer(leaf.serial_number)),alg(SHA256),tlv(0xa0,b''.join(sorted(attrs))),alg('1.2.840.113549.1.1.1'),octets(sig))
    return seq(oid('1.2.840.113549.1.7.2'),tlv(0xa0,seq(integer(1),setof(alg(SHA256)),seq(oid(CTL),tlv(0xa0,octets(content))),tlv(0xa0,der(leaf)),setof(signer))))
(folder/'catalog.der').write_bytes(catalog(bytes(range(256))))

def fat(pk):
    disk=bytearray(4*1024*1024)
    disk[:3]=b'\xeb\x3c\x90';disk[3:11]=b'WPI TEST'
    struct.pack_into('<HBHBHHBHHHII',disk,11,512,1,1,2,512,8192,0xf8,32,32,64,0,0)
    disk[36:39]=b'\x80\x00\x29';disk[43:54]=b'SYNTHETIC  ';disk[54:62]=b'FAT16   ';disk[510:512]=b'\x55\xaa'
    table=bytearray(32*512);struct.pack_into('<HHHH',table,0,0xfff8,0xffff,0xffff,0xffff)
    count=(len(pk)+511)//512
    for i in range(count):struct.pack_into('<H',table,(4+i)*2,5+i if i+1<count else 0xffff)
    disk[512:33*512]=table;disk[33*512:65*512]=table
    def entry(name,cluster,size,directory=False):
        e=bytearray(32);e[:11]=name;e[11]=0x10 if directory else 0x20
        struct.pack_into('<H',e,26,cluster);struct.pack_into('<I',e,28,size);return e
    disk[65*512:65*512+32]=entry(b'NOKIA      ',2,0,True)
    disk[97*512:97*512+32]=entry(b'SECURITY   ',3,0,True)
    short=b'NOKIA_~1BIN';checksum=0
    for b in short:checksum=(((checksum&1)<<7)+(checksum>>1)+b)&255
    text=list('Nokia_Production_PK.bin'.encode('utf-16le'))+[0,0]
    text+= [255]*((-len(text))%26)
    long=[]
    for n in range(len(text)//26,0,-1):
        e=bytearray(32);e[0]=n|(0x40 if n==len(text)//26 else 0);e[11]=0xf;e[13]=checksum
        t=bytes(text[(n-1)*26:n*26]);e[1:11]=t[:10];e[14:26]=t[10:22];e[28:32]=t[22:26];long.append(e)
    directory=b''.join(long)+entry(short,4,len(pk))
    disk[98*512:98*512+len(directory)]=directory
    disk[99*512:99*512+len(pk)]=pk
    return disk

base=(out/'synthetic.ffu').read_bytes();chunk=4096
for name,c in [('synthetic-image-issuer.ffu',root),('synthetic-wrong-issuer.ffu',wrong)]:
    payload=bytearray(128*chunk)+fat(pk_file(c))+bytearray(chunk);entries=bytearray(128*128)
    entries[:16]=bytes.fromhex('28732AC11FF8D211BA4B00A0C93EC93B');entries[16:32]=bytes([1])*16
    struct.pack_into('<QQ',entries,32,128*chunk//512,len(payload)//512-2);entries[56:68]='EFIESP'.encode('utf-16le')
    header=bytearray(512);header[:8]=b'EFI PART';struct.pack_into('<III',header,8,0x10000,92,0)
    struct.pack_into('<QQQQ',header,24,1,len(payload)//512-1,34,len(payload)//512-2);header[56:72]=b'\x55'*16
    struct.pack_into('<QIII',header,72,2,128,128,zlib.crc32(entries));struct.pack_into('<I',header,16,zlib.crc32(header[:92]))
    payload[512:1024]=header;payload[1024:1024+len(entries)]=entries
    image,store=bytearray(base[chunk:2*chunk]),bytearray(base[2*chunk:3*chunk]);struct.pack_into('<I',store,252,len(payload)//chunk);struct.pack_into('<I',store,260,0)
    hashed=image+store+payload;table=b''.join(hashlib.sha256(hashed[i:i+chunk]).digest() for i in range(0,len(hashed),chunk))
    cat=catalog(table);security=bytearray((32+len(cat)+len(table)+chunk-1)//chunk*chunk);security[:32]=base[:32]
    struct.pack_into('<II',security,24,len(cat),len(table));security[32:32+len(cat)]=cat;security[32+len(cat):32+len(cat)+len(table)]=table
    (out/name).write_bytes(security+hashed)
print('Generated image-local issuer fixtures; all keys synthetic and discarded.')
