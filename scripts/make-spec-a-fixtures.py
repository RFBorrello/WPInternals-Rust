"""Deterministic, non-flashable Spec A fixtures using an existing synthetic cert.

No OEM binaries, private keys, executable loaders, or exploit payloads are used.
"""
from pathlib import Path
import hashlib, struct, zlib, json

root = Path(__file__).resolve().parents[1]
fixtures = root / 'tests/fixtures'
out = fixtures / 'spec-a'
out.mkdir(exist_ok=True)
cert = (fixtures / 'image-issuer/root.der').read_bytes()

def mbn(long=False, offset=0, sbl2=False, loader=False):
    code = bytearray(128)
    pattern = bytes.fromhex('112233e3010e42e32800d0e51eff2fe1' if sbl2 else '04009fe52800d0e51eff2fe1')
    code[16:16+len(pattern)] = pattern
    if loader:
        marker = 'QHSUSB_ARMPRG'.encode('utf-16le')
        code[64:64+len(marker)] = marker
    data = bytearray(offset + (80 if long else 40))
    if long:
        data[offset:offset+20] = bytes.fromhex('d1dc4b843410d773ffffffffffffffffffffffff')
    else:
        struct.pack_into('<II', data, offset, 0x18, 3)
    payload_at = len(data)
    struct.pack_into('<8I', data, offset+(20 if long else 8), payload_at, 0x2a000000, len(code)+256+6144, len(code), 0x2a000000+len(code), 256, 0x2a000000+len(code)+256, 6144)
    return data + code + bytes(256) + cert + bytes([255])*(6144-len(cert))

def hex_record(kind, address, data=b''):
    record = bytes([len(data)])+struct.pack('>H',address)+bytes([kind])+data
    return ':'+(record+bytes([-sum(record)&255])).hex().upper()+'\n'

sbl1 = mbn(True,0x2800)
sbl2 = mbn(sbl2=True)
sbl3 = mbn()
loader = mbn(True,loader=True)
(out/'sbl3.bin').write_bytes(sbl3)
(out/'loader.mbn').write_bytes(loader)
text = hex_record(4,0,bytes.fromhex('2a00'))
for at in range(0,len(loader),16): text += hex_record(0,at,loader[at:at+16])
text += hex_record(5,0,bytes.fromhex('2a000000'))+hex_record(1,0)
(out/'loader.hex').write_text(text,encoding='ascii',newline='\n')

chunk=4096
base=(fixtures/'synthetic.ffu').read_bytes()
payload=bytearray(176*512)
entries=bytearray(128*128)
for i,(name,start,count,data) in enumerate([('SBL1',64,64,sbl1),('SBL2',128,16,sbl2),('SBL3',144,16,sbl3)]):
    at=i*128; entries[at:at+16]=bytes([i+1])*16;entries[at+16:at+32]=bytes([i+8])*16
    struct.pack_into('<QQ',entries,at+32,start,start+count-1)
    encoded=name.encode('utf-16le');entries[at+56:at+56+len(encoded)]=encoded
    payload[start*512:start*512+len(data)]=data
header=bytearray(512);header[:8]=b'EFI PART';struct.pack_into('<III',header,8,0x10000,92,0)
struct.pack_into('<QQQQ',header,24,1,175,34,174);header[56:72]=b'\x55'*16
struct.pack_into('<QIII',header,72,2,128,128,zlib.crc32(entries));struct.pack_into('<I',header,16,zlib.crc32(header[:92]))
payload[512:1024]=header;payload[1024:1024+len(entries)]=entries
image,store=bytearray(base[chunk:2*chunk]),bytearray(base[2*chunk:3*chunk])
struct.pack_into('<I',store,252,len(payload)//chunk)
hashed=image+store+payload;table=b''.join(hashlib.sha256(hashed[i:i+chunk]).digest() for i in range(0,len(hashed),chunk))
security=bytearray(chunk);security[:32]=base[:32];struct.pack_into('<II',security,24,0,len(table));security[32:32+len(table)]=table
(fixtures/'synthetic-spec-a.ffu').write_bytes(security+hashed)
(out/'reference.json').write_text(json.dumps({'root_certificate_sha256':hashlib.sha256(cert).hexdigest(),'sbl2_patch_offset':40+16+8,'sbl3_patch_offset':40+16+4,'loader_decoded_sha256':hashlib.sha256(loader).hexdigest(),'phone_writes_enabled':False},indent=2)+'\n')
print('Generated synthetic, non-flashable Spec A fixtures.')
