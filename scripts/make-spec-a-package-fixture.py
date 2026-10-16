"""Non-flashable package fixture: invented layout, existing synthetic boot data.
Run after make-bcd-fixture.py and make-spec-a-offline-fixtures.py.
"""
from pathlib import Path
import struct, zlib, hashlib
root=Path(__file__).resolve().parents[1];fixtures=root/'tests/fixtures'
old=(fixtures/'synthetic-spec-a-offline.ffu').read_bytes()
chunk=4096
security_size=((struct.unpack_from('<I',old,28)[0]+32+chunk-1)//chunk)*chunk
disk=old[security_size+2*chunk:]
fat=bytearray(disk[256*512:(256+8192)*512])
hive=(fixtures/'spec-a/bcd.synthetic.hive').read_bytes()
fat[(95+9)*512:(95+9)*512+len(hive)]=hive
for start in [512,33*512]:
    for i in range(9,41):struct.pack_into('<H',fat,start+i*2,i+1 if i<40 else 0xffff)
struct.pack_into('<I',fat,(95+8)*512+28,len(hive))
payload=bytearray(0x2228*512);entries=bytearray(16384)
specs=[('SBL1',0x100,64,disk[64*512:128*512]),('SBL2',0x140,16,disk[128*512:144*512]),('SBL3',0x150,16,disk[144*512:160*512]),('UEFI',0x160,64,disk[160*512:224*512]),('TZ',0x1a0,16,b'Invented TZ fixture'),('RPM',0x1b0,16,b'Invented RPM fixture'),('WINSECAPP',0x1c0,16,b'Invented WINSECAPP fixture'),('EFIESP',0x200,8192,fat)]
for i,(name,first,count,data) in enumerate(specs):
    at=i*128;entries[at:at+16]=bytes([i+1])*16;entries[at+16:at+32]=bytes([i+17])*16
    struct.pack_into('<QQ',entries,at+32,first,first+count-1);encoded=name.encode('utf-16le');entries[at+56:at+56+len(encoded)]=encoded
    payload[first*512:first*512+len(data)]=data
header=bytearray(disk[512:1024]);struct.pack_into('<QQQQ',header,24,1,len(payload)//512-1,34,len(payload)//512-2)
struct.pack_into('<I',header,88,zlib.crc32(entries));struct.pack_into('<I',header,16,0);struct.pack_into('<I',header,16,zlib.crc32(header[:92]))
payload[512:1024]=header;payload[1024:1024+len(entries)]=entries
image=bytearray(old[security_size:security_size+chunk]);store=bytearray(old[security_size+chunk:security_size+2*chunk]);struct.pack_into('<I',store,252,len(payload)//chunk)
hashed=image+store+payload;table=b''.join(hashlib.sha256(hashed[i:i+chunk]).digest()for i in range(0,len(hashed),chunk))
security=bytearray(((32+len(table)+chunk-1)//chunk)*chunk);security[:32]=old[:32];struct.pack_into('<II',security,24,0,len(table));security[32:32+len(table)]=table
(fixtures/'synthetic-spec-a-package.ffu').write_bytes(security+hashed)
