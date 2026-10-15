"""Make a synthetic PLAT-version fixture from this project's synthetic FFU.

Sparse mapping semantics follow the attributed reference-ffu-check.py. No phone
or OEM firmware data is used. Recompute GPT CRCs and FFU chunk hashes.
"""
from pathlib import Path
import struct, hashlib, zlib
root=Path(__file__).resolve().parents[1]/'tests'/'fixtures'
b=bytearray((root/'synthetic.ffu').read_bytes())
u32=lambda at:struct.unpack_from('<I',b,at)[0]
chunk=u32(16)*1024
align=lambda n:(n+chunk-1)//chunk*chunk
security=align(u32(0)+u32(24)+u32(28))
store=security+align(u32(security)+u32(security+16))
header=store+align(248+u32(store+212)+u32(store+220))
at=store+248+u32(store+220);payload=0;mapping={}
for _ in range(u32(store+208)):
    locations,blocks=struct.unpack_from('<II',b,at)
    for i in range(locations):
        access,disk=struct.unpack_from('<II',b,at+8+i*8)
        if access==0:
            for k in range(blocks):mapping[disk+k]=payload+k
    payload+=blocks;at+=8+locations*8
def offset(disk):return header+mapping[disk//chunk]*chunk+disk%chunk
def read(disk,n):return bytes(b[offset(disk+i)] for i in range(n))
def write(disk,data):
    for i,v in enumerate(data):b[offset(disk+i)]=v
gpt=bytearray(read(512,512)); table_at=struct.unpack_from('<Q',gpt,72)[0]*512
count,size=struct.unpack_from('<II',gpt,80)
table=bytearray(read(table_at,count*size))
first,last=struct.unpack_from('<QQ',table,32)
assert (last-first+1)*512>=512
table[56:128]='PLAT'.encode('utf-16le')+bytes(72-8)
struct.pack_into('<I',gpt,88,zlib.crc32(table))
struct.pack_into('<I',gpt,16,0)
struct.pack_into('<I',gpt,16,zlib.crc32(gpt[:struct.unpack_from('<I',gpt,12)[0]]))
write(table_at,table);write(512,gpt)
write(first*512,b'SWVERSION=1.2.3.4\r\n')
hashes=b''.join(hashlib.sha256(b[i:i+chunk]).digest() for i in range(security,len(b),chunk))
assert len(hashes)==u32(28)
b[u32(0)+u32(24):u32(0)+u32(24)+len(hashes)]=hashes
(root/'synthetic-plat.ffu').write_bytes(b)
print('Generated synthetic PLAT firmware-version fixture.')
