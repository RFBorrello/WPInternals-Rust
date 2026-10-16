"""Synthetic FV/FFS/LZMA and SBL1 prerequisites. Never flashable firmware."""
from pathlib import Path
import struct,uuid,lzma,hashlib,json,zlib
out=Path(__file__).resolve().parents[1]/'tests/fixtures/spec-a'
cert=(out.parent/'image-issuer/root.der').read_bytes()
def aligned(b,n,pad=0):return b+bytes([pad])*((-len(b))%n)
def section(kind,data):return (len(data)+4).to_bytes(3,'little')+bytes([kind])+data
def ffs(kind,data,index):
    h=bytearray(24);h[:16]=uuid.UUID(int=index).bytes_le;h[17]=0xaa;h[18]=kind;h[20:23]=(24+len(data)).to_bytes(3,'little');h[23]=0xf8
    h[16]=(-sum(h[:17]+h[18:23]))&255
    return bytes(h)+data
def volume(files):
    body=b''.join(aligned(f,8,255) for f in files);size=(72+len(body)+4095)//4096*4096
    h=bytearray(72);h[16:32]=uuid.UUID('8c8ce578-8a3d-4f1c-9935-896185c32dd3').bytes_le
    struct.pack_into('<Q',h,32,size);h[40:44]=b'_FVH';struct.pack_into('<I',h,44,0x800);struct.pack_into('<H',h,48,72);h[55]=2
    struct.pack_into('<II',h,56,1,size);struct.pack_into('<H',h,50,(-sum(struct.unpack('<36H',h)))&65535)
    return bytes(h)+body+bytes([255])*(size-72-len(body))
def executable(name):
    b=bytearray(1024);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0';struct.pack_into('<HH',b,132,0x1c2,1);struct.pack_into('<H',b,148,224);struct.pack_into('<H',b,152,0x10b)
    at=128+24+224;b[at:at+8]=b'.text\0\0\0';struct.pack_into('<II',b,at+16,512,512);struct.pack_into('<I',b,at+36,0x60000020)
    if name=='SecurityDxe':b[576:600]=bytes.fromhex('f0412de90250b0e128d04de20000a0e1000000132000a0e3')
    else:
        b[576:588]=bytes.fromhex('100000e5800010e30000000a');b[640:652]=bytes.fromhex('110000e5400010e30000000a')
    return bytes(b)
targets=[];reference=[]
for i,name in enumerate(['SecurityDxe','SecurityServicesDxe']):
    exe=executable(name);(out/(name+'.synthetic.efi')).write_bytes(exe)
    data=aligned(section(0x10,exe),4)+section(0x15,(name+'\0').encode('utf-16le'))
    targets.append(ffs(7,data,i+1));reference.append({'name':name,'sha256':hashlib.sha256(exe).hexdigest(),'code_patch_offsets':[576] if i==0 else [587,651]})
decompressed=section(0x17,volume(targets))
compressed=lzma.compress(decompressed,format=lzma.FORMAT_ALONE,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':1024*1024,'lc':3,'lp':0,'pb':2}])
compressed=compressed[:5]+struct.pack('<Q',len(decompressed))+compressed[13:]
guid=uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le
fv=volume([ffs(11,section(2,guid+struct.pack('<HH',24,1)+compressed),3)])
def mbn(code,offset=0,long=False):
    h=bytearray(offset+(80 if long else 40));at=offset+(20 if long else 8)
    if long:h[offset:offset+20]=bytes.fromhex('d1dc4b843410d773ffffffffffffffffffffffff')
    else:struct.pack_into('<II',h,offset,5,3)
    struct.pack_into('<8I',h,at,len(h),0x2a000000,len(code)+256+6144,len(code),0x2a000000+len(code),256,0x2a000000+len(code)+256,6144)
    return bytes(h)+code+bytes(256)+cert+bytes([255])*(6144-len(cert))
(out/'uefi.synthetic.bin').write_bytes(mbn(fv));(out/'uefi.decompressed.bin').write_bytes(decompressed)
code=bytearray(512);code[16:32]=bytes.fromhex('04009fe52800d0e51eff2fe10010002a');code[64:84]=bytes.fromhex('0100a0e30000a0e11cd08de2f04fbde81eff2fe1')
table=bytes.fromhex('15000000000000001b0000000000000005000000010000000100000000000000000000000000000000000000');code[128:128+len(table)]=table
(out/'sbl1.synthetic.bin').write_bytes(mbn(bytes(code),0x2800,True))
(out/'offline-reference.json').write_text(json.dumps({'decompressed_sha256':hashlib.sha256(decompressed).hexdigest(),'targets':reference,'sbl1_loader_table_offset':0x2800+80+128,'sbl1_security_flag_address':0x2a001028,'sbl1_return_address':0x2a000040},indent=2)+'\n')

def fat():
    disk=bytearray(4*1024*1024);disk[:3]=b'\xeb\x3c\x90';disk[3:11]=b'WPI TEST'
    struct.pack_into('<HBHBHHBHHHII',disk,11,512,1,1,2,512,8192,0xf8,32,32,64,0,0)
    disk[36:39]=b'\x80\0\x29';disk[43:54]=b'SYNTHETIC  ';disk[54:62]=b'FAT16   ';disk[510:512]=b'\x55\xaa'
    table=bytearray(32*512);struct.pack_into('<HH',table,0,0xfff8,0xffff)
    for n in range(2,10):struct.pack_into('<H',table,n*2,0xffff)
    disk[512:33*512]=table;disk[33*512:65*512]=table
    def entry(name,cluster,size=0,directory=True):
        e=bytearray(32);e[:11]=name;e[11]=16 if directory else 32;struct.pack_into('<H',e,26,cluster);struct.pack_into('<I',e,28,size);return e
    def cluster(n,data):disk[(95+n)*512:(95+n)*512+len(data)]=data
    disk[65*512:65*512+64]=entry(b'WINDOWS    ',2)+entry(b'EFI        ',6)
    cluster(2,entry(b'SYSTEM32   ',3));cluster(3,entry(b'BOOT       ',4))
    short=b'MOBILE~1EFI';checksum=0
    for b in short:checksum=(((checksum&1)<<7)+(checksum>>1)+b)&255
    name='mobilestartup.efi'.encode('utf-16le')+bytes(2);name+=bytes([255])*((-len(name))%26);lfn=[]
    for n in range(len(name)//26,0,-1):
        e=bytearray(32);e[0]=n|(64 if n==len(name)//26 else 0);e[11]=15;e[13]=checksum;t=name[(n-1)*26:n*26];e[1:11]=t[:10];e[14:26]=t[10:22];e[28:32]=t[22:];lfn.append(e)
    boot=b'Synthetic unsupported boot bytes';cluster(4,b''.join(lfn)+entry(short,5,len(boot),False));cluster(5,boot)
    short=b'MICROS~1   ';checksum=0
    for b in short:checksum=(((checksum&1)<<7)+(checksum>>1)+b)&255
    name='Microsoft'.encode('utf-16le')+bytes(2);name+=bytes([255])*((-len(name))%26);lfn=[]
    for n in range(len(name)//26,0,-1):
        e=bytearray(32);e[0]=n|(64 if n==len(name)//26 else 0);e[11]=15;e[13]=checksum;t=name[(n-1)*26:n*26];e[1:11]=t[:10];e[14:26]=t[10:22];e[28:32]=t[22:];lfn.append(e)
    cluster(6,b''.join(lfn)+entry(short,7));cluster(7,entry(b'BOOT       ',8));cluster(8,entry(b'BCD        ',9,4,False));cluster(9,b'test')
    return disk
chunk=4096;base=(out.parent/'synthetic.ffu').read_bytes();old=(out.parent/'synthetic-spec-a.ffu').read_bytes()[3*chunk:]
payload=bytearray((256+8192+8)*512);payload[:len(old)]=old;payload[64*512:64*512+len(mbn(bytes(code),0x2800,True))]=mbn(bytes(code),0x2800,True)
payload[160*512:160*512+len(mbn(fv))]=mbn(fv);payload[256*512:(256+8192)*512]=fat()
entries=payload[1024:1024+128*128]
for i,(name,first,count)in enumerate([('UEFI',160,64),('EFIESP',256,8192)],3):
    at=i*128;entries[at:at+16]=bytes([i+1])*16;entries[at+16:at+32]=bytes([i+8])*16;struct.pack_into('<QQ',entries,at+32,first,first+count-1);encoded=name.encode('utf-16le');entries[at+56:at+56+len(encoded)]=encoded
payload[1024:1024+len(entries)]=entries;header=bytearray(payload[512:1024]);struct.pack_into('<Q',header,32,len(payload)//512-1);struct.pack_into('<Q',header,48,len(payload)//512-2);struct.pack_into('<I',header,88,zlib.crc32(entries));struct.pack_into('<I',header,16,0);struct.pack_into('<I',header,16,zlib.crc32(header[:92]));payload[512:1024]=header
image,store=bytearray(base[chunk:2*chunk]),bytearray(base[2*chunk:3*chunk]);struct.pack_into('<I',store,252,len(payload)//chunk)
hashed=image+store+payload;table=b''.join(hashlib.sha256(hashed[i:i+chunk]).digest()for i in range(0,len(hashed),chunk))
security=bytearray((32+len(table)+chunk-1)//chunk*chunk);security[:32]=base[:32];struct.pack_into('<II',security,24,0,len(table));security[32:32+len(table)]=table
(out.parent/'synthetic-spec-a-offline.ffu').write_bytes(security+hashed)
print('Generated synthetic SBL1 and compressed UEFI fixtures; signatures are zero-filled.')
