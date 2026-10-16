"""Independent pinned-source comparison of local SBL1, UEFI and EFIESP checks.
Known valid profiles only. No proprietary output, modified files or device I/O.
"""
import argparse,hashlib,json,lzma,struct,uuid,xml.etree.ElementTree as ET
from pathlib import Path
def sha(b):return hashlib.sha256(b).hexdigest()
def read(path,limit=4*1024*1024):
    if not path.is_file():raise ValueError('Regular input required')
    with path.open('rb')as f:b=f.read(limit+1)
    if len(b)>limit:raise ValueError('Input exceeds bound')
    return b
def u16(b,a):return struct.unpack_from('<H',b,a)[0]
def u32(b,a):return struct.unpack_from('<I',b,a)[0]
def u24(b,a):return int.from_bytes(b[a:a+3],'little')
def matches(b,p,m):
    values=[i for i in range(len(b)-len(p)+1)if all(mask==255 or x==y for x,y,mask in zip(b[i:i+len(p)],p,m))]
    if len(values)!=1:raise ValueError('Reference requires unique pattern')
    return values[0]
def sbl1(b):
    source,address,size,code,*_=struct.unpack_from('<8I',b,0x2800+20);codebytes=b[source:source+code]
    p=bytes.fromhex('15000000000000001b0000000000000005000000010000000100000000000000000000000000000000000000');table=matches(codebytes,p,bytes(len(p)))
    p=bytes.fromhex('04009fe52800d0e51eff2fe100000000');security=matches(codebytes,p,bytes(12)+bytes([255])*4);shared=u32(codebytes,security+12)
    p=bytes.fromhex('0100a0e30000a0e11cd08de2f04fbde81eff2fe1');ret=matches(codebytes,p,bytes([0,255,0,0,255,255]+[0]*14))
    return dict(loader_table_offset=source+table,loader_table_size=80,security_function_offset=source+security,shared_memory_address=shared,security_flag_address=shared+40,return_function_offset=source+ret,return_address=address+ret,payload_generated=False)
def files(b):
    size=struct.unpack_from('<Q',b,32)[0];header=u16(b,48)
    if b[40:44]!=b'_FVH' or sum(struct.unpack('<'+'H'*(header//2),b[:header]))&65535:raise ValueError('Bad FV')
    at=header;out=[]
    while at+24<=size:
        h=b[at:at+24]
        if h==bytes([255])*24:break
        n=u24(h,20)
        if n<24 or at+n>size or (sum(h[:17]+h[18:23])&255):raise ValueError('Bad FFS')
        out.append((h[18],str(uuid.UUID(bytes_le=h[:16])),b[at+24:at+n]));at=(at+n+7)//8*8
    return out
def sections(b):
    at=0;out=[]
    while at<len(b):
        n=u24(b,at)
        if n<4 or at+n>len(b):raise ValueError('Bad section')
        out.append((b[at+3],b[at:at+n]));at=(at+n+3)//4*4
    return out
def uefi(b):
    outer=files(b[40:]);fv_size=struct.unpack_from('<Q',b,72)[0];container=[x for x in outer if x[0]==11][0]
    compressed=[v for t,v in sections(container[2])if t==2][0];compressed=compressed[u16(compressed,20):]
    size=struct.unpack_from('<Q',compressed,5)[0]
    if size>16*1024*1024:raise ValueError('Output too large')
    decoded=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=64*1024*1024).decompress(compressed,max_length=size)
    if len(decoded)!=size:raise ValueError('Short output')
    inner=files([v for t,v in sections(decoded)if t==23][0][4:]);targets=[]
    for name in ['SecurityDxe','SecurityServicesDxe']:
        found=[]
        for kind,guid,data in inner:
            entries=sections(data)if kind!=240 else []
            names=[v[4:].decode('utf-16le').rstrip('\0 ')for t,v in entries if t==21]
            if name not in names:continue
            exe=[v[4:]for t,v in entries if t==16][0];checksum=u32(exe,60)+88
            patches=[dict(label='PE checksum clear',offset=checksum,expected=exe[checksum:checksum+4].hex(),replacement='00000000')]
            definitions=[('SecurityDxe authentication','f0412de90000b0e128d04de20000a0e1000000132000a0e3','00000000ffff000000000000ffff00000000ff0000ff0000',0,'0000a0e31eff2fe1')]if name=='SecurityDxe'else [('SecurityServicesDxe policy 1','100000e5800010e30000000a','00ffff0000ff0000ffffff00',11,'ea'),('SecurityServicesDxe policy 2','110000e5400010e30000000a','00ffff0000ff0000ffffff00',11,'ea')]
            for label,p,m,skip,new in definitions:
                at=matches(exe,bytes.fromhex(p),bytes.fromhex(m))+skip;patches.append(dict(label=label,offset=at,expected=exe[at:at+len(new)//2].hex(),replacement=new))
            found.append(dict(name=name,guid=guid,size=len(exe),sha256=sha(exe),pe_checksum_offset=checksum,patches=patches))
        if len(found)!=1:raise ValueError('Ambiguous target')
        targets+=found
    return dict(partition_sha256=sha(b),outer_volume_size=fv_size,compressed_size=len(compressed),decompressed_size=len(decoded),decompressed_sha256=sha(decoded),file_count=len(inner),targets=targets,rebuilt_image=False)
def efiesp(b):
    digest=hashlib.sha1(b).hexdigest().upper();definition=ET.parse(Path(__file__).resolve().parents[1]/'resources/upstream/PatchDefinitions.xml').find(".//PatchDefinition[@Name='SecureBootHack-V1.1-EFIESP']")
    matches=[v for v in definition.findall('TargetVersions/TargetVersion')if v.find('TargetFiles/TargetFile').get('HashOriginal')==digest]
    patched=None
    if matches:
        target=matches[0].find('TargetFiles/TargetFile');patched=bytearray(b)
        for p in target.findall('Patches/Patch'):
            at=int(p.get('Address'),0);old=bytes.fromhex(p.get('OriginalBytes'));new=bytes.fromhex(p.get('PatchedBytes'))
            if patched[at:at+len(old)]!=old:raise ValueError('Expected bytes mismatch')
            patched[at:at+len(old)]=new
        if hashlib.sha1(patched).hexdigest().upper()!=target.get('HashPatched'):raise ValueError('Patched hash mismatch')
    return dict(path='Windows/System32/Boot/mobilestartup.efi',size=len(b),sha256=sha(b),sha1=digest,status='original_supported'if matches else'unsupported_donor_required',catalog_target_descriptions=[v.get('Description')for v in matches],prepared_copy_sha256=sha(patched)if patched is not None else None)
def main():
    p=argparse.ArgumentParser()
    for name in ['sbl1','uefi','stock-boot','donor-boot','rust-report']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();rust=json.loads(read(a.rust_report));result=dict(sbl1_prerequisites=sbl1(read(a.sbl1)),uefi=uefi(read(a.uefi)),efiesp=efiesp(read(a.stock_boot)),donor_efiesp=efiesp(read(a.donor_boot)))
    for key,value in result.items():
        for field,item in value.items():
            if rust[key][field]!=item:raise ValueError('Reference mismatch: '+key+'.'+field)
    print(json.dumps(dict(comparison='matches',**result),indent=2))
if __name__=='__main__':main()
