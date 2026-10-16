"""Independent valid-profile offline package comparison, WPInternals 2.9.2.
FFU.cs/GPT.cs/SBL1.cs/SBL2.cs/SBL3.cs: Rene Lergner (2018), MIT.
Reads only regular local files/ZIP members. Never extracts or contacts a phone.
"""
import argparse, hashlib, importlib.util, json, struct, uuid, zipfile, zlib
from pathlib import Path

def module(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
ref=module('reference-spec-a-offline');assembly=module('reference-spec-a-assembly')
u32,u16,sha=ref.u32,ref.u16,ref.sha

class Ffu:
    def __init__(self,path):
        self.file=path.open('rb');f=self.file;s=f.read(32);assert s[4:16]==b'SignedImage '
        self.chunk=u32(s,16)*1024;align=lambda n:(n+self.chunk-1)//self.chunk*self.chunk
        security=align(u32(s,0)+u32(s,24)+u32(s,28));f.seek(security);image=f.read(24)
        store_at=security+align(u32(image,0)+u32(image,16));f.seek(store_at);store=f.read(248)
        count,length,_,validation=struct.unpack_from('<IIII',store,208)
        assert length<=32*1024*1024
        self.header=store_at+align(248+length+validation);f.seek(store_at+248+validation);descriptors=f.read(length)
        self.index={};at=payload=0
        for _ in range(count):
            locations,blocks=struct.unpack_from('<II',descriptors,at)
            for i in range(locations):
                access,chunk=struct.unpack_from('<II',descriptors,at+8+i*8)
                if access==0:
                    for n in range(blocks): self.index[chunk+n]=payload+n
            at+=8+locations*8;payload+=blocks
        assert at==length and len(self.index)<=262144
    def read(self,start,size):
        result=bytearray()
        while size:
            block,within=divmod(start,self.chunk);n=min(size,self.chunk-within)
            if block in self.index:
                self.file.seek(self.header+self.index[block]*self.chunk+within);b=self.file.read(n);assert len(b)==n
            else:b=bytes(n)
            result.extend(b);start+=n;size-=n
        return result

def gpt_entries(primary):
    header=primary[512:1024];assert header[:8]==b'EFI PART'
    checked=bytearray(header[:u32(header,12)]);checked[16:20]=bytes(4)
    assert zlib.crc32(checked)==u32(header,16) and zlib.crc32(primary[1024:])==u32(header,88)
    entries=[]
    for at in range(1024,len(primary),128):
        b=bytearray(primary[at:at+128])
        if any(b[:16]): entries.append((b[56:128].decode('utf-16le').rstrip('\0'),b))
    return entries

def expected_gpt(original,external):
    entries=gpt_entries(original);by_name=dict(entries);swapped=[]
    for name in ['SBL1','SBL2','SBL3','UEFI','TZ','RPM','WINSECAPP']:
        active=by_name[name];backup=by_name.get('BACKUP_'+name)
        if backup is not None and struct.unpack_from('<Q',active,32)[0]>struct.unpack_from('<Q',backup,32)[0]:
            active[32:48],backup[32:48]=backup[32:48],active[32:48];swapped.append(name)
    first,second=by_name['SBL1'],by_name['SBL2'];last=struct.unpack_from('<Q',first,40)[0]
    hack=bytearray(second);hack[32:48]=struct.pack('<QQ',last,last);hack[56:128]=bytes(72);hack[56:64]='HACK'.encode('utf-16le')
    struct.pack_into('<Q',first,40,last-1);second[:32]=bytes([0x74])*32;entries.append(('HACK',hack))
    if external:
        flag=bytearray(128)
        for at,label in [(0,b'SpecA marker type'),(16,b'SpecA marker id')]:
            raw=bytearray(hashlib.sha256(original+label).digest()[:16]);raw[6]=raw[6]&15|64;raw[8]=raw[8]&63|128;flag[at:at+16]=uuid.UUID(bytes=bytes(raw)).bytes_le
        struct.pack_into('<QQ',flag,32,64,64);name='IS_UNLOCKED_SBL3'.encode('utf-16le');flag[56:56+len(name)]=name;entries.append(('IS_UNLOCKED_SBL3',flag))
    out=bytearray(original);out[1024:]=bytes(len(out)-1024)
    for i,(_,entry) in enumerate(entries):out[1024+i*128:1024+(i+1)*128]=entry
    struct.pack_into('<I',out,600,zlib.crc32(out[1024:]));out[528:532]=bytes(4);struct.pack_into('<I',out,528,zlib.crc32(out[512:604]))
    return out,swapped

def extra_sector(first,second):
    p=ref.sbl1(first)
    template=bytes.fromhex('16000000030000002800000028bd0200d8010000d8010000000000000000000000000000000000000000a0e33c109fe50000c1e538009fe538109fe5000081e534109fe5000081e530009fe520109fe52c309fe5002090e5002081e5040080e2041081e2030050e1f9ffffba14f09fe5000000000010020090bf0200d0bf0200a0bd0200a0be020000000000')
    out=bytearray(512);out[:len(template)]=template;out[:12]=second[:12]
    struct.pack_into('<I',out,0x70,p['security_flag_address']);struct.pack_into('<I',out,0x88,p['return_address'])
    table=first[p['loader_table_offset']:p['loader_table_offset']+80];out[0xa0:0xf0]=table;out[0xd0:0xd4]=bytes(4)
    out[0xf0:0x140]=table;out[0x11c:0x120]=bytes(4);struct.pack_into('<I',out,0x128,0x210f0);out[0x190:0x1a0]=bytes([0x74])*16;struct.pack_into('<I',out,508,0x2bd28)
    return out

def patch_boot(original,second):
    out=bytearray(original)
    if second:at=ref.matches(out,bytes.fromhex('000000e3010e42e32800d0e51eff2fe1'),bytes([255,255,255]+[0]*13))+8
    else:at=ref.matches(out,bytes.fromhex('04009fe52800d0e51eff2fe1'),bytes(12))+4
    assert out[at:at+4]==bytes.fromhex('2800d0e5');out[at:at+4]=bytes.fromhex('0000a0e3');return out

def main():
    p=argparse.ArgumentParser();p.add_argument('package',type=Path);p.add_argument('--source',required=True,type=Path);p.add_argument('--donor-boot',required=True,type=Path);a=p.parse_args()
    ffu=Ffu(a.source)
    with zipfile.ZipFile(a.package) as z:
        infos=z.infolist();assert len(infos)<=128 and len({i.filename for i in infos})==len(infos)
        assert all(i.compress_type==0 and i.file_size<=128*1024*1024 for i in infos);assert z.testzip() is None
        manifest=z.read('manifest.json');m=json.loads(manifest)
        assert m['kind']=='wpi-spec-a-offline-reference' and m['schema']==1
        assert not m['phone_writes_enabled'] and not m['originals_are_installed_backup'] and not m['backup_gpt_captured']
        assert {i.filename for i in infos}=={f['path']for f in m['files']}|{'manifest.json'}
        for file in m['files']:
            data=z.read(file['path']);assert len(data)==file['size'] and sha(data)==file['sha256'] and zlib.crc32(data)==file['crc32']
        with a.source.open('rb')as src: assert hashlib.file_digest(src,'sha256').hexdigest()==m['source_ffu_sha256']
        primary=z.read('original/GPT-primary.bin');assert primary==ffu.read(0,34*512)
        original=dict(gpt_entries(primary))
        for entry in m['restore']:
            name=entry['path'].removeprefix('original/').removesuffix('.img')
            if name=='GPT-primary.bin':continue
            first,last=struct.unpack_from('<QQ',original[name],32);assert entry['reference_start_sector']==first and entry['byte_length']==(last-first+1)*512
            assert sha(ffu.read(first*512,(last-first+1)*512))==sha(z.read(entry['path']))
        expected,swapped=expected_gpt(primary,m['external_sbl3']);assert z.read('prepared/GPT-primary.bin')==expected;assert m['normalized_backup_pairs']==swapped
        first=z.read('original/SBL1.img');second=patch_boot(z.read('original/SBL2.img'),True)
        assert z.read('prepared/SBL1.img')==first[:-512] and z.read('prepared/SBL2.img')==second
        assert z.read('prepared/HACK.img')==extra_sector(first,second)
        third=z.read('imports/SBL3.bin')if m['external_sbl3']else z.read('original/SBL3.img')
        assert z.read('prepared/SBL3.img')==patch_boot(third,False)
        for name in ['TZ','RPM','WINSECAPP']:assert z.read('prepared/'+name+'.img')==z.read('original/'+name+'.img')
        uefi=assembly.verify_uefi(z.read('original/UEFI.img'),z.read('prepared/UEFI.img'))
        esp=assembly.verify_efiesp(z.read('original/EFIESP.img'),z.read('prepared/EFIESP.img'),a.donor_boot.read_bytes())
        with a.package.open('rb')as pkg:digest=hashlib.file_digest(pkg,'sha256').hexdigest()
        print(json.dumps(dict(comparison='matches',size=a.package.stat().st_size,sha256=digest,manifest_sha256=sha(manifest),files=len(infos),sbl1_payload_sha256=sha(z.read('prepared/HACK.img')),prepared_gpt_sha256=sha(expected),uefi=uefi,efiesp=esp,phone_writes_enabled=False,originals_are_installed_backup=False,backup_gpt_captured=False),indent=2))
if __name__=='__main__':main()
