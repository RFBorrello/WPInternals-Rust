"""Independent valid-input comparison with pinned WPInternals 2.9.2 algorithms.

Reads extracted local SBLs and optional programmer files; exports hashes/offsets,
never binary data. This is a reference check, not an unlock or trust validator.
"""
import argparse, hashlib, json, struct
from pathlib import Path
from cryptography import x509

def sha(data): return hashlib.sha256(data).hexdigest()
def read(path, limit):
    if not path.is_file() or path.stat().st_size > limit: raise ValueError('Select a bounded regular file')
    with path.open('rb') as source: data=source.read(limit+1)
    if len(data)>limit: raise ValueError('File grew beyond the input limit')
    return data

def inspect(data, offset=0, patch=None):
    long = data[offset:offset+8] == bytes.fromhex('d1dc4b843410d773')
    header = offset + (20 if long else 8)
    source, address, size, code, sig_addr, sig_size, cert_addr, cert_size = struct.unpack_from('<8I',data,header)
    source = source or offset+(80 if long else 40)
    sig_at, cert_at = sig_addr-address+source, cert_addr-address+source
    if min(source, sig_at, cert_at) < 0 or source+size > len(data) or cert_at+cert_size > len(data): raise ValueError('Out-of-range reference image')
    certs=[]; at=cert_at
    while at < cert_at+cert_size and data[at:at+2] == b'\x30\x82':
        length=struct.unpack_from('>H',data,at+2)[0]+4
        if at+length > cert_at+cert_size: raise ValueError('Truncated certificate')
        cert=data[at:at+length]; x509.load_der_x509_certificate(cert);certs.append(sha(cert));at+=length
    if not certs: raise ValueError('No chain')
    preview=None
    if patch:
        pattern=bytes.fromhex('000000e3010e42e32800d0e51eff2fe1' if patch=='sbl2' else '04009fe52800d0e51eff2fe1')
        skip=8 if patch=='sbl2' else 4
        matches=[at+skip for at in range(len(data)-len(pattern)+1) if (data[at+3:at+len(pattern)] == pattern[3:] if patch=='sbl2' else data[at:at+len(pattern)] == pattern)]
        preview={'status':'unique' if len(matches)==1 else 'missing' if not matches else 'ambiguous','match_count':len(matches),'offset':matches[0] if len(matches)==1 else None,'expected':'2800d0e5','replacement':'0000a0e3'}
    return {'size':len(data),'sha256':sha(data),'image':{'header_kind':'long' if long else 'short_v3','header_offset':header,'image_offset':source,'image_address':address,'image_size':size,'code_size':code,'signature_offset':sig_at,'signature_size':sig_size,'certificates_offset':cert_at,'certificates_size':cert_size,'certificate_sha256':certs,'root_certificate_sha256':certs[-1]},'patch':preview,'error':None}

def decode(data):
    if not data.startswith(b':'): return data
    # Upstream's valid-input concatenation algorithm, independently checked for
    # checksums; Rust also rejects noncontiguous addressing and malformed EOF.
    output=bytearray()
    for line in data.decode('ascii').splitlines():
        record=bytes.fromhex(line[1:])
        if len(record)!=record[0]+5 or sum(record)&255: raise ValueError('Invalid HEX')
        if record[3]==0: output+=record[4:-1]
    return bytes(output)

def main():
    parser=argparse.ArgumentParser()
    for name in ['sbl1','sbl2','sbl3']: parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--loader',type=Path,action='append',default=[])
    parser.add_argument('--rust-report',type=Path)
    args=parser.parse_args()
    stock=[]
    for name,offset,patch in [('sbl1',0x2800,None),('sbl2',0,'sbl2'),('sbl3',0,'sbl3')]:
        stock.append({'name':name.upper(),**inspect(read(getattr(args,name),4*1024*1024),offset,patch)})
    loaders=[]
    root=stock[0]['image']['root_certificate_sha256']
    for path in args.loader:
        original=read(path,512*1024);data=decode(original);decoded=inspect(data);code=decoded['image']
        loaders.append({'name':path.name,'input_sha256':sha(original),'decoded':{'name':path.name,**decoded},'v1_marker_present':'QHSUSB_ARMPRG'.encode('utf-16le') in data[code['image_offset']:code['image_offset']+code['code_size']],'matches_stock_sbl1_root':root==code['root_certificate_sha256'],'error':None})
    output={'upstream_revision':'d8fd0aa516b16dc094df0422a3adc525af005c29','stock':stock,'loaders':loaders,'phone_writes_enabled':False}
    if args.rust_report:
        rust=json.loads(read(args.rust_report,1024*1024))
        for key in ['stock','loaders','phone_writes_enabled']:
            if rust[key]!=output[key]: raise ValueError('Reference mismatch: '+key)
        output['rust_reference_comparison']='matches'
    print(json.dumps(output,indent=2))
if __name__=='__main__': main()
