"""Independent valid-profile comparison for offline UEFI/EFIESP assembly.
Uses Python lzma and direct REGF/FAT16 readers, never Rust, mounts or phone I/O.
Inputs are local extracted originals and newly assembled images. No binary output.
"""
import argparse
import hashlib
import importlib.util
import json
import lzma
import struct
from pathlib import Path

spec = importlib.util.spec_from_file_location('reference', Path(__file__).with_name('reference-spec-a-offline.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
u16, u32, u24, sha = reference.u16, reference.u32, reference.u24, reference.sha

def records(volume):
    reference.files(volume)  # Independent FV/header validation.
    size = struct.unpack_from('<Q', volume, 32)[0]
    at, out = u16(volume, 48), []
    while at + 24 <= size and volume[at:at+24] != bytes([255])*24:
        n = u24(volume, at+20)
        data = volume[at:at+n]
        if data[19] & 64:
            assert (sum(data[24:])+data[17]) & 255 == 0
        out.append((at, data))
        at = (at+n+7)//8*8
    return out

def decoded_uefi(b):
    container = [f for _, f in records(b[40:]) if f[18] == 11]
    assert len(container) == 1
    section = [s for t, s in reference.sections(container[0][24:]) if t == 2][0]
    compressed = section[u16(section, 20):]
    size = struct.unpack_from('<Q', compressed, 5)[0]
    assert size <= 16*1024*1024
    decoded = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=64*1024*1024).decompress(compressed, max_length=size)
    assert len(decoded) == size
    return decoded

def verify_uefi(old, new):
    assert len(old) == len(new)
    header = bytearray(old[:40])
    struct.pack_into('<I', header, 16, u32(old, 20))
    header[24:40] = bytes(16)
    assert new[:40] == header and not any(new[40+u32(old,20):])
    before, after = decoded_uefi(old), decoded_uefi(new)
    expected = bytearray(before)
    fv_offset = next(before.index(s) + 4 for t, s in reference.sections(before) if t == 23)
    patches = reference.uefi(old)['targets']
    for offset, file in records(before[fv_offset:]):
        for target in patches:
            if str(reference.uuid.UUID(bytes_le=file[:16])) != target['guid']: continue
            executable = [s[4:] for t, s in reference.sections(file[24:]) if t == 16][0]
            start = fv_offset + offset
            pe_at = start + file.index(executable)
            for patch in target['patches']:
                at = pe_at + patch['offset']
                original, replacement = bytes.fromhex(patch['expected']), bytes.fromhex(patch['replacement'])
                assert expected[at:at+len(original)] == original
                expected[at:at+len(replacement)] = replacement
            if file[19] & 64: expected[start+17] = (-sum(expected[start+24:start+len(file)])) & 255
            expected[start+16] = 0
            expected[start+16] = (-sum(expected[start:start+17]+expected[start+18:start+23])) & 255
    assert after == expected, 'Unexpected decompressed UEFI change'
    records(after[fv_offset:])
    old_outer, new_outer = records(old[40:]), records(new[40:])
    assert len(old_outer) == len(new_outer)
    for (_, a), (_, b) in zip(old_outer, new_outer):
        assert a[:16] == b[:16]
        if a[18] != 11: assert a == b
    return dict(resulting_sha256=sha(new), decompressed_sha256=sha(after), patched_executables=len(patches), other_files_preserved=True)

def fat16_files(image):
    # Known-profile reference reader, intentionally separate from fatfs.
    bps, spc, reserved, copies, entries = u16(image,11), image[13], u16(image,14), image[16], u16(image,17)
    total, table_sectors = u16(image,19) or u32(image,32), u16(image,22)
    assert bps == 512 and spc > 0 and table_sectors and total*bps == len(image)
    root_size = ((entries*32+bps-1)//bps)*bps
    root_at = (reserved+copies*table_sectors)*bps
    data_at = root_at+root_size
    clusters = (len(image)-data_at)//(bps*spc)
    assert 4085 <= clusters < 65525, 'Reference supports FAT16 only'
    fat = image[reserved*bps:(reserved+table_sectors)*bps]
    for n in range(1,copies): assert image[(reserved+n*table_sectors)*bps:(reserved+(n+1)*table_sectors)*bps] == fat
    used, output = set(), {}
    def chain(cluster):
        seen, chunks = set(), []
        while cluster < 65528:
            assert 2 <= cluster < clusters+2 and cluster not in seen and cluster not in used
            seen.add(cluster); used.add(cluster)
            at = data_at+(cluster-2)*bps*spc
            chunks.append(image[at:at+bps*spc])
            cluster = u16(fat,cluster*2)
        return b''.join(chunks)
    def directory(data, prefix='', depth=0):
        assert depth <= 16
        long = {}
        for at in range(0,len(data),32):
            entry = data[at:at+32]
            if not entry or entry[0] == 0: break
            if entry[0] == 229: long = {}; continue
            if entry[11] == 15:
                long[entry[0]&31] = entry[1:11]+entry[14:26]+entry[28:32]
                continue
            if entry[11] & 8: long = {}; continue
            if long:
                name = b''.join(long[k] for k in sorted(long)).decode('utf-16le').split('\0')[0].rstrip('\uffff')
            else:
                name = entry[:8].decode('ascii').rstrip()
                ext = entry[8:11].decode('ascii').rstrip()
                if ext: name += '.'+ext
            long = {}
            if name in ('.','..'): continue
            path = prefix+name.lower()
            assert path not in output
            cluster, size = u16(entry,26), u32(entry,28)
            content = chain(cluster) if cluster else b''
            if entry[11] & 16:
                output[path] = None
                directory(content,path+'/',depth+1)
            else:
                assert size <= len(content)
                output[path] = content[:size]
            assert len(output) <= 4096
    directory(image[root_at:root_at+root_size])
    return output

def registry(bytes):
    assert bytes[:4] == b'regf' and u32(bytes,4) == u32(bytes,8)
    checksum = 0
    for at in range(0,508,4): checksum ^= u32(bytes,at)
    assert u32(bytes,508) == (1 if checksum == 0 else 0xfffffffe if checksum == 0xffffffff else checksum)
    def cell(ref):
        at = ref+4096
        length = struct.unpack_from('<i',bytes,at)[0]
        assert length < 0 and at-length <= len(bytes)
        return bytes[at+4:at-length]
    def name(data, at, length, ascii): return data[at:at+length].decode('ascii' if ascii else 'utf-16le').lower()
    def children(ref):
        data = cell(ref); count = u16(data,2)
        if data[:2] == b'ri': return [r for n in range(count) for r in children(u32(data,4+4*n))]
        stride = 8 if data[:2] in (b'lh',b'lf') else 4
        assert data[:2] in (b'lh',b'lf',b'li')
        return [u32(data,4+stride*n) for n in range(count)]
    seen, output = set(), {}
    def key(ref,path):
        assert ref not in seen; seen.add(ref)
        data = cell(ref); assert data[:2] == b'nk'
        values = {}
        if u32(data,36):
            refs = cell(u32(data,40))
            for n in range(u32(data,36)):
                value = cell(u32(refs,n*4)); assert value[:2] == b'vk'
                title = name(value,20,u16(value,2),u16(value,16)&1)
                raw = u32(value,4); size = raw & 0x7fffffff
                payload = value[8:8+size] if raw >> 31 else cell(u32(value,8))[:size] if size else b''
                values[title] = (u32(value,12),payload.hex())
        output[path] = values
        refs = children(u32(data,28)) if u32(data,20) else []
        assert len(refs) == u32(data,20)
        for child in refs:
            nk = cell(child); assert u32(nk,16) == ref
            key(child,path+'/'+name(nk,76,u16(nk,72),u16(nk,2)&32))
    key(u32(bytes,36),'')
    return output

def verify_efiesp(old,new,donor_boot):
    assert len(old) == len(new)
    original, changed = fat16_files(old), fat16_files(new)
    path, bcd = 'windows/system32/boot/mobilestartup.efi','efi/microsoft/boot/bcd'
    assert changed[path] is not None
    donor = reference.efiesp(donor_boot)
    assert sha(changed[path]) == donor['prepared_copy_sha256']
    expected = registry(original[bcd])
    for obj in ['{01de5a27-8705-40db-bad6-96fa5187d4a6}','{7619dcc9-fafe-11d9-b411-000476eba25f}']:
        expected.setdefault('/objects/'+obj+'/elements/16000048',{})['element'] = (3,'01')
    assert registry(changed[bcd]) == expected, 'Unrelated BCD entries changed'
    original[path], original[bcd] = changed[path], changed[bcd]
    assert original == changed, 'Unrelated FAT contents changed'
    return dict(resulting_sha256=sha(new),boot_sha256=sha(changed[path]),bcd_sha256=sha(changed[bcd]),other_files_preserved=True,other_bcd_entries_preserved=True)

def main():
    p = argparse.ArgumentParser()
    for field in ['uefi','rebuilt-uefi','efiesp','assembled-efiesp','donor-boot']: p.add_argument('--'+field,required=True,type=Path)
    a = p.parse_args()
    result = dict(uefi=verify_uefi(a.uefi.read_bytes(),a.rebuilt_uefi.read_bytes()),efiesp=verify_efiesp(a.efiesp.read_bytes(),a.assembled_efiesp.read_bytes(),a.donor_boot.read_bytes()))
    print(json.dumps(dict(comparison='matches',**result),indent=2))
if __name__ == '__main__': main()
