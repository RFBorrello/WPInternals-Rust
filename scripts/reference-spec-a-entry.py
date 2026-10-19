"""Independent offline check of local FlashApp anchors and GPT recovery ZIP.

Outputs hashes/ranges only. Never opens a phone, executes firmware, extracts an
archive to disk, or authenticates the installed firmware. Standard library only.
"""
import argparse
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct
import zipfile
import zlib


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit):
    with path.open('rb') as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input exceeds reference bound')
    return data


def u64(data, at):
    return struct.unpack_from('<Q', data, at)[0]


def gpt(header, table):
    if len(header) != 512 or len(table) != 16384 or header[:8] != b'EFI PART':
        raise ValueError('Unsupported GPT shape')
    if struct.unpack_from('<II', header, 80) != (128, 128):
        raise ValueError('Unknown GPT entry geometry')
    check = bytearray(header[:92]); check[16:20] = bytes(4)
    if zlib.crc32(check) != struct.unpack_from('<I', header, 16)[0]:
        raise ValueError('GPT header CRC mismatch')
    if zlib.crc32(table) != struct.unpack_from('<I', header, 88)[0]:
        raise ValueError('GPT entries CRC mismatch')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['uefi', 'primary', 'capsule', 'rust-code-report']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    spec = importlib.util.spec_from_file_location('offline', Path(__file__).with_name('reference-spec-a-offline.py'))
    offline = importlib.util.module_from_spec(spec); spec.loader.exec_module(offline)
    uefi = read(a.uefi, 4 * 1024 * 1024)
    containers = [data for kind, _, data in offline.files(uefi[40:]) if kind == 11]
    assert len(containers) == 1
    compressed = [v for t, v in offline.sections(containers[0]) if t == 2]
    assert len(compressed) == 1
    compressed = compressed[0][offline.u16(compressed[0], 20):]
    decoded = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE, memlimit=64*1024*1024).decompress(compressed, max_length=16*1024*1024)
    volume = [v[4:] for t, v in offline.sections(decoded) if t == 23]
    assert len(volume) == 1
    matches = []
    for kind, _, data in offline.files(volume[0]):
        if kind == 240:
            continue
        sections = offline.sections(data)
        names = [v[4:].decode('utf-16le').rstrip('\0 ') for t, v in sections if t == 21]
        if names == ['NokiaFlashApp']:
            matches.extend(v[4:] for t, v in sections if t == 16)
    assert len(matches) == 1
    exe = matches[0]
    assert sha(exe) == '503578ed1bb90406e19067664235f974a19216e25ff4c33565bdda9365b8a1e2'
    rust = json.loads(read(a.rust_code_report, 16384))
    assert rust['reference_uefi_sha256'] == sha(uefi)
    assert rust['reference_flash_app_sha256'] == sha(exe)
    pe = offline.u32(exe, 60); optional = pe+24
    assert exe[pe:pe+4] == b'PE\0\0'
    assert offline.u32(exe, optional+28) == 0
    section_table = optional+offline.u16(exe, pe+20)
    for i in range(offline.u16(exe, pe+6)):
        at = section_table+i*40
        assert offline.u32(exe, at+12) == offline.u32(exe, at+20), 'RVA/file offsets differ'
    branches = [(0xbbb0, 0xbbe8), (0xbb74, 0xbbe8), (0xe5c8, 0x96b8), (0x9738, 0xcb44)]
    for at, expected in branches:
        word = offline.u32(exe, at)
        assert (word >> 25) & 7 == 5
        immediate = word & 0xffffff
        if immediate & 0x800000:
            immediate -= 0x1000000
        assert at+8+immediate*4 == expected
    assert offline.u32(exe, 0xbbac) == 0xe3510002
    assert offline.u32(exe, 0x972c) == 0xe3a03021
    assert offline.u32(exe, 0x9730) == 0xe2402021

    primary = read(a.primary, 17408); assert len(primary) == 17408
    gpt(primary[512:1024], primary[1024:])
    capacity = u64(primary, 544)+1
    with zipfile.ZipFile(a.capsule) as archive:
        assert archive.namelist() == ['captured/primary-gpt.bin', 'reconstructed/secondary-gpt.bin', 'manifest.json']
        assert all(i.file_size <= 17408 and i.compress_type == 0 for i in archive.infolist())
        assert archive.testzip() is None
        assert archive.read('captured/primary-gpt.bin') == primary
        secondary = archive.read('reconstructed/secondary-gpt.bin'); assert len(secondary) == 16896
        manifest = json.loads(archive.read('manifest.json'))
    table, header = secondary[:16384], secondary[16384:]
    gpt(header, table)
    assert table == primary[1024:]
    assert (u64(header, 24), u64(header, 32), u64(header, 72)) == (capacity-1, 1, capacity-33)
    assert manifest['regions'][0]['sha256'] == sha(primary)
    assert manifest['regions'][1]['sha256'] == sha(secondary)
    assert not any(manifest[k] for k in ['phone_contacted', 'phone_writes_enabled', 'original_secondary_captured', 'data_preservation_validated'])
    parts = {}
    for entry in [primary[i:i+128] for i in range(1024, len(primary), 128)]:
        if any(entry[:16]):
            parts[entry[56:128].decode('utf-16le').rstrip('\0')] = struct.unpack_from('<QQ', entry, 32)
    data_first, data_last = parts['Data']
    overlap = lambda first, last: max(0, min(last, data_last)-max(first, data_first)+1)
    targets = ['SBL1', 'SBL2', 'SBL3', 'UEFI', 'TZ', 'RPM', 'WINSECAPP', 'EFIESP', 'UEFI_BS_NV']
    targeted_bytes = 256*1024+256*1024+sum((parts[n][1]-parts[n][0]+1)*512 for n in targets)
    print(json.dumps(dict(
        comparison='matches', scope='offline_reference_binary_and_historical_gpt_only',
        code=rust, capacity_sectors=capacity, primary_sha256=sha(primary),
        reconstructed_secondary_sha256=sha(secondary),
        capsule_sha256=sha(read(a.capsule, 65536)),
        capsule_bytes=a.capsule.stat().st_size,
        conservative_end_chunk_data_overlap_sectors=overlap(capacity-256,capacity-1),
        reference_header_clear_data_overlap_sectors=overlap(capacity-33,capacity-1),
        targeted_snapshot_planned_bytes=targeted_bytes, targeted_snapshot_created=False,
        installed_binary_verified=False, phone_contacted=False, phone_writes_enabled=False,
        data_preservation_validated=False), indent=2))


if __name__ == '__main__':
    main()
