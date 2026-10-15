"""Synthetic Nokia-style package metadata inside NTFS and a legacy FFU.

Reuse the project's generated NTFS record builders. No phone data is included.
Outputs are deliberately not mountable or flashable.
"""
from pathlib import Path
import gzip, hashlib, runpy, struct, zlib

root = Path(__file__).resolve().parents[1]
ns = runpy.run_path(str(root / 'scripts/generate-ntfs-fixture.py'))
disk, cluster = ns['disk'], ns['CLUSTER']
mft, resident, nonresident, entry = (ns[n] for n in ('mft', 'resident', 'nonresident', 'entry'))
reg = 'Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\SYSTEM\\Platform\\DeviceTargetingInfo]\r\n"PhoneFirmwareRevision"="1.2.3.0004"\r\n'
dsm = '<Package xmlns="http://schemas.microsoft.com/embedded/2004/10/ImageUpdate"><Identity><Owner>Nokia</Owner><Component>DeviceInfo</Component><SubComponent>PhoneFirmwareRevision</SubComponent><Version Major="1" Minor="2" QFE="3" Build="4" /></Identity><Partition>MainOS</Partition><IsRemoval>false</IsRemoval></Package>'
reg = gzip.compress(b'\xff\xfe' + reg.encode('utf-16le'), mtime=0)
dsm = gzip.compress(dsm.encode(), mtime=0)

def directory(number, items):
    entries = bytearray()
    for child, name, size, is_dir in sorted(items, key=lambda i: i[1].upper()):
        encoded = entry(child, name, size)
        if is_dir:
            struct.pack_into('<I', encoded, 16 + 56, 0x10000000)
        entries += encoded
    entries += struct.pack('<QHHI', 0, 16, 0, 2)
    index = bytearray(32) + entries
    struct.pack_into('<IIIB', index, 0, 0x30, 1, 4096, 8)
    struct.pack_into('<IIIB', index, 16, 16, 16 + len(entries), 16 + len(entries), 0)
    mft(number, [resident(0x90, index, '$I30')], True)

mft(0, [nonresident(0x80, bytes([0x11, 2, 1, 0]), 2, 2 * cluster)])
directory(5, [(11, 'Windows', 0, True)])
directory(11, [(12, 'Packages', 0, True)])
directory(12, [(13, 'DsmFiles', 0, True), (14, 'RegistryFiles', 0, True)])
directory(13, [(16, 'Nokia.DeviceInfo.PhoneFirmwareRevision.dsm.xml', len(dsm), False)])
directory(14, [(15, 'Nokia.DeviceInfo.PhoneFirmwareRevision.reg', len(reg), False)])
mft(15, [resident(0x80, reg)])
mft(16, [resident(0x80, dsm)])
(root / 'tests/fixtures/ntfs-firmware.img').write_bytes(disk)

# Keep the original synthetic header profile; rebuild mapping, GPT and hashes.
chunk = 4096
payload = bytearray(128 * chunk + len(disk))
mainos_start = 128 * chunk
payload[mainos_start:] = disk
entries = bytearray(128 * 128)
entries[:16] = bytes.fromhex('28732AC11FF8D211BA4B00A0C93EC93B')
entries[16:32] = bytes([1]) * 16
struct.pack_into('<QQ', entries, 32, mainos_start // 512, len(payload) // 512 - 2)
entries[56:68] = 'MainOS'.encode('utf-16le')
gpt = bytearray(512)
gpt[:8] = b'EFI PART'
struct.pack_into('<III', gpt, 8, 0x10000, 92, 0)
struct.pack_into('<QQQQ', gpt, 24, 1, len(payload) // 512 - 1, 34, len(payload) // 512 - 2)
gpt[56:72] = b'\x55' * 16
struct.pack_into('<QIII', gpt, 72, 2, 128, 128, zlib.crc32(entries))
struct.pack_into('<I', gpt, 16, zlib.crc32(gpt[:92]))
payload[512:1024] = gpt
payload[1024:1024 + len(entries)] = entries
base = (root / 'tests/fixtures/synthetic.ffu').read_bytes()
image, store = bytearray(base[chunk:chunk*2]), bytearray(base[chunk*2:chunk*3])
struct.pack_into('<I', store, 260, 0)
struct.pack_into('<I', store, 252, len(payload) // chunk)
hashed = image + store + payload
hashes = b''.join(hashlib.sha256(hashed[i:i+chunk]).digest() for i in range(0, len(hashed), chunk))
security = bytearray((32 + len(hashes) + chunk - 1) // chunk * chunk)
security[:32] = base[:32]
struct.pack_into('<I', security, 28, len(hashes))
security[32:32 + len(hashes)] = hashes
(root / 'tests/fixtures/synthetic-mainos.ffu').write_bytes(security + hashed)
print('Generated synthetic MainOS package metadata fixtures.')
