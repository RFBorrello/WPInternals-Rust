"""Deterministic REGF fixture with invented BCD objects and spare hive cells.
Layout follows pinned DiscUtils.Registry (see THIRD_PARTY_NOTICES.md).
Contains no firmware or OEM data.
"""
import struct
from pathlib import Path

disk = bytearray(16384)
disk[:4] = b'regf'
struct.pack_into('<II', disk, 4, 1, 1)
struct.pack_into('<IIII', disk, 20, 1, 3, 0, 1)
struct.pack_into('<I', disk, 40, len(disk) - 4096)
disk[4096:4100] = b'hbin'
struct.pack_into('<II', disk, 4100, 0, len(disk) - 4096)
cursor = 4128

def cell(data):
    global cursor
    at = cursor
    size = (len(data) + 11) // 8 * 8
    struct.pack_into('<i', disk, at, -size)
    disk[at+4:at+4+len(data)] = data
    cursor += size
    return at - 4096

sk = bytearray(40)
sk[:2] = b'sk'
struct.pack_into('<IIIII', sk, 4, 32, 32, 0, 20, 0x80000001)
security = cell(sk)
keys = []

def value(name, data, kind=3):
    b = bytearray(20 + len(name))
    b[:2] = b'vk'
    struct.pack_into('<H', b, 2, len(name))
    if len(data) <= 4:
        struct.pack_into('<I', b, 4, 0x80000000 | len(data))
        b[8:8+len(data)] = data
    else:
        struct.pack_into('<II', b, 4, len(data), cell(data))
    struct.pack_into('<IH', b, 12, kind, 1)
    b[20:] = name.encode('ascii')
    return cell(b)

def key(name, parent=0xffffffff, children=None, values=None):
    nk = bytearray(76 + len(name))
    nk[:2] = b'nk'
    struct.pack_into('<H', nk, 2, 32 | (4 if parent == 0xffffffff else 0))
    struct.pack_into('<I', nk, 16, parent)
    for at in [28, 32, 40, 48]: struct.pack_into('<I', nk, at, 0xffffffff)
    struct.pack_into('<I', nk, 44, security)
    struct.pack_into('<H', nk, 72, len(name))
    nk[76:] = name.encode('ascii')
    idx = cell(nk)
    keys.append(idx)
    subs = [(n, key(n, idx, c, v)) for n, c, v in children or []]
    if subs:
        lh = bytearray(b'lh' + struct.pack('<H', len(subs)))
        for n, ref in sorted(subs, key=lambda x: x[0].lower()):
            h = 0
            for ch in n.upper(): h = (h * 37 + ord(ch)) & 0xffffffff
            lh.extend(struct.pack('<II', ref, h))
        struct.pack_into('<II', disk, 4096+idx+4+20, len(subs), 0)
        struct.pack_into('<I', disk, 4096+idx+4+28, cell(lh))
    if values:
        refs = [value(n, d, t) for n, d, t in values]
        struct.pack_into('<II', disk, 4096+idx+4+36, len(refs), cell(struct.pack('<'+'I'*len(refs), *refs)))
    return idx

objects = ['{01de5a27-8705-40db-bad6-96fa5187d4a6}', '{7619dcc9-fafe-11d9-b411-000476eba25f}']
root = key('BCD00000000', children=[('Objects', [(o, [('Elements', [('12000002', None, [('Element', b'unchanged fixture description', 3)])], None)], None) for o in objects], None)], values=[('Description', b'preserve me', 3)])
struct.pack_into('<I', disk, 36, root)
struct.pack_into('<I', disk, 4096+security+4+12, len(keys))
struct.pack_into('<i', disk, cursor, len(disk)-cursor)
checksum = 0
for i in range(0, 508, 4): checksum ^= struct.unpack_from('<I', disk, i)[0]
struct.pack_into('<I', disk, 508, checksum or 1)
(Path(__file__).resolve().parents[1]/'tests/fixtures/spec-a/bcd.synthetic.hive').write_bytes(disk)
