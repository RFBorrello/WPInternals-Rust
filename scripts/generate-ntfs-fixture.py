"""Minimal synthetic NTFS reader fixture, not a mountable phone filesystem.

16 KiB clusters, 4 KiB directory records, resident and fragmented file data.
All bytes are generated test data, not copied from proprietary firmware.
"""
from pathlib import Path
import struct

CLUSTER = 16384
disk = bytearray(32 * CLUSTER)
align = lambda size: (size + 7) // 8 * 8

def fixup(record, at):
    count = len(record) // 512 + 1
    struct.pack_into('<HH', record, 4, at, count)
    struct.pack_into('<H', record, at, 0xA55A)
    for sector in range(1, count):
        end = sector * 512 - 2
        record[at + sector * 2:at + sector * 2 + 2] = record[end:end + 2]
        struct.pack_into('<H', record, end, 0xA55A)

def resident(ty, data, name=''):
    encoded = name.encode('utf-16-le')
    value_at = align(24 + len(encoded))
    result = bytearray(align(value_at + len(data)))
    struct.pack_into('<IIBBHHH', result, 0, ty, len(result), 0, len(name), 24 if name else 0, 0, 0)
    struct.pack_into('<IH', result, 16, len(data), value_at)
    result[24:24 + len(encoded)] = encoded
    result[value_at:value_at + len(data)] = data
    return result

def nonresident(ty, runs, clusters, size, name=''):
    encoded = name.encode('utf-16-le')
    runs_at = align(64 + len(encoded))
    result = bytearray(align(runs_at + len(runs)))
    struct.pack_into('<IIBBHHH', result, 0, ty, len(result), 1, len(name), 64 if name else 0, 0, 0)
    struct.pack_into('<QQHH', result, 16, 0, clusters - 1, runs_at, 0)
    struct.pack_into('<QQQ', result, 40, clusters * CLUSTER, size, size)
    result[64:64 + len(encoded)] = encoded
    result[runs_at:runs_at + len(runs)] = runs
    return result

def mft(number, attributes, directory=False):
    record = bytearray(1024)
    record[:4] = b'FILE'
    struct.pack_into('<HHHHII', record, 16, 1, 1, 56, 3 if directory else 1, 0, 1024)
    struct.pack_into('<I', record, 44, number)
    at = 56
    for index, attribute in enumerate(attributes):
        attribute = bytearray(attribute)
        struct.pack_into('<H', attribute, 14, index)
        record[at:at + len(attribute)] = attribute
        at += len(attribute)
    struct.pack_into('<I', record, at, 0xFFFFFFFF)
    struct.pack_into('<I', record, 24, at + 8)
    fixup(record, 48)
    disk[CLUSTER + number * 1024:CLUSTER + (number + 1) * 1024] = record

boot = bytearray(512)
boot[3:11] = b'NTFS    '
struct.pack_into('<H', boot, 11, 512)
boot[13] = CLUSTER // 512
struct.pack_into('<QQQ', boot, 40, len(disk) // 512 - 1, 1, 2)
boot[64] = 256 - 10
boot[68] = 256 - 12
boot[510:512] = b'\x55\xaa'
disk[:512] = boot
disk[-512:] = boot
mft(0, [nonresident(0x80, bytes([0x11, 1, 1, 0]), 1, CLUSTER)])

# A large index whose child VCN 16 means byte offset 8192, not 16 clusters.
root = bytearray(56)
struct.pack_into('<IIIB', root, 0, 0x30, 1, 4096, 8)
struct.pack_into('<IIIB', root, 16, 16, 40, 40, 1)
struct.pack_into('<QHHIQ', root, 32, 0, 24, 0, 3, 16)
mft(5, [resident(0x90, root, '$I30'), nonresident(0xA0, bytes([0x11, 1, 5, 0]), 1, 12288, '$I30')], True)

def entry(number, name, length):
    encoded = name.encode('utf-16-le')
    key = bytearray(66 + len(encoded))
    struct.pack_into('<Q', key, 0, 5 | (1 << 48))
    struct.pack_into('<QQI', key, 40, length, length, 0x20)
    key[64:66] = bytes([len(name), 1])
    key[66:] = encoded
    result = bytearray(align(16 + len(key)))
    struct.pack_into('<QHHI', result, 0, number | (1 << 48), len(result), len(key), 0)
    result[16:16 + len(key)] = key
    return result

leaf = bytearray(4096)
leaf[:4] = b'INDX'
struct.pack_into('<q', leaf, 16, 16)
entries = entry(7, 'big.bin', 2 * CLUSTER) + entry(6, 'tiny.txt', 8) + struct.pack('<QHHI', 0, 16, 0, 2)
struct.pack_into('<IIIB', leaf, 24, 40, 40 + len(entries), 4096 - 24, 0)
leaf[64:64 + len(entries)] = entries
fixup(leaf, 40)
disk[5 * CLUSTER + 8192:5 * CLUSTER + 12288] = leaf
mft(6, [resident(0x80, b'resident')])
mft(7, [nonresident(0x80, bytes([0x11, 1, 20, 0x11, 1, 2, 0]), 2, 2 * CLUSTER)])
disk[20 * CLUSTER:21 * CLUSTER] = b'A' * CLUSTER
disk[22 * CLUSTER:23 * CLUSTER] = b'B' * CLUSTER
upcase = b''.join(struct.pack('<H', ord(chr(i).upper()) if 97 <= i <= 122 else i) for i in range(65536))
disk[8 * CLUSTER:16 * CLUSTER] = upcase
mft(10, [nonresident(0x80, bytes([0x11, 8, 8, 0]), 8, len(upcase))])
output = Path(__file__).resolve().parents[1] / 'tests/fixtures/ntfs-large-cluster.img'
output.write_bytes(disk)
print(f'Generated {output.name}: {len(disk)} bytes')
