"""Independent comparison using upstream 2.9.2 FFU.cs mapping logic.

Does not execute upstream C# or authenticate the signing catalog. Outputs hashes
and format metadata only, not firmware bytes. For legacy single-store FFUs only.
Copyright (c) 2018 Rene Lergner; see THIRD_PARTY_NOTICES.md and upstream MIT license.
"""
import hashlib
import json
import struct
import sys

path = sys.argv[1]
partition = sys.argv[2]
with open(path, 'rb') as f:
    file_size = f.seek(0, 2)
    f.seek(0)
    security = f.read(32)
    u32 = lambda data, offset: struct.unpack_from('<I', data, offset)[0]
    chunk = u32(security, 16) * 1024
    assert security[4:16] == b'SignedImage '
    assert 512 <= chunk <= 4 * 1024 * 1024 and chunk & (chunk - 1) == 0
    align = lambda size: (size + chunk - 1) // chunk * chunk
    sec_size = align(u32(security, 0) + u32(security, 24) + u32(security, 28))
    assert sec_size <= min(file_size, 32 * 1024 * 1024)
    f.seek(sec_size)
    image = f.read(24)
    assert image[4:16] == b'ImageFlash  '
    image_size = align(u32(image, 0) + u32(image, 16))
    f.seek(sec_size + image_size)
    short = f.read(248)
    count, length, _, validation = struct.unpack_from('<IIII', short, 208)
    assert count <= length // 16 and length <= 32 * 1024 * 1024
    header_size = sec_size + image_size + align(248 + length + validation)
    assert header_size <= min(file_size, 32 * 1024 * 1024)
    f.seek(sec_size + image_size + 248 + validation)
    descriptors = f.read(length)
    indexes = {}
    pos = payload = 0
    for _ in range(count):
        locations, blocks = struct.unpack_from('<II', descriptors, pos)
        assert locations > 0 and blocks > 0 and pos + 8 + locations * 8 <= length
        assert payload + blocks <= file_size // chunk
        for location in range(locations):
            access, disk_chunk = struct.unpack_from('<II', descriptors, pos + 8 + location * 8)
            if access == 0:
                for k in range(blocks):
                    indexes[disk_chunk + k] = payload + k
                    assert len(indexes) <= 262144, 'Reference-tool mapping limit exceeded'
        pos += 8 + locations * 8
        payload += blocks
    assert pos == length
    f.seek(0, 2)
    assert header_size + payload * chunk == f.tell()

    def disk_read(start, length):
        result = bytearray()
        while length:
            disk_chunk, within = divmod(start, chunk)
            amount = min(length, chunk - within)
            source = indexes.get(disk_chunk)
            if source is None:
                data = bytes(amount)
            else:
                f.seek(header_size + source * chunk + within)
                data = f.read(amount)
                assert len(data) == amount
            result.extend(data)
            start += amount
            length -= amount
        return result

    gpt = disk_read(512, 512)
    assert gpt[:8] == b'EFI PART'
    table_lba = struct.unpack_from('<Q', gpt, 72)[0]
    entries, entry_size = struct.unpack_from('<II', gpt, 80)
    assert entry_size >= 128 and entries * entry_size <= 32 * 1024 * 1024
    table = disk_read(table_lba * 512, entries * entry_size)
    selected = None
    for offset in range(0, len(table), entry_size):
        entry = table[offset:offset + entry_size]
        if not any(entry[:16]):
            continue
        name = entry[56:128].decode('utf-16-le').rstrip('\0')
        if name.casefold() == partition.casefold():
            first, last = struct.unpack_from('<QQ', entry, 32)
            selected = (first * 512, (last - first + 1) * 512)
    assert selected is not None
    start, length = selected
    digest = hashlib.sha256()
    for offset in range(0, length, chunk):
        digest.update(disk_read(start + offset, min(chunk, length - offset)))
    print(json.dumps({'platform': short[12:204].rstrip(b'\0 ').decode('ascii'),
                      'chunk_size': chunk, 'header_size': header_size,
                      'payload_size': payload * chunk, 'write_descriptors': count,
                      'partition': partition, 'partition_size': length,
                      'partition_sha256': digest.hexdigest()}, indent=2))
