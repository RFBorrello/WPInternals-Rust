"""Independent valid-profile FFU recovery audit; local regular files only.
Python configparser, CRC and SHA implementations check Rust's reported facts.
The existing FFU reference is derived from WPInternals 2.9.2, Rene Lergner, MIT.
No device operations, extraction, simulated recovery or GUID-value output.
Run without Python -O so the assertions remain enabled.
"""
import argparse
import configparser
import hashlib
import importlib.util
import json
import struct
import zlib
from pathlib import Path

spec = importlib.util.spec_from_file_location('package_ref', Path(__file__).with_name('reference-spec-a-package.py'))
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('ffu', type=Path)
    p.add_argument('primary', type=Path)
    p.add_argument('report', type=Path)
    a = p.parse_args()
    assert a.ffu.is_file() and a.primary.is_file() and a.report.is_file()
    assert a.primary.stat().st_size == 17408 and a.report.stat().st_size <= 1024*1024
    r = json.loads(a.report.read_text())
    primary = a.primary.read_bytes()
    assert r['schema'] == 1 and r['kind'] == 'wpi-stock-recovery-file-audit'
    assert ref.sha(primary) == r['saved_primary_sha256']
    assert struct.unpack_from('<Q', primary, 544)[0]+1 == r['recorded_capacity_sectors']
    with a.ffu.open('rb') as f:
        assert hashlib.file_digest(f, 'sha256').hexdigest() == r['source_ffu_sha256']
        f.seek(0)
        s = f.read(32)
        chunk = ref.u32(s, 16)*1024
        align = lambda n: (n+chunk-1)//chunk*chunk
        security = align(ref.u32(s, 0)+ref.u32(s, 24)+ref.u32(s, 28))
        f.seek(ref.u32(s, 0)+ref.u32(s, 24))
        hashes = f.read(ref.u32(s, 28))
        f.seek(security)
        for at in range(0, len(hashes), 32):
            assert hashlib.sha256(f.read(chunk)).digest() == hashes[at:at+32]
        assert f.tell() == a.ffu.stat().st_size
        f.seek(security)
        im = f.read(24)
        f.seek(security+ref.u32(im, 0))
        text = f.read(ref.u32(im, 16)).decode()
        store_at = security+align(ref.u32(im, 0)+ref.u32(im, 16))
        f.seek(store_at)
        store = f.read(248)
        f.seek(store_at+248+ref.u32(store, 220))
        desc = f.read(ref.u32(store, 212))
        header = store_at+align(248+len(desc)+ref.u32(store, 220))
        # Delegate property syntax/duplicate-key checking to Python's INI parser;
        # repeated Partition sections receive independent synthetic section names.
        lines = []
        begun = False
        partition = 0
        for line in text.splitlines():
            if line.strip().lower() == '[store]':
                begun = True
            if not begun:
                continue
            if line.strip().lower() == '[partition]':
                line = f'[Partition{partition}]'
                partition += 1
            lines.append(line)
        config = configparser.ConfigParser(interpolation=None)
        config.read_string('\n'.join(lines))
        m = r['manifest']
        assert config['Store'].getint('SectorSize') == m['sector_size'] == 512
        minimum = config['Store'].getint('MinSectorCount')
        assert minimum == m['minimum_sector_count']
        assert (r['recorded_capacity_sectors'] >= minimum) == r['capacity_meets_manifest_minimum']
        assert len(m['partitions']) == partition
        for i, row in enumerate(m['partitions']):
            section = config[f'Partition{i}']
            assert section['Name'] == row['name']
            assert section.getint('TotalSectors', fallback=None) == row['total_sectors']
            assert section.getboolean('UseAllSpace', fallback=False) == row['use_all_space']
            assert section.getboolean('RequiredToFlash', fallback=None) == row['required_to_flash']
        source = ref.Ffu(a.ffu)
        original = source.read(0, 17408)
        original_entries = dict(ref.gpt_entries(original))
        source.file.close()
        live = dict(ref.gpt_entries(primary))
        assert struct.unpack_from('<Q', original, 544)[0]+1 == r['source_template_capacity_sectors']
        assert r['template_capacity_equals_manifest_minimum'] == (r['source_template_capacity_sectors'] == minimum)
        assert r['expanding_partitions'] == [v['name'] for v in m['partitions'] if v['use_all_space']]
        assert r['partitions_with_changed_ranges'] == [n for n, e in live.items() if n in original_entries and e[32:48] != original_entries[n][32:48]]
        at = payload = begin = end_count = backups = 0
        for _ in range(ref.u32(store, 208)):
            locations, blocks = struct.unpack_from('<II', desc, at)
            for j in range(locations):
                method, index = struct.unpack_from('<II', desc, at+8+j*8)
                if method == 0:
                    begin += 1
                    continue
                assert method == 2
                row = r['end_relative_payloads'][end_count]
                end_count += 1
                assert (index, blocks, payload) == (row['disk_chunk_index'], row['chunk_count'], row['payload_chunk'])
                inspect = index == 0 and blocks == 1 and chunk >= 33*512
                assert inspect == row['inspected_as_single_final_chunk']
                if not inspect:
                    assert row['all_zero'] is None and row['backup_template'] is None
                    continue
                f.seek(header+payload*chunk)
                data = f.read(chunk)
                assert (not any(data)) == row['all_zero']
                h = data[-512:]
                if h[:8] != b'EFI PART':
                    assert row['backup_template'] is None
                    continue
                checked = bytearray(h[:ref.u32(h, 12)])
                checked[16:20] = bytes(4)
                assert zlib.crc32(checked) == ref.u32(h, 16)
                entries = data[-33*512:-512]
                assert zlib.crc32(entries) == ref.u32(h, 88)
                differences = []
                for at in range(0, 16384, 128):
                    left, right = original[1024+at:1152+at], entries[at:at+128]
                    assert left[:48] == right[:48] and left[56:] == right[56:]
                    if left[48:56] != right[48:56]:
                        assert any(left[:16])
                        differences.append(dict(partition=left[56:].decode('utf-16le').rstrip('\0'),
                            primary_attributes=f'0x{struct.unpack_from("<Q",left,48)[0]:016x}',
                            backup_attributes=f'0x{struct.unpack_from("<Q",right,48)[0]:016x}'))
                backup = row['backup_template']
                assert struct.unpack_from('<QQ', h, 24) == (backup['current_lba'], backup['alternate_lba']) == (r['source_template_capacity_sectors']-1, 1)
                assert backup['matches_source_primary_entries'] == (entries == original[1024:])
                assert backup['header_and_table_crc_valid'] and backup['attribute_differences'] == differences
                backups += 1
            payload += blocks
            at += 8+locations*8
        assert begin == r['beginning_relative_mapping_count'] and end_count == len(r['end_relative_payloads'])
        assert not any(r[k] for k in ['device_layout_expansion_validated', 'recovery_validated', 'phone_contacted', 'phone_writes_enabled'])
        print(json.dumps(dict(comparison='matches', report_sha256=ref.sha(a.report.read_bytes()),
            source_ffu_sha256=r['source_ffu_sha256'], primary_sha256=r['saved_primary_sha256'],
            manifest_partitions=partition, minimum_sector_count=minimum,
            expanding_partitions=r['expanding_partitions'], source_backup_templates_checked=backups,
            end_relative_payloads=end_count, phone_contacted=False, recovery_validated=False,
            phone_writes_enabled=False), indent=2))


if __name__ == '__main__':
    main()
