"""Independent local comparison of an advisory live-layout report.

Uses Python's ZIP/CRC/SHA implementations and the separate GPT translation of
WPInternals 2.9.2 (Rene Lergner, MIT). Never extracts images or contacts a phone.
No identifiers or raw GPT bytes are printed. Assertions require ordinary Python
execution without -O. This validates offline calculations, not recovery safety.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'package_reference', Path(__file__).with_name('reference-spec-a-package.py'))
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
BOOT = ['SBL1', 'SBL2', 'SBL3', 'UEFI', 'TZ', 'RPM', 'WINSECAPP']


def digest(path):
    assert path.is_file()
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def bounds(entry):
    first, last = struct.unpack_from('<QQ', entry, 32)
    return dict(first_sector=first, last_sector=last)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('package', type=Path)
    p.add_argument('primary', type=Path)
    p.add_argument('report', type=Path)
    a = p.parse_args()
    assert a.primary.is_file() and a.primary.stat().st_size == 17408
    assert a.package.is_file() and a.package.stat().st_size <= 512*1024*1024
    assert a.report.is_file() and a.report.stat().st_size <= 1024*1024
    primary = a.primary.read_bytes()
    r = json.loads(a.report.read_text())
    assert r['schema'] == 1 and r['kind'] == 'wpi-spec-a-live-layout-advisory'
    assert digest(a.package) == r['package_sha256']
    assert ref.sha(primary) == r['saved_primary_sha256']
    with zipfile.ZipFile(a.package) as z:
        infos = z.infolist()
        assert 1 <= len(infos) <= 128
        assert len({i.filename.casefold() for i in infos}) == len(infos)
        assert all(i.compress_type == 0 and i.file_size <= 128*1024*1024 for i in infos)
        assert z.getinfo('manifest.json').file_size <= 1024*1024
        manifest = z.read('manifest.json')
        m = json.loads(manifest)
        assert ref.sha(manifest) == r['manifest_sha256']
        assert {i.filename for i in infos} == {f['path'] for f in m['files']} | {'manifest.json'}
        for f in m['files']:
            i = z.getinfo(f['path'])
            assert f['size'] == i.file_size and f['crc32'] == i.CRC
            with z.open(i) as member:
                assert hashlib.file_digest(member, 'sha256').hexdigest() == f['sha256']
        candidate, swapped = ref.expected_gpt(primary, m['external_sbl3'])
        assert ref.sha(candidate) == r['candidate_primary_sha256']
        assert swapped == r['normalized_backup_pairs']
        for b in [primary, candidate]:
            assert len(b) == 17408
            current, backup, first, last = struct.unpack_from('<QQQQ', b, 536)
            assert current == 1 and backup == r['recorded_capacity_sectors']-1
            assert 34 <= first <= last and last+33 <= backup
            parts = ref.gpt_entries(b)  # Independent header/table CRCs.
            assert len({n.casefold() for n, _ in parts}) == len(parts)
            assert len({bytes(e[16:32]) for _, e in parts}) == len(parts)
            ranges = sorted(struct.unpack_from('<QQ', e, 32) for _, e in parts)
            assert all(first <= x <= y <= last for x, y in ranges)
            assert all(a[1] < b[0] for a, b in zip(ranges, ranges[1:]))
        live = dict(ref.gpt_entries(primary))
        prepared = dict(ref.gpt_entries(candidate))
        original_bytes = z.read('original/GPT-primary.bin')
        source = dict(ref.gpt_entries(original_bytes))
        reference_prepared = dict(ref.gpt_entries(z.read('prepared/GPT-primary.bin')))
        assert len(live) == r['partition_count'] == len(r['partitions'])
        assert (primary == original_bytes) == r['primary_matches_reference']
        assert (primary[568:584] == original_bytes[568:584]) == r['disk_identity_matches_reference']
        assert struct.unpack_from('<Q', original_bytes, 544)[0]+1 == r['reference_capacity_sectors']
        for row in r['partitions']:
            name = row['partition']
            assert row['installed'] == bounds(live[name])
            assert row['candidate'] == bounds(prepared[name])
            assert row['reference'] == (bounds(source[name]) if name in source else None)
            assert row['reference_identity_matches'] == (name in source and source[name][:32] == live[name][:32])
            assert row['reference_attributes_match'] == (name in source and source[name][48:56] == live[name][48:56])
            assert row['candidate_identity_preserved'] == (live[name][:32] == prepared[name][:32])
        placements = {p['path']: p for p in m['prepared'] if p['path'] != 'prepared/GPT-primary.bin'}
        files = {f['path']: f for f in m['files']}
        assert len(r['payloads']) == len(placements)
        for row in r['payloads']:
            path = row['path']
            name = path.removeprefix('prepared/').removesuffix('.img')
            b = bounds(prepared[name])
            capacity = (b['last_sector']-b['first_sector']+1)*512
            assert row['byte_length'] == placements[path]['byte_length'] == files[path]['size']
            assert row['sha256'] == files[path]['sha256']
            assert row['source_reference_start_sector'] == placements[path]['reference_start_sector']
            assert row['candidate_start_sector'] == b['first_sector']
            assert row['candidate_capacity_bytes'] == capacity
            assert row['fits'] == (row['byte_length'] <= capacity)
            assert row['source_and_live_partition_identity_match'] == (reference_prepared[name][:32] == prepared[name][:32])
        unchanged = all(e == prepared[n] for n, e in live.items()
                        if n not in BOOT and n not in ['BACKUP_'+n for n in swapped])
        assert unchanged == r['unaffected_partition_entries_preserved']
        assert r['all_payloads_fit'] == all(row['fits'] for row in r['payloads'])
        assert set(r['required_installed_partition_captures']) == set(BOOT+['EFIESP']+['BACKUP_'+n for n in swapped])
        assert not any(r[k] for k in ['phone_contacted', 'phone_writes_enabled', 'backup_gpt_captured', 'installed_partitions_preserved'])
        print(json.dumps(dict(comparison='matches', report_sha256=digest(a.report),
            package_sha256=r['package_sha256'], primary_sha256=r['saved_primary_sha256'],
            candidate_primary_sha256=r['candidate_primary_sha256'],
            partition_count=len(live), payload_count=len(r['payloads']),
            normalized_backup_pairs=swapped, all_payloads_fit=r['all_payloads_fit'],
            unaffected_partition_entries_preserved=unchanged, phone_contacted=False,
            phone_writes_enabled=False), indent=2))


if __name__ == '__main__':
    main()
