"""Independently compare local Spec A programmer-phase metadata; no device I/O.

Uses Python ZIP/CRC/SHA and the separate pinned GPT translation, not Rust output
bytes. Never prints identifiers or extracts firmware. Assertions require Python
without -O. This verifies calculations, not phone acceptance or preservation.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "reference_package", Path(__file__).with_name("reference-spec-a-package.py"))
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
BOOT = {"SBL1", "SBL2", "SBL3", "UEFI", "TZ", "RPM", "WINSECAPP"}
ORDER = ["HACK", "MBR", "GPT", "SBL2", "SBL3", "UEFI", "SBL1", "TZ", "RPM", "WINSECAPP"]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check(package, primary_path, report_path):
    assert package.is_file() and package.stat().st_size <= 512 * 1024 * 1024
    assert primary_path.is_file() and primary_path.stat().st_size == 17408
    assert report_path.is_file() and report_path.stat().st_size <= 1024 * 1024
    primary = primary_path.read_bytes()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == 1 and report["kind"] == "wpi-spec-a-programmer-replay-plan"
    layout = report["layout"]
    assert digest(package) == layout["package_sha256"]
    assert ref.sha(primary) == layout["saved_primary_sha256"]
    assert struct.unpack_from("<Q", primary, 544)[0] + 1 == layout["recorded_capacity_sectors"]
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        assert len(infos) <= 128 and len({i.filename for i in infos}) == len(infos)
        assert all(i.compress_type == 0 and i.file_size <= 128 * 1024 * 1024 for i in infos)
        assert archive.getinfo("manifest.json").file_size <= 1024 * 1024
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        assert ref.sha(manifest_bytes) == layout["manifest_sha256"]
        assert manifest["source_platform"] == "Nokia.MSM8960.P5217"
        assert manifest["source_ffu_sha256"] == layout["source_ffu_sha256"]
        assert {i.filename for i in infos} == {f["path"] for f in manifest["files"]} | {"manifest.json"}
        for file in manifest["files"]:
            info = archive.getinfo(file["path"])
            assert file["size"] == info.file_size and file["crc32"] == info.CRC
            with archive.open(info) as source:
                assert hashlib.file_digest(source, "sha256").hexdigest() == file["sha256"]
        candidate, swapped = ref.expected_gpt(primary, manifest["external_sbl3"])
        assert ref.sha(candidate) == layout["candidate_primary_sha256"]
        assert swapped == layout["normalized_backup_pairs"]
        current = dict(ref.gpt_entries(primary))
        prepared = dict(ref.gpt_entries(candidate))
        assert primary[-1] == candidate[-1]
        assert [t["target"] for t in report["transfers"]] == ORDER
        intervals = []
        for row in report["transfers"]:
            target = row["target"]
            if target == "MBR":
                path, start, data, omitted = "saved-primary/MBR", 0, primary[:512], 0
            elif target == "GPT":
                path, start, data, omitted = "live-derived/GPT-primary", 512, candidate[512:-1], 1
                assert len(data) == 0x41FF
            else:
                path = f"prepared/{target}.img"
                original = archive.read(path)
                first, last = struct.unpack_from("<QQ", prepared[target], 32)
                start, capacity = first * 512, (last - first + 1) * 512
                assert len(original) <= capacity
                if target == "SBL1":
                    source = archive.read("original/SBL1.img")
                    assert len(source) == capacity + 512 and len(original) == capacity
                    assert source[:capacity] == original
                    length = capacity - 512
                elif target == "WINSECAPP":
                    length = min(len(original), 0x1E7FE00 - start)
                else:
                    length = len(original)
                assert 0 < length <= len(original)
                data, omitted = original[:length], len(original) - length
            assert row == dict(target=target, source_path=path, start_bytes=start,
                byte_length=len(data), sha256=ref.sha(data), omitted_tail_bytes=omitted)
            end = start + len(data)
            assert 0 <= start < end <= 2**32
            for table in [current, prepared]:
                for name, entry in table.items():
                    if name in BOOT or name == "HACK" or name.removeprefix("BACKUP_") in BOOT:
                        continue
                    first, last = struct.unpack_from("<QQ", entry, 32)
                    assert end <= first * 512 or start >= (last + 1) * 512
            intervals.append((start, end))
        intervals.sort()
        assert all(left[1] <= right[0] for left, right in zip(intervals, intervals[1:]))
        assert sum(t["byte_length"] for t in report["transfers"]) == report["total_transfer_bytes"]
        assert report["unrelated_partition_write_ranges_excluded"] and report["replay_only"]
        assert not any(report[k] for k in ["phone_contacted", "phone_writes_enabled", "data_preservation_validated"])
        assert not any(layout[k] for k in ["phone_contacted", "phone_writes_enabled", "backup_gpt_captured", "installed_partitions_preserved"])
    return dict(comparison="matches", report_sha256=digest(report_path),
        package_sha256=layout["package_sha256"], saved_primary_sha256=layout["saved_primary_sha256"],
        candidate_primary_sha256=layout["candidate_primary_sha256"], transfer_count=len(ORDER),
        total_transfer_bytes=report["total_transfer_bytes"],
        unrelated_partition_write_ranges_excluded=True, data_preservation_validated=False,
        phone_contacted=False, phone_writes_enabled=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("primary", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.package, args.primary, args.report), indent=2))


if __name__ == "__main__":
    main()
