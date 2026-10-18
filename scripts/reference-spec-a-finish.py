"""Independent Spec A UEFI-variable/dual-EFIESP calculation; local files only.

Ports LumiaUnlockUEFI and LumiaGenerateEFIESPFlashPayload from WPInternals 2.9.2
(Rene Lergner, MIT). Does not extract images or contact USB. Never prints disk
identifiers. Run without -O: assertions validate calculations, not phone support.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import struct
import uuid
import zipfile
import zlib
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "package_reference", Path(__file__).with_name("reference-spec-a-package.py"))
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check(package, primary_path, report_path):
    assert package.is_file() and package.stat().st_size <= 512 * 1024**2
    assert primary_path.is_file() and primary_path.stat().st_size == 17408
    assert report_path.is_file() and report_path.stat().st_size <= 1024**2
    primary = primary_path.read_bytes()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == 1 and report["kind"] == "wpi-spec-a-finish-reference-plan"
    assert digest(package) == report["package_sha256"]
    assert ref.sha(primary) == report["saved_primary_sha256"]
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        assert len(infos) <= 128 and len({i.filename for i in infos}) == len(infos)
        assert all(i.compress_type == 0 and i.file_size <= 128 * 1024**2 for i in infos)
        assert archive.getinfo("manifest.json").file_size <= 1024**2
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["external_sbl3"]
        assert manifest["source_ffu_sha256"] == report["source_ffu_sha256"]
        for file in manifest["files"]:
            with archive.open(file["path"]) as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == file["sha256"]
        boot, _ = ref.expected_gpt(primary, True)
        assert ref.sha(boot) == report["expected_boot_primary_sha256"]
        entries = ref.gpt_entries(boot)
        current = dict(entries)
        assert "BACKUP_BS_NV" not in current
        old = current["UEFI_BS_NV"]
        first, last = struct.unpack_from("<QQ", old, 32)
        start = last + 1
        end = start + last - first
        assert all(name == "UEFI_BS_NV" or b < start or a > end
                   for name, entry in entries
                   for a, b in [struct.unpack_from("<QQ", entry, 32)])
        backup = bytearray(old)
        backup[56:128] = "BACKUP_BS_NV".encode("utf-16le").ljust(72, b"\0")
        for at, label in [(16, b"SpecA NV backup id"), (0, b"SpecA NV backup type")]:
            raw = bytearray(hashlib.sha256(boot + label).digest()[:16])
            raw[6] = raw[6] & 15 | 0x40
            raw[8] = raw[8] & 63 | 0x80
            backup[at:at+16] = uuid.UUID(bytes=bytes(raw)).bytes_le
        active = bytearray(old)
        struct.pack_into("<QQ", active, 32, start, end)
        all_entries = [backup if name == "UEFI_BS_NV" else entry for name, entry in entries] + [active]
        table = b"".join(all_entries).ljust(16384, b"\0")
        result = bytearray(boot)
        result[1024:] = table
        struct.pack_into("<I", result, 600, zlib.crc32(table))
        result[528:532] = b"\0" * 4
        struct.pack_into("<I", result, 528, zlib.crc32(result[512:604]))
        ref.gpt_entries(result)
        assert ref.sha(result) == report["nv_primary_sha256"]
        original = archive.read("original/EFIESP.img")
        patched = archive.read("prepared/EFIESP.img")
        esp_first, esp_last = struct.unpack_from("<QQ", current["EFIESP"], 32)
        assert len(original) == len(patched) == (esp_last - esp_first + 1) * 512
        old_reserved = struct.unpack_from("<H", original, 14)[0]
        reserved = min(65535, (esp_last - esp_first + 1) // 2 - old_reserved + 1)
        assert reserved > old_reserved
        prefix = bytearray(original[:old_reserved * 512])
        struct.pack_into("<H", prefix, 14, reserved)
        tail = patched[old_reserved * 512:old_reserved * 512 + len(patched) - reserved * 512]
        assert report["enlarged_reserved_sectors"] == reserved
        assert ref.sha(original) == report["original_efiesp_sha256"]
        assert ref.sha(patched) == report["prepared_efiesp_sha256"]
        compressed = (Path(__file__).parents[1] / "resources/upstream/SBA").read_bytes()
        assert ref.sha(compressed) == "3fb77d37da8bb42cb65ff54998b5ba46ec625e3f949ec7ce3d3c2cb42bfbfb2a"
        nv = gzip.decompress(compressed[37:])
        assert len(nv) == (last - first + 1) * 512 == 262144
        assert ref.sha(nv) == "a6f1f290b1672abbb5e0eb8bf4482e033f3dc4b428f1f3374e127e461d29c7c6"
        def row(name, first, data):
            return dict(target=name, start_sector=first, byte_length=len(data), sha256=ref.sha(data))
        assert report["nv_stage"] == [row("UEFI_BS_NV", start, nv), row("GPT-primary", 0, result)]
        assert report["efiesp_stage"] == [row("EFIESP-prefix", esp_first, prefix),
                                          row("EFIESP-second-view", esp_first + reserved, tail)]
        assert report["original_nv_partition_retained"] and report["unrelated_partition_entries_preserved"]
        assert not any(report[k] for k in ["installed_originals_captured", "data_preservation_validated", "phone_writes_enabled", "phone_contacted"])
    return dict(comparison="matches", scope="offline_first_uefi_efiesp_pass_only",
                report_sha256=digest(report_path), source_ffu_sha256=report["source_ffu_sha256"],
                package_sha256=report["package_sha256"], saved_primary_sha256=report["saved_primary_sha256"],
                nv_primary_sha256=report["nv_primary_sha256"], transfer_count=4,
                enlarged_reserved_sectors=reserved,
                total_transfer_bytes=sum(r["byte_length"] for key in ["nv_stage", "efiesp_stage"] for r in report[key]),
                installed_originals_captured=False, data_preservation_validated=False,
                phone_contacted=False, phone_writes_enabled=False, device_unlock_verified=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["package", "primary", "report"]:
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.package, args.primary, args.report), indent=2))
