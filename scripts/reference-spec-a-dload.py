"""Generate/check synthetic legacy DLOAD vectors with the pinned C# CRC table.
No phone or OEM binaries. Independent byte-array overload translation from
QualcommDownload.cs (WPInternals 2.9.2, Rene Lergner, MIT).
"""
import argparse
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "programmer_reference", Path(__file__).with_name("reference-spec-a-programmer.py"))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def vectors(upstream):
    frame = reference.frame_encoder(upstream)
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    data = (fixtures / "spec-a" / "loader.mbn").read_bytes()
    root = hashlib.sha256((fixtures / "image-issuer" / "root.der").read_bytes()).digest()
    exchanges = []

    def add(request, reply):
        exchanges.append(dict(request=frame(request), response=frame(reply), error=None))

    add(b"\x06", b"\x02")
    add(b"\x18", b"\x18\x01\x00" + root)
    for offset in range(0, len(data), 256):
        chunk = data[offset:offset + 256]
        add(b"\x0f" + struct.pack(">IH", 0x2A000000 + offset, len(chunk)) + chunk, b"\x02")
    add(b"\x05" + struct.pack(">I", 0x2A000000), b"\x02")
    return dict(reference_commit=reference.COMMIT, synthetic_only=True,
        phone_writes_enabled=False, loader_sha256=hashlib.sha256(data).hexdigest(),
        decoded_bytes=len(data), exchanges=exchanges)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = vectors(args.upstream)
    if args.check:
        if json.loads(args.fixture.read_text(encoding="utf-8")) != expected:
            raise ValueError("Synthetic DLOAD fixture differs from independent reference")
        print("Synthetic DLOAD reference vectors match; no phone contacted")
    else:
        with args.fixture.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(expected, output, separators=(",", ":"))
            output.write("\n")
        print("Created synthetic DLOAD vectors; no phone contacted")


if __name__ == "__main__":
    main()
