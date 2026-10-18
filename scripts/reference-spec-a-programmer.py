"""Generate/check synthetic V1 vectors with the pinned C# CRC lookup table.

No phone or firmware access. Uses git show rather than the upstream working tree.
Copyright (c) 2018 Rene Lergner for the referenced algorithm; MIT, see
resources/upstream/LICENSE. This independent translation does not import Rust.
"""
import argparse
import json
import re
import struct
import subprocess
from pathlib import Path

COMMIT = "d8fd0aa516b16dc094df0422a3adc525af005c29"


def frame_encoder(upstream):
    source = subprocess.run(
        ["git", "-C", str(upstream), "show", f"{COMMIT}:Models/QualcommSerial.cs"],
        check=True, capture_output=True, text=True,
    ).stdout
    table_source = source.split("ChecksumTable =", 1)[1].split("};", 1)[0]
    table = [int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{4})", table_source)]
    if len(table) != 256:
        raise ValueError("Expected the pinned 256-entry CRC table")

    def frame(payload):
        crc = 0xFFFF
        for byte in payload:
            crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
        escaped = bytearray([0x7E])
        for byte in payload + struct.pack("<H", crc ^ 0xFFFF):
            escaped.extend([0x7D, byte ^ 0x20] if byte in (0x7D, 0x7E) else [byte])
        escaped.append(0x7E)
        return list(escaped)

    return frame


def vectors(upstream):
    frame = frame_encoder(upstream)
    regions = [
        {"start_bytes": 0x200, "data": [(i * 17 + 0x7D) % 256 for i in range(2051)]},
        {"start_bytes": 0x1000, "data": [0x7E, 0x7D] * 256},
    ]
    exchanges = []

    def add(request, response):
        exchanges.append({"request": list(request), "response": frame(response), "error": None})

    add(b"\x01QCOM fast download protocol host\x02\x02\x01", b"\x02")
    add(b"\x17\x00", b"\x18")
    add(b"\x1b\x21", b"\x1c")
    for region in regions:
        data = bytes(region["data"])
        for offset in range(0, len(data), 0x400):
            address = struct.pack("<I", region["start_bytes"] + offset)
            add(b"\x07" + address + data[offset:offset + 0x400], b"\x08" + address)
    add(b"\x15", b"\x16")
    add(b"\x0b", b"\x0c")
    return {
        "reference_commit": COMMIT, "synthetic_only": True,
        "phone_writes_enabled": False, "regions": regions, "exchanges": exchanges,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upstream", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = vectors(args.upstream)
    if args.check:
        if json.loads(args.fixture.read_text(encoding="utf-8")) != expected:
            raise ValueError("Synthetic V1 fixture differs from the independent translation")
        print("Synthetic V1 reference vectors match; no phone contacted")
    else:
        with args.fixture.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(expected, output, separators=(",", ":"))
            output.write("\n")
        print("Created synthetic V1 reference vectors; no phone contacted")


if __name__ == "__main__":
    main()
