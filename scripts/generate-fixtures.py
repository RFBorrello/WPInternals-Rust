"""Create tiny synthetic format fixtures. These are NOT flashable phone firmware."""
from pathlib import Path
import hashlib
import struct
import zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "fixtures"
OUT.mkdir(parents=True, exist_ok=True)
SECTOR = 512
CHUNK = 4096
disk = bytearray(48 * SECTOR)
disk[510:512] = b"\x55\xaa"
entries = bytearray(128 * 128)
for index, (name, first, last) in enumerate([("EFIESP", 34, 37), ("MainOS", 38, 46)]):
    at = index * 128
    entries[at:at + 16] = bytes.fromhex("28732AC11FF8D211BA4B00A0C93EC93B")
    entries[at + 16:at + 32] = bytes([index + 1]) * 16
    struct.pack_into("<QQQ", entries, at + 32, first, last, 0)
    encoded = name.encode("utf-16-le")
    entries[at + 56:at + 56 + len(encoded)] = encoded
header = bytearray(SECTOR)
header[:8] = b"EFI PART"
struct.pack_into("<III", header, 8, 0x10000, 92, 0)
struct.pack_into("<QQQQ", header, 24, 1, 47, 34, 46)
header[56:72] = bytes([0x55]) * 16
struct.pack_into("<QIII", header, 72, 2, 128, 128, zlib.crc32(entries))
struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
disk[512:1024] = header
disk[1024:1024 + len(entries)] = entries
disk[34 * SECTOR:38 * SECTOR] = b"\xab" * (4 * SECTOR)
disk[38 * SECTOR:47 * SECTOR] = b"\xcd" * (9 * SECTOR)

security = bytearray(CHUNK)
security[4:16] = b"SignedImage "
struct.pack_into("<I", security, 0, 32)
struct.pack_into("<IIII", security, 16, CHUNK // 1024, 0x800c, 0, 8 * 32)
image = bytearray(CHUNK)
manifest = b'<FullFlashUpdateImage><Description>Synthetic fixture; do not flash</Description></FullFlashUpdateImage>'
struct.pack_into("<I", image, 0, 24)
image[4:16] = b"ImageFlash  "
struct.pack_into("<II", image, 16, len(manifest), CHUNK // 1024)
image[24:24 + len(manifest)] = manifest
store = bytearray(CHUNK)
struct.pack_into("<IHHHH", store, 0, 0, 1, 0, 2, 0)
platform = b"SYNTHETIC.LUMIA.TEST"
store[12:12 + len(platform)] = platform
struct.pack_into("<IIIII", store, 204, CHUNK, 1, 16, 0, 0)
struct.pack_into("<IIII", store, 248, 1, len(disk) // CHUNK, 0, 0)
hashed = bytes(image + store + disk)
hashes = b"".join(hashlib.sha256(hashed[i:i + CHUNK]).digest() for i in range(0, len(hashed), CHUNK))
security[32:32 + len(hashes)] = hashes
(OUT / "synthetic.ffu").write_bytes(security + hashed)
(OUT / "synthetic.img").write_bytes(disk)
(OUT / "gpt.bin").write_bytes(header + entries)
(OUT / "README.md").write_text("# Synthetic fixtures\n\nFFU/GPT images are generated with `python scripts/generate-fixtures.py`.\nThe minimal NTFS reader image is generated with `python scripts/generate-ntfs-fixture.py`.\nThese images contain recognizable test bytes, not a phone operating system. Never flash or mount them.\n\n`rm875-validation.json` records metadata and hashes for a separately supplied real image; proprietary firmware is not included.\n", encoding="utf-8")
print(f"Generated fixtures in {OUT}")
