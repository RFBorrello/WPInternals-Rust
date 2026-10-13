"""Deterministic code-generated app icon; no external assets or image dependencies."""
from pathlib import Path
import struct
import zlib

root = Path(__file__).resolve().parents[1] / "apps" / "desktop" / "icons"
root.mkdir(parents=True, exist_ok=True)

def png(size):
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            nx, ny = x / size, y / size
            ink = abs(nx - 0.5) + abs((ny - 0.43) * 2) < 0.27
            stripe = (0.30 < ny < 0.58 and abs(nx - 0.5) < 0.23 and abs((ny - 0.50) - (nx - 0.5) * 0.48) < 0.02)
            border = x < size * 0.07 or y < size * 0.07 or x > size * 0.93 or y > size * 0.93
            rgba = (21, 25, 30, 255) if border or ink or stripe else (178, 234, 203, 255)
            rows.extend(rgba)
    def chunk(name, data):
        return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")

for size in (32, 128, 256):
    (root / f"{size}x{size}.png").write_bytes(png(size))
icon = png(256)
(root / "icon.png").write_bytes(icon)
(root / "icon.ico").write_bytes(struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(icon), 22) + icon)
# macOS icon container with a 256px PNG representation.
(root / "icon.icns").write_bytes(b"icns" + struct.pack(">I", len(icon) + 16) + b"ic08" + struct.pack(">I", len(icon) + 8) + icon)
print(f"Generated icons in {root}")
