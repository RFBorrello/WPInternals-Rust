"""Invented, read-only Flash preflight exchanges. No device/OEM response bytes.
Run after make-spec-a-package-fixture.py. Uses the independent FFU reader.
"""
import hashlib
import importlib.util
import json
import struct
from pathlib import Path

root = Path(__file__).resolve().parents[1]
fixtures = root / 'tests/fixtures'
spec = importlib.util.spec_from_file_location('package_reference', Path(__file__).with_name('reference-spec-a-package.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
ffu = reference.Ffu(fixtures / 'synthetic-spec-a-package.ffu')
primary = bytes(ffu.read(0, 34 * 512))
# Synthetic FFU platform comes from its actual store header, not a phone label.
ffu.file.seek(ffu.header - ffu.chunk + 12)
platform = ffu.file.read(192).rstrip(b'\0 ')
assert platform.startswith(b'SYNTHETIC.')
rrkh = hashlib.sha256((fixtures / 'image-issuer/root.der').read_bytes()).digest()
assert rrkh.hex() == json.loads((fixtures / 'spec-a/reference.json').read_text())['root_certificate_sha256']

def parameter_request(name):
    return b'NOKXFR\0' + name.ljust(4, b'\0')

def parameter(payload):
    return b'NOKXFR' + bytes(10) + bytes([len(payload)]) + payload

terminal_request = bytearray(172)
terminal_request[:8] = b'NOKXFT\0\x01'
struct.pack_into('>II', terminal_request, 8, 0x18, 0x9c)
terminal_request[20:36] = bytes([1, 0, 16, 4] + [0] * 11 + [64])
terminal = bytearray(60)
terminal[:6] = b'NOKXFT'
struct.pack_into('>I', terminal, 20, 36)
struct.pack_into('<IIII', terminal, 24, 0x10000, 28, 3, 20)
terminal[40:] = bytes(range(1, 21))  # Invented disposable ID, never a real phone.

def exchange(request, response):
    return dict(request=list(request), response=list(response), error=None)

for locked in (True, False):
    app = b'NOKV\0\x02\x01\x12\x02\x02\x02' + bytes([5, 0, len(platform)]) + platform
    app += bytes([15, 0, 8, 3, 1, int(locked), 1, 0, 0, 1, 1])
    exchanges = [exchange(b'NOKV', app), exchange(terminal_request, terminal),
                 exchange(parameter_request(b'RRKH'), parameter(rrkh)),
                 exchange(parameter_request(b'SS'), parameter(bytes([0, 1, int(locked), 1, 0, 0, 1, 1])))]
    if not locked:
        exchanges.append(exchange(b'NOKT', b'NOKT' + bytes(4) + primary))
    exchanges += [exchange(b'NOKV', app), exchange(terminal_request, terminal)]
    name = 'spec-a-preflight-locked.json' if locked else 'spec-a-preflight-primary.json'
    (fixtures / name).write_text(json.dumps(dict(exchanges=exchanges), separators=(',', ':')) + '\n')
ffu.file.close()
