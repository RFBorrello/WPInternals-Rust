"""Independent Python codec check of already-extracted local package files.

Usage: python scripts/reference-mainos-version.py firmware.reg firmware.dsm.xml
Outputs only version/length/hash metadata. Does not mount images or access USB.
This is a reference decoder, not the production validation policy.
"""
import argparse, gzip, hashlib, io, json, re
from pathlib import Path
from xml.etree import ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('registry', type=Path)
parser.add_argument('dsm', type=Path)
args = parser.parse_args()

def read(path):
    with path.open('rb') as stream:
        stored = stream.read(65537)
    if len(stored) > 65536:
        raise ValueError('stored package exceeds 64 KiB')
    if stored.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(stored)) as stream:
            expanded = stream.read(65537)
    else:
        expanded = stored
    if len(expanded) > 65536:
        raise ValueError('expanded package exceeds 64 KiB')
    return expanded, {'stored_bytes': len(stored), 'expanded_bytes': len(expanded), 'stored_sha256': hashlib.sha256(stored).hexdigest()}

reg, reg_metadata = read(args.registry)
dsm, dsm_metadata = read(args.dsm)
text = reg.decode('utf-16') if reg.startswith(b'\xff\xfe') else reg.decode('utf-8-sig')
key = r'HKEY_LOCAL_MACHINE\SYSTEM\Platform\DeviceTargetingInfo'
active, values = False, []
for line in text.splitlines():
    line = line.strip()
    if line.startswith('['):
        active = line.casefold() == ('[' + key + ']').casefold()
    elif active:
        match = re.fullmatch(r'"PhoneFirmwareRevision"\s*=\s*"([0-9]+(?:\.[0-9]+){3})"', line, re.I)
        if match:
            values.append(match.group(1))
if len(values) != 1:
    raise ValueError('no unique registry version')
ns = {'i': 'http://schemas.microsoft.com/embedded/2004/10/ImageUpdate'}
identity = ET.fromstring(dsm).find('i:Identity', ns)
version = identity.find('i:Version', ns)
parts = [int(version.attrib[k]) for k in ('Major', 'Minor', 'QFE', 'Build')]
assert parts == [int(n) for n in values[0].split('.')], 'versions disagree'
assert [identity.find('i:' + k, ns).text for k in ('Owner', 'Component', 'SubComponent')] == ['Nokia', 'DeviceInfo', 'PhoneFirmwareRevision']
print(json.dumps({'registry_version': values[0], 'dsm_components': parts, 'versions_agree': True, 'registry': reg_metadata, 'dsm': dsm_metadata}, indent=2))
