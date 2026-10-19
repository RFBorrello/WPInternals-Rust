"""Check the binding's deliberate device/architecture scope, not INF signability.

Microsoft InfVerif/Inf2Cat supply the separate syntax/signability checks.
"""
import configparser
import hashlib
from pathlib import Path
import uuid

path = Path(__file__).resolve().parent.parent / 'resources/windows/emergency/wpi-emergency.inf'
text = path.read_text(encoding='ascii')
assert hashlib.sha256(path.read_bytes()).hexdigest() == '7cbc413e8d74653a597531beabad26a4d3371199902d73ad70194cc668c1e3dd'
inf = configparser.ConfigParser(interpolation=None, strict=True, allow_no_value=True,
                               delimiters=('=',), comment_prefixes=(';',),
                               inline_comment_prefixes=(';',))
inf.read_string(text)
assert set(inf.sections()) == {'Version', 'Manufacturer', 'Models.NTarm64.10.0',
                              'Models.NTamd64.10.0', 'Emergency.NT',
                              'Emergency.NT.Services', 'Emergency.NT.HW',
                              'EmergencyInterface', 'Strings'}
assert inf['Manufacturer']['%ProviderName%'].replace(' ', '') == 'Models,NTarm64.10.0,NTamd64.10.0'
for arch in ['NTarm64', 'NTamd64']:
    assert dict(inf[f'Models.{arch}.10.0']) == {'%devicename%': r'Emergency,USB\VID_05C6&PID_9008'}
assert inf['Version']['class'] == 'USBDevice'
assert inf['Version']['classguid'].upper() == '{88BAE032-5A81-49F0-BC3D-A4FF138216D6}'
assert inf['Version']['pnplockdown'] == '1'
assert inf['Version']['catalogfile'] == 'wpi-emergency.cat'
assert dict(inf['Emergency.NT']) == {'include': 'winusb.inf', 'needs': 'WINUSB.NT'}
assert dict(inf['Emergency.NT.Services']) == {'include': 'winusb.inf', 'needs': 'WINUSB.NT.Services'}
assert dict(inf['Emergency.NT.HW']) == {'addreg': 'EmergencyInterface'}
registry_lines = list(inf['EmergencyInterface'])
assert len(registry_lines) == 1
guid = '{8f66c6e8-c607-4d4d-b107-7ec707a76620}'
assert registry_lines[0] == f'hkr,,deviceinterfaceguids,0x00010000,"{guid}"'
assert uuid.UUID(guid).int != 0
assert not any(word in text.lower() for word in ['pid_f006', 'ms_comp_winusb', 'coinstallers=', 'servicebinary', 'copyfiles'])
print('Scope checked: ARM64/x64, exact 05c6:9008 only, in-box WinUSB, one GUID; no broad class binding.')
