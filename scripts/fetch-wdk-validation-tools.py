"""Fetch pinned Microsoft WDK validators into a NEW private tool directory.

Does not install the WDK, stage drivers, run installers, or access a phone.
Microsoft's package/license stays local; no tool binary is redistributed.
"""
import argparse
import hashlib
from pathlib import Path
import urllib.request
import zipfile

VERSION = '10.0.28000.2526'
SHA256 = 'dcd83a77c83ee3163fa07b26421c0b132af0ea446d391bda2e63ac6664a261a5'
URL = f'https://api.nuget.org/v3-flatcontainer/microsoft.windows.wdk.arm64/{VERSION}/microsoft.windows.wdk.arm64.{VERSION}.nupkg'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=False, exist_ok=False)
    package = output / 'wdk.nupkg'
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(URL, timeout=30) as response, package.open('xb') as target:
        while block := response.read(65536):
            total += len(block)
            if total > 64 * 1024 * 1024:
                raise ValueError('WDK package exceeds selected bound')
            digest.update(block)
            target.write(block)
    if digest.hexdigest() != SHA256:
        raise ValueError('WDK package digest changed; review upstream before updating the pin')
    with zipfile.ZipFile(package) as archive:
        entries = [e for e in archive.infolist() if
                   e.filename.startswith('c/bin/10.0.28000.0/x86/') or
                   e.filename.startswith('c/tools/10.0.28000.0/ARM64/') or
                   e.filename == 'LICENSE.txt']
        if len(entries) > 400 or sum(e.file_size for e in entries) > 64 * 1024 * 1024:
            raise ValueError('Validator extraction exceeds selected bound')
        seen = set()
        for entry in entries:
            path = (output / entry.filename).resolve()
            if not path.is_relative_to(output) or str(path).casefold() in seen:
                raise ValueError('Unsafe or duplicate validator archive path')
            seen.add(str(path).casefold())
            if entry.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, path.open('xb') as target:
                count = 0
                while block := source.read(65536):
                    count += len(block)
                    if count > entry.file_size:
                        raise ValueError('Validator stream exceeds declared length')
                    target.write(block)
                if count != entry.file_size:
                    raise ValueError('Truncated validator archive member')
    print(f'Pinned WDK {VERSION}: {total} downloaded bytes; local validators only.')


if __name__ == '__main__':
    main()
