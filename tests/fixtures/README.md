# Synthetic fixtures

`python scripts/make-spec-a-offline-fixtures.py` generates synthetic SBL1 patterns,
UEFI FV/FFS/LZMA containers, dummy ARM PE sections and `synthetic-spec-a-offline.ffu`
with a small FAT tree. `spec-a/offline-reference.json` contains independent expected
hashes/offsets. Firmware signatures are zero-filled; no real firmware, exploit
sector, private keys or usable programmer is included. The dummy BCD file is only
a presence/read fixture, not a validated hive. Real metadata/provenance comparisons
are in `rm875-offline-checks-validation.json`; downloaded SBL3 bytes are excluded.

`python scripts/make-spec-a-fixtures.py` generates the non-flashable
`synthetic-spec-a.ffu` and `spec-a/` raw/HEX fixtures, using the existing synthetic
image-issuer certificate. The code regions are invented test bytes, signatures
are zero-filled, and no executable programmer or exploit payload is included.
`spec-a/reference.json` records expected hashes/offsets. Metadata from separately
supplied real RM-875 files is recorded in `rm875-spec-a-validation.json`.

`python scripts/make-image-issuer-fixture.py` creates disposable production/wrong-key
provisioning files under `image-issuer` and two FAT-backed synthetic FFUs. Complete
authority-name/serial identifiers exercise the narrow issuer profile. The auth
wrappers contain no valid enrollment authorization; all keys are discarded.
`rm875-image-issuer-validation.json` records only real-image certificate metadata,
signature comparisons and bounded I/O, never OEM certificate or firmware bytes.

`python scripts/make-signer-fixtures.py` creates disposable public certificate
chains and policy-failure catalogs under `signer-policy`, plus `synthetic-chain.ffu`
and `synthetic-bad-signer.ffu`. No private keys are saved; none is an OEM anchor.
`rm875-signer-targeting-validation.json` retains only offline validation metadata.
The MainOS generator also includes synthetic `OEMSettings.reg` targeting values.

`rm875-browser-integrity-validation.json` records complete browser hashing and
chunk verification of the separately supplied local FFU, read-size/progress
auditing and comparison with the prior native digest. It contains no image bytes.

`python scripts/make-mainos-fixture.py` generates `ntfs-firmware.img` and
`synthetic-mainos.ffu` with project-generated, gzip-compressed registry/DSM package
metadata, nested NTFS directories and matching version `1.2.3.0004`. These are
reader fixtures, never flashable firmware. `rm875-mainos-validation.json` records
only local validation metadata; no proprietary package contents are included.

FFU/GPT images are generated with `python scripts/generate-fixtures.py`.

`python scripts/make-spec-a-preflight-fixtures.py` generates
`spec-a-preflight-locked.json` and `spec-a-preflight-primary.json` from the
synthetic package FFU. Both contain invented Flash security responses and an
invented public ID. The locked replay contains no NOKT/context change; the other
contains only synthetic primary GPT sectors. These files are protocol tests,
not device observations or authorization to flash.
The minimal NTFS reader image is generated with `python scripts/generate-ntfs-fixture.py`.
These images contain recognizable test bytes, not a phone operating system. Never flash or mount them.

`mode-normal-to-flash.json` is generated with `python scripts/generate-mode-fixture.py`.
It contains invented descriptors, a synthetic serial, normal information responses,
one send-only mode request and fresh flash responses. It runs only through the
concrete replay engine, without contacting USB. It is not hardware evidence.

`rm875-validation.json` records metadata and hashes for a separately supplied real image; proprietary firmware is not included.
