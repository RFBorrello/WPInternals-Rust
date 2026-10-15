# Synthetic fixtures

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
The minimal NTFS reader image is generated with `python scripts/generate-ntfs-fixture.py`.
These images contain recognizable test bytes, not a phone operating system. Never flash or mount them.

`mode-normal-to-flash.json` is generated with `python scripts/generate-mode-fixture.py`.
It contains invented descriptors, a synthetic serial, normal information responses,
one send-only mode request and fresh flash responses. It runs only through the
concrete replay engine, without contacting USB. It is not hardware evidence.

`rm875-validation.json` records metadata and hashes for a separately supplied real image; proprietary firmware is not included.
