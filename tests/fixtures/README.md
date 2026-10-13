# Synthetic fixtures

FFU/GPT images are generated with `python scripts/generate-fixtures.py`.
The minimal NTFS reader image is generated with `python scripts/generate-ntfs-fixture.py`.
These images contain recognizable test bytes, not a phone operating system. Never flash or mount them.

`mode-normal-to-flash.json` is generated with `python scripts/generate-mode-fixture.py`.
It contains invented descriptors, a synthetic serial, normal information responses,
one send-only mode request and fresh flash responses. It runs only through the
concrete replay engine, without contacting USB. It is not hardware evidence.

`rm875-validation.json` records metadata and hashes for a separately supplied real image; proprietary firmware is not included.
