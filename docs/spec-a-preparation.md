# Offline Spec A boot-file preparation

Open a local FFU on the firmware page, optionally import an extracted raw SBL3
and local HEX/MBN programmers, then select **Check boot files**. Desktop uses
Tauri IPC and native Rust; the browser uses the same Rust parser in its worker.
Neither route enumerates USB, changes modes, generates exploit payloads, or
writes to a phone. Reports always keep `phone_writes_enabled: false` and cannot
grant execution permission.

```sh
wpi prepare-spec-a stock.ffu --loader programmer.hex --loader another.mbn
wpi prepare-spec-a stock.ffu --sbl3 extracted-sbl3.bin --loader programmer.hex
```

Repeat `--loader` for at most 32 files. Raw SBL3 imports are limited to 4 MiB and
programmers to 512 KiB each. To use SBL3 from another FFU, first extract its SBL3
partition. Extraction and filenames do not prove engineering status or donor
suitability. All processing and imports stay local.

## Implemented checks

- Unique SBL1/SBL2/SBL3 GPT names, checked ranges, and partitions at most 4 MiB,
  reconstructed through the existing FFU mapping reader.
- Raw short v3 and long Qualcomm MBN headers; upstream's `0x2800` SBL1 offset;
  bounded contiguous code/signature/chain regions; address overflow; bounded DER
  X.509 parsing. ELF programmers remain explicitly unsupported.
- Complete partition/import SHA-256 and each DER certificate's SHA-256. The last
  certificate's fingerprint is what upstream compares with RRKH. It is **not**
  a phone RRKH reading, signature verification, independent trust anchor, or
  the FFU catalog's Nokia Production PK.
- Intel HEX lengths, checksums, contiguous addresses, address-space bounds,
  supported record types and EOF. Decoded HEX is limited to 256 KiB. Upstream
  concatenates data records; this implementation rejects gaps and overlaps.
- UTF-16LE `QHSUSB_ARMPRG` V1 marker inside parsed loader code, plus equality with
  stock SBL1's last-certificate fingerprint. Programmers are never uploaded or
  executed, and marker/fingerprint matches do not establish phone acceptance.
- SBL2/SBL3 patch previews only when the expected upstream pattern occurs exactly
  once inside parsed code. Expected/replacement bytes are shown without modifying
  sources or exporting patched binaries.
- External SBL3 size versus the stock SBL3 partition. Size establishes neither
  engineering status nor hardware compatibility.

Browser File references go to the worker without copying whole FFUs through UI
messages. Rust's file callbacks read at most 64 KiB. Only bounded boot partitions
and imported programmers are retained. Exports contain hashes/offsets/metadata,
not firmware or certificate bytes, serials, IMEIs or public IDs.

Derived from WPInternals stable 2.9.2, commit
`d8fd0aa516b16dc094df0422a3adc525af005c29`: `QualcommPartition.cs`,
`QualcommLoader.cs`, `SBL2.cs` and `SBL3.cs`. Attribution and MIT license are
preserved in `THIRD_PARTY_NOTICES.md` and `resources/upstream/LICENSE`.

## RM-875 evidence — October 15, 2026

Read-only native identification confirmed the connected Lumia 1020 RM-875,
product code 059T909, firmware `3051.50009.1451.1003`, in Normal mode on Windows
ARM64. No mode changes, programmer uploads or partition writes were sent.

The existing stock FFU is `3051.50009.1424.0002`, platform
`Nokia.MSM8960.P5217`, older than the installed firmware. All three boot images
parsed; SBL2/SBL3 each have one expected patch location. Two existing programmers,
`FAST8960_RM875.hex` and `RM875_prg_v1.0.hex`, passed HEX/MBN checks, contained the
V1 marker, and shared stock SBL1's last-certificate fingerprint. Native results
match the independent pinned-algorithm translation `scripts/reference-spec-a.py`.
Metadata-only evidence is in `tests/fixtures/rm875-spec-a-validation.json`.

No external engineering SBL3 was identified in the searched local phone project
and Downloads locations. Stock SBL3 patch matching does not prove engineering
mass-storage support.

## Remaining work before a live unlock

This milestone does not implement SBL1 exploit prerequisites/payload generation,
UEFI reconstruction/patching, EFIESP donor applicability, GPT changes, or an unlock
executor. FFU integrity, OEM trust and firmware applicability still require the
separate recovery preparation checks; boot-file preparation does not reverify
the entire FFU.

A separately reviewed hardware step must establish fresh device RRKH, Flash
application/security state, live partition layout, installed originals where
recoverable, and interruption recovery. Neither programmer candidate has been
tested on the phone. Engineering SBL3 provenance and suitability remain unresolved.
Spec B and WP7 need distinct workflows. Builds, patterns and fingerprints cannot
enable live writes.
