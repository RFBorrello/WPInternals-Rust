# Spec A offline intermediate images

The shared Rust engine can rebuild UEFI and assemble EFIESP into new local files.
This advances image processing; neither output is a complete unlock package or a
signed FFU. No device discovery, mode commands, loader uploads or phone writes
are part of these operations. Spec B and WP7 require separate implementations.

In the web or desktop interface, import the stock FFU and use **Save rebuilt UEFI
copy** in Spec A bootloader preparation. For EFIESP, import a separately assessed
donor FFU and use **Save assembled EFIESP copy**. Each operation verifies its
output before saving and offers an assembly report containing hashes and checks.
Use a new destination; nonempty browser destinations and existing native output
paths are refused. Nothing is uploaded to a processing service.

CLI equivalents:

```text
wpi assemble-spec-a stock.ffu uefi UEFI-offline.img
wpi assemble-spec-a stock.ffu efiesp EFIESP-offline.img --donor donor.ffu
```

UEFI output supports the short v3 Qualcomm MBN layout and the bounded FV/FFS,
GUID-defined LZMA and ARM32 PE profiles accepted by inspection. It applies only
the reviewed SecurityDxe and SecurityServicesDxe patches, clears their PE
checksums, recalculates FFS checksums and recompresses with a portable Rust LZMA
encoder (preset 6, 4 MiB dictionary, lc=3/lp=0/pb=2). Compression must fit the
original fixed volume. Repacking preserves other outer files byte for byte;
unsupported alignment requirements fail explicitly. Reparsed output must
decompress to the expected patched contents with valid filesystem checksums.
The original partition length is retained. The invalidated MBN signature and
certificate references are cleared and their old region zeroed. The result is
deliberately unsigned; the signed-input parser will refuse it as a new input.

EFIESP assembly accepts an extracted FAT partition of at most 128 MiB with
matching geometry. It copies the stock partition in bounded chunks, replaces
`Windows/System32/Boot/mobilestartup.efi` with the hash-pinned catalog-patched
donor bytes, and edits `efi/Microsoft/Boot/BCD`. The original boot file may be a
different length. Directory names and contents of every other file are compared
before and after assembly; target hashes must match the expected results.
The boot import is limited to 4 MiB, BCD to 1 MiB. Directory depth/count, bytes
hashed and filesystem I/O calls have explicit budgets, including corrupt chains.

The REGF editor sets the one-byte REG_BINARY NoCodeIntegrity element `16000048`
under the mobile startup object `{01de5a27-8705-40db-bad6-96fa5187d4a6}` and
Windows loader object `{7619dcc9-fafe-11d9-b411-000476eba25f}`. Missing element
keys and values are allocated from existing free cells. Clean supported REGF
versions, cell extents, parent links, subkey indexes/hashes and value bounds are
checked. Dirty hives needing log replay, insufficient free cells, unsupported
names/types and cycles fail. A full semantic comparison permits exactly these
two value changes. Repeating an already applied edit is idempotent.

The Chromium worker maps source FFU ranges through bounded synchronous reads
(at most 64 KiB, eight cached read-only pages). EFIESP random writes use a new
OPFS scratch file; the verified result is streamed to the selected destination
in 1 MiB chunks, then scratch storage is removed. Images never travel through
UI messages. Browser saving requires the file picker and scratch access; missing
APIs or storage quota errors are explicit. Use the desktop app when unavailable.
Native output uses temporary regular files and atomic creation without overwrite.
Cancellation is observed at copy/stage/publication boundaries; synchronous
compression or filesystem validation finishes its bounded batch first.

These transforms do not reverify the complete FFU or establish OEM trust,
firmware applicability, engineering-loader provenance or cross-version donor
compatibility. The current stock RM-875 image is older than installed firmware.
SBL1 payload generation, GPT changes, a complete unlock package and an executor
remain outstanding, along with preservation of installed originals and hardware
validation. No live capability is enabled by successful local assembly.

Synthetic tests cover reconstruction, unchanged files, malformed cells, cycles,
allocation exhaustion, idempotence, cancellation and atomic output preservation.
`scripts/reference-spec-a-assembly.py` independently compares real output using
Python LZMA and direct FAT16/REGF readers. See the metadata-only evidence in
`tests/fixtures/rm875-assembly-validation.json`; proprietary binaries are excluded.
