# RM-875 emergency entry: reference FlashApp analysis and recovery material

This milestone resolves the **reference binary's** end-relative mapping behavior.
It does not establish which binary is installed on the phone, perform an unlock,
or establish data preservation. No phone command was sent during this work.

## Exact artifact and observed instructions

The local, unmodified `3051.50009.1424.0002` FFU has SHA-256
`ce4724a1e4225f629ee4092400715dcd85d160470e1173c71c8065527e73e8c4`.
The image engine extracts `NokiaFlashApp` from its bounded UEFI FV/FFS/LZMA layers:

- UEFI SHA-256: `9497815e89f9359e8a7f4f181564cb7a62dcf949e6e41588547ec1e491fb7e4d`.
- FlashApp PE SHA-256: `503578ed1bb90406e19067664235f974a19216e25ff4c33565bdda9365b8a1e2`.
- PE machine `0x1c2`, image base zero. All file-backed section RVAs equal their
  raw file offsets in this particular PE; this is not a general PE assumption.

REA's configured deep providers could not analyze ARM firmware on this Windows
ARM64 host. Existing LLVM 21.1.8 disassembly, explicitly selecting
`--triple=armv7-windows`, supplied the instruction evidence. This is static ARM
assembly analysis and inference, not recovered source or runtime measurement.
Firmware executables and complete assembly stay local under ignored `artifacts/`.

| Location in this PE | Observed instructions and interpretation |
| --- | --- |
| `0xBBAC–0xBBB0` | Compare descriptor access method against 2; branch to `0xBBE8`, skipping creation of an extent for that location. |
| `0xBB70–0xBB74` | The pending-extent case makes the same comparison and branches to `0xBBE8`. |
| `0xBBE8–0xBC64` | Flush any pending begin-relative extent, then advance past the end-relative location without creating another write. |
| `0xB600–0xB658` | The chunk writer calls the disk-write routine at `0xCB44` with its supplied start sector/count. |
| `0xE5C0–0xE5C8` | Successful header import calls `erase_backup_gpt` at `0x96B8`. This precedes payload submission. |
| `0x96B8–0x9738` | Allocate and zero `33 * 512` bytes, obtain disk sector count, pass start `capacity - 33` and count 33 to `0xCB44`. |
| `0xE5C4`, `0xE5F0–0xE5F8` | The header-import status retained in `r6` forms the reply. The erase routine's return value is not propagated here. A success reply alone cannot prove the clear succeeded. |

For the pinned first zero chunk (one begin-zero and one end-zero location), the
inferred footprint is **sectors 0–255 plus the final 33 sectors**, rather than
two complete 256-sector boundary chunks. On the saved installed geometry, the
33-sector clear overlaps no Data sectors. The older conservative model's
223-sector Data intersection is retained as a separate bound for unknown
implementations. This analysis covers the entry sequence, not complete stock
FFU flashing or every command path in FlashApp.

`entry_code::inspect_uefi` requires this complete executable hash and checks the
documented instruction anchors. Unknown binaries receive no interpretation.
`EntryPlan` selects this evidence only after pinning the complete known source
FFU and extracting its UEFI through the verified chunk reader. Reports remain
non-authoritative; no installed profile or write capability is enabled.

The phone reports firmware `3051.50009.1451.1003`. A matching FlashApp UI version
does not prove binary equality. Its installed UEFI has not been captured. The
[LumiaDB catalog](https://lumiadb.com/database.json) still listed the older
1424.0002 file for product code `059T909` when checked for this milestone; the
catalog check did not provide an exact installed-version FFU. The non-payload
`NOKXCBE` alternative remains untested on RM-875; pinned upstream describes that
route as available on newer Lumias. The command-path analysis below now rules
it out for the exact reference FlashApp; the installed binary remains unknown.
No command fallback was added.

## Non-payload entry command: bounded negative result

The upstream switch-mode UI sends `NOKXCBE` to request emergency mode, but its
Normal-mode route is commented "Only available in new Lumia's". The older
Spec A unlock flow instead calls `PerformSoftBrick`, which sends the FFU header,
zero payload and reboot. These source observations do not by themselves prove
what either FlashApp binary implements.

Static ARM analysis of the exact reference PE resolves this command path:

| PE RVA / file offset | Observed control flow |
| --- | --- |
| `0x12684–0x12690` | Load command byte 3; subtract `D`; dispatch through a 23-slot branch table. |
| `0x126E8`, `0x127B0–0x127B4` | The `X` slot selects the extended handler at `0xFDA0`. |
| `0xFDA8`, `0xFDB8–0xFDBC` | Load command byte 4 and compare with `F`; only equality enters the implemented extended subcommands at `0xFDF0`. |
| `0xFDE0–0xFDEC` | Byte `C` follows the default path, preserving arguments and branching to `0xFEE0`. |
| `0xFEE0–0xFEE8` | Tail-branch to the unknown-command handler at `0x11E00`. |
| `0x11E50–0x11E78` | Store `N`, `O`, `K`, `U` into the reply buffer and return length four. |

This is a **reference-binary inference of an unsupported command**, not an
observed phone response. It does not establish that every non-payload route is
absent, or that the installed 1451.1003 image behaves identically. A matching
FlashApp version string is still insufficient to identify that image. The
result gives no reason to send a speculative emergency-mode request or to use
the storage-changing entry merely to discover a driver.

`inspect-spec-a-entry-code` now includes `reference_nokxcbe_supported=false` and
`reference_nokxcbe_response="NOKU"` only after the complete executable hash and
command-path instruction anchors agree. Mutation/truncation tests guard every
new anchor. The independent Python checker decodes the branch destinations,
calculates the `X` jump-table index and reconstructs the response from the ARM
immediates. See the [updated metadata evidence](../tests/fixtures/rm875-entry-code-validation.json).
Neither implementation executes firmware or contacts USB.

## GPT recovery capsule

`wpi prepare-spec-a-entry-recovery PRIMARY OUTPUT.zip --disk-sectors CAPACITY
--expect-primary-sha256 SHA256` creates a new private ZIP with:

- The supplied primary GPT, byte for byte, including its MBR.
- A **reconstructed** secondary using the same entries and disk GUID, reciprocal
  current/backup LBAs, the correct trailing table location, and recalculated CRC.
- A manifest identifying addresses, hashes, provenance limitations and disabled
  execution flags. The generated ZIP is reread before successful publication.

The real saved primary produced a 36,250-byte capsule. Its reconstructed
secondary has SHA-256
`35081151f513c5729c62e9cf726a59fc26a400c690cf97618004f7c79e3b6d36`.
The original installed secondary, front padding, and boot partitions are not in
this capsule. Differences between historical primary/secondary copies cannot be
recovered from a primary alone. This is useful GPT recovery material, not a
complete rollback, installed-data backup, or permission to restore a raw disk.
The ZIP contains private disk identifiers and must not be committed publicly.

## Targeted installed capture

`wpi storage capture-spec-a DISK OUTPUT.zip --expect-gpt STORAGE_SHA256
--expect-primary-sha256 PRIMARY_SHA256` is a new read-only Windows path for an
**already exposed**, offline, read-only phone disk under exclusive access. It
does not enter mass storage, change attributes, mount filesystems or write a disk.
Both complete pins are required before disk opening. The existing native disk
adapter checks held-handle identity, geometry, short reads and disconnects.

The image engine derives 12 disjoint ranges from the pinned GPT: complete first
and last 128 KiB, seven boot partitions, EFIESP, UEFI_BS_NV and its vacant future
destination. Unknown geometry, occupied destinations, overlapping regions and
oversized images fail. Source copying uses at most 64 KiB per read, rereads every
captured range and compares hashes, checks primary/secondary GPT bookends, then
rereads the output ZIP. Cancellation and faults stop without retry. The native
wrapper validates the disk again before publishing atomically without overwrite.

Use an optimized CLI build (`cargo build --release -p wpi-cli`) for large firmware
preparation. Debug-mode hashing is substantially slower; all integrity passes
remain enabled in either build.

On the saved RM-875 layout the planned capture is **77,172,736 bytes (73.6 MiB)**,
bounded by 128 MiB, rather than a full device image. It includes the conservative
Data-tail exposure range. This snapshot has **not** been created on hardware.
The phone has not exposed mass storage in this project. A snapshot taken after
an entry or write cannot recover earlier lost bytes; reports explicitly describe
current state and never claim pre-unlock originals or an authenticated phone.

## Validation and remaining native work

Synthetic tests cover independent executable extraction, damaged enclosures,
unknown code profiles, GPT CRCs/pins/geometry, reciprocal secondary reconstruction,
missing/occupied snapshot ranges, every source-read failure and cancellation
boundary, source changes, bounded reads and verified archive contents. CLI
subprocess tests cover the Windows ARM default stack and new command help.

[`reference-spec-a-entry.py`](../scripts/reference-spec-a-entry.py) independently
extracts the private reference PE, checks its hash and branch destinations,
validates both capsule CRCs and ZIP contents, and recalculates range intersections
and snapshot size. Its [public metadata record](../tests/fixtures/rm875-entry-code-validation.json)
contains no raw firmware, phone identifiers or GPT bytes.

The [experimental native controller](spec-a-native-controller.md) now joins the
entry/programmer stages, correlated storage capture and finish continuation.
It has not run physically. Emergency USB access, installed entry-code identity,
data preservation and physical interruption/recovery behavior remain unverified.
No browser unlock capability or new command fallback follows from this analysis.
