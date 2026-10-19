# Local validation — October 13–18, 2026

## October 18: entry-code interpretation and targeted recovery material

The [reference FlashApp audit](spec-a-entry-code.md) adds bounded executable
extraction and an exact-hash static profile. ARM disassembly shows that binary
skipping end-relative payload locations and separately clearing the final 33 GPT
sectors after successful header import. The installed binary was not read, and
no phone command was sent in this milestone. The conservative exposure model is
retained alongside the conditional reference interpretation.

A local GPT recovery ZIP preserves the previously captured primary and a clearly
marked reconstructed secondary. Both CRCs, ZIP contents, hashes and reciprocal
geometry passed independent Python verification. The private capsule is 36,250
bytes; only [metadata evidence](../tests/fixtures/rm875-entry-code-validation.json)
is public. This is not a capture of the original secondary or a full rollback.

The new native read-only targeted snapshot path uses an already exposed exclusive
Windows phone disk, two GPT pins, 64 KiB source reads, double reads of every range,
source/GPT bookends, archive readback and atomic publication. It does not change
phone mode, disk attributes or disk bytes. The saved real layout requires
77,172,736 bytes (73.6 MiB), below its 128 MiB cap. No such installed snapshot has
been captured. A later capture is not evidence of pre-unlock originals.

The full affected core/image/protocol/transport/storage/CLI run passed **314 tests**.
Two subsequent regression additions (corrupt snapshot output and invalid native
capture pins) passed with the complete affected snapshot and CLI startup suites,
for **316 distinct passing tests**. Those focused reruns also cover the final
64 KiB read bound. Strict all-target Clippy and WASM compilation passed. The CLI
subprocess checks caught and verified a fix for a default-stack overflow by
moving command handlers out of the main dispatch frame. Formatting passed.
UI/IPC code did not change. Remote CI for this revision is pending.

An optimized CLI build also completed full pinned FFU, package, saved-GPT and
loader preparation in 11,193 ms, then rejected an intentionally invalid device
selection. It opened no phone interface. The slow debug attempt was stopped and
was not counted as a completed validation. The previous remote revision failed
Rust 1.99 Clippy's new constant-`chunks_exact` lint; those comparisons now use
`as_chunks` without suppressing warnings. Their five recovery-audit and twelve
recovery-replay tests passed locally after the change.

The physical native unlock controller, post-write storage correlation and return
continuation remain unfinished; the installed FlashApp identity, installed backup
and hardware recovery evidence are still absent. Live unlocking remains disabled.

## October 18: boot-integrity plans, interruption inspection and native session handoff

The [finish-stage implementation](spec-a-finish-stages.md) now composes the
UEFI-variable layout and two first-pass EFIESP slices, and reconstructs a second
pass from a complete captured EFIESP. A concrete replay persists per-command
intents/acknowledgements; a bounded inspector diagnoses incomplete or corrupt
finish-stage logs without resuming them. The [prepared native cycle](spec-a-session.md)
retains one artifact context through Normal/Flash/Normal checks. It is CLI-only
and sends no GPT, firmware, programmer or partition-write commands.

On Windows ARM64, 291 tests passed in the full core/image/protocol/transport/CLI
run. Six subsequent regression additions passed in focused checks, for **297
distinct passing tests** across these crates. The complete 77-test native
transport suite passed after the final handle-lifetime and return-check changes.
Strict all-target Clippy, formatting and WASM compilation passed. The CLI help
subprocess test caught and verified a fix for another default-stack startup
overflow; the new command's arguments are boxed rather than increasing the stack.

The actual reference ZIP and saved live primary produced four first-pass
transfers totaling 33,835,520 bytes. An independent Python translation matched
their bytes, addresses, sizes, NV resource and rebuilt-primary digest; only
[metadata evidence](../tests/fixtures/rm875-finish-plan-validation.json) is public.
The 64 MiB image members exercise the new bounded image reader rather than the
32 MiB metadata allocator. The second pass has synthetic evidence only.

After those local checks, the [prepared native hardware cycle](../tests/hardware/lumia-1020-rm875-prepared-cycle.json)
passed once on Windows ARM64 using commit `729f6ab`: two mode commands, matching
Normal/Flash/Normal IDs, source-root/security/capacity checks and returning Normal
USB, in 57,503 ms excluding local preparation. No entry, upload, GPT query or
storage write was sent. The complete native emergency writer, mass-storage
continuation, installed originals/recovery policy and successful physical unlock
remain unvalidated or unimplemented. The subsequent [entry impact model](spec-a-entry-preservation.md)
flags a potential 223-sector Data-tail intersection; actual write behavior and
preservation remain unverified. UI tests were not
rerun because no UI or IPC implementation changed. Remote CI for this revision
is pending.

## Earlier validation

Host: Windows ARM64 (`aarch64-pc-windows-msvc`), stable Rust 1.94, Node 24,
headless Microsoft Edge. Native storage milestone `ed3e008` passed GitHub CI on all
four native host targets and Chromium ([run `38675937109`](https://github.com/RFBorrello/WPInternals-Rust/actions/runs/38675937109)).
Those remote build results do not establish device support.
The latest local milestone adds complete source-derived Spec A reference ZIPs,
including the SBL1 extra sector, boot patches, primary GPT changes and restore
metadata. Native/browser outputs agree with independent reference calculations.
Native identification was previously repeated on October 15. No phone commands
were sent during this extension; SBL3 and donor candidates were inspected offline.
Remote CI for this new source is pending.

| Check | Result |
| --- | --- |
| Rust tests | 180 passed on Windows: 110 integration tests, 37 native transport/harness unit tests, 31 image/parser/cache/archive unit tests and two Windows metadata-decoder unit tests |
| Rust Clippy, all workspace targets and WASM adapter, warnings denied | Passed |
| WebAssembly target check and release build | Passed |
| React/TypeScript production build | Passed |
| Frontend range/format unit tests | 3 passed |
| Real-WASM browser / mocked desktop IPC integration tests | 54 passed |
| Tauri native Windows ARM64 release build with embedded UI | Passed |
| npm dependency audit after lockfile update | No reported vulnerabilities |
| USB discovery | Lumia 1020 RM-875 detected in normal mode, USB 0421:0661 |
| Hardware identification | Model, product code and firmware read successfully through native interface 3 / Microsoft WinUSB |
| Browser hardware identification | User reported Lumia 1020 / RM-875 / Spec A / 3051.50009.1451.1003 in normal mode, matching native results; exact browser version not recorded |
| Phone firmware / partition writes | Not performed |
| Live native mode experiment | One Normal-to-Flash request sent; identity guard stopped automatic return; user reported normal boot after manual restart |
| Real RM-875 FFU | 1,716,256,768-byte image: headers, 28 GPT partitions and SHA-256 chunk table validated |
| Real EFIESP extraction | 64 MiB; SHA-256 matched independent upstream-algorithm translation; FAT16 EFI directory read |
| Real FFU browser inspection | Headless Edge and real WASM worker matched the native platform ID and 28 partitions |
| Real MainOS reconstruction | 2,393,669,632 bytes; SHA-256 matched independent mapping calculation |
| Real NTFS access | System32: 1,969 entries; extracted 5,289,976-byte kernel matches upstream catalog original SHA-1 |
| Native recovery preparation | Real FFU digest/chunk checks passed; advisory report kept recovery blocked |
| Backup engine | Replay-only ranges, hashing, atomic publication and interruption/cancellation tests; no physical storage access |
| Offline Spec A preparation | Real stock SBL1/SBL2/SBL3 and two local V1 programmers match native Rust, browser WASM and independent upstream-algorithm results; unlock remains blocked |
| Extended offline checks | Real SBL1 patterns, 75-file compressed UEFI, community SBL3 candidate and local donor boot-file checks agree across native/browser/reference implementations; no patched image exported |
| Offline image assembly | Real 2,560,000-byte unsigned UEFI and 67,108,864-byte EFIESP copies match native Rust, real browser worker and independent Python checks; source files and unrelated contents preserved; no phone commands |

Tests cover malformed/truncated image metadata, FFU hash corruption, GPT CRCs,
lossless 64-bit GPT attribute serialization, sparse map precedence, output
preservation, cancellation, reversible patches, FAT file access, protocol framing,
read-only normal-mode request allowlisting, operation gate bypass attempts, stock
recovery replay for v1/v2, and interrupted acknowledgements without retry.
New coverage exercises NTFS indexes smaller than clusters, resident/fragmented
files, invalid/overflowing VCNs, oversized/cyclic indexes and rejected compressed
data. Backup tests include failed reads after a completed chunk and cancellation
before final publication. Preparation tests cover missing inputs, platform
mismatches, corrupted chunks, identifier redaction and execution-gate bypass.

Browser tests use the actual Rust WASM module and worker to inspect a synthetic
FFU, compare exported partition bytes, retain a prior valid selection after corrupt
input, export GPT XML, verify unsupported WebUSB fallback, reject USB permission
without establishing a connection, and check responsive navigation.
Recovery preparation also runs through real WASM, exports a blocked report with
missing/unverified checks, and clears the report on a changed artifact.
Seven additional normal-mode WebUSB tests mock the OS USB boundary while running
the real Rust adapter: allowlisted model/product/firmware requests, vendor interface
3 selection, wrong response IDs, short writes, read timeouts, awaited interface
release, blocked ambiguous retries, observed disconnection, renewed selection,
and late-result rejection. These are software tests, not browser hardware evidence.

Synthetic fixtures do not prove compatibility with real Lumia firmware. The first
real FFU exposed an image-header chunk-unit error that synthetic data had mirrored.
Image and security headers use KiB; the store uses bytes. The corrected fixture
and parser now check these units, mismatches and conversion overflow.
The first real NTFS read exposed incorrect index VCN units in the `ntfs` dependency
when index records are smaller than clusters. A documented vendored patch fixes
addressing and bounds traversal; original dependency licenses are preserved.
All device writing workflows remain blocked.

Spec A preparation tests cover short/long MBN bounds, size/address overflow,
malformed DER and chain padding, unsupported ELF, HEX checksums/addresses/EOF,
code-only unique patch matching, wrong certificate fingerprints, missing markers,
oversized imports, and reports that never enable writes. Additional tests exercise
FV/FFS checksums and duplicate GUIDs, malformed PE regions, decompression bounds,
exact expected/resulting EFIESP bytes, stale donor reassessment and bounded FAT
cache behavior. Browser tests cover real
worker/WASM imports, stale-report clearing, missing boot partitions, oversized
inputs and desktop IPC routing. The extended real-file browser audit observed
64 KiB maximum synchronous reads and a 1,310,720-byte maximum asynchronous header
slice while reading stock and donor FFUs. Whole multi-gigabyte FFUs were not copied
through UI messages. See [Spec A preparation](spec-a-preparation.md).

Mode-transition coverage includes fresh source contradictions, Spec A protocol-1
removal requirements, Spec B protocol-2 in-place observation, Flash-to-Normal
replay, acknowledged context changes, partial/uncertain command delivery, stale
arrivals, permission renewal without deadline resets, wrong/ambiguous/missing
identities, malformed or interrupted probes, monotonic/bounded observations,
pre/post-command cancellation and coordinator-compatible event transitions.
The normal native codec now validates each response before sending the next query.
Six new browser tests cover blocked redacted previews, remembered baselines,
fresh read-only correlation, serial/firmware contradictions, absent serials,
late disconnect results and forgetting a baseline. These tests are simulated USB
boundary tests, not hardware mode-change or reconnection evidence.
The connected RM-875 also passed the native read-only mode-preparation preview;
`tests/hardware/lumia-1020-rm875-native-mode-preview.json` records its blocked
result separately. That earlier preview sent no mode command and performed no hardware reconnection.

Three additional reconnection regressions cover USB `NotFoundError`, `AbortError`
and timeout feedback within the panel. The NotFoundError case reproduced missing
feedback before the fix. USB failures are no longer treated as silent picker
cancellations, and read progress/disconnect instructions appear beside the button.

Offline evidence for the local RM-875 `3051.50009.1424.0002` image is recorded in
`tests/fixtures/rm875-validation.json`. Its EFIESP hash matched the independently
translated mapping algorithm in `scripts/reference-ffu-check.py`; this comparison
did not execute upstream C#. MainOS reconstruction also matched that calculation,
and the extracted kernel SHA-1 matched the unchanged upstream patch catalog.
Firmware bytes are not committed. Catalog authenticity
and applicability to the phone's different installed firmware remain unverified.

The first read-only hardware result is recorded in
`tests/hardware/lumia-1020-rm875-windows-arm64-normal-info.json`. Firmware reported
by the device: `3051.50009.1451.1003`. This is one successful session; broader
hardware support remains unverified and existing capability gates are unchanged.

The user's subsequent successful browser result is recorded separately in
`tests/hardware/lumia-1020-rm875-browser-normal-info.json`. This is reported UI
evidence, not a captured wire transcript. The browser name/version is unknown;
Windows ARM64 host details come from the existing session context. No phone
writing capability is enabled by this identification result.

The subsequent browser comparison export reported `correlated` in normal mode.
The user explicitly confirmed an unplug/replug after remembering the phone.
`tests/hardware/lumia-1020-rm875-browser-normal-reconnection.json` preserves that
report and its SHA-256, with the confirmed sequence and provenance limitations.
USB serial, variant, firmware and family checks passed; platform stayed unverified.
This is one user-confirmed normal-mode cycle. No raw event/wire transcript or exact
browser version was captured, no phone mode was changed, and no writing capability
was enabled.

The next native harness was tested with a private simulated driver for direct
Normal/Flash/Normal sequencing, BootManager 1/2 transitions, uncertain delivery,
wrong/missing/ambiguous identity, changed topology, Windows interface readiness,
protocol/platform/firmware contradictions, boot transients, cancellation and
journal failures, exact admission and native-probe exclusion. A new read-only
preview on the connected RM-875 succeeded using the direct bulk adapter; no mode
request is sent by a preview. These unit tests and preview do not establish live
Flash-mode hardware support. Live test evidence, when obtained, is recorded separately.

The final read-only readiness check found an empty generic USB port chain on this
Windows ARM64 host. The Windows binding now uses nusb's parent hub instance and
connection index directly. Both physical binding and native hotplug readiness
passed in the updated preview. A Windows-only regression covers absent, matching
and changed hub/port keys. This check did not reboot the phone.

The first explicitly approved live native experiment at `7a81c19` sent one
`SetDeviceMode(Flash, HwReset)` request. The returning USB interface failed the
combined serial/physical-port check, so the harness stopped with recovery required
without NOKS, NOKR or any firmware/partition write. A separate read-only probe
observed FlashApp 2.2, protocol 1.18, platform `Nokia.MSM8960.P5217.3.2.1`, and no
FVER value. That inspection did not correlate the interface with the baseline.
The separate Flash probe exposed no USB serial, while the initial and returning
Normal probes had a serial. The journal's combined binding error does not reveal
whether the physical-port check also failed. The user reported a normal boot
after the requested manual restart; a native read-only recheck confirmed Normal
mode, Lumia 1020 RM-875 and the unchanged installed firmware. The sanitized result and journal
digest are recorded in
`tests/hardware/lumia-1020-rm875-native-mode-test-first.json`.
This is an interrupted experiment, not a validated round trip or recovery profile.

The next identity milestone adds five public-ID protocol tests and four native
tests for FVER diagnostics, independent serial/port error reporting, and blocking
the known failed live profile. Public-ID codecs reject oversized/truncated nodes,
duplicate/excessive nodes, invalid lengths, malformed Normal responses, mismatched
request IDs and blank identifiers. Fixed query bytes match a transcription of the
pinned upstream source; comparison of synthetic Normal/Flash IDs is not hardware
evidence. The new type deliberately cannot serialize its identifier and redacts Debug.

The CLI `identity-probe` successfully queried the connected RM-875's public ID in
Normal mode without exporting its bytes or sending a mode change. The sanitized
record is `tests/hardware/lumia-1020-rm875-normal-public-id.json`. Live Flash
terminal parsing and cross-mode equality are still unvalidated. The old experiment
is blocked before any mode command; its private synthetic driver remains testable.

Eleven new native tests exercise a separate public-ID mode experiment: missing
Flash serial with matching public ID, wrong IDs/ports/available serials, fresh
command-handle contradictions, exact Flash versions/platform, changed Normal
firmware/serial/variant, stale arrivals, malformed/interrupted queries, deadlines,
uncertain delivery without retries, readiness before queries, boot transients,
safe cancellation and journal failure. Replay verifies Normal query ID 4 and
Flash NOKV/terminal order without FVER; an unexpected NOKV profile stops before
the terminal query. These are synthetic tests, not a live Flash identity result.

The connected RM-875 passed the new release binary's read-only preview: exact
Normal admission, public-ID availability, physical-port metadata and hotplug
watch readiness passed with no blockers. The sanitized evidence is
`tests/hardware/lumia-1020-rm875-public-id-mode-preview.json`. No mode command
was sent by the preview; live approval and validation remain separate.

The first approved public-ID mode run at `953f7e8` observed a matching Flash ID
and physical port, with the expected FlashApp/platform. It delivered one entry
request and one NOKR after fresh command-handle identity checks. The harness
rejected an observation during return before final Normal public-ID verification.
A separate native read-only probe then found Normal RM-875, unchanged firmware
and a serial matching the earlier Normal session. No manual restart was requested
or reported. The journal omitted failing NOKV details, so the boot-stage cause is
inferred, not established. At that milestone, full harness success was unvalidated.
The sanitized journal/digest and recheck are in
`tests/hardware/lumia-1020-rm875-public-id-mode-test-first.json`.

Three new tests cover unverified BootManager 1/2 observations during the return
wait, NOKV-only probing without terminal or mode requests, source BootManager
rejection before NOKR, and deadlines/unknown protocols/changed topology. Fresh
profile rejection records safe mode/version/match flags. The subsequent attempts
are recorded below; firmware-writing capabilities stay blocked.

On October 14, the approved corrected run again matched the Flash public ID and
port and delivered both mode requests once. It recorded 49 BootManager NOKV
observations (protocol 1.1 / application 1.16), then stopped on an information-query
OUT timeout. No failed transfer was retried. A separate native probe found Normal
with unchanged firmware and serial correlation to the earlier Normal session.
The compact record is `tests/hardware/lumia-1020-rm875-public-id-mode-test-boot-timeout.json`.

Three new regressions retire an observed intermediate interface until fresh removal
or a Normal USB descriptor, including reused IDs, repeated boot/Flash observations,
wrong returning public IDs, fresh generations and fixed deadlines. Readiness may
still retry before any query; failed queries remain fatal. Query-stage diagnostics
now identify Normal, public-ID, NOKV or terminal phases without payload logging.

A fresh cycle was blocked before process launch by automatic approval review,
which required a new explicit approval after the earlier run. The user approved
one new cycle. That run at `b28ea9f` matched Flash identity again and delivered both
mode requests once. Only one BootManager observation was queried, but the then
30-second return deadline expired. A separate probe found Normal with unchanged
firmware and matching serial. The sanitized record is
`tests/hardware/lumia-1020-rm875-public-id-mode-test-retired-deadline.json`.

Four new tests verify that retired waits limit enumeration and never repeat the retired
probe, unrelated events do not unretire a boot interface, new interface readiness
can retry without another event, and a longer Normal window leaves Flash arrival
bounded at 30 seconds. The Normal deadline is now 90 seconds and previews expose
both limits. CLI journals include monotonic elapsed times. Hotplug observation is
armed before queries to retain events arriving during them. These changes have
not yet been tested live at that milestone; another cycle required new approval.

The user reports quick visible boot, well below 90 seconds; the timeout cannot be
interpreted as measured boot duration. Read-only Windows PnP/native checks at that point
both find Normal. Hotplug-only waiting has a notification-loss gap: nusb 0.2.7's
Windows adapter can discard an arrival when metadata is not ready. A two-second
fallback now discovers Normal without another notification, while retaining the
retired-interface guard. A new regression checks recovery with a reused ID and
rejection of a wrong public ID. Discovery/probe journal events expose enumeration
timing and readiness without identifiers. This fixes a software gap, not a proven
hardware root cause; no further cycle had run at that correction milestone.

A newly approved single cycle at revision `8f6c8ca` completed in 54.252 seconds,
with all Normal/Flash/returning Normal public-ID checks matching, serial/port
correlation and unchanged firmware. Exactly two mode OUTs completed once; one
BootManager observation authorized no command. Normal USB was discovered 34.979
seconds after NOKR, then 24 pre-query interface-readiness failures preceded final
identity confirmation 2.905 seconds later. Discovery calls took 2–10 ms. A Windows
PnP snapshot during the wait found no Lumia functions; the user reported the normal
screen during the wait. Visible boot duration was not measured. No firmware or
partition writes or manual restart occurred. The record is
`tests/hardware/lumia-1020-rm875-public-id-mode-test-completed.json`.
This is one complete native Windows ARM64/RM-875 cycle, not repeatability or broader
operation/host evidence. Production capabilities remain blocked. Normal arrival
used hotplug, so the fallback's causal effect was not established by this run.

## Offline catalog and firmware evidence — October 14

Portable RustCrypto CMS/DER/X.509/RSA verification now checks legacy FFU catalog
signatures and explicit signed hash-table membership, independently from chunk
hashes and signer trust. Five image tests cover PKCS#7/CMS encodings, content/table/
signature changes, duplicate critical attributes, unsupported algorithms, bounds,
PLAT version format, contradictions, boundary scanning and cancellation. Three
new preparation tests cover unsigned trust remaining unverified, a changed table,
unvalidated downgrade handling and bounded platform-family prefix matching.

Three new real-WASM Edge tests verify signed-catalog checklist results, a failed
tampered signature, and PLAT metadata taking precedence over a filename version.
The full browser suite passed all 27 cases. Rust passed all 96 Windows tests,
strict native Clippy, WASM build/check, shared TypeScript production build and
Windows ARM64 CLI/Tauri release builds. Remote CI for this new source is pending;
the earlier CI link above applies to the earlier tested mode-observer revision.

The real RM-875 FFU's full fingerprint still matches the earlier record and all
payload chunk hashes pass. Its RSA/SHA-256 catalog signature agrees with Windows
`.NET SignedCms.CheckSignature(true)`; its SHA-1 catalog member binds the hash
table. Production browser WASM inspection matches the native catalog report
exactly. Signer trust and device acceptance remain unverified. Its 8 MiB PLAT
partition contains no SWVERSION record, so the image version is missing rather
than inferred from the filename. A fresh Normal-mode information probe supplied
phone metadata during native preparation; no mode or device writes were sent.
See `tests/fixtures/rm875-catalog-validation.json` and
[the verification limits](firmware-validation.md). OEM bytes, extracted PLAT and
personal paths/identifiers are excluded from the published evidence.
The final parser review also added a decoded-CTL depth/node guard, because CMS
octet-string wrappers are opaque to the outer ASN.1 walk. A regression exercises
deep and node-dense decoded blocks before schema parsing.

## MainOS firmware revision fallback — October 14

When PLAT lacks a version, native and browser inspection now use the same Rust
NTFS parser to look up the Nokia PhoneFirmwareRevision registry and DSM package
files. Both must agree, with explicit source locations in inspection and checklist
reports. Gzip, UTF-16 and XML parsing are bounded; malformed/contradictory metadata
fails without enabling recovery. Synthetic tests cover encodings, missing files,
duplicate/conflicting values, CRC/truncation/trailing gzip members, oversized
expansion, XML namespace/DTD/depth limits, partition geometry, cancellation and
truncated input. Two browser tests exercise positive and corrupt MainOS FFUs.

The real RM-875 package files independently decode with Python gzip/UTF-16/XML
and agree with native Rust and production WASM on `3051.50009.1424.0002`. Browser
MainOS lookup fetched 2,228,224 bytes in 34 reads, each at most 65,536 bytes, from
the 1.6 GiB FFU; it did not reconstruct MainOS. The full native fingerprint and
chunk checks still pass. Comparison with previously recorded phone firmware
`3051.50009.1451.1003` now fails the unvalidated-downgrade check. This comparison
used saved, redacted phone metadata, not a fresh device query. All recovery gates
remain blocked. See [the metadata-only record](../tests/fixtures/rm875-mainos-validation.json)
and [profile limits](firmware-validation.md).

## Complete browser FFU integrity — October 14

Browser **Check preparation** now streams the selected FFU in 1 MiB blocks to
an owned Rust/WASM verifier. It computes the full-file SHA-256 and checks all
image/store-header and payload chunks in one pass. Headers must match inspection,
the exact declared file length must be supplied, and incomplete/failed sessions
cannot publish a fingerprint. A payload mismatch retains its actual digest and
fails chunk integrity without granting trust or recovery permission.

Five new Rust tests cover arbitrary split boundaries, native/reference digest
agreement, payload corruption, partial/oversized/extra input, changed headers,
unsupported algorithms and malformed hash tables. A metadata-only case describes
a file larger than 4 GiB without allocating or verifying its payload. Four new
browser tests cover actual digest export, valid-catalog/corrupt-payload separation,
partial cancellation/restart, short reads and read errors; the full suite has
33 tests. Local Rust has 105 passing tests. Native/WASM Clippy and release builds
also pass. The earlier constant-size UTF-16 chunk conversion now uses `as_chunks`
to satisfy the newer CI toolchain without changing decoding behavior.

The real 1,716,256,768-byte RM-875 FFU passed all 13,090 chunk checks in the
production browser worker. Its full digest matches the previous independent
native result. Read auditing confirms async slices at most 1 MiB and MainOS
sync slices at most 64 KiB; monotonic progress ends at the exact file length.
The UI checklist and JSON export show passing fingerprint/chunk checks while
OEM signer trust remains unverified. Comparing with saved phone metadata still
fails unvalidated downgrade preparation. No phone queries, mode commands or
partition/firmware writes were sent. See
[the metadata-only evidence](../tests/fixtures/rm875-browser-integrity-validation.json).

## Signer and hardware targeting assessment — October 14

The shared inspector now assesses explicit local-time certificate dates, signing
key usage, code-signing EKU, supported critical extensions and embedded issuer
signatures. No self-signed or supplied certificate becomes an OEM anchor. Missing
issuers, unsupported constraints, revocation and exact OEM policy remain visible.
This is a limited profile, not a complete PKIX validator. MainOS OEMSettings
targeting metadata supplies an explicit RM hardware variant; matching is advisory
and contradictions fail. Product-code/region and recovery profiles remain unknown.

Six new Rust tests cover complete-but-untrusted synthetic chains, missing or
ambiguous issuers, bad certificate signatures, non-CA issuers, incorrect KU/EKU,
expiry, unsupported critical extensions, explicit-time requirements, bounded
targeting parsing, conflicts/deletions, real NTFS lookup, cancellation and checklist
gating. Two new browser tests cover chain consistency without OEM trust and a valid
catalog signature with an unsuitable certificate usage. The existing MainOS browser
test also checks the explicit image variant and unverified regional applicability.

The real RM-875 image's variant matches saved phone metadata. Its catalog signer
has digital-signature/code-signing usages and is in date at the local reference
time, but its `CN=PK,O=Nokia` issuer is absent. Python cryptography independently
confirms the single certificate, usages, dates and missing issuer; it also confirms
the complete synthetic chain and rejects a corrupted issuer signature. Native and
production WASM agree on the image targeting and signer check statuses. The full
fingerprint/chunk checks still pass; the older-firmware check still fails.
No phone query/mode/write was sent. See
[the metadata-only record](../tests/fixtures/rm875-signer-targeting-validation.json)
and [the assessment limits](oem-trust-and-applicability.md).

## Image-local production PK — October 14

The missing catalog issuer was found in the same image's
`EFIESP/Nokia/Security/Nokia_Production_PK.bin`. A bounded FAT lookup and narrow
authenticated-variable/signature-list parser now supply this untrusted candidate
to the shared chain assessment. The production certificate's self-signature and
catalog certificate signature pass RSA/SHA-256 verification. The similarly named
R&D PK fails the link in independent Python cryptography. No root is pinned or
authenticated by these same-image results.

Eight additional Rust tests cover full authority issuer/serial constraints,
same-name wrong keys, every provisioning-file truncation, oversized lengths,
incorrect types/extra entries/trailing bytes, missing/ambiguous/short partitions,
bounded reads, disconnects, FAT metadata limits and cancellation. Two additional
real-WASM browser tests check successful internal consistency and wrong-key failure,
with all device writes still blocked.

Final native and production browser reports agree except for their explicit
local clock readings. The full real-image browser check again passed all 13,090
chunks and the unchanged SHA-256; async slices stay at most 1 MiB and synchronous
slices at most 64 KiB. The existing chain row now passes internal consistency;
OEM anchor, revocation and exact applicability remain unverified. The unvalidated
downgrade check still fails. No fresh phone query or command was sent. See
[the metadata-only record](../tests/fixtures/rm875-image-issuer-validation.json).

## Read-only native storage research — October 14

The shared copy engine now serves both replay and a private Windows read-only
adapter. Sixteen new Rust tests cover candidate admission/redaction, native query
response parsing, paired GPTs, range/identity/state failures, cancellation,
disconnect/no-retry behavior and operation locking. Browser coverage adds an
explicit native-storage fallback without USB requests and desktop IPC empty/error
feedback (39 total). General Backup
plans remain non-executable; the Windows CLI research path requires already
exposed, offline/read-only phone storage under exclusive access.

A real Windows ARM64 inventory returned no recognized phone-storage disks.
No raw handle was opened and no USB protocol/mode/write command was sent.
This is discovery-only evidence: raw access, disk reads, full/partition backup,
serial decoding and snapshot consistency have not been hardware validated.
macOS/Linux raw adapters are not yet implemented. The offline firmware search
found the current 059T909 listing names the existing older recovery image;
no verified exact-version FFU was located or downloaded.
See [native backup limits](native-backup.md) and
[firmware search findings](rm875-firmware-search.md).

## Offline image assembly — October 15

UEFI rebuilding applies the three reviewed code patches across two EFI targets,
clears PE checksums, recomputes FFS checksums and recompresses to the original
volume capacity. Signature references and old signature/certificate data are
removed. EFIESP assembly replaces the unsupported stock boot file with the
catalog-patched local donor and creates two one-byte BCD NoCodeIntegrity entries.
The entire resulting partition and every other file are checked. Both native
outputs and the actual browser-published files have identical SHA-256 digests.

Independent Python LZMA, direct FAT16 allocation traversal and REGF semantic
comparison confirm the exact expected changes. Metadata-only evidence is in
[the assembly record](../tests/fixtures/rm875-assembly-validation.json). Real
proprietary inputs and modified images remain local ignored artifacts. Browser
synchronous reads are at most 64 KiB; the largest metadata slice observed was
1,310,720 bytes. Assembly and publication took approximately 3.8 seconds for UEFI
and 16.5 seconds for EFIESP in this test, with no residual scratch file.

Twelve additional Rust tests cover hive creation/update/idempotence, dirty or
truncated/oversized inputs, cyclic indexes, invalid parents/hashes, free-cell
exhaustion, UEFI reconstruction and unrelated file preservation, FAT reallocation,
unsupported donors, cancellation and atomic output cleanup. Four new browser
tests cover real UEFI export, refusal of nonempty destinations, failed EFIESP
cleanup and native fallback; desktop IPC tests also cover both assembly paths.
The two real images are intermediate artifacts only: no complete unlock package,
SBL1 payload, GPT modification, phone executor or hardware write validation.

## Offline Spec A reference package — October 15

The real RM-875 source and previously imported SBL3, two V1 programmers and donor
produced a 151,966,175-byte ZIP with 27 hashed members plus its manifest. Native
Rust, actual browser-published bytes and independent Python agree on SHA-256
`2dd482d7b6ba7fe72ad045e3191d3a4a30aa8988fc211e6d57009fa3caeb1a58`.
The checker independently reconstructs primary GPT normalization/hack/marker
bytes, the 512-byte SBL1 sector, SBL2/SBL3 instruction patches, original FFU
partition bytes and restore coordinates, then runs the prior UEFI/FAT/REGF checks.
ZIP CRCs and every member hash are independently checked.

The actual browser run used 53,204 bounded synchronous reads (maximum 64 KiB)
and took about 94 seconds, including full stock integrity/fingerprint checks and
publication. Queued browser cancellation was separately tested during stock
verification: construction finished its synchronous batch, then the destination
remained empty, both scratch files were removed and no report was published.
No phone discovery, query, mode change, programmer upload or partition write
was sent. Metadata is in
[the package record](../tests/fixtures/rm875-package-validation.json).

Fifteen additional Rust tests cover the complete package, deterministic GUIDs/ZIPs,
exact GPT restoration and backup-bound swaps, capacity/overlap/duplicate/range
failures, model-specific payload fields, expected boot instructions, repeated
patch refusal, invalid chunks/donors, all construction interruption stages, final
chunk cancellation, partial writes, corrupt/truncated ZIP metadata and member
data, and atomic cleanup/no-overwrite. Four additional real-WASM/browser tests
cover failures/cleanup, empty-output protection, fallback and single-use session
cancellation. Desktop IPC tests also carry all package imports.

The user's OS reading `8.10.14226.359`, with previously probed firmware
`3051.50009.1451.1003`, is consistent with the 1020 Denim release despite the
Extras + Info Cyan label. It is user-reported context, not a fresh hardware
observation or compatibility grant. Source FFU originals remain distinct from
installed backups; backup GPT is not captured. Hardware preflight, recovery
validation and a reviewed executor remain outstanding. These private firmware
packages are excluded from public source and application development bundles.

## Read-only Spec A preflight — October 16

The new shared query engine and advisory assessment pass nine additional Rust
tests. Synthetic coverage includes exact RRKH/SS request bytes, strict security
encodings, duplicate/truncated/oversized messages, blank/mismatched roots,
contradictory security reports, changed applications/public IDs, conditional GPT
access, and disconnect/timeout/partial-transfer/cancellation at every query.
CRC-valid but different GPT identities/attributes fail the reference comparison;
malformed tables and layouts beyond reported eMMC capacity are rejected.
Passing comparisons never authorize writes or claim installed backups.

Both published synthetic CLI scenarios run successfully without USB: locked
FlashApp skips NOKT and reports a required context transition; the insecure
scenario reads and compares only synthetic primary sectors. The full Rust suite
passes 189 tests. Native and WASM strict Clippy checks pass.

The reference-only command also parsed the real local RM-875 source FFU. Its
primary GPT and SBL1 SHA-256 digests match the originals in the previously verified
offline package. This step did not recheck complete FFU integrity or establish
OEM trust. See the metadata-only
[reference record](../tests/fixtures/rm875-preflight-reference-validation.json).
No fresh phone queries, mode transitions, programmer uploads or writes were sent.
Device preflight remains unvalidated on hardware; the command does not switch
contexts, preserve installed originals, capture backup GPT or enable recovery.

## Preparation for the identity-bound preflight cycle — October 16

The separate RM-875 CLI harness now supports RRKH/SS preflight between a fresh
Normal/Flash/Normal round trip. Five additional tests cover the Normal public-ID
anchor, the preflight request allowlist/exact Flash profile, event ordering,
old-harness isolation, and failures/cancellation/journal errors before the return
command. All 194 local Rust tests and native/WASM strict Clippy checks pass.
This records implementation/replay coverage, not a completed hardware cycle.

A fresh native Normal probe confirmed RM-875 / 3051.50009.1451.1003. Restricted
process enumeration returned an empty list while the authorized native process
and Windows PnP saw the healthy connected phone; an empty restricted-process list
must not be treated as proof that the cable/device is absent. These read-only
checks sent no mode change or firmware/partition writes.

The preceding commit's cross-platform CI succeeded on all configured hosts:
[run 38977704228](https://github.com/RFBorrello/WPInternals-Rust/actions/runs/38977704228).
The new hardware harness still needs its own reviewed physical cycle.

## First hardware preflight — October 16

One approved cycle entered Flash after approximately 15.4 seconds and matched the
fresh Normal public ID on the same physical USB port. At approximately 16.0
seconds the new strict parser rejected a nine-byte version-3 NOKV security block;
the cycle stopped before RRKH/SS or the return reset. No mode retry was sent.

A separate, single-query NOKV diagnostic on the existing Flash connection
recorded the exact reviewed FlashApp 2.2 / protocol 1.18 / platform
Nokia.MSM8960.P5217.3.2.1, response length 86 and security bytes
`03 01 01 01 00 00 01 01 FF`. The pinned upstream reader uses the first eight
bytes. The parser now preserves this exact ninth `0xFF` byte as an opaque tail,
without assigning it meaning or allowing it to enable GPT access.

The subsequent separate read-only Flash preflight matched RRKH to the source
SBL1 certificate fingerprint, matched its own public-ID bookends and observed
agreement of the checked NOKV/SS fields. Secure boot and secure FFU were enabled;
RDC and authentication were false. Debug/JTAG/key/test-device fields retain their
separate raw meanings; no engineering-device or trusted-signer conclusion is
drawn. This standalone session does not claim Normal-session correlation.

The user restarted manually with Volume Down + Power and confirmed the normal
screen. A fresh native read-only probe then confirmed Lumia 1020 RM-875 in Normal
with unchanged firmware 3051.50009.1451.1003. The approved automatic round trip
remains **incomplete**. No GPT, programmer, firmware or partition write command
was sent. Installed originals, backup GPT, firmware applicability, recovery and
unlocking remain unvalidated. Metadata only is in
[the hardware record](../tests/hardware/lumia-1020-rm875-flash-preflight.json).

All 195 local Rust tests and strict native/WASM Clippy checks pass after the
extension fix. New coverage retains the opaque byte, refuses other extensions,
blocks GPT even with insecure-looking understood flags, and bounds diagnostic
metadata. Browser and non-Windows hardware preflight have not been validated.

## Return-boot primary GPT reader preparation — October 16

The new CLI experiment uses the existing identity-bound preflight cycle and
captures the primary GPT only during the transient BootManager stage of its
normal return. The four-query reader accepts the previously observed BootMgr
1.16/protocol 1.1 profile, requires two identical primary reads and unchanged
application information, and checks GPT geometry/CRCs/partition bounds against
the same cycle's fresh Flash capacity. It sends no NOKD timer hold, context
switch, extra reset, firmware write or BootManager public-ID query.

The primary remains in memory until the original Normal identity returns.
Atomic publication then verifies the new local file's digest and refuses
overwrite. Six additional tests cover query faults/cancellation, malformed or
changing GPT data, capacity/profile contradictions, output protection, missed
boot windows, changed returning identity and journal/cancellation ordering.
All 201 local Rust tests and native/WASM Clippy checks pass; Windows ARM64 CLI
release build passes. Read-only Normal readiness passed. This preparation entry
does not establish physical GPT capture or a completed cycle.

## Completed primary GPT hardware cycle — October 16

The user approved one new cycle with the reviewed release CLI at `e2beca7`.
It sent exactly one Normal-to-Flash request and one identity-revalidated NOKR.
Fresh Normal/Flash/returning-Normal public IDs and physical port agreed; the
returned Normal serial, RM-875 identity and firmware 3051.50009.1451.1003 matched
the baseline. RRKH matched the source SBL1 certificate fingerprint and the
checked NOKV/SS fields agreed. The cycle completed in 58.369 seconds without a
manual restart, context switch, timer hold, programmer or firmware/partition write.

During return boot, the reader captured two identical primary GPT responses
under the observed BootMgr 1.16/protocol 1.1 profile and fresh Flash capacity
61,071,360 sectors. The 17,408-byte candidate was complete at 25.522 seconds.
Returning Normal identity was confirmed at 58.355 seconds, then the primary
was atomically saved at 58.365 seconds. File SHA-256 is
`cf5cb926cf149d15f4090c54caa65cd1edbaa8de20090b6898f185b9727afeec`.
An independent Python read confirms the digest, GPT header/table CRCs, 28 valid
partition ranges without overlaps and the actual disk geometry.

The source reference is a 10 GiB GPT template, while the live GPT agrees with the
approximately 29.1 GiB physical disk. MainOS/Data/MMOS ranges differ and active
RPM/TZ/WINSECAPP locations are exchanged with their backups. Many partition
GUIDs differ; their values remain private. This does not prove stock recovery
inapplicability, but the existing offline unlock reference GPT/restore positions
must not be substituted for the installed layout. Installed boot partitions,
backup GPT, donor/loader acceptance, recovery and unlocking remain unvalidated.

The local binary/checksum/journal are ignored artifacts. The public
[hardware record](../tests/hardware/lumia-1020-rm875-boot-gpt-cycle-completed.json)
contains metadata, digests, timing and comparison results only. It does not
export raw GPT sectors, GUID values, public IDs or phone serials. This validates
one experimental native profile/session, not general device/host write support.

## Offline live-layout advisory — October 16

The new CLI planner compares the pinned reference ZIP with the saved 34-sector
primary and recorded 61,071,360-sector capacity. It verifies the bounded ZIP,
member hashes/CRCs, manifest, source/prepared GPTs and placement lists before
calculating an in-memory candidate from the saved live layout. It retains the
live disk geometry and unrelated entries, normalizes TZ/RPM/WINSECAPP ranges,
and checks all nine prepared payloads against the resulting partition bounds.
All nine fit. Python's independent ZIP/CRC/hash and upstream GPT translation
matches the candidate digest, partition/payload comparisons and capture list.
No candidate GPT binary or replacement ZIP is published, and no phone command
is sent. See [the guide](spec-a-live-layout.md) and
[metadata-only evidence](../tests/fixtures/rm875-live-layout-validation.json).

Six additional tests cover bounded ZIP import, unsupported formats/paths,
corrupt/truncated/oversized metadata, cancellation, live/reference geometry and
identity differences, swapped boot slots, oversized payloads, misleading
manifest/placement claims and prior GPT modification. All 207 Rust tests pass;
native all-target and WASM Clippy pass, and the Windows ARM64 release CLI builds.
CLI smoke checks preserve an existing report and publish no output on a wrong
package digest. The first restricted suite run encountered an existing atomic
temporary-file publication permission error; the full offline rerun outside
that filesystem restriction passed. No production checks were weakened.

This milestone adds no UI operation or phone-write capability. Captured primary
metadata and payload fit cannot replace installed boot/EFIESP originals, backup
GPT, firmware/donor/loader applicability or recovery validation. The locked
retail phone's mass-storage backup limitation remains explicit; a feasible
capture or independently validated alternative recovery path needs research.

## Stock recovery file audit — October 16

The CLI-only `audit-recovery` command reads the pinned stock FFU and the saved
primary GPT. A bounded legacy INI parser checks Store/Partition layout fields;
the audit verifies full FFU chunks/fingerprint, saved-primary/capacity bindings,
manifest/GPT sizes and recognized end-relative source backup templates.
It does not emulate FlashApp, generate disk sectors, connect to a phone or
authorize writes. See [the recovery-path investigation](rm875-recovery-path.md)
and [metadata-only evidence](../tests/fixtures/rm875-recovery-audit-validation.json).

The real image declares a 20,971,520-sector minimum and Data `UseAllSpace=true`.
The recorded phone capacity satisfies that constraint. Two end-relative payloads
include an initial all-zero chunk and a final CRC-valid backup template. Source
primary and backup entries differ only in the MainOS attribute's bit 63; the
report exposes both attribute values without normalizing or interpreting them.
The initial audit stopped on table inequality. Attribute-only reporting now
preserves that observation; valid-CRC identity/range/name contradictions remain
rejected, and physical recovery remains unvalidated. Python's separate INI,
FFU/GPT/CRC/SHA implementation matches the real-file results.

Five new tests cover manifest ambiguity/limits, minimum-capacity and expansion
reporting, contradictory GPT/manifest evidence with valid enclosing FFU hashes,
source attribute differences, corruption, digest/capacity mismatch and all
cancellation stages (including terminal callbacks). All 212 Rust tests pass;
native all-target and WASM Clippy pass, and the Windows ARM64 release CLI builds.
Native CLI smoke checks preserve an existing report and publish nothing on an
incorrect source FFU digest. Browser/desktop UI code was not changed or retested
for this CLI/image-engine milestone. Cross-host hardware recovery is not claimed.

Pinned upstream emergency entry and programmer paths were reviewed as source:
they modify GPT regions and upload/start a programmer, not a read-only backup
shortcut. No such commands were added or sent. Source-template backup data is
distinct from missing installed originals and the live backup GPT. Stock/native
execution, applicability/downgrade, interruption handling, preservation and
physical recovery validation remain outstanding.

## Bounded iteration: final FFU verification cancellation — October 16

The shared FFU chunk verifier now returns `Cancelled` when its final progress
callback declines completion. Previously it ignored that callback's result and
could report success after cancellation. A regression test cancels at every
chunk boundary, including completion, and checks that no further reads occur.
Focused image/integrity/recovery-audit, stock-recovery replay and the existing
package final-cancellation tests pass, as does image-crate all-target Clippy.
The full suite and UI were not rerun for this small change. No phone access,
write-policy change or firmware processing was performed on real inputs.

## Bounded iteration: recovery replay cancellation boundaries — October 16

Two added regression tests exercise synchronous FFU v1 and v2 cancellation.
Cancellation before the header leaves every simulated write queued. Cancellation
at each subsequent payload boundary stops further submissions and returns
`RecoveryRequired`, preserving the distinction from cancellation before writes.
Each test verifies the complete unconsumed transcript, rather than merely checking
the returned error. All five recovery-replay tests and focused Clippy pass.
Production code, phone-write gates and the data-preservation requirement are
unchanged; no physical phone is contacted. The full suite was not rerun.

## Bounded iteration: uncertain recovery-header acknowledgement — October 16

A new replay regression covers timeout, disconnect, empty/truncated replies,
wrong signatures, nonzero status, unsupported commands and oversized replies
after header submission, for both synchronous FFU protocols (16 fault cases).
Every case requires `RecoveryRequired`, reports no payload progress and leaves
the entire payload transcript unconsumed. A declined terminal event does not
trigger a retry, reset or continued transfer. The six focused recovery-replay
tests and targeted Clippy pass; the full suite was not rerun. Only synthetic
images are used, and production code and phone-write policy remain unchanged.
Local checks disable incremental compilation and debug symbols to reduce cache
growth after the storage cleanup.

## Bounded iteration: payload acknowledgement failures — October 16

The payload-failure regression now exercises the same eight acknowledgement
faults at all six v1 and three v2 payload boundaries (72 cases). Each result
requires recovery, reports only previously acknowledged bytes, and leaves later
payloads queued. A sentinel remains after the final payload so an unexpected
retry or extra command cannot be hidden by an already exhausted replay queue.
All six focused recovery-replay tests and targeted Clippy pass with incremental
compilation/debug symbols disabled. Production code and write gates are unchanged;
the full suite was not rerun.

A separate read-only Normal-mode probe confirmed the connected Lumia 1020
RM-875 still reports `3051.50009.1451.1003`. It sent no mode changes or
firmware/partition writes and does not validate recovery. The user's requirement
to preserve the phone's data remains in force.

## Recovery replay journal

The journaled replay engine now fingerprints the complete source and records
ready state, header/payload intents, separate acknowledgements, cancellation,
recovery-required state and transfer completion. A new regular JSONL file is
flushed and synchronized at each entry. Existing files are never overwritten,
failed appends poison the sink, and partial files remain for inspection. Every
entry is replay-only, disallows automatic resume/phone writes and requires fresh
device checks. No journal import or native recovery executor is implemented.

Five additional tests cover both protocols, source binding, ordered metadata,
lost final replies, cancellation, file protection and journal failures at all
26 checkpoints across the two synthetic success sequences. Remaining transcripts
and a final sentinel verify no subsequent submission or retry after failure.
All 77 core/protocol tests pass; core/CLI all-target Clippy, the CLI build and
WASM compilation pass with compact local build settings. The full image/UI suite
and hardware were not exercised for this milestone.

CLI smoke tests used a public synthetic FFU and bounded synthetic transcript.
Success persisted 16 entries and 24,576 acknowledged payload bytes. A lost final
reply persisted 15 entries, retained the final intent and confirmed only 20,480
bytes before reporting `RecoveryRequired`. Both cases preserved an existing
journal on a repeated invocation. These local artifacts are ignored by Git.
Power-loss behavior and crash-safe directory publication are not validated;
transfer completion does not establish successful device recovery. See
[the journal guide](recovery-journal.md). No phone communication occurred.

## Recovery preflight cancellation — October 17

The CLI now observes cancellation during FFU chunk verification and bounded
whole-file fingerprinting, before consuming even the replay information query.
A new regression stops at every preflight checkpoint for both protocols and
checks that no subsequent image read, transfer event, journal entry or protocol
request occurs. Both terminal hash callbacks are included. Existing event-based
transfer cancellation and journal behavior remain covered. All 12 focused
recovery replay tests and strict core/CLI all-target Clippy pass with compact
local build settings. The full suite and hardware were not exercised.

The owner confirmed this Lumia can be used for live tests and reaffirmed the
preference to preserve its data. No phone command or data-changing operation
was performed in this iteration; the preservation and native-executor gaps
remain open.

## Spec A programmer-phase executor rehearsal — October 17

The unlock track now has pure V1 programmer codecs and a concrete-replay-only
phase executor. Requests preserve the pinned upstream unframed format; replies
require bounded HDLC/CRC validation and exact write-address echoes. Region
validation precedes the session, byte counters advance only after valid replies,
and cancellation/error stops without retries or later cleanup/reboot commands.
Completion describes the simulated phase, not verified device unlock or boot.

Eight new tests include an independent synthetic C#-algorithm translation,
81 command-fault cases, all nine cancellation boundaries, range/overlap/resource
limits and 32-bit edge cases. All 86 core/protocol tests pass. Strict all-target
core/protocol/CLI Clippy, formatting and WASM compilation pass with incremental
compilation and debug symbols disabled. The Python reference check passes.
The full image/UI suite and hardware were not exercised; no phone command,
programmer upload or partition write occurred. No native writer or UI unlock
control is enabled. Package/live-layout composition, emergency entry, durable
checkpoints, boot patches and preservation/recovery validation remain separate
integration work. See [the executor guide](spec-a-unlock-executor.md).

## Live-layout programmer composition — October 17

The image engine now constructs an immutable replay-only programmer plan from
the existing package/saved-GPT verification. Core `run_plan` binds this object
to the concrete programmer replay; advisory JSON cannot be imported as a plan.
The new CLI exports only a report, using regular local inputs, cancellable
verification and atomic new-file output. It opens no device transport.

Composition follows ten boot-stage regions, retains the saved MBR, derives GPT
and boot addresses from the saved installed geometry, checks SBL1/HACK geometry
and signed extent, and explicitly reproduces the GPT/SBL1/WINSECAPP length rules.
Both installed and candidate maps exclude unrelated partition intersections.
Synthetic tests prove MainOS/Data/EFIESP entry equality and disjoint write ranges,
check installed MBR differences, reject changed geometry and internally consistent
tampered members, detect package mutation after verification, and cancel at all
eleven composition boundaries. The full image/core/protocol suite passed;
the final six focused composition tests also pass after test-only additions.
Strict image/core/CLI all-target Clippy, formatting, CLI build and WASM check pass.
Browser/UI tests were not rerun for this CLI/engine-only change.

The pinned local RM-875 package and saved primary produce ten regions totaling
7,529,371 bytes. GPT omits one byte, SBL1 and WINSECAPP each omit 512 bytes.
The candidate GPT digest remains
`8bd4ecb71c8599300dafc897b2647ad9749faeddcc738130d071783d690c0f50`.
An independent Python ZIP/GPT/CRC/SHA calculation matches all transfer addresses,
lengths and hashes. This is a historical-file calculation, not a live probe or
unlock test. No phone commands or partition writes occurred. Installed backups,
fresh identity, emergency entry/upload, journaled native execution and subsequent
boot patches remain open; actual data preservation is unvalidated. See
[the record](../tests/fixtures/rm875-programmer-plan-validation.json) and
[the executor guide](spec-a-unlock-executor.md#package-bound-programmer-composition).

## Spec A emergency entry and DLOAD upload replay — October 17

The core now rehearses the storage-changing emergency-entry sequence, one
fingerprinted V1 programmer upload and a returning programmer handshake. Pure
DLOAD codecs follow the pinned upstream byte-array overload, with HDLC framing,
big-endian memory addresses/lengths, actual short-tail lengths and bounded ACK/
RKH validation. A poisoned single-frame decoder and concrete fragmented replay
transport exercise partial replies, including split escapes and checksums.

An immutable source plan pins the full FFU and captures its bounded header in
that hashing pass, validates chunk hashes/GPT, and requires the explicit 128 KiB
first-payload boundary-mapping/zero profile. Loader preparation pins one local
HEX/MBN, V1 marker and reference certificate fingerprint. Bound Flash preflight,
root comparison after entry, disconnect/arrival ordering, deadlines, mode and
physical-port correlation precede later commands. Correlation is not authenticated
unique identity; RKH fingerprints can be shared. No native execution grant exists.

Ten new tests cover synthetic success, 195 per-command fault cases, all 44
command/arrival cancellation boundaries, source public-ID changes at both
bookends, download root changes, sixteen invalid arrival timelines, range/profile/
import checks and every source-preparation cancellation callback. Sentinels prove
no later command, retry or loader fallback occurs after uncertainty. Failed RAM
replies do not advance acknowledged-byte counters. Independent Python vectors
use the pinned C# CRC table and agree with all upload command bytes. The existing
V1 reference vectors remain unchanged after the shared reference-helper refactor.

All 96 core/protocol tests, strict core/protocol/CLI all-target Clippy, formatting
and WASM compilation pass with compact local build settings. Image/UI suites
were not rerun. This milestone used only synthetic inputs/transcripts and sent
no phone commands, entry writes or programmer uploads. Durable phase journals,
native adapters/arrival observation, recovery/preservation policy and later live
boot-integrity stages remain unimplemented. See [the emergency rehearsal guide](spec-a-emergency-replay.md).

## Joined Spec A phase journal — October 17

The replay engine now joins entry/upload and the first boot-transfer phase through
one programmer connection, without a duplicate Hello. Its public API accepts the
image composer's opaque plan, checks its source FFU/platform against the entry
plan and validates ranges before entry. Six artifact digests bind every metadata
checkpoint. Intent is saved before submission, acknowledgement after validation,
and the send-only entry reboot uses a distinct submitted status. Arrival waits,
matched arrivals and the handoff are also checkpointed. One progress sequence
publishes completion only after transfer completion is saved; no unlock or boot
verification is claimed.

Five new composition tests exercise 90 synthetic journal checkpoints, save failure
at every checkpoint, cancellation at every outer boundary, uncertain final writes,
terminal-save failures, artifact contradictions and native JSONL protection. A
poisoned journal is never called again. Persistence errors retain their cause even
when a child phase reports cancellation. Native sinks create new files, flush and
sync each record; the existing recovery journal shares the sink with its original
2 KiB limit, while the joined journal uses 4 KiB. Existing files are preserved and
oversized/failed saves poison the sink. Crash/power-loss durability is unvalidated.

All 101 core/protocol tests, strict core/CLI all-target Clippy, formatting and
WASM compilation pass with compact local build settings. The emergency fixture
helpers are shared between existing phase tests and the joined tests. The latter
compose independent synthetic V1 regions through a private worker; public callers
still require the verified image plan. Real-package execution, hardware, image
suite and UI tests were not exercised for this milestone. No phone commands,
mode changes, loader uploads or partition writes occurred. This is a Rust-library
component with no native execution, journal import or automatic resume API. See
[the joined journal guide](spec-a-joined-journal.md).

## Native USB session retirement — October 18

Native single-message transactions now retire permanently on uncertain transfer
results. Errors cancel both endpoints; later calls cannot consume queued stale
completions, retry OUT or send another command. Local bound/packet/deadline checks
precede submission. One five-second transaction deadline covers OUT and IN, capped
by the existing operation deadline. The adapter validates completed IN lengths
and returns only those bytes. Send-only mode commands retain their OUT-only behavior.

All 50 transport tests pass, including seven new deterministic injected-I/O tests
for partial/failed writes, failed/empty/oversized reads, queued replies, deadline
expiry, local validation and successful reuse. Strict transport/CLI all-target
Clippy and the CLI build pass. Core/image/UI suites were not rerun for this native
adapter change. Physical USB cancellation/disconnect behavior remains unvalidated.

One read-only identity probe with the updated CLI succeeded on the connected
Lumia 1020 RM-875 in Normal mode on Windows ARM64, reporting the existing firmware
3051.50009.1451.1003, public-ID availability and physical-port availability. No
mode changes, programmer uploads or firmware/partition writes were sent. The
[sanitized record](../tests/hardware/lumia-1020-rm875-usb-session-probe.json) includes
the executable hash. This does not enable native unlock execution or establish
data preservation. See [native USB transaction behavior](native-usb-transactions.md).

## Native fragmented emergency replies — October 18

The private native session now assembles one CRC-checked HDLC reply across multiple
IN completions with a total 8 KiB bound and one shared OUT/IN deadline. Short reads
never repeat OUT or reset time. Empty, malformed, oversized, incomplete or failed
replies retire the session. A new explicit CLI `probe-emergency` command selects
DLOAD alive/root or V1 Hello on an already exposed recognized emergency endpoint.
It accepts exactly one vendor bulk pair, requires physical-port binding, and
rechecks descriptor/port uniqueness before each query and after completion. It
never guesses protocols, uploads, writes, changes modes or enables the replay
executor's hardware path. Reports export presence only, not identifiers or roots.

Eleven new tests bring the transport suite to 61 passing tests, including maximum
8 KiB bytewise/full-packet assembly without an extra zero-length terminator, every
split in escaped replies, injected failure/deadline
cases, admission/interface checks, fixed read-only sequences and reference-vector
integration through the framed adapter. Strict transport/CLI all-target Clippy,
formatting and the CLI build pass; missing protocol selection is rejected at parse
time. Both protocol choices rejected the connected Normal-mode RM-875 before open
or queries, and its Normal interface remained present. The
[sanitized refusal record](../tests/hardware/lumia-1020-rm875-emergency-probe-normal-refusal.json)
includes the executable hash. No emergency hardware communication, mode change,
upload, write or driver change occurred. Core/image/UI suites were not rerun.
Cross-mode unlock admission, arrival handling, serial transport and preservation/
recovery policy remain pending. See the [emergency probe guide](native-emergency-probe.md).

## Native serial transport and discovery-only arrivals — October 18

Read-only DLOAD/V1 queries now also have a serial CLI adapter. An explicitly selected
enumerated port must uniquely match the selected emergency USB device's nonblank
serial and VID/PID; fresh descriptors/physical port and both discovery sources are
checked before each query and after completion. Missing/duplicate metadata cannot
fall back to a port name or VID/PID alone. Native line settings use 115200 8N1 with
no flow control and request DTR preservation; OS/library opening side effects remain
unvalidated. Pending post-open input is rejected, partial writes are never retried,
and failed sessions close rather than purge/reopen. The framed transaction policy
is shared with USB. The minimum serialport API now matches the already locked 4.10.1.

A separate observer discovers USB absence then confirms two identical arrivals at
the original physical port, 250 ms apart. It retains unknown USB records, stops on
changed/ambiguous/unexpected endpoints, and never opens interfaces, queries the
phone or changes modes. One 1–30 second deadline covers all observations; late results
cannot complete, and cancellation stops at a scan boundary. Reports are metadata
only and cannot identify DLOAD versus programmer mode or authorize writes.

All 73 transport tests pass, including twelve new serial/arrival tests with reference
vectors, partial I/O and timeout failures, pending data, duplicate metadata, ordered
arrival, wrong devices, unstable candidates, cancellation and deadlines. Strict
transport/CLI all-target Clippy, formatting and CLI build pass. Option parsing checks
explicit USB selection and timeout bounds. Both serial protocols rejected the
connected Normal RM-875 before port open, and a two-second discovery-only observer
timed out after eight scans with no disappearance/arrival or phone queries. The
same Normal interface remained present. See the [sanitized hardware record](../tests/hardware/lumia-1020-rm875-serial-arrival-readiness.json).
No serial port was opened on hardware, mode changes were sent, programmers uploaded
or partitions written. Positive serial/arrival hardware behavior and other hosts
remain unvalidated; core/image/UI suites were not rerun. The joined unlock executor
is still replay-only. See [native serial and arrival behavior](native-serial-arrival.md).

## Artifact-bound read-only Spec A session — October 18

A prepared context now owns the pinned entry plan, one loader and the opaque image
programmer plan. It checks complete source/platform agreement, a source-digest-bound
pinned reference, full original-SBL1 equality between source/package, loader root
equality and supported saved capacity. Six artifact digests remain bound to the
in-memory context. References parsed by metadata-only inspection cannot satisfy the
pinned-source requirement, and reports cannot reconstruct the context or session.

Entry verification now reads hash tables from retained headers. Later reference,
GPT and zero-payload reads verify chunks against that pinned table before using
their bytes, with one cached chunk and bounded seeks. Tests reject a changed payload
even when the live file's hash table is also rewritten. Source reconstruction does
not trust a later header read or copy an entire firmware image to memory/disk.

Five ordered Normal queries check public-ID bookends and the reviewed RM-875 model,
product and firmware. A consuming read-only Flash check uses the same private public
ID/root context, checks Spec A/security/capacity at NOKV before later requests, then
validates root/security and application/ID bookends. Flash logic was exercised only
through replay. The native adapter exposes Normal only, revalidates descriptors and
physical port before each query and after completion, caps the session at 30 seconds
subject to OS discovery, and permits only the five fixed requests. Any binding or
transport error retires it; mode changes, writes and recovery commands are absent.

The core/image/protocol/transport suite passed 279 tests. One subsequently added
source-coherence test and one CLI subprocess regression also passed, for 281 distinct
tests across the relevant suites. New cases cover source/reference swapping,
mutable headers/payloads, bounded reads, identity/root/profile/capacity changes,
every query fault/cancellation boundary and native request allowlisting. Synthetic
session tests use private contexts; public bundle construction was exercised with
the real local inputs below. Strict all-target Clippy, formatting, CLI build and
WASM compilation pass. UI tests were not rerun. The initial CLI help run overflowed
the Windows ARM64 process stack before phone access; boxed arguments and a separate
handler fixed it, and the subprocess test now guards startup on the default stack.

The new CLI verified the real RM-875 FFU, package, saved GPT and FAST8960 import,
constructed the public bundle and completed five native Normal queries on the
connected 1020. Public-ID bookends, USB descriptors and physical port matched.
No Flash transition/probe, GPT query, programmer upload or phone write occurred.
The result keeps fresh Flash/GPT evidence missing, recovery/preservation unvalidated,
hardware validation false, writes disabled and automatic resume disabled. See the
[sanitized record](../tests/hardware/lumia-1020-rm875-session-check.json) and
[session guide](spec-a-session.md). This establishes one read-only Normal check,
not device acceptance of the older source firmware or live unlock readiness.
