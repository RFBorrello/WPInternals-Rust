# Local validation — October 13–15, 2026

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
