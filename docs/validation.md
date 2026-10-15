# Local validation — October 13–14, 2026

Host: Windows ARM64 (`aarch64-pc-windows-msvc`), stable Rust 1.94, Node 24,
headless Microsoft Edge. Catalog milestone `e6ed0bc` passed GitHub CI on all
four native host targets and Chromium ([run `38659589224`](https://github.com/RFBorrello/WPInternals-Rust/actions/runs/38659589224)).
Those remote build results do not establish device support.
The latest local milestone adds complete browser FFU integrity verification.
Phone/USB evidence below remains historical; no phone commands were sent during
this change. MainOS milestone `83e11fb` passed remote tests and Chromium, but
native jobs stopped on a new Rust 1.99 Clippy lint about constant-size
`chunks_exact`. This change uses `as_chunks` for that UTF-16 conversion; behavior
is unchanged. Remote CI for the new source is pending.

| Check | Result |
| --- | --- |
| Rust tests | 105 passed on Windows: 67 integration tests, 37 native transport/harness unit tests and one decoded-CTL bounds unit test |
| Rust Clippy, all workspace targets and WASM adapter, warnings denied | Passed |
| WebAssembly target check and release build | Passed |
| React/TypeScript production build | Passed |
| Frontend range/format unit tests | 3 passed |
| Real-WASM browser integration tests | 33 passed |
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
