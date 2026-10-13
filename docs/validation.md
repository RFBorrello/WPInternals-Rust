# Local validation — October 13, 2026

Host: Windows ARM64 (`aarch64-pc-windows-msvc`), stable Rust 1.94, Node 24,
headless Microsoft Edge. The preceding milestone at commit `10d0fba` also passed
GitHub CI on all four native host targets and Chromium (run `38476781716`). Those remote build results
do not establish device support; this milestone's CI is recorded separately.

| Check | Result |
| --- | --- |
| Rust integration tests | 45 passed |
| Rust Clippy, all workspace targets and WASM adapter, warnings denied | Passed |
| WebAssembly target check and release build | Passed |
| React/TypeScript production build | Passed |
| Frontend range/format unit tests | 3 passed |
| Real-WASM browser integration tests | 24 passed |
| Tauri native Windows ARM64 release build with embedded UI | Passed |
| npm dependency audit after lockfile update | No reported vulnerabilities |
| USB discovery | Lumia 1020 RM-875 detected in normal mode, USB 0421:0661 |
| Hardware identification | Model, product code and firmware read successfully through native interface 3 / Microsoft WinUSB |
| Browser hardware identification | User reported Lumia 1020 / RM-875 / Spec A / 3051.50009.1451.1003 in normal mode, matching native results; exact browser version not recorded |
| Phone writes / mode changes | Not performed |
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
result separately. No mode command or hardware reconnection was performed.

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
