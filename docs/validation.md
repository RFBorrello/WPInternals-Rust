# Local validation — October 13, 2026

Host: Windows ARM64 (`aarch64-pc-windows-msvc`), stable Rust 1.94, Node 24,
headless Microsoft Edge. The preceding milestone at commit `06b5cc3` also passed
GitHub CI on all four native host targets and Chromium. Those remote build results
do not establish device support; this milestone's CI is recorded separately.

| Check | Result |
| --- | --- |
| Rust integration tests | 32 passed |
| Rust Clippy, all workspace targets and WASM adapter, warnings denied | Passed |
| WebAssembly target check and release build | Passed |
| React/TypeScript production build | Passed |
| Frontend range/format unit tests | 3 passed |
| Real-WASM browser integration tests | 15 passed |
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
