# WPInternals Rust

A local Lumia workbench with a Rust engine, a browser UI, native desktop apps,
and a CLI. Public project code is MIT licensed; upstream attribution is retained.

**This is a development implementation, not full WPInternals parity.**
Production device flashing, unlocking, relocking, restore and root installation
remain blocked. A CLI-only [experimental native RM-875 unlock controller](docs/spec-a-native-controller.md)
is implemented with an offline preview by default; its physical execution and
data preservation are unvalidated. No physical device, firmware, host, or transport combination has
been comprehensively hardware-validated. A native normal-mode identification
session has succeeded on a Lumia 1020 RM-875 / firmware `3051.50009.1451.1003`
using Windows ARM64 and Microsoft WinUSB. The user also reported a successful
browser identification matching that model, variant and firmware. See the
sanitized records in `tests/hardware/`; the browser version was not recorded.
The Lumia 730, other hosts, repeatability and phone writing workflows still await
hardware validation.

## What works

- Local [Spec A UEFI-variable/EFIESP finish-stage plans](docs/spec-a-finish-stages.md),
  including installed-image second-pass reconstruction, failure-contained replay
  and interruption-journal inspection. A separate native controller now joins
  entry, programmer, mass-storage capture, both EFIESP passes and return checks;
  it has not been executed on a phone.
- A reviewed [experimental RM-875 test procedure](docs/rm875-experimental-test.md),
  with session-bound manual driver and disk-state checkpoints. The separate disk
  helper previews by default; explicit operator use can set only a pinned phone
  disk's read-only/offline flags. No physical unlock or recovery is validated.

- Windows/macOS/Linux USB discovery with nusb, and browser WebUSB selection.
- Read-only NOKV identification on vendor-specific Lumia flash interfaces; native
  and browser Nokia Care Suite model/firmware queries on normal-mode vendor
  interface 3. One native result and one matching user-reported browser result
  exist for the RM-875; status remains experimental.
- Legacy single-store FFU inspection, SHA-256 chunk verification, sparse primary
  partition extraction, GPT CRC/bounds checks, and Partitions.xml export.
- Portable [FFU catalog verification](docs/firmware-validation.md): RSA/SHA-256
  signatures, signed hash-table membership, bounded PLAT scanning and a corroborated
  MainOS registry/DSM firmware-version fallback.
  Signer trust and device acceptance remain unverified; valid signatures cannot enable recovery.
- Experimental [Windows read-only backup access](docs/native-backup.md): recognized
  already exposed phone disks, exclusive read-only access, paired GPT validation
  and bounded copies. Physical backup behavior is not hardware validated.
- Offline [signer and applicability assessment](docs/oem-trust-and-applicability.md):
  certificate dates/usages, limited chain checks with image-local production PK
  discovery, missing-issuer diagnostics
  and MainOS hardware-variant comparison. Independent OEM trust, product-code/region
  applicability and device acceptance remain unverified.
- FAT/NTFS boot-sector inspection, native filesystem directory listing and file extraction.
- Reversible, hash-pinned upstream patches on extracted files and **new copies** of FAT images.
- Shared React UI, Rust WebAssembly processing in a worker, bounded streaming,
  native extraction cancellation, and a capability matrix that blocks phone writes.
- Recovery preparation checklist in CLI, browser and desktop; native preparation
  and browser preparation verify full-file/chunk hashes with progress and cancellation.
- Mode-change previews and read-only reconnection checks in all frontends;
  the core transition engine runs in replay, with cancellation,
  permission, identity and deadline checks. Live mode switching remains blocked.
- A CLI-only [native mode-validation experiment](docs/native-mode-test.md) for
  RM-875 / 3051.50009.1451.1003 / Windows ARM64. Its first live attempt entered
  Flash but could not correlate the returning interface, which had no USB serial.
  Execution is now blocked pending further identity validation; read-only previews remain available.
- CLI-only [public-ID inspection](docs/public-identity.md), using a dedicated
  read-only query and redacted report. Normal-mode public-ID presence has been
  observed on the connected RM-875. A subsequent native experiment matched the
  Normal/Flash IDs; one complete native round trip also verified the returning
  Normal identity on Windows ARM64.
- A separate [public-ID mode-validation harness](docs/public-id-mode-test.md)
  requires fresh public-ID equality and physical-port continuity before its return
  request. One RM-875 cycle completed with unchanged firmware and two mode
  requests sent once. See [the timing/evidence record](tests/hardware/lumia-1020-rm875-public-id-mode-test-completed.json).
  Preview is read-only; explicit execution remains a hardware experiment.

NTFS directory and kernel reads have been validated on one real RM-875 MainOS
image. A small patched dependency handles index records smaller than clusters;
synthetic tests cover resident/fragmented files, invalid VCNs and cyclic indexes.
One local RM-875 FFU passed native and browser inspection, chunk-hash verification,
and matching EFIESP/MainOS reconstructions. Metadata-only evidence is recorded in
`tests/fixtures/rm875-validation.json`; proprietary firmware is not included.
NTFS image writes, modern/multi-store FFUs, WP7 protocols, and complete device
workflows are not implemented. Hash verification does not authenticate an FFU’s
signing catalog. The browser also uses Rust NTFS lookup for the narrow MainOS
firmware-version fallback; general filesystem browsing and patching are CLI features.
Compressed/encrypted NTFS streams are rejected. The backup engine also has an
experimental Windows read-only storage adapter for phones already exposing a
suitable disk; it has not been validated on phone storage. See
[native backup](docs/native-backup.md) for its guarded CLI workflow.

[Spec A offline preparation](docs/spec-a-preparation.md) now parses stock boot
images and imported V1 programmers, checks HEX records and fingerprints, and
previews unique SBL2/SBL3 patch locations. It also checks SBL1 prerequisites,
compressed UEFI targets, and stock/optional-donor EFIESP patch applicability.
Separate [offline image assembly](docs/spec-a-assembly.md) can now export new
unsigned UEFI and donor-patched EFIESP copies, with narrow BCD editing and
verification of unchanged files. The [offline package builder](docs/spec-a-package.md)
adds the SBL1 extra sector, SBL2/SBL3 patches, GPT changes, source originals and
a hashed restore manifest in one ZIP. It is a source-based reference package;
the [read-only preflight](docs/spec-a-preflight.md) CLI can now compare FlashApp
RRKH/security evidence and conditionally inspect its primary GPT without changing
contexts. One native RM-875 Flash session matched the source root fingerprint
and checked security fields. The first integrated mode cycle stopped on a parser
assumption and required a manual restart; a subsequent GPT-read cycle completed
automatically with unchanged firmware. Recovery validation, installed partition
backups and an unlock executor remain outstanding.
The [Spec A executor work](docs/spec-a-unlock-executor.md) now includes V1
programmer codecs and a replay-only transfer phase with address-bound replies,
command-boundary cancellation and fail-stop error handling. It does not enable
live unlocking or establish preservation of installed data.
`wpi plan-spec-a-programmer` now composes the ten boot-stage regions from a
pinned package and saved live-derived layout, with explicit GPT/SBL1/WINSECAPP
length rules and checks excluding unrelated partition writes. Its report is
metadata only; the immutable in-memory plan can feed the concrete replay phase.
An [emergency-entry/upload rehearsal](docs/spec-a-emergency-replay.md) now covers
the preceding storage-changing entry, one legacy DLOAD loader, split framed
replies, root/port correlation and a returning programmer handshake. It uses
concrete replay transports only and exposes no live execution control.
A [joined Spec A replay](docs/spec-a-joined-journal.md) now persists artifact-bound
intent/acknowledgement and mode-arrival checkpoints across entry, upload and the
first boot-transfer phase. Save failures stop before the next command; journal
files cannot authorize execution or automatic resume.
A separate [artifact-bound session check](docs/spec-a-session.md) joins pinned FFU,
package, GPT and loader inputs with fresh Normal identity bookends. Its native CLI
can also run one explicit read-only Normal/Flash/Normal cycle; one Windows ARM64
cycle passed source-root/security/capacity and returning identity checks. Storage
writes remain disabled. The [reference FlashApp audit](docs/spec-a-entry-code.md)
distinguishes the conservative Data-tail exposure bound from that exact binary's
33-sector backup-GPT clear. Local GPT recovery capsules and a bounded, read-only
targeted storage snapshot are implemented; installed binary verification and the
complete native unlock/recovery continuation remain outstanding.
The separate [return-boot GPT experiment](docs/boot-gpt-capture.md) can preserve
the live primary GPT after verified return to Normal. It uses a bounded read
window and retains the same blocked phone-write capabilities.
An [offline live-layout planner](docs/spec-a-live-layout.md) now checks a pinned
reference ZIP against that saved primary and recorded capacity. Its candidate
uses the installed geometry, reports slot/range/identity differences and payload
fit, and leaves the source package and all phone-write gates unchanged.
The [stock recovery file audit](docs/rm875-recovery-path.md) verifies the FFU's
minimum-size/expansion rules and source backup-GPT template, including explicit
primary/backup attribute differences. It does not validate physical recovery.
The [recovery session journal](docs/recovery-journal.md) records intents and
acknowledgements durably for bounded protocol replays. Save failures stop further
submissions; there is no native flashing or automatic resume capability.

## Quick start

Prerequisites: stable Rust, Node.js **22.12+** (Node 24 recommended), npm, and the
platform build tools required by Rust/Tauri. Windows builds use the MSVC toolchain.

```sh
npm --prefix apps/ui ci
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked --no-default-features --root .tools
npm run wasm
npm run dev
```

Open `http://localhost:1420`. The browser works without a local helper. USB needs
Chrome/Edge, a secure context, and host USB access; offline image inspection does
not need WebUSB. For local browser experiments, use the generated images in
`tests/fixtures/`. **They are synthetic test data, not flashable firmware.**
See [browser identification](docs/browser-identification.md) for the normal-mode
read-only check and recovery after an interrupted USB query.
See [mode transitions and reconnection](docs/mode-transitions.md) for a read-only
unplug/replug check, replay routes and remaining hardware prerequisites.

The wasm-bindgen CLI version must match the `wasm-bindgen` version in Cargo.lock.
The build script looks in `.tools/bin` first, then PATH. Rust’s cargo must be on
PATH, or installed at its standard `~/.cargo/bin` location.

### Desktop

```sh
npm run wasm
npm run desktop:dev
# Build distributable packages:
npm run desktop:build
```

The desktop app shares the UI and uses native Rust commands through Tauri IPC.
It does not route device traffic through a local HTTP server.
See [platform setup](docs/platforms.md) for WebView/runtime, USB and packaging details.

### CLI

```sh
cargo run -p wpi-cli -- devices
cargo run -p wpi-cli -- probe '<device-id-from-devices>'
cargo run -p wpi-cli -- identity-probe '<device-id-from-devices>'
cargo run -p wpi-cli -- prepare-mode '<device-id-from-devices>' flash
cargo run -p wpi-cli -- mode-test '<device-id-from-devices>'
cargo run -p wpi-cli -- mode-public-id-test '<device-id-from-devices>'
cargo run -p wpi-cli -- replay-mode tests/fixtures/mode-normal-to-flash.json
cargo run -p wpi-cli -- inspect path/to/firmware.ffu
cargo run -p wpi-cli -- prepare-recovery path/to/firmware.ffu
cargo run -p wpi-cli -- prepare-spec-a path/to/firmware.ffu --loader path/to/programmer.hex
cargo run -p wpi-cli -- verify path/to/firmware.ffu
cargo run -p wpi-cli -- extract path/to/firmware.ffu EFIESP efiesp.img
cargo run -p wpi-cli -- convert-gpt path/to/firmware.ffu Partitions.xml
cargo run -p wpi-cli -- files mainos.img Windows/System32
cargo run -p wpi-cli -- extract-file mainos.img Windows/System32/NTOSKRNL.EXE kernel.exe
cargo run -p wpi-cli -- patches
cargo run -p wpi-cli -- patch-files extracted-files patched-files RootAccess-MainOS
cargo run -p wpi-cli -- patch-fat efiesp.img patched-efiesp.img RootAccess-EFIESP
cargo run -p wpi-cli -- plan unlock_bootloader
```

`patch-files` outputs only catalog target files to a new directory; it does not
copy an entire source tree. `--reverse` restores catalog-original bytes. Output
files are never overwritten by native operations. FFU extraction reconstructs
primary mappings; end-relative writes remain metadata until disk capacity and
backup GPT reconstruction are implemented.

## Tests

```sh
python scripts/generate-fixtures.py
python scripts/generate-ntfs-fixture.py
cargo test
cargo clippy --all-targets -- -D warnings
cargo check -p wpi-wasm --target wasm32-unknown-unknown
npm --prefix apps/ui test
npm --prefix apps/ui run test:browser
```

Browser tests run real WebAssembly and verify partition export bytes, corruption
handling, XML export, responsive navigation, and compatibility status. Mocked USB
boundaries exercise normal-mode information, interface selection, partial requests,
wrong response IDs, timeouts, cleanup, retry blocking, and reconnection. Local
Windows tests use installed Edge by default. On Linux, install Playwright Chromium
and set `WPI_BROWSER_CHANNEL=chromium`.

## Architecture and next steps

- `wpi-types`: shared serializable contracts.
- `wpi-image`: bounded firmware/GPT/filesystem parsing and offline patching.
- `wpi-protocol`: OS-independent Lumia and Qualcomm codecs plus replay transport.
- `wpi-core`: compatibility, inspection, atomic artifacts, and operation coordination.
- `wpi-transport`: native USB/serial discovery and read-only probes.
  [Native USB transactions](docs/native-usb-transactions.md) retire uncertain sessions
  and share one bounded deadline across OUT/IN transfers.
  An explicit [emergency USB probe](docs/native-emergency-probe.md) handles fragmented
  DLOAD/V1 replies for already exposed endpoints; it cannot enter those modes or write.
  Separate [serial probes and arrival observation](docs/native-serial-arrival.md)
  add bounded native reads and discovery without enabling the unlock executor.
- `wpi-cli`, `wpi-wasm`, `apps/desktop`, `apps/ui`: frontends and adapters.

See the [agreed roadmap](docs/roadmap.md), [feature parity](docs/parity.md), [hardware validation](docs/hardware-validation.md),
and [third-party notices](THIRD_PARTY_NOTICES.md). Recognition must never be
promoted to verified support solely because the application builds.
