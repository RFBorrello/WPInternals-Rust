# Agreed product roadmap

Build a public, MIT-licensed successor to WPInternals with a shared Rust engine,
modern browser interface and native desktop apps. Full WPInternals functionality
is the product goal; ship validated capabilities incrementally. Universal
unlocking remains a research goal, not a promised outcome.

## Targets and architecture

- Windows ARM64, Apple Silicon, and Linux x86-64/ARM64.
- Validate Lumia 1020 (Spec A) and Lumia 730 (Spec B) first, then expand across
  hardware variants and Lumia generations. Investigate WP7 as a separate protocol
  family rather than assuming WP8/10 workflows apply.
- Separate firmware/image processing, protocols, profiles, and orchestration into
  Cargo crates; keep host APIs outside the core.
- Use nusb for native USB and WebUSB, with separate native serial and block-device
  capabilities. Share React/TypeScript/Vite UI between Rust WASM and Tauri 2 IPC.
- Share DeviceIdentity, CapabilityReport, OperationPlan, and OperationEvent
  contracts across discovery, inspection, preparation, execution, and progress.
- Process multi-gigabyte artifacts in bounded, seekable chunks; browser firmware
  processing runs in a worker rather than copying whole images through UI messages.
- Keep device communication, firmware and backups local. Serve the browser build
  as static HTTPS content without accounts or a processing server.

## Functionality goal

Use upstream stable 2.9.2 as the parity baseline, preserving attribution and
dependency licenses; review later source changes individually. Implement device
information, mode switching, stock FFU recovery, unlock/restore for both bootloader
families, root enable/disable, partition/full-device backup and restore, firmware
extraction, custom flashing, and GPT inspection/conversion. Port portable FAT/NTFS
image operations and patch processing without requiring host filesystem mounting.

Local firmware and loader imports are mandatory. Preserve complete offline
workflows; add downloads only from verified available sources. Guide users through
preparation, missing files, operation previews, progress, and actionable recovery.
Allow one active phone operation at a time.

## Compatibility and safety requirements

Track support by hardware variant, firmware, operation, host and transport using
verified, experimental, unsupported and unknown states. Unknown profiles cannot
write. Builds and successful identification do not validate flashing or unlocking.

Enable installation-free browser operations individually after complete workflow
validation. Require explicit device selection and renewed permissions after mode
changes. Route protected raw-storage interfaces and unvalidated browser workflows
to desktop. Windows ARM64 requires native WinUSB/class drivers and, where needed,
signed binding packages; legacy x86/x64 kernel drivers are not a solution. Provide
narrow Linux permission rules and OS-specific disk identity, exclusive access and
privilege handling for storage.

Before writes, validate identity, applicability, partition bounds, artifacts and
expected patch bytes; preserve recoverable originals. Model mode changes and writes
as explicit transitions. Retry only operations known to be repeatable. After an
interruption, inspect state before selecting recovery; cancel at safe boundaries.

## Implementation sequence

1. Foundation: workspace, CI, contracts, CLI/UI, image inspection, native/browser
   read-only probes, and recorded descriptors/transitions for both phones.
2. Recovery and imaging: stock recovery, extraction, GPT, backup/restore and native
   storage access before enabling unlock workflows.
3. Parity: distinct Spec A/B unlock and restoration, root patching and custom
   flashing; enable browser workflows only after their own validation.
4. Releases: desktop packages, static webapp, documentation and compatibility
   evidence; expand WP8/10 coverage and pursue WP7 separately.

## Acceptance evidence

- Parser/patch comparisons against upstream reference results, malformed input,
  oversized lengths and synthetic filesystem images.
- Protocol replay for partial transfers, disconnects, timeouts, mode changes,
  unexpected devices and interrupted operations.
- Physical 1020/730 validation for every advertised operation/host combination.
- Browser permission, reconnection, unsupported-capability, large-file and desktop
  fallback tests.
- Native build coverage for all four targets; packages with checksums and
  compatibility evidence. Additional hardware and signing credentials are required
  for broader verified coverage and signed public distribution.

Current implementation and results are documented in [parity](parity.md) and
[validation](validation.md). This roadmap does not enable unfinished capabilities.
