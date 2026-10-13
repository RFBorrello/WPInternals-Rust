# Hardware validation

No verified device operation is shipped yet. Automated image/replay tests cannot
establish hardware safety. A USB VID/PID identifies an interface, not a model.

## First read-only sessions

1. Connect the Lumia 1020; run `wpi devices` and record the host, OS, app revision,
   USB mode, descriptors, interface classes and driver binding.
2. Run `wpi probe '<id>'`. In flash mode it sends NOKV and, when the application
   is FlashApp, FVER. In normal mode it sends only model/product/firmware read
   queries to vendor-specific interface 3. It does not switch phone modes or touch storage.
3. Record hardware variant separately until it can be authenticated from the device.
   Do not infer RM number from a chosen firmware file or the USB product label.
4. Repeat on Lumia 730, Windows ARM64, Apple Silicon, and Linux x86-64/ARM64.
5. Import real local FFUs and compare parsed metadata and extracted partition
   hashes with the pinned upstream version. Do not commit proprietary images.

## Observed normal-mode browser reconnection

The user supplied `reconnection-check.json` and explicitly confirmed unplugging
and reconnecting USB after **Remember this phone**, before **Check reconnection**.
The report correlated the returning normal-mode interface: USB serial, variant,
firmware and bootloader family checks passed; platform remained unverified.
The sanitized record is
[`lumia-1020-rm875-browser-normal-reconnection.json`](../tests/hardware/lumia-1020-rm875-browser-normal-reconnection.json).

This is one user-confirmed cycle, with an exported comparison report rather than
an independently captured USB event/wire transcript. Device and host identity
context comes from earlier sessions; the export contains agreement checks rather
than identity values. Exact browser name/version and timing were not recorded.
It establishes an observed read-only reconnection result, not an authenticated
identity, Flash-mode transition, validated firmware applicability or write support.
Capability status remains experimental and recovery authorization remains false.

## Evidence required for writes

Before enabling an operation, implement its entire state machine, identity and
firmware checks, expected command transcripts, recovery course, and safe boundaries.
Record hardware results for the exact model/RM, firmware, bootloader state,
host architecture, transport, and operation. A different firmware or USB mode is
not covered automatically. Do not perform destructive disconnect tests on the
user’s only phone; simulate those failures with protocol replay first.

Store sanitized evidence records under `tests/hardware/`. Redact IMEI, serial
numbers and identifiers before public publication. Keep personal raw logs local.
Evidence records alone cannot bypass the Rust gate; enabling writes requires a
reviewed implementation and profile change.
