# Spec A emergency-entry and loader-upload rehearsal

`wpi-core::spec_a_emergency_replay` now rehearses FlashApp preflight, emergency
entry, one legacy DLOAD loader upload and the returning V1 programmer handshake.
Its source is WPInternals 2.9.2 commit
`d8fd0aa516b16dc094df0422a3adc525af005c29`:
`LumiaUnlockBootloaderViewModel.PerformSoftBrick/SendLoader`,
`QualcommDownload.cs` and `QualcommSerial.cs`. Upstream MIT attribution is retained.
This is a Rust-library replay component. No CLI/IPC/UI execution command, native
adapter, physical arrival observer or phone write capability is enabled.

## Source and loader preparation

`EntryPlan::read` pins a regular source stream by the expected complete FFU
SHA-256, captures its bounded header in the same hashing pass, checks chunk
hashes and primary GPT, and requires the narrow 128 KiB entry profile. Payload
chunk zero must map once to beginning-relative chunk zero and once to
end-relative chunk zero, with no other destinations or multi-chunk first write.
Its source data must already be all zero. FFUs are limited to 16 GiB and headers
to the parser's existing 32 MiB limit. Reads remain bounded; the complete FFU is
not retained. Fingerprint/hash verification progress counts bytes monotonically,
with cooperative cancellation including completion boundaries. Parsing and
individual I/O calls are not interrupted mid-call.

`Loader::prepare` pins exactly one HEX/MBN import of at most 512 KiB, decodes it
with the existing bounded parser, checks the V1 code marker and compares its
last-certificate fingerprint to the selected reference root. The decoded bytes
are immutable. This binds local selections and establishes format/family evidence;
it does not authenticate OEM trust, programmer engineering status, firmware
applicability or device acceptance. Neither object is serializable/importable as
authority, and there is no candidate-loader fallback loop.

## Replayed sequence

1. Require one source endpoint on the selected physical port. Reuse fresh bound
   FlashApp preflight: current application, public ID, RRKH, SS, application and
   public-ID bookends. Require Spec A protocol 1, FFU-v1 advertisement and
   interpretable application-security presence before entry submission.
2. Send the FFU header, one 128 KiB zero payload and one send-only `NOKR` reboot.
   This intentionally models **storage-changing** emergency entry at the disk
   boundaries. It is not a read-only mode switch or a preservation guarantee.
3. Require a disconnect followed by exactly one Download endpoint on the same
   physical port. Timelines are bounded to 64 observations and 30 seconds per
   transition; elapsed time must be monotonic. Wrong endpoints, changed ports,
   ambiguous candidates, stale arrivals and surplus events stop the replay.
4. Send framed DLOAD alive (`0x06`) and RKH (`0x18`) queries. Validate the framed
   `18 01 00` plus exactly 32 nonblank root bytes, matching the source reference.
5. Upload at `0x2a000000` with framed `0x0f` requests, big-endian byte addresses
   and big-endian lengths, at most 256 bytes each. A short final request carries
   its actual length and bytes, following the upstream **byte-array overload**;
   the stream overload's fixed-size tail buffer is not reproduced.
6. Send one framed start (`0x05`) command. Require another disconnect/arrival
   on the same port, then one unframed V1 Hello with a framed valid reply.

The source public ID and physical-port values are never exported. A root
fingerprint can be shared by many phones; port continuity and RKH equality are
local correlation evidence, not authenticated unique identity. Download and
Programmer can share USB product IDs. Synthetic endpoint labels alone do not
establish a mode; protocol replies are also checked. Native OS detection and
cross-mode continuity remain unimplemented.

Both DLOAD requests and replies are HDLC framed. The later V1 programmer stage
uses unframed requests. A single-frame decoder now supports split delimiters,
escapes and checksums with an 8 KiB bound. It rejects empty reads, corruption,
trailing/concatenated frames and surplus fragments, and is poisoned on error.
The concrete framed replay transport models partial input and transfer errors;
it performs no OS I/O and does not validate physical USB partial-write behavior.

## Failure and progress semantics

Every command and arrival observation has a safe cancellation boundary.
Cancellation before the entry header sends no storage-changing request.
Any error/cancellation after header submission requires inspection, even if no
acknowledgement was received. No automatic retry, reset, loader fallback or later
command is sent. Errors report acknowledged RAM bytes, whether storage submission
was attempted, and whether the loader-start command was attempted. The counters
advance only after a valid reply. DLOAD `0x02` acknowledgements do not echo the
address or provide a memory digest; the counter is not readback verification.
A lost start reply can mean the loader is running and is never retried.

Completion means only a simulated programmer handshake. It is not bootloader
unlock, verified boot, full-device backup or data preservation. Reports always
keep `device_identity_authenticated`, `data_preservation_validated`,
`phone_contacted` and `phone_writes_enabled` false and label themselves replay-only.
No durable journal or report-import/resume API exists for this phase.

## Evidence and next integration

Ten new core/protocol tests cover a fully synthetic FFU and non-executable loader,
195 command-failure cases, all 44 command/arrival cancellation boundaries, source
public-ID changes at both bookends, changed download root and sixteen invalid
arrival timelines. Sentinel exchanges prove that later commands remain queued.
Failed replies never advance RAM byte counts. Entry/profile/import/digest/marker
checks and cancellation at every preparation callback are covered separately.
Framing tests exercise every split of an escaped reply and one-byte reads.

An independent Python translation uses the pinned C# CRC table and byte-array
overload to generate the public synthetic DLOAD vectors:

```text
python scripts/reference-spec-a-dload.py .reference/WPinternals tests/fixtures/spec-a-dload.json --check
```

The [programmer transfer composer](spec-a-unlock-executor.md) remains a separate
replay phase. Next work must join the phases with durable artifact-bound intent/
acknowledgement checkpoints, a native USB/serial and arrival adapter, fresh device
and recovery policy, and later UEFI/EFIESP boot-integrity stages. The saved
primary GPT and source FFU originals are not installed partition backups. The
phone owner's data-preservation preference remains in force. Only synthetic
transcripts were exercised; no entry, loader execution or phone write occurred.
