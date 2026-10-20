# Experimental captured-primary GPT recovery

`wpi-gpt-recovery` is a separate native Windows ARM64 development executable for
the already exposed DLOAD endpoint of the recorded 32 GB Lumia 1020 RM-875. It
defaults to offline preview. It does not resume the stopped unlock, repeat entry,
install drivers, erase/reset, patch a boot partition or flash a full FFU.

Its narrow purpose is to restore the captured MBR/primary GPT and verify the
original Normal identity. Physical recovery is unvalidated. It can fail or leave
the phone unbootable, and it does not establish user-data preservation.

## Inputs and approval

Use the same five pinned local inputs as native unlock: reference FFU, reference
package, saved installed primary, matching loader and supported donor boot file,
with capacity and all four source/package/primary/loader hashes. These construct
the existing immutable, integrity-checked profile bundle. The donor and transformed
unlock regions are validated inputs but are not recovery payloads.

With no execution flag the executable composes a JSON preview and enumerates no
USB. Execution separately requires `--execute`, explicit `--device-id`, a new
`--journal`, `--expect-port-sha256`, `--expect-normal-serial-sha256` and the exact
confirmation `RM875-RESTORE-CAPTURED-PRIMARY-GPT-FROM-DLOAD`. Previous unlock or
preflight confirmations cannot authorize it. A saved journal or imported report
is never an execution/resume credential.

Keep target selectors private. The Windows port digest is SHA-256 over the
uppercase parent-hub instance string, a newline and the decimal connection index.
It must describe the independently checked current physical target. The expected
Normal serial digest comes from the previously identified phone. A DLOAD root
fingerprint is a family comparison, not authenticated Lumia model identification;
the operator must already know that this is the same owned RM-875 on that port.

## Fixed sequence

1. Check the exact immutable source/layout/loader bundle and captured GPT CRCs,
   61,071,360-sector geometry and zero final byte. Require a new journal and the
   current Windows ARM64 host. Acquire the native phone-operation lock.
2. Select only the present 05c6:9008 endpoint at the pinned physical port. Require
   healthy whole-device WinUSB metadata and one vendor interface with two bulk
   endpoints. No automatic driver/configuration change is permitted.
3. On one bound DLOAD session, send alive and root queries. Compare the fresh root
   with the pinned FFU/reference-loader root before uploading anything. Submit
   only that one pinned loader in bounded RAM chunks and start it once.
4. Observe actual removal/arrival at the same physical port and validate the
   programmer with V1 hello, security mode zero and boot partition 0x21. A missing
   interface, incompatible driver, wrong response or timeout stops. There is no
   protocol guessing or alternate loader.
5. Write captured MBR bytes 0..511, followed by GPT bytes 512..17406 in at most
   1,024-byte V1 packets: **17,407 bytes in 18 write requests**. No other storage
   address or payload is admitted by the process-local packet guard.
6. Close the programmer partition and submit one planned programmer reboot.
   Observe the known BootManager 1.16/protocol 1.1 stage, read the primary twice
   and require all **17,408 bytes** to match the captured original. No NOKS,
   boot-timer hold or additional reset is sent by this recovery path.
7. Wait for Normal within the same fixed 120-second observation deadline. Reuse
   its successfully opened arrival handle for the guarded five-query identity
   check. Require expected serial, RM-875, 059T909 and 3051.50009.1451.1003 before
   reporting recovery completion.

The shared loader/transport machinery retains per-command durable intent and ACK
records, short-transfer/session retirement, physical binding, bounded buffers and
safe cancellation boundaries. An exact packet/stage/storage-flag allowlist rejects
entry packets, unlock-region writes, altered addresses/bytes, repeated or extra
commands. Failures stop without cleanup writes, fallback loaders or automatic
reboot/retry. The operation lock spans all stages.

## Boundary quirk and incomplete rollback

The primary-write length follows upstream stable 2.9.2 `TestCode.RecoverBadGPT`
and the Spec A bootloader workflows (Rene Lergner, MIT): the loader has a bad
boundary check at the last GPT byte, so upstream writes 0x41ff bytes at 0x200.
This tool also restores the captured MBR that entry may have cleared. Byte 17407
is deliberately omitted and must already be zero; the entire subsequent
BootManager readback verifies that assumption. A nonzero captured final byte
rejects preparation. ACKs alone cannot establish correct stored metadata.

The **secondary GPT is not restored**. The programmer's V1 write address is a
32-bit byte address; the backup on this 32 GB disk lies beyond that range. This
tool does not wrap the address or attempt unvalidated writes through locked
Flash. Captured primary metadata references the original backup location, but
this is not proof that valid backup bytes exist there.

Front-padding sectors 34..255, installed boot partitions and any possible
Data-tail damage are not recovered. Only three exposed files have verified local
backups; private app data/full-device originals are absent. A successful boot or
primary comparison does not establish a complete rollback or preservation.

If programmer arrival, readback or Normal verification fails, preserve the new
journal and inspect the actual mode before proposing another operation. Missing
the BootManager read window is a failed verification, not a reason for another
automatic restart. A successful report explicitly leaves `secondary_gpt_restored`,
`unlock_attempted`, `data_preservation_validated` and general `hardware_validated`
false.

## Software verification

Four new transport regressions check exact address coverage/boundary omission,
rejected packet mutations/retries, invalid selectors/shapes and intent/ACK save
faults at every packet boundary. The standalone CLI has subprocess checks for
default-stack startup, explicit selection/confirmation and rejected unlock flags.
The main CLI's arguments remain unchanged. Windows ARM64 local transport/CLI
tests, strict Clippy and optimized builds passed. Actual pinned-input offline
preview reports no contact and the expected 18 requests. These checks do not
validate loader acceptance or physical GPT recovery.
