# Experimental native Spec A controller

`wpi unlock-spec-a` now composes the complete RM-875 native controller. Its
default action is an **offline preview**: pin the source FFU, reference ZIP,
saved primary GPT and one loader; verify the donor against the patch catalog;
bind boot/finish layouts; calculate the reciprocal secondary GPT. It does not
enumerate USB. Reports cannot be imported as execution or resume authority.

```text
wpi unlock-spec-a SOURCE.ffu REFERENCE.zip SAVED-PRIMARY.bin LOADER.hex DONOR-BOOT.efi \
  --disk-sectors CAPACITY_SECTORS \
  --expect-source-sha256 SOURCE_SHA256 \
  --expect-package-sha256 PACKAGE_SHA256 \
  --expect-primary-sha256 PRIMARY_SHA256 \
  --expect-loader-sha256 LOADER_INPUT_SHA256
```

Only an explicitly selected native Windows ARM64 experiment can execute. The
current profile is Lumia 1020 RM-875, product 059T909, firmware
3051.50009.1451.1003, with the analyzed 1424.0002 reference source. Unknown Normal
identities, firmware, source, roots, layout, capacity or donor fail admission.
Execution also requires Administrator access, three distinct new output files,
`--execute`, `--device-id`, `--journal`, `--first-snapshot`, `--final-snapshot`,
and `--confirm RM875-EXPERIMENTAL-UNLOCK-WITHOUT-FULL-BACKUP`. The preview must
be reviewed first. Supplying these flags changes phone storage; this is not a
read-only mode test or a validated consumer unlock workflow.

Run `wpi native-unlock-readiness` for a read-only Administrator/driver check.
The controller refuses execution before any mode request if elevation is absent
or no eligible historical Qualcomm emergency endpoint has a WinUSB binding.
Whole-device bindings use nusb's standard USB device path; composite interfaces
also require a registered custom interface GUID. Unknown instance-ID shapes,
protected/HID-class metadata, an incompatible setup
class, or a present device error cannot satisfy this check. A historical
binding is availability evidence only: actual arrival still needs strict port,
endpoint, root and protocol checks. This check installs no driver and elevates
no process. The initial host check found a non-elevated process, one historical
matching VID/PID candidate and zero emergency WinUSB bindings. That historical
candidate uses HidUsb and is not established as this phone's emergency endpoint;
the readiness check does not treat its label or VID/PID as proof of identity.
See [Windows emergency access](windows-emergency-access.md) for the sanitized
per-endpoint report, read-only Administrator helper and endpoint-specific setup
requirements. No driver-binding package or automatic rebind is installed.
An optional first-time checkpoint is now available with
`--manual-emergency-driver-setup`. It uses a distinct execution confirmation,
retains the live phone session and waits for manually configured access after
entry. Default execution still requires the historical binding. See the
[first-time workflow](windows-emergency-access.md#first-time-setup-checkpoint).

The browser/desktop capability matrix is unchanged. Native experiments do not
establish general unlock support, browser support, Lumia 730 support or parity.

## Sequence and verification

The controller retains one native operation lock across all stages:

1. Capture the five Normal identity queries and correlate Flash public ID,
   RRKH, security and capacity. Return through the known BootManager window,
   read the installed primary GPT twice, verify returning Normal and require
   byte equality to the prepared layout before entry.
2. Re-enter Flash and repeat bound identity checks. Send one pinned FFU header,
   one 128 KiB zero chunk and one reboot. Header intent already means storage
   may have changed: the reference implementation clears the secondary GPT.
3. Observe emergency arrival on the same physical port, verify DLOAD root,
   upload exactly one pinned loader in bounded RAM transfers and start it.
   Require a new arrival and validate the V1 programmer handshake. No alternate
   loader, protocol guessing or serial fallback is attempted.
   With manual setup selected, pause before opening the DLOAD endpoint and again
   before opening the returning programmer endpoint. Each checkpoint is limited
   to a directly bound `05c6:9008` device with one vendor bulk interface; F006,
   HID, serial and composite setups are excluded. An already healthy binding
   needs no operator change. See the workflow for polling and interruption limits.
4. Send the ten immutable programmer regions, close and reboot. The returning
   BootManager may receive one version-checked NOKS. Revalidate the original
   Flash identity/root/capacity and require the candidate primary twice before
   any finish-stage write.
5. Write the NV and first EFIESP pass. Write a derived, CRC-checked reciprocal
   secondary GPT at capacity minus 33 sectors. This additional metadata repair
   is necessary because entry cleared it; read-only storage admission requires
   both GPTs to agree. The original stock recovery capsule remains separate
   and still rejects unlock markers in the entry footprint.
6. Request NOKM mass storage. Bind the physical port, complete Windows USB
   instance ancestry, exact capacity, disk identity, paired GPT and exclusive
   read-only raw handle. The disk must **already be offline and read-only**;
   no host disk attribute, mount, drive letter or privilege is changed. Missing
   admission stops here, before opening a raw disk. Native ARM64 WinUSB access
   to emergency/programmer modes must be available before testing this route.
7. Stream a targeted snapshot in 64 KiB reads, reread every range and verify
   the output archive. On a post-NV layout, capture BACKUP_BS_NV rather than
   assuming another adjacent hole is vacant. Read the full captured EFIESP
   through its pinned archive and prepare the second pass from that image.
8. Close disk handles and request a manual Volume Down + Power restart.
   Capture returning BootManager, issue at most one NOKS and recheck Flash
   identity/GPT. No speculative old/new serial reset packets are sent.
9. Write the second EFIESP pass, repeat bound mass-storage capture and compare
   the **entire installed EFIESP** against the expected overlaid image. ACKs
   alone do not prove stored bytes.
10. After another manual restart, require the original Flash identity, expected
    primary and unlocked platform/UEFI security observations. Reboot once and
    verify all five Normal queries against the original identity.

Hotplug watches are armed before mode requests. Disconnects between inventory
polls are retained; a reused Windows instance ID is eligible only after its own
new event. Unrelated USB events do not revive a retired BootManager interface.
Unknown devices or multiple devices on the bound port stop observation. Each
wait has a fixed 120-second deadline; no mode request is repeated on timeout.

## Interruption and recovery

Each command has a synchronized JSONL intent before submission and a paired
validated acknowledgement or send-only submission record afterward. Bindings
include all artifact hashes, both transformed primary hashes, donor and capacity.
Write records identify byte addresses and lengths; request bytes and public IDs
are not logged. A journal failure, short OUT, timeout, wrong reply, disconnect,
cancellation, readback mismatch or identity change stops with no further command.
There is no automatic retry, cleanup write, reset, rollback or crash resume.
Manual setup repeats only read-only inventory checks, never interface-open,
protocol-query or command attempts. Its journal records `manual_setup_selected`
and `awaiting_driver_setup`; neither authorizes importing or resuming a session.

```text
wpi inspect-spec-a-native-journal interrupted-native.jsonl
```

The inspector bounds records/files, checks bindings, sequence, paired intents,
terminal states and monotonic storage uncertainty. Torn final records and
unmatched intents require state inspection. Imported completion records are
advisory; they do not authenticate hardware evidence or admit another operation.

After failure, leave the cable connected and record the phone's actual mode.
Preserve the journal and any completed snapshots. A failure before entry can
still leave the phone in Flash. An entry/programmer failure can leave emergency
mode; an interrupted NV/EFIESP pass can leave boot state incomplete. Do not rerun
the unlock command as recovery or restore source-FFU coordinates onto the larger
installed disk. Inspect the last durable intent and current identity/layout;
choose any recovery write separately. Full stock recovery can erase data and
is not automatically selected by this controller.

## Evidence and limits

Software includes focused fault tests for transaction/journal ordering, short
or failed native transfers, cancellation, hotplug identity reuse, wrong devices,
ambiguous disks, geometry changes, output collisions, post-NV capture, malformed
GPTs and torn journals, alongside existing upstream protocol/patch replay tests.
The optimized CLI also prepares a preview from the local pinned RM-875 artifacts.
The physical controller has **not** run on the test phone.

Installed FlashApp binary identity remains unverified. The reference analysis
does not prove the installed binary's entry behavior. Snapshots taken after entry
cannot recover originals lost before capture and are not a full userdata backup.
No full data-preservation claim or validated physical rollback follows from this
implementation. Optional upstream MainOS patching is not implemented; a phone
that needs it can fail to return to Windows. Driver binding, loader acceptance,
engineering SBL3 behavior, acknowledgement policy and the complete return path
still require physical validation. These are external evidence requirements,
not flags to clear after a successful build.
