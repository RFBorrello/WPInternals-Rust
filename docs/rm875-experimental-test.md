# Preparing one experimental RM-875 unlock test

This is a native Windows ARM64 CLI experiment on the owner's Lumia 1020 RM-875,
product 059T909, firmware 3051.50009.1451.1003. It can lose data or leave the phone
unable to boot. Preparation was requested with that data-loss risk acknowledged;
this does **not** mean an unlock has started or physical recovery is validated.
Browser write capabilities remain disabled.

## Concrete scope

Use the pinned 1424.0002 reference FFU, reviewed reference ZIP, saved installed
primary GPT, matching FAST8960 loader and catalog-supported donor. The preview
checks their hashes and composes 7,529,371 programmer bytes and 33,835,520 first-pass
bytes, plus a derived secondary GPT and the capture-dependent second pass. The
reference ZIP contains reference originals, not installed boot-partition backups.

The test's sequence is the [native controller sequence](spec-a-native-controller.md):
fresh Normal/Flash correlation and double GPT capture; emergency entry; one
programmer; both boot/NV/EFIESP passes; USB-bound snapshots and complete final
EFIESP readback; unlocked security observation and original Normal identity.
There is no reset, full stock FFU flash, Data-partition payload, alternative loader
or automatic recovery. Windows mounting behavior and the installed entry binary
remain unverified, so this scope does not guarantee preservation of Data.

The known reference entry clears the first 256 sectors and final 33 GPT sectors.
Its installed binary has not been identified; the conservative unknown-code model
also exposes 223 Data-tail sectors (114,176 bytes). Only three MTP-visible files
have verified local backups. Private app data and the original boot partitions
have no pre-entry backup. A post-entry snapshot cannot recover overwritten bytes.

## Before the run

Review the actual offline preview and pinned launcher locally. The launcher must
default to preview, verify the optimized executable digest, preserve existing run
directories, and require explicit execution and the distinct first-time setup
confirmation. It must select only the unique current Normal endpoint with the
reviewed USB serial hash and verify model/product/firmware before execution.
The native controller repeats its complete identity/GPT checks independently.

Use an Administrator terminal, keep the cable on its current physical port, and
leave browser phone controls idle. Keep Device Manager and a second Administrator
PowerShell available for the two manual setup procedures. Reserve at least 512 MiB
of free local space for the two targeted snapshots and logs. Do not accept Windows
offers to initialize or format the phone disk.

## Manual checkpoints

Emergency/programmer arrival can require the reviewed in-box WinUSB binding.
Match the **exact instance printed by the running controller** in Device Manager.
The [driver checkpoint](windows-emergency-access.md#first-time-setup-checkpoint)
waits up to ten minutes per 9008 endpoint; it does not rebind automatically, touch
the historical F006 HID device or install the unsigned development INF.

Each mass-storage arrival now has its own ten-minute checkpoint before raw access.
Discovery binds one disk through the complete live USB ancestor, expected capacity,
512-byte sectors, serial and phone-storage hardware tokens. It rejects host
boot/system disks. Once selected, changes in its number, identity or ancestry stop
the run. The controller polls metadata only and does not set host attributes.

The console prints a command for `scripts/prepare-bound-phone-disk.ps1` containing
the exact USB instance and separate PnP/serial SHA-256 pins. Keep it local. In the
second Administrator terminal, omit `-Apply` first to inspect the helper's preview.
Then use its explicit `-Apply` form on that exact target if state changes are
needed. The helper verifies fresh inventory, capacity and both serial sources,
then rechecks the same CIM ObjectId before **each** operation. It sets read-only
first and verifies it before setting offline. It never clears either flag, selects
by disk number alone, opens a raw disk, initializes/formats, or changes global
automount policy. Missing or contradictory facts and uncertain commands stop
without retry or rollback. These flags can persist; no automatic reversal occurs.

Microsoft documents `Set-Disk -InputObject` for read-only and offline in separate
[parameter sets](https://learn.microsoft.com/en-us/powershell/module/storage/set-disk).
The helper uses two separately checked calls. Offlining can involve OS filesystem
activity, and Windows may already have mounted the disk before this checkpoint.
The helper does not prove that Windows made no writes or that user data survived.
The helper runs in a separate terminal: controller cancellation or expiry does
not cancel an in-flight Windows state operation there. After interruption, wait
for that helper's outcome and inspect current disk state before further action.

After two ready observations, the controller opens one exclusive **read-only**
handle and repeats disk identity, attributes and paired GPT verification before
capture. Metadata readiness alone is not raw access. Existing readback and archive
checks remain required. Manual Volume Down + Power restarts occur only when the
running controller requests them after closing disk handles.

## Failure and recovery decision

| Last durable stage | Consequence and next action |
| --- | --- |
| Before entry intent | No planned storage command yet. Record actual mode and identity; a failed preflight may leave Flash. No automatic reset was sent. |
| Header/zero entry, driver setup, DLOAD or programmer | GPT/boot bytes may already have changed. Keep the cable connected and preserve the journal. Inspect the exact endpoint and last command before choosing a loader or recovery write. A manual restart is not a rollback. |
| NV/EFIESP pass or disk setup | Boot state may be incomplete. Preserve any complete snapshots and inspect the current layout. Do not rerun the launcher or apply source-template GPT coordinates to the larger disk. |
| Readback or final boot failure | Do not claim success or issue a cleanup/reset automatically. Compare the expected stage and actual state before a separate recovery operation. |

The small recovery capsule preserves the captured primary and a reconstructed
secondary, not the captured original secondary or all overwritten boot bytes.
The available stock FFU is older than installed firmware; downgrade acceptance,
layout application and physical recovery are unvalidated. No guaranteed rollback
or automatic full-stock rescue is part of this test. A subsequent recovery flash
requires its own reviewed plan and can erase remaining data.

## Evidence after a successful return

Preserve the native journal, both snapshots, full EFIESP comparison and final
Normal/security observations. Recopy the exposed files and compare their hashes
against the fresh pre-test manifest. Ask the owner to check important apps/data
on the phone. Report these individual outcomes; neither three matching files nor
a successful boot establishes that every private app database was preserved.
