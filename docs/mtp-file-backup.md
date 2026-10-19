# Normal-mode MTP file backup

The Windows research helper `scripts/backup-rm875-mtp.ps1` can copy the files
already exposed by the connected 1020's Normal-mode MTP interface. It does not
unlock, change modes, install drivers, mount a disk, or write to phone storage.
It needs no Administrator token. Keep the phone in Normal mode and leave other
phone controls idle while it runs. Preview is the default:

```powershell
.\scripts\backup-rm875-mtp.ps1
.\scripts\backup-rm875-mtp.ps1 -Copy -OutputDirectory .\artifacts\my-new-mtp-backup
```

The output directory must be new and its parent must exist. A complete result
contains `files/`, an independent `verification-copy/`, and `manifest.json`.
Each file is read from MTP twice into separate local destinations. Both completed
local files are opened exclusively and SHA-256 hashed. Their lengths must match
the exposed metadata and their hashes must agree. The exposed names and sizes
are enumerated again before publishing a completion manifest. Both copies are
retained, requiring about twice the exposed file size in local storage.

The helper uses canonical `System.FileName`, since Shell display names can hide
extensions. Unsafe Windows names, traversal, duplicates/case collisions, unknown
lengths, more than 10,000 items, depth over 16, or more than 256 MiB of files stop
before copying. This small-file research helper is deliberately bounded; it is
not the engine's large-image streaming adapter. Source data passes through the
Windows Shell MTP copy service rather than UI messages or a full-image buffer.

Each copy has a 30-second completion-observation window. Underlying Shell/COM
calls are not a hard wall-clock-bounded API. Copies are asynchronous: cancellation,
timeout or mismatch leaves local outputs incomplete, and a submitted Shell copy
may still finish. There is no cleanup, move/delete, automatic retry, overwrite or
resume. Only a successful run publishes the completion manifest. Preserve an
incomplete directory for inspection and use a different new path for another run.

## Scope and privacy

This copies **only MTP-exposed files**. It excludes application-private data,
settings, credentials, boot partitions, GPTs and anything the phone does not
expose through MTP. Two matching host copies are consistency evidence, not a
phone-authenticated source checksum. Selection requires exactly one exposed
`0421:0661` device and checks its Shell path repeatedly. That path and VID/PID
do not authenticate the phone or detect every disconnect/reuse race. The manifest
keeps device authentication, full-device backup, app-data coverage, unlock
authorization and data-preservation validation false. It cannot admit a phone write.

The manifest includes relative personal filenames and hashes. Keep the actual
backup private; the repository's `artifacts/` directory is ignored. Share only
sanitized metadata when reporting validation.

## Observed RM-875 result

On October 19, 2026, the connected Normal-mode phone exposed three files totaling
2,289,461 bytes. The helper copied all three twice and matched every SHA-256.
An independent Python pass reread both local trees and verified every size/hash
against the manifest. Existing-output rejection preserved the completed backup.
Preview worked in Windows PowerShell 5.1 and PowerShell 7. Synthetic Shell tests
cover hidden extensions, path traversal/reserved names, duplicate paths, missing
and oversized lengths, ambiguous phones, and mismatching independent copies.
No raw disk, driver, phone mode or phone-storage write was involved. See the
[sanitized record](../tests/hardware/lumia-1020-rm875-mtp-file-backup.json).

This result reduces exposure for the visible files. It does not provide the
installed UEFI/FlashApp, validate emergency USB access, or establish a complete
rollback after an unlock failure. The [native raw backup](native-backup.md) and
[entry-preservation investigation](spec-a-entry-preservation.md) remain separate.
