# RM-875 recovery-path investigation

The next requirement is a feasible recovery strategy for the locked retail
Lumia 1020, not a promise of a pre-unlock backup that existing access cannot
provide. This milestone audits local stock firmware and saved GPT evidence.
It sends no USB commands and does not validate physical recovery.

## Stock FFU facts

The local `3051.50009.1424.0002` FFU has a legacy INI manifest containing
`SectorSize=512`, `MinSectorCount=20971520` and a Data partition with
`UseAllSpace=true`. Its approximately 10 GiB GPT is a template matching that
minimum, while the saved phone capacity is 61,071,360 sectors. The minimum-size
constraint is satisfied. This is evidence that the template is intended for
application-specific layout handling; a larger-capacity FFU is not established
as necessary merely because the phone is larger. Actual FlashApp GPT/NTFS
expansion behavior has not been implemented, emulated or hardware validated.

There are 13,086 beginning-relative mappings and two end-relative mappings. The
auditor inspects only the bounded single-chunk/index-zero end-relative profile;
other shapes remain uninterpreted. One source payload carries a backup GPT at
its final sector. Header/table CRCs, template geometry, identities, partition
bounds and names agree with the source primary, except for a MainOS attribute:
the primary has `0x0000000000000000`, the backup `0x8000000000000000`.
The differing tables have separately valid CRCs. The audit records this
difference, preserves both source inputs and leaves runtime interpretation
unvalidated. It rejects contradictions in identities, bounds or names and does
not normalize the templates. Initial audit rejection of the unequal tables led
to this explicit difference report; no phone policy gate was changed.

Neither the source backup template nor a reconstructed backup from a saved
primary is a capture of the installed backup GPT. Stock recovery can replace
the OS and user-data layout; payload sparseness, a matching disk size or a valid
chunk table is not evidence of data preservation. The source image is older
than the installed `3051.50009.1451.1003`; downgrade acceptance, product-code
applicability and firmware trust remain unresolved.

## Available routes and limitations

| Route | Established evidence | Remaining work |
| --- | --- | --- |
| Stock FFU through FlashApp | Local manifest/CRC/hash checks; existing replay-only stock stream; one identity-bound Flash round trip | Applicable firmware/downgrade policy, runtime layout handling, a reviewed native executor, interruption behavior and physical recovery validation |
| Emergency programmer | Imported V1 files parse and match a boot-chain fingerprint; upstream source describes the workflow | Programmer execution/acceptance, ARM64 emergency USB/serial behavior, exact restore operations and physical validation |
| Installed partition backup | Saved live primary GPT; Windows copy engine for an already exposed mass-storage disk | A feasible locked-device read path; live backup GPT and installed boot/EFIESP captures |

The pinned [Spec A emergency entry](https://github.com/ReneLergner/WPinternals/blob/d8fd0aa516b16dc094df0422a3adc525af005c29/ViewModels/LumiaUnlockBootloaderViewModel.cs)
sends an FFU header, submits an empty first chunk mapped to disk beginnings/ends,
and reboots. It then uploads and starts a programmer. That is a storage-changing
workflow, not a harmless mode probe or a read-only pre-unlock backup shortcut.
Its [V1 flasher](https://github.com/ReneLergner/WPinternals/blob/d8fd0aa516b16dc094df0422a3adc525af005c29/Models/QualcommFlasher.cs)
exposes programming commands; this inspection did not establish a supported
generic sector-read command. It is not evidence that no such protocol could
ever be researched.

Upstream `BackupPartitionToRam` is limited to MODEM_FSG/MODEM_FS1/MODEM_FS2/SSD/DPP;
its [implementation](https://github.com/ReneLergner/WPinternals/blob/d8fd0aa516b16dc094df0422a3adc525af005c29/Models/NokiaFlashModel.cs)
does not export those RAM copies as host backup files or cover the required
boot/EFIESP partitions. Normal/MTP information queries do not provide raw disk
reads. The [mass-storage backup limitation](native-backup.md) still applies.

## Offline CLI audit

```text
wpi audit-recovery stock.ffu saved-primary.bin new-report.json --disk-sectors RECORDED_SECTORS --expect-primary-sha256 PRIMARY_SHA256 --expect-ffu-sha256 FFU_SHA256
python scripts/reference-recovery-audit.py stock.ffu saved-primary.bin new-report.json
```

This reads regular local files, verifies every FFU chunk plus its complete
fingerprint, checks saved-primary integrity/capacity and compares manifest
partition sizes with the source GPT. The narrow INI parser bounds text to
128 KiB, individual lines to 4 KiB, sections to one Store plus 128 Partitions
and properties to 64 per section. Duplicate/ambiguous keys/names, unsupported
layout sections/aliases, bad booleans, oversized numbers, contradictory sizes,
invalid CRCs and non-attribute backup differences fail. Only selected layout
properties are interpreted; this is not a complete manifest or device emulator.

Cancellation is checked during chunk verification, whole-file fingerprinting
and before completion. Reports publish atomically to a new file, and existing
outputs are preserved. `device_layout_expansion_validated`, `recovery_validated`,
`phone_contacted` and `phone_writes_enabled` remain false. No disk image, backup
GPT or executable recovery plan is generated. This comparison is CLI-only;
there is no new browser or desktop UI operation.

The independent checker uses Python's INI parser and separate FFU/GPT/CRC/SHA
calculations. Public evidence contains metadata and digests only; private inputs
remain local. See [the validation record](../tests/fixtures/rm875-recovery-audit-validation.json).

Next development should address the stock FlashApp executor and its offline
fault/reconnection rehearsal, together with applicability and data preservation.
A physical recovery test would modify the phone and may erase data; it requires
a separately reviewed implementation and explicit approval. No new mode cycle,
programmer upload or recovery write is authorized by this offline audit.
The [session journal](recovery-journal.md) is now implemented for replay only as
the first native-recovery building block. It does not resolve the hardware,
applicability or data-preservation gaps above.
