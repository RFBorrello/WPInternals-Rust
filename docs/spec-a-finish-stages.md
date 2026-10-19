# Spec A UEFI-variable and EFIESP stages

The first Qualcomm boot-component transfer is not a complete unlock. This
milestone implements local composition and replay of the following stages from
WPInternals **2.9.2**, commit `d8fd0aa516b16dc094df0422a3adc525af005c29`,
`LumiaUnlockBootloaderViewModel.LumiaUnlockUEFI`. It does not expose a native
storage writer or enable the browser/desktop unlock button.

## Composed bytes

`wpi-image::spec_a::finish_plan::build` accepts the immutable programmer plan,
reverifies its reference ZIP, and checks the exact saved primary and source
digests. The initial implementation requires the engineering-SBL3 path used by
the local package. Prior NV modifications are refused rather than inferred.

1. Preserve the original `UEFI_BS_NV` range as `BACKUP_BS_NV`. Create the new
   active range immediately after it, retaining the original active GUIDs and
   attributes. The adjacent range must be vacant and inside the usable disk.
   Generate deterministic backup GUIDs and validate the rebuilt primary's CRCs,
   names, GUIDs, bounds and overlaps. Other partition entries remain unchanged.
2. Compose the upstream Spec A variable image followed by the changed primary.
   The unchanged MIT-licensed upstream `SBA` resource is bundled and its compressed
   and decompressed SHA-256 digests and exact 256 KiB size are pinned. It is not a
   Qualcomm programmer or a phone firmware import.
3. Compose the first EFIESP pass using upstream's enlarged FAT reserved-sector
   calculation and exact two slices. For Spec A the prefix contains the original
   reserved sectors with only the reserved count changed; the second view starts
   at the enlarged reserved count. Both writes stay inside the existing EFIESP.
   Sector arithmetic, sizes and source/prepared geometry must agree.

The actual package contains 64 MiB EFIESP members. The separate image reader
copies and hashes them in bounded chunks, with cancellation and a 128 MiB image
limit. It does not route them through the 32 MiB metadata allocator. The plan
retains bounded image/payload buffers; it does not load a multi-gigabyte FFU.

These first-pass bytes come from **reference firmware**. They do not establish
the contents or preservation of the installed EFIESP. All reports explicitly
keep installed-original capture, data preservation, phone contact and writes
false. The planner does not make a native admission decision from its report.

## Installed-image second pass

The engineering-SBL3 sequence requires a mass-storage continuation. The consuming
workflow is not yet connected to native storage. The local `prepare_second_pass`
implementation requires a complete EFIESP capture, a pinned capture digest and
the exact expected post-NV primary. It verifies the expected first-pass ranges,
restores the original FAT reserved count in a separate copy, and applies the
catalog-checked boot-file patch and BCD edit to that reconstructed filesystem.
The existing FAT inventory verifier checks all unrelated file contents. It then
composes the final two EFIESP slices from this installed-image copy.

An input file and a caller-supplied digest do not authenticate which phone
produced the capture. Nor can an after-write capture recover bytes lost before
it was taken. A native continuation must bind the disk and captures to the
in-memory device session and establish the preservation/recovery policy before
the initial destructive entry. No complete raw backup has been captured on the
locked test phone, and the source ZIP is not such a backup.

## Commands and interruption handling

```text
wpi plan-spec-a-finish reference.zip saved-primary.bin NEW-report.json \
  --disk-sectors RECORDED_SECTORS \
  --expect-primary-sha256 PRIMARY_SHA256 \
  --expect-package-sha256 PACKAGE_SHA256

python scripts/reference-spec-a-finish.py reference.zip saved-primary.bin NEW-report.json

wpi inspect-spec-a-finish-journal stage.jsonl
```

The planner performs local processing only and atomically publishes a new
metadata report. There is no execute flag or image export. The independent Python
translation compares the rebuilt primary, resource, both EFIESP slices, addresses,
sizes and digests without extracting firmware or printing disk identifiers.

The pure `NOKF` codec implements pinned `NokiaFlashModel.FlashSectors` with aligned
payloads up to 2 MiB, checked 32-bit sector arithmetic and bounded progress.
The replay requires an exact eight-byte successful status envelope. That reply
policy still needs positive hardware validation; there is no readback guarantee.

`wpi-core::spec_a_finish_replay` accepts concrete replay transports only and a
composed immutable plan. Each command's artifact/layout binding, payload digest,
address and length are journaled before submission. Byte counters advance only
after validated replies. Cancellation, lost replies, invalid status or any save
failure stop without another command, retry, reset or cleanup write. A new-file
JSONL sink flushes and synchronizes each bounded record and retires on I/O failure.

The inspector accepts only this finish-stage replay journal format, not the
earlier joined journal or mode-test events. It bounds line/file sizes and checks
sequence, stable artifact bindings, paired intents/acknowledgements, address and
counter consistency. A torn final line or unmatched intent remains uncertain.
A complete stage is distinct from unlock success. Reports/journals cannot be
imported as execution or resume authority, and the inspector never contacts USB.

## Validation and remaining execution work

Synthetic tests cover variable-range collisions and malformed geometry, exact
dual-FAT slices, large chunked reads, installed-file preservation, changed captures,
cancellation, every transfer/journal failure boundary, and torn/corrupt journals.
The actual RM-875 package and saved primary produce four first-pass transfers
totaling **33,835,520 bytes**, independently matched by Python. This is local
calculation evidence, not a phone write. The second pass has synthetic evidence
only; an installed capture is not available. See the
[metadata record](../tests/fixtures/rm875-finish-plan-validation.json).

The [artifact-bound native mode cycle](spec-a-session.md) now connects Normal,
Flash and returning-Normal identity checks and passed once on Windows ARM64.
The [entry impact audit](spec-a-entry-preservation.md) also identified an unresolved
potential Data-tail intersection under a conservative end-chunk interpretation.
Remaining work includes resolving that exposure and the complete native emergency-entry/
loader/programmer writer, subsequent mode/storage continuation, physical disk
capture binding, recovery decisions after each uncertain phase, and successful
physical unlock/return-to-Windows validation. Those are implementation and
validation gaps; another approval or a changed capability flag cannot fill them.
No storage write was sent in this milestone. Its local calculations did not contact a phone.
