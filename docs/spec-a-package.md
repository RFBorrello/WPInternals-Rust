# Offline Spec A reference packages

Import the stock FFU and a donor FFU, optionally select a raw SBL3 and local V1
programmers, then choose **Build offline package**. Browser and desktop use the
same Rust package builder. The CLI equivalent is:

```text
wpi package-spec-a stock.ffu new-package.zip --donor donor.ffu --sbl3 engineering-candidate.bin --loader programmer.hex
```

`--sbl3` and repeatable `--loader` are optional. A supplied SBL3/programmer must
pass bounds, format, unique patch-pattern and internal fingerprint checks;
programmers also require the V1 marker. These checks do not authenticate an
engineering loader or establish phone compatibility. No transport is opened.

The result is a deterministic stored ZIP, not a signed FFU or a validated flash
plan. `original/` contains the stock FFU's primary GPT, affected boot partitions,
EFIESP, and affected backup ranges when normalization swaps them. `prepared/`
contains the generated extra sector, patched boot images, primary GPT, rebuilt
UEFI and assembled EFIESP. `imports/` preserves selected SBL3/programmers and
decoded MBN forms. The ZIP also includes UEFI/EFIESP reports and `manifest.json`.

The builder follows WPInternals 2.9.2 commit
`d8fd0aa516b16dc094df0422a3adc525af005c29`:

- SBL1's final sector becomes the one-sector `HACK` partition. Its signed image
  must fit wholly in the shortened SBL1 partition. The 512-byte payload uses the
  upstream template, model-specific first 12 SBL2 header bytes, reviewed SBL1
  addresses and two adjusted 80-byte loader-table copies.
- SBL2/SBL3 each receive exactly one expected, aligned four-byte instruction
  replacement inside bounded code. Other bytes are preserved. These edits
  invalidate their retained signatures, as in upstream.
- Active/backup boot bounds are normalized with the upstream V1 limit. HACK
  inherits SBL2 identity and attributes; SBL2 receives the pinned `0x74` GUIDs.
  External SBL3 adds the upstream marker partition at sector `0x40`.
- Primary GPT output requires 128 packed entries of 128 bytes at sectors 0–33.
  Duplicate identities/names, already modified layouts, occupied marker space,
  insufficient capacity, overlaps and out-of-range payloads fail. CRCs are rebuilt
  and the result re-parsed. Marker GUIDs derive deterministically from the source
  primary GPT and two domain labels, replacing upstream random GUIDs.
- Existing UEFI and EFIESP transforms retain their independent verification.
  [Assembly details](spec-a-assembly.md) describe their limits and checks.

The complete stock FFU is checked against its chunk table and fingerprinted
before archiving. Each archive member has a CRC32, byte length and SHA-256 in
the manifest, except the manifest itself; its digest is returned in the package
report. Output headers, contents, data descriptors and central directory are
re-read and checked before publication. The report includes the whole ZIP digest.
CRC/hash integrity does not authenticate an OEM signer, firmware or a manifest.

The restore list records **source FFU reference coordinates**. It is not an
installed-phone backup: `originals_are_installed_backup` is always false.
End-relative backup GPT data is not synthesized or represented as a captured
backup; `backup_gpt_captured` is false. The exact original primary GPT is retained,
and the local restoration helper accepts only its corresponding transformed
layout. Installed originals and both live GPTs still require separate acquisition
and validation. The selected RM-875 source is older than the installed phone.

All inputs/outputs remain local. ZIPs are limited to 128 stored members and
512 MiB; individual files are capped at 128 MiB, boot imports at 4 MiB, loaders
at 512 KiB each (32 maximum) and source FFUs at 16 GiB. FAT/hive limits still
apply. Native output uses atomic creation with no overwrite. Chromium uses two
new OPFS scratch files, at most 64 KiB synchronous reads/writes and 1 MiB export
chunks. Scratch files are removed after success or handled failure; browser
destinations must be empty. A newly created empty picker placeholder may remain
after a failed operation. Missing APIs/quota require desktop fallback.

Native cancellation is checked at stage/copy/verification boundaries. Browser
progress remains visible while Rust runs, but queued cancellation waits until
the synchronous construction batch returns and is checked before publication.
Cancellation during final export aborts the destination stream. Crashes/power loss
are distinct from handled cancellation; leftover scratch/temporary files may
require cleanup, and no device recovery is implied by these local tests.

`phone_writes_enabled` remains false. Fresh RRKH, Flash/security state, live GPT,
installed-original preservation, firmware applicability, loader/donor acceptance,
recovery validation and a reviewed executor remain prerequisites for hardware.
Spec B and WP7 have separate workflows. A successful build cannot bypass these
requirements or enable an Unknown compatibility profile.

Synthetic tests cover full construction, deterministic output, GPT reversal and
normalization, payload limits, missing/ambiguous patterns, invalid source chunks,
unsupported donors, cancellation, truncated/corrupt ZIPs, partial output writes,
atomic cleanup, browser fallback and native IPC. The independent Python checker
uses its own FFU/GPT/SBL translations, ZIP CRCs and prior UEFI/FAT/REGF comparisons:

```text
python scripts/reference-spec-a-package.py package.zip --source stock.ffu --donor-boot extracted-donor-mobilestartup.efi
```

See `tests/fixtures/rm875-package-validation.json` for metadata-only real-file
evidence. Neither proprietary source images nor modified packages are distributed
in the public project or development application bundles.
