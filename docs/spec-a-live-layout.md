# Offline Spec A live-layout analysis

The CLI can compare a saved RM-875 primary GPT with a pinned offline reference
ZIP. It reads regular local files only. It does not discover USB devices, change
modes, unlock, flash, or make the ZIP executable. Browser/desktop UI controls for
this comparison are not implemented yet; the image engine remains portable.

```text
wpi plan-spec-a-layout reference.zip saved-primary.bin new-report.json --disk-sectors RECORDED_SECTORS --expect-primary-sha256 PRIMARY_SHA256 --expect-package-sha256 PACKAGE_SHA256
```

Supply the capacity and digest from the completed capture, and the ZIP digest
from its independently checked build. These bind selected files to historical
evidence; they do not establish fresh device identity or OEM authenticity.
The output is created atomically, and existing files are never overwritten.
No modified GPT binary or replacement ZIP is exported by this command.

The bounded ZIP reader accepts only the builder's stored, descriptor-based ZIP
format: at most 128 members, 128 MiB per member, 512 MiB overall, and a 1 MiB
manifest. It rejects ZIP64, compression, comments, extra fields, duplicate/unsafe
paths, gaps, inconsistent offsets, truncated data and unsupported metadata.
Payload reads are at most 64 KiB. CRC32, SHA-256, headers, descriptors and the
central directory are checked before interpreting the manifest. Manifest member
records, source/prepared GPTs, placement lists and upstream normalization must
agree with the verified bytes. The current advisory scope requires the
`Nokia.MSM8960.P5217` source platform and schema 1 reference-package format.

The saved primary must match its supplied digest and recorded capacity, including
the end-of-disk backup pointer and reserved backup-table space. The existing
[upstream-derived layout transform](spec-a-package.md) validates CRCs, packed
unique identities, bounds, overlaps, marker space and V1 boot limits. It creates
a candidate in memory from the **saved live primary**, retaining its disk GUID,
disk geometry, partition identities and attributes except the deliberate HACK/
SBL2/marker edits. Active/backup pairs with the higher active location are
normalized by exchanging their ranges, as in the pinned upstream algorithm.
Unrelated partition entries must remain exactly equal; no partition contents
are read or preserved by this calculation.

The JSON compares reference, installed and candidate ranges, reports identity
equality without exporting GUID values, checks each prepared payload's byte
length against its candidate partition, and lists affected installed partitions
whose originals are not captured. A fit result says nothing about signed-image,
loader, donor, BCD, firmware or device acceptance. A differing SBL1 capacity also
requires rebuilding/rechecking the SBL1/HACK relationship. The source ZIP still
contains source-based GPT and restore coordinates; it is never silently updated
or reclassified as an installed-device backup.

`phone_contacted`, `phone_writes_enabled`, `backup_gpt_captured` and
`installed_partitions_preserved` remain false regardless of fit or manifest
claims. Unsupported/malformed inputs fail, and oversized payloads appear as
explicit blockers. A future executor must not accept this serialized report as
authority. Fresh device/transport checks and a validated recovery strategy
remain separate work. In particular, the existing [mass-storage backup
path](native-backup.md) cannot provide pre-unlock full backup of the locked retail
1020. Preserving recoverable originals where available or validating an
alternative recovery path requires further research, not another unchecked mode
cycle.

## Local RM-875 comparison

The saved primary from the completed read-only hardware cycle contains 28
partitions and declares 61,071,360 sectors. The source template declares
20,971,520 sectors. All nine prepared payloads fit the candidate's bounds;
TZ/RPM/WINSECAPP are normalized to their lower ranges, while MainOS, Data, MMOS,
EFIESP and other unaffected entries remain unchanged. Candidate primary SHA-256
is `8bd4ecb71c8599300dafc897b2647ad9749faeddcc738130d071783d690c0f50`.
This is a local calculation, not a device write or unlock validation.

The independent Python checker uses the separate WPInternals 2.9.2 GPT
translation and Python ZIP/CRC/hash implementations:

```text
python scripts/reference-spec-a-live-plan.py reference.zip saved-primary.bin new-report.json
```

It compares the candidate digest, disk geometry, CRCs, identities, normalization,
all reported partition/payload ranges and capture requirements. It prints only
digests, counts and comparison results. See the
[metadata-only validation record](../tests/fixtures/rm875-live-layout-validation.json).
Raw installed GPT data and local artifacts are not distributed.
The subsequent [recovery-path investigation](rm875-recovery-path.md) records
the stock FFU's minimum-capacity/Data-expansion rules and the separate limits
of emergency entry and installed-backup access.
