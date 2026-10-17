# RM-875 firmware search — October 14, 2026

The previously read phone identity is Lumia 1020 **RM-875**, product code
**059T909**, manufacturer model `RM-875_eu_euro1_267`, installed firmware
**3051.50009.1451.1003**. This investigation did not refresh the phone or query
unique identifiers.

## Findings

The [059T909 directory listing](https://lumiafirmware.com/model/RM-875/hwid/059T909)
identifies the Scandinavian black variant and lists firmware
`3051.50009.1424.0002`. Its named FFU is the same one already imported locally:

```text
RM875_3051.50009.1424.0002_RETAIL_eu_euro1_267_02_448151_prd_signed.ffu
```

The listing also names `RM875_059T909_3051.50009.1424.0002_062.vpl` and matching
DCP/package metadata. These are directory observations, not an authenticated OEM
package manifest. No listed download was fetched or authenticated in this step.
The existing FFU's complete local digest remains
`ce4724a1e4225f629ee4092400715dcd85d160470e1173c71c8065527e73e8c4`.

Targeted filename searches in Downloads and the known Windows Phone project tree
found this RM-875 FFU plus a separate RM-1038 image. The latter is a different
hardware variant and is not a replacement for this phone. A partial extended search of
additional cache/document roots also found unrelated RM-983 and RM-1085 images.
Some cache locations were unavailable or inaccessible; this is not an exhaustive
search of all disks or cloud content.

Exact-version/product-code searches did not produce a verified downloadable FFU
for `3051.50009.1451.1003`. Other regional RM-875 listings were encountered, but
their product codes differ; a numerically newer filename does not prove they
apply to 059T909. They were not downloaded or recommended for cross-flashing.
The search does not establish that an exact-version FFU does not exist or why the
versions differ. In particular, OTA-only distribution has not been verified from
an authenticated primary source here.

## Consequences

The existing file has matching observed variant and cataloged product-family
metadata, but independent OEM trust, exact product applicability, rollback
acceptance and recovery execution remain unvalidated. It remains blocked as an
unvalidated downgrade. No blocker or trust anchor was relaxed because a newer
file was difficult to locate.

Continue through local imports if an authenticated matching package or OEM
manifest becomes available. Stock recovery profiles can later establish whether
the correct older recovery package is acceptable; an exact installed-version FFU
must not be assumed to be a universal prerequisite or silently substituted with
another region's package. Mass-storage backup access has separate bootloader
prerequisites, documented in [native backup](native-backup.md).
The later [offline recovery audit](rm875-recovery-path.md) confirms a 10 GiB
manifest minimum and `UseAllSpace=true` for Data. The smaller source template
alone does not establish a need for a larger-capacity FFU; device layout handling
and downgrade acceptance are still unvalidated.
