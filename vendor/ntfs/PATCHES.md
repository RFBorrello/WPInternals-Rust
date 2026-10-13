# Local ntfs 0.4.0 patch

Upstream: https://github.com/ColinFinck/ntfs, crates.io `ntfs` 0.4.0.
Crate source commit: `3110cafc0440a84f2593b5d3691e0b23b68ccb8f`.
Copyright Colin Finck; original MIT and Apache-2.0 licenses are retained.

`structured_values/index_allocation.rs` addresses index VCNs in sectors when the
index record is smaller than the filesystem cluster, and in clusters otherwise.
It rejects negative/overflowing VCNs, oversized records and records extending
outside the allocation stream before reading. Data-run addressing is unchanged.
This fixes directory lookup on the RM-875 MainOS image (16 KiB clusters, 4 KiB
index records). A synthetic fixture exercises sector-based index addressing,
resident and fragmented nonresident file data, and malformed records.

Four return types explicitly spell their existing elided lifetime for current
Rust diagnostics; this has no behavior change.

The upstream example manifest entry is omitted because this vendored runtime
copy excludes upstream examples and test images. Production dependencies and
features are unchanged. Workspace tests exercise the patched library as a
dependency; upstream's own tests are not shipped or claimed as run.
Index iteration and lookup also stop after 64 nested nodes, preventing malformed
cyclic indexes from causing unbounded traversal or memory growth.

Format reference (no Linux implementation code is copied):
[NTFS index block layout](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/865730eec5435ce40a5dc3c615077d04c8f95098/fs/ntfs/layout.h).
