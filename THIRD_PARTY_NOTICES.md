# Upstream attribution

The FFU layout, Lumia wire protocols, Qualcomm HDLC framing, Spec A MBN/header
and loader preparation, SBL1 prerequisites, UEFI/FFS inspection, SBL2/SBL3/UEFI
patch previews, EFIESP applicability and patch catalog
are derived from [ReneLergner/WPinternals](https://github.com/ReneLergner/WPinternals),
tag **2.9.2**, commit `d8fd0aa516b16dc094df0422a3adc525af005c29`.

Copyright (c) 2018, Rene Lergner — wpinternals.net — @Heathcliff74xda.

The upstream MIT license is preserved in `resources/upstream/LICENSE`.
`resources/upstream/PatchDefinitions.xml` is copied unchanged from that release
and retains its original copyright and license text. Derived Rust modules name
the upstream reference in their module documentation.

This project is an independent implementation and is not an official upstream release.
Offline package generation additionally ports `SBL1.GenerateExtraSector`,
`SBL2.Patch`, `SBL3.Patch`, `GPT.InsertHack`/`RestoreBackupPartitions` and the
Spec A preparation sequence from the same pinned release. Marker GUIDs are
deterministic for reproducibility; their generation is an independent choice.

# Dependency licenses

Rust and JavaScript dependencies retain their respective licenses. Cargo.lock
and apps/ui/package-lock.json pin the resolved dependency graph. Key libraries:

| Dependency | License |
| --- | --- |
| nusb, Tauri, ntfs, serde, RustCrypto hashes | MIT OR Apache-2.0 |
| fatfs | MIT |
| React, Vite, lucide-react | MIT |
| serialport | MPL-2.0 |
| ctrlc | MIT OR Apache-2.0 |
| Playwright | Apache-2.0 |
| RustCrypto cms, der, x509-cert, rsa | MIT OR Apache-2.0 |
| flate2, miniz_oxide | MIT OR Apache-2.0 (miniz_oxide also offers Zlib) |
| adler2 | 0BSD OR MIT OR Apache-2.0 |
| simd-adler32 | MIT |
| windows-sys | MIT OR Apache-2.0 |
| lzma-rs | MIT |
| lzma-rust2 | Apache-2.0 |
| crc, crc-catalog | MIT OR Apache-2.0 |

Review the complete transitive license inventory before publishing release bundles.
The patched `ntfs` 0.4.0 runtime source is included under `vendor/ntfs`, with its
original MIT/Apache-2.0 licenses and local changes documented in `PATCHES.md`.
Do not redistribute proprietary phone firmware or loaders as project assets.
The Ctrl+C handler's license texts are retained under `resources/licenses/ctrlc-*`.
New cryptography license texts are retained under `resources/licenses/rsa-*`,
`der-*`, `x509-cert-*` and `RustCrypto-formats-*`. The CMS package/source omits
standalone license files; its dual-license declaration and source provenance are
retained in `resources/licenses/cms-declaration.txt`, alongside the shared
RustCrypto formats license texts from DER. Synthetic signing fixtures use only
project-generated test data; no OEM catalog bytes or private test keys are included.
The MainOS package reader uses flate2's portable Rust backend; its flate2,
miniz_oxide, adler2 and simd-adler32 license texts are retained under
`resources/licenses`. No native compression library is required by this reader.
The read-only Windows storage adapter uses windows-sys bindings; its license
texts are retained as `resources/licenses/windows-sys-MIT` and `windows-sys-APACHE`.
Storage candidate recognition follows the pinned upstream `Models/MassStorage.cs`;
the OS access and validation policy is an independent, more conservative implementation.

The narrow REGF/BCD editor follows DiscUtils.Registry and DiscUtils.BootConfig,
commit `59d7cadab839c6d8dfcf52f8be5efe6d2ced190f` from
[DiscUtils/DiscUtils](https://github.com/DiscUtils/DiscUtils).
Copyright (c) 2008–2011 Kenneth Bell and (c) 2014 Quamotion, MIT; the license is
retained in `resources/licenses/DiscUtils-MIT`. This is a limited Rust format
implementation, not a port of the full DiscUtils library. UEFI rebuilding and
the two selected BCD options follow the pinned WPInternals 2.9.2 workflow.
The portable LZMA encoder license is retained in `resources/licenses/lzma-rust2-APACHE`.
