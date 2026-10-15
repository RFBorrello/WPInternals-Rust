# Upstream attribution

The FFU layout, Lumia wire protocols, Qualcomm HDLC framing, and patch catalog
are derived from [ReneLergner/WPinternals](https://github.com/ReneLergner/WPinternals),
tag **2.9.2**, commit `d8fd0aa516b16dc094df0422a3adc525af005c29`.

Copyright (c) 2018, Rene Lergner — wpinternals.net — @Heathcliff74xda.

The upstream MIT license is preserved in `resources/upstream/LICENSE`.
`resources/upstream/PatchDefinitions.xml` is copied unchanged from that release
and retains its original copyright and license text. Derived Rust modules name
the upstream reference in their module documentation.

This project is an independent implementation and is not an official upstream release.

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
