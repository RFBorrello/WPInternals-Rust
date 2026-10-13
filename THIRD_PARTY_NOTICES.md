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
| Playwright | Apache-2.0 |

Review the complete transitive license inventory before publishing release bundles.
The patched `ntfs` 0.4.0 runtime source is included under `vendor/ntfs`, with its
original MIT/Apache-2.0 licenses and local changes documented in `PATCHES.md`.
Do not redistribute proprietary phone firmware or loaders as project assets.
