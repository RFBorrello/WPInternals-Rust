# Platform setup

| Target | Build target | Desktop distribution |
| --- | --- | --- |
| Windows ARM64 | aarch64-pc-windows-msvc | Native EXE; NSIS installer |
| Apple Silicon | aarch64-apple-darwin | App/DMG; public distribution needs signing and notarization |
| Linux x86-64 | x86_64-unknown-linux-gnu | AppImage and DEB |
| Linux ARM64 | aarch64-unknown-linux-gnu | AppImage and DEB |

Windows needs WebView2 and the MSVC build tools/Windows SDK for building.
Linux builds need WebKitGTK 4.1 and Tauri’s GTK/build dependencies. Test packages
on the distribution baseline; an AppImage does not remove all kernel/glibc constraints.
macOS builds need Xcode command-line tools.

## USB

- Windows nusb and WebUSB use WinUSB. A compatible binding must exist for each
  vendor-specific interface/mode. Windows ARM64 cannot load legacy x86/x64 kernel
  drivers. This repository does **not** ship signed driver bindings yet.
- Linux: install the narrowly scoped sample rules from `resources/linux/` with
  administrator privileges, reload udev rules, then reconnect. No global USB
  permission changes are needed. Review matching PIDs against captured descriptors.
- macOS: a vendor-specific interface already claimed by a system driver may be
  unavailable to nusb. Mass storage is handled through the system driver; its native
  block adapter is not implemented in this release.
- Chromium WebUSB cannot claim protected classes such as mass storage. Safari
  and Firefox can inspect local files but need the desktop app for device access.

## Release preparation

Build artifacts are development packages until hardware evidence exists. Use
`scripts/checksums.mjs` for SHA-256 manifests. Signing credentials, Apple notarization,
signed Windows driver packages, and a public web hosting destination
are not configured locally. The source repository is
[RFBorrello/WPInternals-Rust](https://github.com/RFBorrello/WPInternals-Rust).
CI verifies builds; publication must use a configured
release repository and signing/hosting credentials. Do not mark CI builds as hardware support.

Sources: [nusb](https://docs.rs/nusb/0.2.7/nusb/),
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/),
[Windows ARM emulation](https://learn.microsoft.com/en-us/windows/arm/apps-on-arm-x86-emulation),
[WebUSB](https://developer.chrome.com/docs/capabilities/usb).
