# Experimental emergency WinUSB binding

**Unsigned development source. Do not install or stage it as a released driver.**

`wpi-emergency.inf` binds Microsoft's in-box `WinUSB.sys` and registers an
application interface GUID on Windows ARM64 and x64. It contains no kernel
binary, coinstaller, certificate import, installer or signing-policy change.
The only model match is `USB\VID_05C6&PID_9008`. F006 charging/HID, Normal,
Flash, mass-storage interfaces and generic USB classes are excluded.

The Qualcomm 9008 hardware ID is shared with other manufacturers. This INF does
not identify a Lumia or make a device safe to write. A staged package can affect
other matching devices when Windows selects drivers. Before any actual setup,
identify the selected phone's endpoint through physical-port correlation and
review competing serial/other driver needs. Never bind the historical F006 HID
candidate or install the package globally as a discovery technique.

## Reproduce offline package validation

From a Windows ARM64 repository checkout, with Python 3.9+:

```powershell
New-Item -ItemType Directory -Path .tools -ErrorAction SilentlyContinue
python scripts/fetch-wdk-validation-tools.py .tools/wdk-arm64-10.0.28000.2526
.\scripts\prepare-windows-emergency-driver.ps1 `
  -OutputDirectory .\artifacts\my-new-unsigned-emergency-package `
  -InfVerifPath .\.tools\wdk-arm64-10.0.28000.2526\c\tools\10.0.28000.0\ARM64\infverif.exe `
  -Inf2CatPath .\.tools\wdk-arm64-10.0.28000.2526\c\bin\10.0.28000.0\x86\Inf2Cat.exe
python scripts/check-emergency-driver-scope.py
```

The fetcher downloads Microsoft's pinned 10.0.28000.2526 ARM64 WDK NuGet package
(49,371,679 bytes), verifies its complete SHA-256 and extracts bounded tool files
and the Microsoft license into a NEW local cache. It runs no installation. Tool
binaries are not redistributed. The catalog tool supplied in that package is an
x86 **user-mode build tool**; the INF selects Microsoft's native ARM64 kernel
driver on an ARM64 host. Existing x64 WDK installations can instead supply their
own reviewed InfVerif/Inf2Cat paths directly to the builder.

The builder copies the INF into a NEW output folder, runs universal INF checks,
then generates an unsigned catalog after signability checks for Windows 11
24H2/25H2 ARM64 and x64. It verifies the unchanged INF and expected unsigned
catalog state and writes a manifest containing file/tool hashes. A failure leaves
incomplete output; existing directories are never reused or overwritten.
Its source-hash pin ensures that fixed VID/PID/GUID report fields describe the
reviewed INF. Changes require reviewing the model scope and updating the pin;
passing syntax checks alone cannot admit a broader binding.

Local Microsoft tool checks passed without errors or warnings. That establishes
INF syntax/signability for those targets. It does not establish Windows install
acceptance, physical access, phone compatibility, unlock or data preservation.

## Signing and hardware setup still required

For a public package, obtain the appropriate Microsoft Hardware Developer
Center signing result and verify the returned catalog, its binding to the exact
INF, architecture coverage and package hashes before distribution or staging.
Signing credentials/submission are not configured by this repository. The
builder deliberately has no signing, staging or installation option. Do not
disable signature enforcement, enable test signing, or import a local trust
certificate as a substitute for a production package.

The separate documented in-box Device Manager setup route may avoid a custom
driver package, but still needs an identified actual endpoint. nusb uses the
standard USB device path for whole-device WinUSB; composite child interfaces
also need a custom registered interface GUID. Neither route makes the
storage-changing 1020 emergency entry a read-only driver test. The native
controller's existing admission gates remain unchanged. See
[Windows access](../../../docs/windows-emergency-access.md).

References: Microsoft's [WinUSB universal INF and installation guide](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation),
[WDK NuGet acquisition](https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget),
[pinned Microsoft package](https://www.nuget.org/packages/Microsoft.Windows.WDK.ARM64/10.0.28000.2526),
and [Inf2Cat checks](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/inf2cat).
