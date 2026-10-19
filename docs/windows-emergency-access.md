# Windows ARM64 emergency access

Run `wpi native-unlock-readiness` before reviewing a native unlock experiment.
This command reads the current process token and Windows PnP/registry metadata.
It opens no phone and sends no mode request, upload or storage command. All
endpoints in its report have the candidate vendor ID `05c6`; `product_id` is
decimal (`36872` = `9008`, `61446` = `f006`). Serial numbers, device instance
paths, physical ports, friendly labels and interface GUID values are omitted.

The report separates historical records from present endpoints. A service named
WinUSB alone is insufficient: the setup class must be USBDevice, a nonempty
device interface GUID must be registered, protected USB class metadata must be
absent, and a present devnode must report problem code zero. Serial and HID
bindings are reported separately and never satisfy this controller's USB gate.
Even an eligible historical binding is only availability evidence. It does not
authenticate a Lumia, prove that the future endpoint will open, or validate an
unlock. Actual arrival still needs port, descriptor, root and protocol checks.

On the development host, the connected RM-875 has healthy Normal-mode WinUSB
access. The only matching historical emergency candidate is an **absent
`05c6:f006` HID device**, with protected class metadata and no WinUSB compatible
ID or registered interface GUID. It is not established as this phone's emergency
endpoint. Leave that HID driver intact. Do not select a device for rebinding
from its VID/PID, friendly label, or this report alone.

## Administrator diagnostic

From an Administrator PowerShell terminal in the repository, collect a NEW local
report using the reviewed optimized CLI:

```powershell
$cliDigest = (Get-FileHash -LiteralPath .\target\release\wpi.exe -Algorithm SHA256).Hash
.\scripts\check-native-unlock-host.ps1 `
  -OutputPath .\artifacts\native-host-admin.json `
  -ExpectedExecutableSha256 $cliDigest
```

The helper verifies the executable digest, calls **only**
`native-unlock-readiness`, and saves a new advisory JSON report. It does not
elevate itself, install drivers, modify disk state or run the unlock controller.
An administrator report cannot be imported to authorize a later process: the
controller checks its own live token and host metadata again.

## Choosing a binding after endpoint identification

First establish the actual phone endpoint through reviewed arrival observation
and physical-port correlation. Do not use the storage-changing FFU-zero entry
as a harmless driver-discovery test. The current 1020 entry route is not a
validated way to preserve data, and no read-only emergency-entry shortcut has
been validated for this phone.

The exact older reference FlashApp rejects the proposed non-payload `NOKXCBE`
route through its unknown-command handler. The installed binary's identity is
still unknown. See the [command-path evidence](spec-a-entry-code.md#non-payload-entry-command-bounded-negative-result).
This rules out that shortcut for the reference, rather than just leaving its
support untested; it does not prove all alternatives impossible.

Microsoft documents an in-box WinUSB route in Device Manager: Update driver,
Browse my computer, Let me pick, Universal Serial Bus devices, WinUsb Device.
Its instructions also require a registered device interface GUID for application
access; selecting the service alone is insufficient. This is a potential setup
route **after verifying the exact endpoint**, not an instruction to rebind the
historical HID device. Automatic in-box binding requires the device's WinUSB OS
descriptors/compatible ID. See Microsoft's
[WinUSB installation instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation)
and [automatic installation requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/automatic-installation-of-winusb).

For distribution, Microsoft's universal INF example supports NTarm64 and
NTamd64, includes `winusb.inf`, registers an interface GUID and needs a signed
catalog. This repository does not yet ship such a signed package. Legacy x86/x64
kernel drivers are not an ARM64 solution. Driver setup and observed emergency
access remain unvalidated; an Administrator token by itself resolves neither.

## Audited legacy driver package

The locally available `EmergencyDownloadDriver.msi` (SHA-256
`3d58722990e737e8e3e0fb3e9645edf34bf7d45fdab376237e0f85ecb4e572bd`)
was opened as a read-only Windows Installer database and its embedded cabinet
was inspected with existing 7-Zip 25.01 ARM64. The installer and bundled
executables were not run. Only INF/catalog copies were extracted locally.

Its 2014 Nokia INF, version 1.0.0.1, declares `DeviceList.NTx86` and
`DeviceList.NTamd64` for `USB\VID_05C6&PID_9008`; it has **no NTarm64 model**.
It also references legacy WinUSB/WDF coinstallers. The MSI template is Intel
and its bundled DPInst programs are x86/x64. This package does not supply the
needed ARM64 binding. Running its installer under emulation cannot add a missing
ARM64 INF model. Windows reported the extracted catalog signature valid when
inspected as a `.cat` file; catalog-member binding was not separately checked,
and a valid signature does not establish architecture compatibility.

The host's own `winusb.inf` does contain a native NTarm64 section matching
`USB\MS_COMP_WINUSB`. That is evidence of the available in-box driver, not a
binding or access test on this phone's future emergency endpoint. No certificate,
INF, driver or device setting was installed or modified. The
[metadata audit](../tests/fixtures/nokia-emergency-driver-architecture-audit.json)
contains hashes and declarations only; proprietary installer contents stay local.
