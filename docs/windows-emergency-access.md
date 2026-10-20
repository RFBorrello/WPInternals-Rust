# Windows ARM64 emergency access

Run `wpi native-unlock-readiness` before reviewing a native unlock experiment.
This command reads the current process token and Windows PnP/registry metadata.
It opens no phone and sends no mode request, upload or storage command. All
endpoints in its report have the candidate vendor ID `05c6`; `product_id` is
decimal (`36872` = `9008`, `61446` = `f006`). Serial numbers, device instance
paths, physical ports, friendly labels and interface GUID values are omitted.

The report separates historical records from present endpoints. A service named
WinUSB alone is insufficient: the setup class must be USBDevice, protected USB
class metadata must be absent, and a present devnode must report problem code
zero. `binding_target` distinguishes whole devices from composite interfaces;
unknown instance-ID shapes cannot satisfy admission. Serial and HID bindings
are reported separately and never satisfy this controller's USB gate.

For whole-device WinUSB, nusb 0.2.7 uses Windows' standard
`GUID_DEVINTERFACE_USB_DEVICE` path. It does **not** require a custom registry
GUID for this branch. USBCCGP composite child interfaces additionally require
that custom GUID. `interface_guid_registered` reports this custom registry
value, so false does not by itself reject a whole-device binding. For composite
interfaces, a later valid plural GUID cannot rescue an invalid first entry.
The singular property is a fallback only when the plural parse fails; a parsed
empty GUID remains unusable. These rules follow the pinned dependency's
[`claim_interface` dispatch](https://github.com/kevinmehall/nusb/blob/bdc148c123c102785cd1d506b77bfeeb794ffeb1/src/platform/windows_winusb/device.rs#L182-L209)
and [device-path helpers](https://github.com/kevinmehall/nusb/blob/bdc148c123c102785cd1d506b77bfeeb794ffeb1/src/platform/windows_winusb/enumeration.rs#L225-L296).
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
Its general application setup instructions register a custom device interface
GUID. This remains useful for other clients and is required for nusb's composite
interface path, while nusb's whole-device path uses the standard USB GUID. This
is a potential setup route **after verifying the exact endpoint**, not an
instruction to rebind the historical HID device. Automatic in-box binding
requires the device's WinUSB OS
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

## New universal binding source

The repository now includes a coinstaller-free
[ARM64/x64 binding](../resources/windows/emergency/README.md) to Microsoft's
in-box WinUSB driver. Its model list is limited to `05c6:9008` and registers one
project interface GUID; F006/HID and generic USB-class matches are excluded.
The ID is shared by non-Lumia Qualcomm devices, so the package is not model
authentication and must not be staged broadly as a discovery technique.

Microsoft InfVerif universal checks and Inf2Cat signability checks passed for
Windows 11 24H2/25H2 ARM64 and x64 without errors or warnings. A new local package
contains the INF, an **unsigned** catalog, README and hash manifest. CI repeats
the build with a pinned Microsoft WDK NuGet package and publishes it separately
as unsigned validation material. This is not a signed or installable release.
No driver, certificate, signature policy, phone mode or storage state was changed.

Production catalog signing and verification, actual endpoint identification,
driver binding and physical emergency access remain unvalidated. The documented
manual in-box setup remains a separate route once that actual endpoint is
available; a custom package signature is not a universal prerequisite for it.
Neither route clears the controller's live token/driver gates or validates entry.

## First-time setup checkpoint

**Hardware limitation observed October 20, 2026:** the first actual unconfigured
9008 devnode appeared in Windows PnP with code 28 and no driver, but was absent
from nusb's registered USB interface discovery. The controller timed out after
entry, before reaching the setup checkpoint below. Do not repeat entry as a
driver-discovery test. The same-process arrival path needs a bounded, physically
correlated PnP fallback before this first-time setup workflow can be validated.
Installing a host driver after that failure does not resume the stopped run.
See the [entry outcome](../tests/hardware/lumia-1020-rm875-entry-emergency-unconfigured.json).

Default execution still requires an eligible historical binding **before**
entry. The explicit `--manual-emergency-driver-setup` alternative removes only
that historical-binding prerequisite, retaining the Windows ARM64, Administrator,
artifact, identity, GPT and output-file checks. Add this option to the normal
offline preview command first; it does not enumerate USB. The preview reports
`emergency_access: "manual_setup"` and a 600-second limit per emergency endpoint.
Execution requires the distinct confirmation
`RM875-EXPERIMENTAL-ENTRY-BEFORE-DRIVER-SETUP-WITHOUT-FULL-BACKUP`, together with
the existing `--execute`, device and new journal/snapshot arguments. The ordinary
unlock confirmation cannot enable manual setup.

This alternative sends the same storage-changing header/zero entry **before**
emergency driver availability has been established. It is an unvalidated native
experiment, not a read-only discovery test. A setup failure can leave the phone
in emergency mode with GPT/boot state already changed; cancellation does not
restore those bytes. It does not resolve the missing installed FlashApp identity,
pre-entry boot originals, full app-data backup or physical recovery validation.
Do not run entry solely to install a driver on a phone whose data must be safe.

The checkpoint retains the original Normal/Flash proof, prepared artifacts,
operation lock and physical port in the same running process. It admits only the
observed whole-device `05c6:9008` endpoint, a device class of 0/FF and exactly one
vendor interface with two bulk endpoints and alternate zero. An unconfigured
endpoint must have no service, an unknown/USBDevice setup class and Windows
problem code 28. HID, serial, composite, F006, protected class metadata, existing
incompatible drivers and other present-device errors stop the experiment. The
script does not advise replacing any of those drivers.

The local console shows the **exact Windows instance target** for Device Manager
selection. Match its Details → Device instance path before using the reviewed
in-box WinUSB route. If the target is not available or does not match, stop and
inspect. Do not use a VID/PID label to choose another node. This private instance
path is not written to the JSON journal or reports; keep captured console logs
private. The program does not install/stage a package, write a registry value,
elevate a process or change signature policy. The unsigned project INF remains
development material, not an installation instruction.

During the fixed ten-minute window, only nusb discovery and exact-instance PnP
metadata are polled. A temporary absence during manual binding resets the ready
count. A different descriptor/identity on the bound port, movement to another
port, an ambiguous target or an inventory error stops immediately. Two successive
ready observations require the selected node to be present, USBDevice/WinUSB and
problem-free. A historical or unrelated node cannot satisfy that check.

The process continues automatically after readiness and fresh descriptor checks;
it opens the bulk interface once. DLOAD alive/root checks must match the prepared
root before any loader upload, and the programmer arrival has a separate setup
window followed by its existing V1 handshake before boot writes. There is no
interface-open retry, alternate loader, protocol fallback or automatic reset.
The deadline is checked after metadata and descriptor work; individual Windows
inventory subprocesses also have their existing 20-second timeout.

Ctrl+C stops at a safe boundary. Keep the process and cable connected while
configuring the exact node; do not restart the unlock command as a continuation.
`awaiting_driver_setup` in an interrupted journal requires inspection of actual
phone state. Imported journal records cannot restore the process-local identity
proof or authorize a resume. Neither software tests nor this option establish
physical emergency access or data-preserving entry on the test 1020.
