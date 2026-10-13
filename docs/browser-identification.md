# Read-only browser identification

Use Chrome or Edge over HTTPS or localhost with a data cable and the phone in
normal mode. On Windows, vendor interface 3 needs a compatible WinUSB driver.
The native RM-875 test used Microsoft's existing driver; no driver change was made.

1. Open the browser app and choose **Connect a device**.
2. Select the Lumia in the browser's USB permission chooser. The 1020 can appear
   as **Nokia Lumia 909 (RM-875)**: that USB label alone does not prove its model.
3. Choose **Read device information**. Successful normal-mode queries populate
   the hardware variant, recognized model, bootloader family, and firmware.
   A platform ID is not queried in normal mode; the field explains this rather
   than asking for another normal-mode probe.

Only `ReadManufacturerModelName`, `ReadProductCode`, and `ReadSwVersion` are sent
on the normal-mode bulk interface. Standard descriptor requests are used to
locate interface 3 and its bulk endpoints. No mode-switch, storage, flash, root,
or bootloader commands are issued. Flash mode uses the separate read-only NOKV
query. Protected MTP or mass-storage interfaces are never claimed.

After a disconnect, reselect the device. After an interrupted probe or timeout,
unplug the phone, **Scan USB devices while it is disconnected**, reconnect, then
select it again. WebUSB cannot cancel a transfer already in progress; the Rust
adapter blocks additional probes on that connection until enumeration observes
its disappearance. There are no automatic protocol retries.

If access is unavailable, the error names the required vendor interface and
directs you to the desktop app. Offline image inspection remains available.

Browser device communication remains experimental. In addition to real-WASM tests
with mocked USB responses, the user reported a successful normal-mode browser
session on the 1020 RM-875 with firmware `3051.50009.1451.1003`, matching native
identification. This is recorded in `tests/hardware/`; the exact browser version
was not reported. Repeatability, the 730, other hosts and mode transitions remain
pending. Record the host, browser version, variant, firmware, transport, and
outcome before expanding the compatibility evidence.
