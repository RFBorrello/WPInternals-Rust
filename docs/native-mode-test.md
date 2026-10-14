# Native RM-875 mode-validation experiment

This CLI-only experiment is limited to **Windows ARM64**, **Lumia 1020 RM-875**,
**Spec A**, normal USB **0421:0661**, and installed firmware
**3051.50009.1451.1003**. It is a hardware-validation harness, not a generally
available mode-switching capability. No Tauri IPC or browser entry point runs it.
Stock flashing, unlocking, backup/restore and other writing gates remain blocked.

## Preview and execution

```sh
wpi devices
wpi mode-test '<selected-device-id>'
```

The default command reads information and prints a redacted preview. It cannot
execute a mode change. Execution requires a separate explicit flag, the exact
confirmation phrase and a new local JSONL journal:

```sh
wpi mode-test '<selected-device-id>' --execute \
  --confirm RM875-NORMAL-FLASH-NORMAL --report mode-test.jsonl
```

Existing reports are never overwritten. The journal is created and synchronized
before the harness runs. Events are flushed/synchronized at command boundaries
and after observations so an interrupted process leaves a partial record. A
journal failure prevents the next command. The CLI catches Ctrl+C using
[`ctrlc` 3.5.2](https://docs.rs/ctrlc/3.5.2/ctrlc/); cancellation stops at the next
safe boundary. After a command attempt it reports that state inspection is needed,
and does not automatically repeat or undo that command.

## Phone actions

1. Re-read the selected phone and check the exact admission profile. Require only
   one recognized phone, a nonempty USB serial and a physical USB port binding.
2. Arm native hotplug observation before the request, then send the upstream
   JSON-RPC `SetDeviceMode` with `DeviceMode=Flash`, `ResetMethod=HwReset` once.
3. Observe removal and probe the returning interface only when its USB serial
   and physical port match. Windows binds the parent hub instance and connection
   index already used by nusb to retrieve descriptors. This works when ARM ACPI
   location paths do not produce a generic bus/port chain. Read NOKV and, in FlashApp, FVER.
4. If a correlated BootManager is observed, require protocol 1 or 2 and re-read
   it before sending NOKS once. Protocol 1 requires removal; protocol 2 permits
   an in-place application change. NOKS is never sent from FlashApp.
5. Require the observed FlashApp platform `Nokia.MSM8960.P5217` and no identity
   contradictions. Re-read FlashApp before sending NOKR once.
6. Observe the return and re-read normal-mode model/product/firmware information.
   Successful transient BootManager/Flash observations during normal boot may be
   queried again, but never trigger an extra reset or context command.

The mode requests may change boot state. No firmware image, partition, loader,
root patch, security change or mass-storage write request is part of the harness.
Do not run another phone client or browser information request concurrently.
Native probing and this harness share an in-process exclusion lock; that lock
does not coordinate unrelated applications or other processes.

## Bounds and failure handling

Each returning-interface wait has a fixed 30-second deadline. A successful
reconnection must be established by fresh information, not an enumeration label.
USB OUT requests use a single bounded transfer and reject short completions without
resending the remainder. Read/write transfer waits are at most five seconds and
are capped by the remaining probe deadline. Timeout requests cancel outstanding
transfers; OS enumeration/open calls and driver teardown are synchronous and can
extend elapsed time. Unplugging may be needed if a driver does not complete cleanup.

Windows interfaces can appear before their WinUSB binding is ready. Opening or
claiming may be retried within the deadline **before any protocol request is sent**.
A failed or malformed information query is never automatically repeated.
An uncertain mode OUT completion is followed by state observation without retry;
only a positively correlated observation permits the next planned mode request.

Missing/changed serials or physical ports, multiple candidates, changed firmware,
unknown BootManager protocols, unexpected modes, platform mismatches, cancellation,
and journal failures stop the experiment. If the phone stays in Flash/BootManager
because USB access is unavailable, inspect its state and restart it manually using
the model-specific soft-restart procedure. Do not use factory reset or stock flashing
to complete this experiment. No driver is installed or rebound by this command.

Journal observations omit USB serial and instance IDs. Keep the journal local
until its metadata/error messages have been reviewed for publication. Serial/port
correlation is not cryptographic authentication; results always keep
`recovery_authorized=false`. One successful round trip does not enable firmware
writing or establish support for a different phone, firmware, host or transport.

## First live result

The first approved RM-875 test at revision `7a81c19` sent the Normal-to-Flash
request, then stopped at USB identity binding. A separate read-only Flash probe
exposed no USB serial, platform `Nokia.MSM8960.P5217.3.2.1` and no FVER value.
No NOKS or NOKR was sent. After a manual restart, the native read-only probe
confirmed the original model, variant and installed firmware in Normal mode.
See the [sanitized evidence](../tests/hardware/lumia-1020-rm875-native-mode-test-first.json).

Do not repeat the current harness on this phone expecting a completed round trip.
Cross-mode identity binding, the platform suffix and unavailable FVER need review
before another live experiment. The strict checks remain in place; this result
does not authorize recovery or firmware writes.
