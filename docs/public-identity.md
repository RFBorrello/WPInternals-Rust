# Read-only public-ID inspection

The first RM-875 mode experiment stopped because its Flash interface exposed no
USB serial. The shared reconnection checks still require a matching serial;
the existing native mode experiment is blocked from repeating this known failure.
Production mode-switching and firmware-writing capabilities remain gated.

## Protocol reference

WPInternals 2.9.2 (`d8fd0aa516b16dc094df0422a3adc525af005c29`) reads a 20-byte
public ID in Normal mode through `ReadPublicId` / JSON-RPC `PublicId`.
`NokiaFlashModel.GetTerminalResponse` constructs the fixed `NOKXFT` terminal query;
`Terminal.Parse` reads the public ID from terminal node 3. The Rust implementation
is in `crates/wpi-protocol/src/identity.rs` and preserves upstream attribution.

The Normal method has a dedicated builder; it does not extend the three-method
allowlist used by normal browser/device-information operations. The terminal
parser checks a bounded response, wrapper/root lengths, byte order, node bounds,
duplicates, a 256-node limit and a nonblank 20-byte ID. It rejects invalid request
IDs, errors and nonbyte JSON arrays. Strict terminal signature/status checks accepted
one live Flash response in the new experiment; other profiles remain unvalidated.
Synthetic success is not hardware evidence.

Public IDs can be compared locally with the typed `PublicId` value. That type has
no serialization implementation or byte getter; its debug representation is
redacted. Equality is an unauthenticated device observation, not proof of device
ownership, firmware applicability or permission to write. No public ID is copied
into `DeviceIdentity`, exported, hashed for publication or logged by this probe.

## CLI

```sh
wpi devices
wpi identity-probe '<explicitly-selected-device-id>'
```

This command never switches modes. In Normal mode it reads model/product/firmware
and one public ID. In Flash mode it requires a fresh NOKV observation of FlashApp,
reads one terminal response, then queries FVER once. BootManager, PhoneInfo,
emergency and mass-storage modes cannot run the public-ID query. There is no
automatic context switch, timeout-disabling request, query retry or driver change.
Normal identification and the dedicated public-ID query share one opened interface.

Reports contain public-ID availability and USB serial/port availability, never
the public-ID bytes, USB serial or device instance ID. The public ID is discarded
after inspection; separate invocations do not compare identity. All reports keep
`identity_authenticated=false`, `mode_change_sent=false` and
`recovery_authorized=false`. The physical-port flag reports usable topology metadata,
not proof that a returning interface belongs to the same phone.

FVER is the final request in Flash mode. Its failure is retained with the response
length and six-byte signature, rather than disappearing into a null firmware field.
No request follows a failed FVER. Transport waits are bounded by the existing
five-second limit and a 20-second session deadline; synchronous OS open/enumeration
and transfer cleanup may extend elapsed time. Other query failures stop the probe.

## Hardware status and next validation

The connected Lumia 1020 RM-875 / `3051.50009.1451.1003` answered `ReadPublicId`
successfully in Normal mode on Windows ARM64. Only presence was exported, with
no mode or firmware writes. See
[`lumia-1020-rm875-normal-public-id.json`](../tests/hardware/lumia-1020-rm875-normal-public-id.json).

One native experiment subsequently parsed a live terminal response and observed
matching Normal/Flash IDs and physical-port continuity. The full in-harness return
identity check, repeatability, other profiles/hosts and FVER behavior remain unvalidated.
Before another live mode attempt, integrate those checks into a reviewed harness,
test interruption and wrong-device cases, and obtain explicit approval for the
mode change. A presence report or a manually edited JSON report cannot enable it.

The separate [public-ID mode experiment](public-id-mode-test.md) now implements
in-memory comparisons and command-handle revalidation. It requires a distinct
confirmation phrase and new journal; the original experiment stays blocked.
The first live run matched the Flash ID but stopped during return; see its
[evidence](../tests/hardware/lumia-1020-rm875-public-id-mode-test-first.json).
FVER is excluded from the mode-only sequence
and remains a separate diagnostic without firmware-write authorization.
