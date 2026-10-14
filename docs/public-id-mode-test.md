# Native public-ID mode-validation experiment

This separate CLI-only experiment replaces the identity assumption that stopped
the first live test. The original `mode-test` remains blocked. Production mode
switching, browser/Tauri execution and all firmware-writing capabilities remain
unavailable. Results never automatically promote a verified capability.

## Exact scope

- Windows ARM64; one Lumia 1020 RM-875 / Spec A in Normal mode, USB `0421:0661`.
- Installed Normal firmware `3051.50009.1451.1003`, a nonempty USB serial, a valid
  20-byte public ID and physical parent-hub/connection-index binding.
- Returning Flash USB `0421:066e`, FlashApp `2.2`, protocol `1.18`, and full platform
  `Nokia.MSM8960.P5217.3.2.1`, observed after the interrupted first experiment.

These define experimental admission, not firmware applicability or authenticated
identity. BootManager/PhoneInfo, other profiles, additional phones and changed
topology stop without a context/reset command.

## Preview and explicit execution

```sh
wpi devices
wpi mode-public-id-test '<explicitly-selected-device-id>'
```

The default only reads model/product/firmware and `ReadPublicId` with JSON-RPC ID
4, exporting a redacted preview. It never changes modes. Identifier bytes are
discarded after preview and cannot be supplied through caller-provided JSON.

```sh
wpi mode-public-id-test '<explicitly-selected-device-id>' --execute \
  --confirm RM875-PUBLIC-ID-ROUNDTRIP --report public-id-mode-test.jsonl
```

The phrase differs from the original test. The journal must be new; existing files
are never overwritten. The CLI flushes/synchronizes headers, command boundaries
and observations, and handles Ctrl+C at safe boundaries. Obtain explicit user
authorization because execution reboots the phone. Keep other phone clients idle.

1. Arm hotplug observation and read fresh Normal information/public ID. Bind the
   serial and physical port. Recheck all fields on the command handle before
   attempting `SetDeviceMode(Flash, HwReset)` once.
2. Require removal and exactly one returning interface on the same port. A missing
   Flash serial permits **read-only inspection only**; a different available serial
   fails. Port or product labels alone never permit the return request.
3. Read NOKV and require the exact Flash profile before reading the fixed `NOKXFT`
   terminal response. Require its public ID to equal the in-memory Normal ID.
4. Reopen the selected Flash interface, read NOKV/public ID again on the command
   handle, and revalidate identity, profile and port before one `NOKR`.
5. Require removal and fresh Normal model, variant, firmware, serial and public-ID
   equality. Matching successful Flash probes during Normal boot can be observed
   again, but never cause an extra reset. BootManager stops the experiment.

Only those two mode requests are accepted. No firmware files, partitions, loaders,
security/authentication payloads, NOKS/context switches, mass storage or implicit
timeout-disabling requests are part of this harness.

## Firmware and identity limits

The mode-only experiment does **not** query FVER. Its response format remains
unvalidated after the first general Flash probe returned no firmware value.
FVER is a separate [read-only identity diagnostic](public-identity.md), retaining
errors and performing no subsequent query after failure. Flash firmware stays
unavailable; it is not copied from Normal. Firmware-writing gates retain separate
applicability requirements and remain blocked.

Public IDs and serials are unauthenticated observations. Journals contain equality
and topology checks, never identifier bytes or Windows instance IDs. Results keep
`identity_authenticated=false` and `recovery_authorized=false`. The shared browser
reconnection report keeps its original serial policy; this alternate binding is
not exposed through the UI.

## Interruption

Each reconnection wait has an absolute 30-second deadline. Open/claim readiness
may retry before any query. Failed/malformed queries never automatically repeat.
An uncertain OUT is inspected without resending; only fresh validated observations
permit the next planned request. Synchronous enumeration/open/cleanup may extend
elapsed time beyond transfer deadlines.

Wrong/missing public IDs, serial contradictions, changed topology, unexpected
profiles, timeout, cancellation and journal failure stop. If left in Flash, inspect
the phone and use the Lumia 1020 Volume Down + Power restart if needed. Do not
automatically repeat the experiment or use flashing to complete it. Terminal
parsing remains a strict synthetic assumption until live validation. Failures
record only response length and a recognized header label, never arbitrary leading
bytes or terminal payloads.
