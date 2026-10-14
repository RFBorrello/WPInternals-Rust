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
identity. BootManager before the return request, PhoneInfo, other profiles,
additional phones and changed topology stop without a context/reset command.

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
   again, but never cause an extra reset. During this return wait only, BootManager
   protocol 1/2 can be observed with NOKV and journaled as unverified. It cannot
   receive a terminal query or command, and cannot complete the identity check.
   After observing an intermediate interface once, the harness retires it until
   a fresh removal/arrival or the Normal USB descriptor appears. It does not keep
   polling NOKV while that boot stage is active. Native
   hotplug events wake enumeration; a two-second discovery fallback handles missing
   notifications without unretiring the boot interface. Open/claim readiness can retry before
   any query. Observation starts before the query so events during it are retained.
   The deadline is not reset.

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

Flash arrival has an absolute 30-second deadline; Normal USB reconnection has a
90-second maximum. This is a software observation bound, not a measured boot time.
The preview exposes both bounds. Open/claim readiness
may retry before any query. Failed/malformed queries never automatically repeat.
An uncertain OUT is inspected without resending; only fresh validated observations
permit the next planned request. Synchronous enumeration/open/cleanup may extend
elapsed time beyond transfer deadlines.

Wrong/missing public IDs, serial contradictions, changed topology, unexpected
profiles, timeout, cancellation and journal failure stop. If left in Flash, inspect
the phone and use the Lumia 1020 Volume Down + Power restart if needed. Do not
automatically repeat the experiment or use flashing to complete it. Failures
record only response length and a recognized header label, never arbitrary leading
bytes or terminal payloads.

## First live result

At revision `953f7e8`, the explicitly approved test observed matching Normal/Flash
public IDs on the same port, then delivered one NOKR after command-handle
revalidation. The harness rejected a subsequent NOKV observation before its final
Normal identity check. The failing profile fields were not captured, so a boot
transition is an inference. A separate native read-only probe found Normal RM-875,
unchanged firmware and a serial matching the earlier Normal session. No manual
restart was requested or reported, and no firmware writes occurred.

See [the sanitized live record](../tests/hardware/lumia-1020-rm875-public-id-mode-test-first.json).
Subsequent software added unverified BootManager observations during return and
safe mode/version diagnostics on profile rejection. At this first milestone,
full in-harness Normal/Flash/Normal public-ID verification was still pending.

An approved October 14 run confirmed BootManager protocol `1.1`, application
`1.16` during return. Both mode OUTs completed once, but 49 repeated successful
BootManager queries were followed by an information-query OUT timeout. A separate
probe again found Normal with unchanged firmware. See
[the compact failure record](../tests/hardware/lumia-1020-rm875-public-id-mode-test-boot-timeout.json).
Interface retirement now prevents repeated queries on that same boot generation;
the effect of the earlier polling on boot timing itself is not established.

The explicitly approved next cycle at `b28ea9f` recorded one BootManager
observation and did not query it repeatedly. It still reached the then-30-second
return deadline; a separate probe again confirmed Normal and unchanged firmware.
See [the second October 14 record](../tests/hardware/lumia-1020-rm875-public-id-mode-test-retired-deadline.json).
That revision continued full USB enumeration while waiting. Subsequent software
added hotplug hints during retired-interface waits, a 90-second Normal USB
observation window, and monotonic `elapsed_ms` in CLI events/outcomes. Timing and
enumeration as causes remained hypotheses; further testing required fresh approval.

The user subsequently reported that visible boot completed quickly, well under
90 seconds. Neither earlier journal timed Windows USB availability, so these
failures do not establish slow phone boot. Read-only checks currently find Normal
in both Windows PnP and native discovery.

Inspection of the pinned nusb 0.2.7 Windows hotplug implementation found that an
arrival consumed before `probe_device` can produce metadata yields no Connected
event; callback property/instance lookup failures can also discard notifications.
This makes hotplug-only waiting insufficient, but does not prove the cause of the
earlier failures (those revisions still polled enumeration). Retired waits now
rediscover at most every two seconds without an event, retaining all port, serial,
profile and public-ID checks. They never repeat a query to the retired boot
generation solely because a timer elapsed. Journal discovery events record trigger,
enumeration duration, observed USB modes and source removal; probe events distinguish
opening readiness from a read-only query attempt. Identifier values stay private.
The fallback has a missing-notification regression, including reused IDs and a
contradictory public ID.

## First complete cycle — October 14

After explicit approval for one new cycle, revision `8f6c8ca` completed the entire
Normal/Flash/Normal identity sequence on native Windows ARM64 RM-875 / firmware
`3051.50009.1451.1003`. Both mode OUTs completed once. Flash public ID and physical
port matched, BootManager was observed once without a command, and returning
Normal public ID, serial, model and firmware matched. No firmware or partition
writes, failed protocol-transfer retries or manual restart were used.

The full experiment took 54.252 seconds. Normal USB was first discovered 34.979
seconds after NOKR; opening readiness delayed final identity confirmation another
2.905 seconds (24 pre-query readiness failures). Discovery calls took 2–10 ms.
A Windows PnP snapshot about 42.9 seconds after journal creation found no present
Lumia functions; its time alignment is wall-clock, separate from CLI monotonic
timing. The user confirmed reaching the normal lock/home screen during the wait;
visible boot duration was not measured.

These observations place the delay before Normal USB discovery and then interface
readiness. They do not establish its Windows/phone/driver cause or retrospectively
explain every earlier failure. This arrival was triggered by hotplug, so live
success does not establish a causal benefit from the fallback itself. One cycle
does not validate repeatability, the Lumia 730, browser mode changes, other hosts
or firmware writing. Production capabilities remain blocked.

See [the sanitized complete-cycle record](../tests/hardware/lumia-1020-rm875-public-id-mode-test-completed.json).
