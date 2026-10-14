# Hardware validation

No verified device operation is shipped yet. Automated image/replay tests cannot
establish hardware safety. A USB VID/PID identifies an interface, not a model.

## First read-only sessions

1. Connect the Lumia 1020; run `wpi devices` and record the host, OS, app revision,
   USB mode, descriptors, interface classes and driver binding.
2. Run `wpi probe '<id>'`. In flash mode it sends NOKV and, when the application
   is FlashApp, FVER. In normal mode it sends only model/product/firmware read
   queries to vendor-specific interface 3. It does not switch phone modes or touch storage.
3. Record hardware variant separately until it can be authenticated from the device.
   Do not infer RM number from a chosen firmware file or the USB product label.
4. Repeat on Lumia 730, Windows ARM64, Apple Silicon, and Linux x86-64/ARM64.
5. Import real local FFUs and compare parsed metadata and extracted partition
   hashes with the pinned upstream version. Do not commit proprietary images.

## Observed normal-mode browser reconnection

The user supplied `reconnection-check.json` and explicitly confirmed unplugging
and reconnecting USB after **Remember this phone**, before **Check reconnection**.
The report correlated the returning normal-mode interface: USB serial, variant,
firmware and bootloader family checks passed; platform remained unverified.
The sanitized record is
[`lumia-1020-rm875-browser-normal-reconnection.json`](../tests/hardware/lumia-1020-rm875-browser-normal-reconnection.json).

This is one user-confirmed cycle, with an exported comparison report rather than
an independently captured USB event/wire transcript. Device and host identity
context comes from earlier sessions; the export contains agreement checks rather
than identity values. Exact browser name/version and timing were not recorded.
It establishes an observed read-only reconnection result, not an authenticated
identity, Flash-mode transition, validated firmware applicability or write support.
Capability status remains experimental and recovery authorization remains false.

## First native mode experiment

The explicitly approved Windows ARM64 RM-875 experiment sent one Normal-to-Flash
request, then stopped because the returning USB serial or physical port did not
match. The combined error does not identify which binding component failed.
No automatic return request, context switch or firmware/partition write followed.
A separate read-only probe observed FlashApp, but did not establish identity
correlation. That probe had no USB serial, unlike Normal mode. The user reported
booting normally after a manual restart; a subsequent native read-only recheck
confirmed Lumia 1020 RM-875, Normal mode and firmware `3051.50009.1451.1003`.

The sanitized record is
[`lumia-1020-rm875-native-mode-test-first.json`](../tests/hardware/lumia-1020-rm875-native-mode-test-first.json).
The Flash platform suffix and unavailable firmware value require further review,
in addition to the USB binding failure. Do not automatically repeat this experiment
or relax identity checks on the basis of a matching platform label. Capability
gates remain unchanged.

## Normal-mode public-ID observation

The dedicated CLI `identity-probe` read a valid, nonblank 20-byte public ID on the
connected RM-875 in Normal mode. The value was discarded and is not in the report.
The report confirms availability, not equality with a Flash-mode observation.
See [`lumia-1020-rm875-normal-public-id.json`](../tests/hardware/lumia-1020-rm875-normal-public-id.json)
and [the probe's limits](public-identity.md). No mode change or firmware write was
sent. The known failed native mode-test profile is now blocked in preview and
execution; hardware cross-mode binding must be validated separately.

The new CLI public-ID mode experiment's read-only preview also passed on the
connected RM-875. See
[`lumia-1020-rm875-public-id-mode-preview.json`](../tests/hardware/lumia-1020-rm875-public-id-mode-preview.json).
This confirms Normal-mode readiness only. The original serial-only test stays
blocked, and the [new experiment](public-id-mode-test.md) requires distinct explicit
confirmation before any live mode request. At that preview, cross-mode equality
was still pending; the subsequent live observation is described below.

The subsequently approved live run is recorded in
[`lumia-1020-rm875-public-id-mode-test-first.json`](../tests/hardware/lumia-1020-rm875-public-id-mode-test-first.json).
It matched Normal/Flash public IDs and physical port, and sent NOKR once. The
harness stopped during return before its final Normal identity comparison. A
separate read-only probe confirmed Normal, the unchanged installed firmware and
serial correlation with the earlier Normal session. The rejected boot-stage
profile was not captured; updated software keeps BootManager return observations
unverified and records safe diagnostics. At that first milestone, full harness
completion was unvalidated. No general mode or firmware-writing profile is enabled.

Two October 14 runs also matched the Flash public ID and sent the return request
once, followed by separate successful Normal information probes. The first timed
out during repeated BootManager probing; the second observed BootManager once
but reached the return deadline. Their sanitized records are
[`boot timeout`](../tests/hardware/lumia-1020-rm875-public-id-mode-test-boot-timeout.json)
and [`retired-interface deadline`](../tests/hardware/lumia-1020-rm875-public-id-mode-test-retired-deadline.json).
Those failures preceded the subsequently approved complete cycle at `8f6c8ca`.
See [the successful timing record](../tests/hardware/lumia-1020-rm875-public-id-mode-test-completed.json):
all three identity checks matched, firmware stayed unchanged, and both mode OUTs
completed once. Normal USB appeared 34.979 seconds after NOKR and the final
identity check completed 2.905 seconds later after interface-readiness retries.
The user confirmed the normal screen during the wait; visible boot duration was
not measured. Only this exact native Windows ARM64/RM-875/firmware combination
has one complete-cycle result. Repeatability, other profiles and hosts, browser
mode changes and firmware-writing operations remain unvalidated.

## Evidence required for writes

Before enabling an operation, implement its entire state machine, identity and
firmware checks, expected command transcripts, recovery course, and safe boundaries.
Record hardware results for the exact model/RM, firmware, bootloader state,
host architecture, transport, and operation. A different firmware or USB mode is
not covered automatically. Do not perform destructive disconnect tests on the
user’s only phone; simulate those failures with protocol replay first.

Store sanitized evidence records under `tests/hardware/`. Redact IMEI, serial
numbers and identifiers before public publication. Keep personal raw logs local.
Evidence records alone cannot bypass the Rust gate; enabling writes requires a
reviewed implementation and profile change.
