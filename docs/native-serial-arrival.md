# Native serial probes and arrival observation

Two CLI research tools add native serial communication and discovery-only arrival
observation. Neither enters emergency mode or connects the Spec A write executor
to hardware. Browser and desktop UI phone operations are unchanged.

## Serial emergency queries

For an already exposed emergency serial interface:

```sh
wpi devices
wpi devices --serial
wpi probe-emergency-serial '<enumerated-port>' --usb-device-id '<selected-usb-id>' --protocol dload
# For an already running V1 programmer, select --protocol programmer-v1 instead.
```

Both the serial port and USB device must be explicitly selected. Before opening,
the adapter requires recognized emergency USB descriptors, an available physical
port, the same nonblank serial string in both discovery sources, and exactly one
matching USB device and serial port. Missing metadata, duplicate serials, multiple
matching serial functions, arbitrary paths, disappearance or changed descriptors
stop the operation. There is no VID/PID-only, model-label or port-name-only fallback.
This intentionally excludes serial drivers/devices whose metadata cannot establish
that local correlation. The matching strings are not authenticated unique identity.

The binding is rechecked immediately before each query and after the last reply.
Private USB snapshots are shared with the existing USB probe; scans now retain
unknown USB records too, so an unexpected device on a watched physical port cannot
be mistaken for absence merely because its VID/PID is unrecognized.

Serial communication uses the existing native `serialport` dependency, now requiring
at least the already locked 4.10.1 API. It requests exclusive access, 115200 baud,
8 data bits, no parity, one stop bit and no flow control. It requests preservation
of DTR rather than explicitly toggling control lines. OS/library open behavior
still applies: Linux can assert DTR on open, and the pinned library's macOS open
path flushes buffers while configuring baud. This is not a guarantee of unchanged
line state or preserved pre-open input. No serial port was opened on hardware in
this milestone, and native class drivers/permissions are required on each host.

Pending input observed after open is rejected rather than purged. The adapter
shares the tested bounded HDLC session with USB: DLOAD sends alive/root only;
V1 sends Hello only. Serial reads allocate at most 256 bytes at a time. Each request
is written once; `write_all`, flush, purge, line-control, upload, security, partition,
reboot and retry commands are absent from the adapter. Short writes, read errors,
empty input, malformed frames or timeout-configuration failures retire the session
and close the handle. Closing cannot unsend output already accepted by a driver.

The remaining transaction timeout is applied before every read/write. OUT and all
reply fragments share five seconds, capped by the 15-second query-session deadline.
OS discovery, open, timeout configuration and close calls are not a hard wall-clock
bounded process. Reports export the existing presence-only probe result and serial
match booleans, without port names, serial strings, physical-port values or roots.
No report can be imported as write authority.

## Arrival observation

```sh
wpi observe-arrival '<currently-connected-usb-id>' --expected emergency --timeout-seconds 30
```

The observer records a fresh source descriptor/physical-port snapshot, then uses
USB discovery at intervals of 250 ms. It never opens interfaces or serial ports,
queries the phone or sends a mode request. Accepted targets are Normal, Flash and
Emergency **USB descriptor classifications**. Flash USB does not prove FlashApp
context; Emergency USB does not distinguish DLOAD, Sahara or a running programmer.

An arrival requires observed absence at the original port, followed by two equal
candidate snapshots separated by the polling interval. Descriptor changes before
absence, unknown/wrong modes, ambiguous records, a moved source, changed available
serials, or candidate replacement/removal stop the observer. A returning Normal
interface must retain the baseline serial when one was available. Unrelated devices
elsewhere do not satisfy the observation. Even a matching arrival is unauthenticated
local correlation and grants no permission to query, upload or write.

The timeout is 1–30 seconds and never resets after disappearance or discovery.
Late scan results cannot confirm arrival. Ctrl+C cancels at a boundary before the
next scan; OS discovery itself may delay cancellation. The native phone-operation
lock prevents concurrent native probe/observer sessions. Progress prints stage
changes; the final JSON contains no private identifiers. A completed observation
can have `timed_out` or `cancelled` outcome with CLI exit code zero: inspect the
outcome and `arrival_confirmed_by_discovery`, not just the exit code. Discovery or
binding errors fail with no retry, reset or recovery command.

## Validation and limits

Twelve new tests bring the transport suite to 73 passing tests. Serial tests cover
unique/missing/duplicate metadata, pinned DLOAD/V1 vectors through fragmented serial
reads, pending input, short/failed output, failed timeout setup, partial replies,
empty reads, handle retirement and no retry. Arrival tests cover ordered removal/
confirmation, unknown and wrong devices, ambiguity, changed candidates, different
ports/serials, timeout, late discovery, cancellation and discovery failure. Fake
drivers/clocks exercise these cases without physical disconnects or phone commands.

Strict transport/CLI all-target Clippy, formatting and CLI build pass. CLI parsing
requires explicit USB/protocol selection and bounds observer timeouts. On Windows
ARM64, both serial protocol choices rejected the connected Normal-mode RM-875
before opening a port. A two-second discovery-only observer timed out after eight
scans, with no disappearance, arrival or phone query; the same Normal USB interface
remained present. See the [sanitized record](../tests/hardware/lumia-1020-rm875-serial-arrival-readiness.json).

Successful emergency serial communication, a physical arrival, disconnect faults,
line behavior, other hosts and device/driver combinations remain unvalidated. No
mode change, programmer upload or firmware/partition write occurred. The
[artifact-bound session checks](spec-a-session.md) now have a shared in-memory
context and a native Normal-only command. Native cross-mode admission,
recovery/preservation policy and later boot-integrity stages still need integration
before live unlock execution.
The joined Spec A executor continues to accept concrete replay transports only.
