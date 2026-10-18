# Native emergency USB probe

`wpi probe-emergency` performs a fixed read-only exchange on an explicitly selected,
already exposed Qualcomm emergency USB endpoint. It does not enter emergency mode,
upload or start a programmer, change security mode, open a partition, write RAM or
storage, or reboot. It is a CLI research adapter; the browser and desktop UI have
no new phone operation. No phone mode change is needed for this development milestone.

```sh
wpi devices
wpi probe-emergency '<selected-emergency-device-id>' --protocol dload
# Alternatively, ONLY for an already running V1 programmer:
wpi probe-emergency '<selected-emergency-device-id>' --protocol programmer-v1
```

Protocol selection is mandatory. The DLOAD choice sends HDLC-framed alive and root
queries, validates the ACK and nonblank 32-byte root fingerprint, and discards the
fingerprint. The V1 choice sends one unframed Hello and validates its HDLC reply.
There is no protocol guessing, alternate protocol attempt, retry or loader search
after a failure. The root query establishes availability only; no comparison with
a source firmware, loader or earlier phone session is made by this command.

## Selection and session checks

The adapter accepts only recognized `05c6:9008` or `05c6:f006` emergency descriptors.
Normal, Flash, mass storage and unknown USB IDs are rejected before opening a
device. These emergency IDs can be shared by other Qualcomm devices and by distinct
protocol stages. They do not identify a Lumia model or prove that the user's chosen
protocol is running.

The selected descriptor snapshot must have a physical-port binding. Fresh discovery
checks require the same USB ID, descriptor fields and physical port, with exactly
one selected record and no second recognized record on that port. Checks run before
opening/claiming, immediately before every query and after the last reply. Changes,
missing endpoints or ambiguity stop the probe. The private snapshots cannot be
serialized or imported as authorization. Discovery and query are separate OS calls;
these checks cannot remove every device-replacement race or authenticate identity.

Only an active configuration with exactly one vendor-class, alternate-zero bulk
interface containing one bulk IN and one bulk OUT is accepted. Multiple candidates
or ambiguous endpoint pairs are rejected. The adapter does not select a USB
configuration, detach a kernel driver or claim protected interface classes. Native
WinUSB/OS permissions must already permit access. Serial-only exposure requires the
separate serial adapter, which remains unimplemented.

## Fragmented replies and failures

The private native USB session sends each request once, then assembles one HDLC
frame across bounded IN completions using the existing CRC-checking decoder. Split
escapes and checksums are supported. Each IN requests one packet, so a frame ending
exactly on a full USB packet does not wait for an extra zero-length packet to finish
a larger host read. Total reply bytes cannot exceed 8 KiB, including framing and
checksum; packet allocations cannot bypass that bound. A short
IN completion is a fragment, never a reason to resend the request. All fragments
share the transaction's five-second OUT/IN deadline, capped by a 15-second query
session deadline. OS discovery/open calls are not a hard wall-clock-bounded process.

Empty input, disconnect/timeout errors, malformed framing, bad CRC, oversized or
incomplete replies retire the session and cancel both endpoints. No later request
is submitted on that handle. Trailing bytes in the completion containing a closing
delimiter are rejected; the reader stops at a complete frame and does not perform
extra reads to prove that no unsolicited data remains queued. Protocol ACK/root
validation follows framing; a failed check exits and drops the session. Fresh-port
failure also exits without a reset, recovery command or automatic reopening.

Success outputs protocol, public VID/PID, query count and presence/match booleans.
It exports no serial, public ID, physical-port value, root fingerprint or payload.
Authentication, Lumia model identification, phone-write availability, unlock and
data-preservation validation remain false. A JSON report is not write authority.
This is not fresh admission for a multi-mode unlock session.

## Validation

Eleven new tests extend the transport suite to 61 passing tests. They cover every
two-fragment split and bytewise delivery across escapes/CRC, an 8 KiB frame delivered
bytewise or in full packets without a zero-length terminator,
invalid/coalesced trailing frames, incomplete bounds, failed reads, short OUT and
shrinking deadlines. Selection tests reject protected classes and ambiguous pairs;
binding failures at every query boundary stop subsequent commands. Query tests
verify the fixed request sequences and no protocol fallback. Existing pinned
upstream-reference DLOAD/V1 vectors also pass through the query policy and native
transaction logic with one-, three- and 64-byte fragments using injected I/O.

The CLI builds, strict transport/CLI Clippy passes, and argument parsing rejects
a missing protocol before dispatch. Both protocol choices rejected the connected
RM-875 in Normal mode before opening or sending queries; its Normal USB interface
remained present. See the [sanitized refusal record](../tests/hardware/lumia-1020-rm875-emergency-probe-normal-refusal.json).
No emergency-mode hardware probe, programmer upload, write, mode change or driver
change was performed. Physical fragmented replies, faults and reconnect behavior
remain unvalidated on every host.

Native serial transport, arrival observation, cross-mode public-ID/root correlation,
fresh unlock admission and recovery/preservation policy remain separate work. The
joined Spec A executor still accepts concrete replay transports only; this command
cannot connect its write phases to hardware.
