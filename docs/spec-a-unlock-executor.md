# Spec A unlock executor development

The current priority is a targeted Lumia 1020 bootloader unlock, retaining the
installed OS and Data partition as the goal. A full stock recovery flash is not
an inherent prerequisite. This is a preservation objective, not a guarantee:
the first unlock can fail before access for a full installed-device backup is
available. The owner has designated the RM-875 as the test phone and reaffirmed
the preference to preserve its existing data.

## Implemented programmer-phase rehearsal

`wpi-protocol::qualcomm::v1` now implements the byte-addressed Lumia programmer
commands from WPInternals 2.9.2, commit
`d8fd0aa516b16dc094df0422a3adc525af005c29`,
[`Models/QualcommFlasher.cs`](https://github.com/ReneLergner/WPinternals/blob/d8fd0aa516b16dc094df0422a3adc525af005c29/Models/QualcommFlasher.cs)
and
[`Models/QualcommSerial.cs`](https://github.com/ReneLergner/WPinternals/blob/d8fd0aa516b16dc094df0422a3adc525af005c29/Models/QualcommSerial.cs).
These are pure codecs, with no transport or device handles.

- Hello, security mode zero, open partition `0x21`, close, and reboot.
- Write `0x07`, a little-endian **byte address**, and at most `0x400` data bytes.
- HDLC response framing/CRC validation and upstream acknowledgement prefixes.
  Write `0x08` replies must echo the submitted address. Bounded extra decoded
  metadata is accepted but uninterpreted, as with upstream prefix matching.
- Requests remain unframed: upstream sets `EncodeCommands=false` for this phase
  while retaining framed response decoding. This differs from loader entry.

`wpi-core::spec_a_programmer_replay::run` rehearses that phase using only the
concrete `ReplayTransport`. It cannot accept a native, serial or browser writer.
It validates nonempty, nonoverlapping 32-bit byte ranges, then sends hello,
security, open, writes in caller order, close and reboot. Chunking is at most
1 KiB; borrowed bytes are not copied into a whole command transcript. Replay
resource limits are 32 regions, 16 MiB per region and 64 MiB total. These are
local rehearsal limits, not discovered device capabilities or applicability rules.

Progress counts only bytes with valid address-bound acknowledgements. Every
command has a cancellation boundary. Cancellation before submission sends
nothing; after any session command, interruption requires state inspection.
The error distinguishes whether a data-write submission was attempted. A lost
reply can follow an accepted command. No retry, automatic close/reboot, reconnect
or subsequent command occurs on failure. Successful completion means only the
simulated programmer transfer and reboot were acknowledged; it does not mean
the phone booted or its bootloader was unlocked. Terminal event callbacks cannot
undo an already completed transfer.

The rehearsal accepts caller-selected regions and does **not** establish that
they are safe boot partitions. It has no device-identity, GPT placement,
artifact-authenticity, persistent journal or preservation admission policy.
It does not parse an executable plan from JSON. There is no CLI/IPC/UI command
for running this phase against hardware, and no capability gate was enabled.

## Evidence

The public fixture is entirely synthetic. Its two regions exercise multiple
full chunks, a three-byte tail, a discontiguous region, and literal `0x7e`/`0x7d`
request bytes. An independent Python translation constructs the transcript
using the actual CRC lookup table read with `git show` from the pinned C# source:

```text
python scripts/reference-spec-a-programmer.py .reference/WPinternals tests/fixtures/spec-a-programmer-v1.json --check
```

Rust tests compare the codecs and complete replay with those vectors. Nine
faults at every one of the nine commands cover transport timeout/disconnect,
empty/truncated frames, invalid CRC, wrong acknowledgement/address, oversized
responses and concatenated frames (81 fault cases). A queued sentinel detects
extra commands after the final uncertain reboot. Cancellation is checked at
all nine command boundaries. Additional tests cover overlap, resource bounds,
address overflow, the final 32-bit byte, adjacent regions and caller ordering.
Transport errors model uncertainty; physical USB fragmentation and partial-write
accounting are not tested by a message-level transcript.

## Remaining integration

The next step is deriving the exact programming regions from the verified
package and live-derived candidate, rather than accepting reference restore
coordinates. The pinned unlock sequence writes HACK first when present, then
MBR, primary GPT, SBL2, SBL3, UEFI, SBL1, TZ, RPM and WINSECAPP. Its GPT write
deliberately omits the final byte (`0x41ff` bytes after sector zero), its SBL1
length has a separate shortened-range rule, and WINSECAPP has a loader-bound
workaround. Those rules require explicit byte-level tests before composition;
the generic rehearsal does not silently derive or apply them.

Full execution also needs emergency-entry and programmer-upload state machines,
fresh identity/RRKH/port binding across modes, installed-layout and recovery
policy, durable intent/acknowledgement checkpoints, and the subsequent UEFI/
EFIESP boot-integrity stages. A full installed backup should be captured once
mass storage becomes accessible, before optional sideloading policy changes.
The existing source ZIP and saved primary GPT are not installed partition
backups. Loader, engineering SBL3, donor and firmware acceptance remain
unvalidated on this phone. No hardware unlock has been attempted.
