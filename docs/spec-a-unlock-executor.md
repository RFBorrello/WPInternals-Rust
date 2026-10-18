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

## Package-bound programmer composition

`wpi-image::spec_a::programmer_plan::build` now verifies the pinned reference ZIP
and saved primary through the existing live-layout checks, then constructs an
immutable **replay-only** plan in memory. `run_plan` in the core programmer
rehearsal accepts this object directly. There is no JSON import, sector-image
export, native writer or new phone capability. The CLI exports metadata only:

```text
wpi plan-spec-a-programmer reference.zip saved-primary.bin new-report.json --disk-sectors RECORDED_SECTORS --expect-primary-sha256 PRIMARY_SHA256 --expect-package-sha256 PACKAGE_SHA256
python scripts/reference-spec-a-programmer-plan.py reference.zip saved-primary.bin new-report.json
```

The ten regions follow the pinned first-unlock programmer order: HACK, MBR,
primary GPT, SBL2, SBL3, UEFI, SBL1, TZ, RPM and WINSECAPP. Boot addresses use the
saved phone's transformed layout, including normalized active/backup slots.
The MBR is retained from the saved installed primary rather than copied from
the source FFU; this is an intentional preservation choice. GPT bytes come from
the live-derived candidate. The rest are hash-verified package boot payloads.

The GPT write omits the last byte (`0x41ff` bytes after sector zero); that byte
must already agree with the saved primary. SBL1 omits a further 512-byte tail
after the HACK layout shrink, reproducing the pinned programmer length. The
source/prepared SBL1 prefixes, exact live-derived capacity and regenerated HACK
must agree, and the entire parsed signed image must fit inside that shorter
transfer. WINSECAPP is capped at exclusive byte address `0x1e7fe00`. Omissions
are explicit in each report row. Unsafe lengths, overflow, overlap and unrelated
partition intersections fail; no fill, relocation or inferred padding occurs.
Both installed and candidate partition maps are checked, excluding boot slots
and their boot backups only. MainOS, Data and EFIESP receive no transfers in
this phase. This does not establish their preservation through a whole unlock.

Inputs remain local. Each boot member is rehashed when read after archive
verification and limited to 4 MiB. Cancellation is observed during archive
verification, before relationship checks, at every region boundary and before
returning the plan. Parsing and individual bounded I/O calls are not interrupted
mid-call. Existing output reports are protected by atomic new-file publication.
The CLI creates no binary plan and has no execute or device-selection argument.
The report retains historical-layout blockers and explicitly leaves
`data_preservation_validated`, `phone_contacted` and `phone_writes_enabled` false.

Synthetic tests cover installed MBR differences, normalized addresses, exact
GPT/SBL1 omissions, WINSECAPP's clipped tail, unchanged MainOS/Data/EFIESP entries
and disjoint write ranges. They also reject changed SBL1 geometry and tampered
HACK/prefix data even with recalculated ZIP hashes, detect later file mutation,
and cancel at all eleven composition boundaries. The local RM-875 inputs yield
ten transfers totaling 7,529,371 bytes, with GPT/SBL1/WINSECAPP omissions of
1/512/512 bytes. Independent Python calculations match the addresses, lengths
and payload hashes. This was a local calculation, not a hardware experiment;
see [the metadata-only record](../tests/fixtures/rm875-programmer-plan-validation.json).

## Remaining integration

The subsequent [UEFI-variable and EFIESP stages](spec-a-finish-stages.md) now have
immutable local plans, installed-image second-pass reconstruction and bounded
NOKF replay with interruption-journal inspection. The [prepared native
cycle](spec-a-session.md) also connects fresh identity checks across both modes
and back to Windows. These additions do not supply a live emergency/programmer
writer or a complete mass-storage continuation. The implementation gaps below
remain relevant to physical execution, rather than missing payload composition.

The [emergency-entry/upload replay](spec-a-emergency-replay.md) now models the
entry writes, one loader, bounded reconnect observations and programmer handshake.
The [joined replay journal](spec-a-joined-journal.md) now persists their handoff
and the first boot-transfer commands through one programmer connection.
Full execution still needs native emergency/upload/arrival adapters,
fresh identity/RRKH/port binding across modes, installed-layout and recovery
policy, native crash/interruption validation, and the subsequent UEFI/
EFIESP boot-integrity stages. A full installed backup should be captured once
mass storage becomes accessible, before optional sideloading policy changes.
The existing source ZIP and saved primary GPT are not installed partition
backups. Loader, engineering SBL3, donor and firmware acceptance remain
unvalidated on this phone. No hardware unlock has been attempted.
