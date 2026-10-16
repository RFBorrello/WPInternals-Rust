# Read-only Spec A device preflight

The shared Rust query engine and advisory assessment are available through a
CLI research adapter. They have synthetic/replay coverage; this workflow has
**not been run on a phone**. Browser/desktop UI controls and live write
capabilities are not enabled by these checks.

Preview the bounded source reference without accessing USB:

```text
wpi preflight-spec-a stock.ffu
```

The reference reads the source primary GPT and SBL1, validates their structure,
and fingerprints both. It uses the last SBL1 DER certificate hash for RRKH
comparison, following WPInternals 2.9.2 commit
`d8fd0aa516b16dc094df0422a3adc525af005c29`. This metadata read does not verify
the complete FFU, authenticate its signer or establish installed firmware
applicability. Full recovery/package verification remains a separate requirement.

An explicitly selected phone must **already expose FlashApp**:

```text
wpi devices
wpi preflight-spec-a stock.ffu --device-id SELECTED_ID
```

This command refuses Normal-mode interfaces before opening them. It sends NOKV,
a terminal public-ID query, RRKH and SS parameter reads, then rechecks NOKV and
the public ID on the same handle. A source platform must equal the observed
platform or be its dot-delimited prefix; a filename/model label cannot substitute
for it. RRKH must be exactly 32 nonblank bytes and match the source fingerprint.
Zero/erased roots do not bypass verification. Public IDs remain in memory and
are never included in the report. Single-handle public-ID equality is local
correlation, not authenticated identity or correlation with a prior Normal session.

The SS response must contain eight bytes with recognized boolean flags. The
NOKV security block uses the pinned version 3 encoding, including authenticated
values 1/2. Unknown versions/flags, duplicate blocks, trailing/truncated data,
security contradictions and changed application/public-ID responses stop the
session. Differently named debug/JTAG and crypto/secondary-key fields are reported
separately rather than assumed identical. No FVER parameter is queried here.

Primary GPT reading is opt-in:

```text
wpi preflight-spec-a stock.ffu --device-id SELECTED_ID --read-primary-gpt
```

NOKT is sent only when both security reports agree and the current FlashApp
reports authentication, RDC, or disabled secure FFU. Locked FlashApp returns
`context_switch_required`; missing application security returns
`security_evidence_missing`. Neither result sends NOKT or a context switch.
Upstream ReadGPT switches to BootManager in the locked case. Our preflight
deliberately leaves that transition for a separately reviewed hardware workflow.
BootManager/PhoneInfo applications are not accepted by this adapter.

NOKT must return exactly an eight-byte header and 34 primary sectors. The shared
assessment checks GPT CRCs, strict Spec A geometry, unique identities/names,
partition bounds/overlaps, stock-layout prerequisites, and reported eMMC capacity
when available. Geometry, disk GUID, ordered partition identities/bounds/types/
attributes are compared to the source. A valid but different layout is an explicit
failed comparison. A CRC/structure failure rejects the assessment. No raw sectors
or disk GUIDs are exported; only the observed primary hash and partition count.
This digest does not preserve a recoverable primary GPT. Backup GPT and installed
partition originals are not acquired or backed up by this command.

Native sessions use the process-wide phone lock, a 30-second transport deadline
and descriptor checks before/after queries. Ctrl+C cancels before the next query;
an in-flight query must return or time out. Disconnects, timeouts, partial
transfers and malformed responses stop without retry, reset, context change,
programmer upload or write. Failure may still require inspecting device state;
the command never attempts recovery automatically.

Synthetic CLI demonstrations contact no USB:

```text
wpi preflight-spec-a tests/fixtures/synthetic-spec-a-package.ffu --replay tests/fixtures/spec-a-preflight-locked.json --read-primary-gpt
wpi preflight-spec-a tests/fixtures/synthetic-spec-a-package.ffu --replay tests/fixtures/spec-a-preflight-primary.json --read-primary-gpt
```

Exports distinguish `reference_preview_only`, `replay_only` and
`native_read_only`. Replays are not hardware evidence. Reports cannot be imported
as execution authority, and `phone_writes_enabled` / `recovery_authorized` are
always false. Installed originals, both GPTs, exact applicability, loader/donor
acceptance, validated recovery and an audited live executor remain prerequisites.
The previously built RM-875 ZIP uses an older source FFU than the installed phone;
a matching root or primary layout cannot establish downgrade acceptance.
