# Recovery replay session journal

This is the first journal component for future native recovery work. Only the
concrete protocol replay transport can execute the journaled engine. No native
USB, serial, WebUSB or block-device writer can be passed to it. The connected
phone is not queried or changed by this workflow, and its data must be preserved.

```text
wpi replay-recovery synthetic.ffu scenario.json new-session.jsonl
```

The CLI accepts a local scenario with an `exchanges` array in the existing
`ReplayTransport` format. Each exchange contains `request` and `response` byte
arrays and an optional `error` string. Scenarios are limited to 1 MiB and 512
exchanges. This is intended for bounded synthetic protocol experiments, not a
multi-gigabyte recorded transfer. There is no device-selection or execute flag.
The existing public `run` API retains its no-file behavior; `run_journaled`
accepts a synchronous sink, whose successful return must mean the entry was saved.

Records bind the replay to the complete image SHA-256 and size and describe:

- Ready state after image and simulated-device preflight.
- Header intent, followed separately by a successful acknowledgement.
- Each payload intent (offset/length), followed separately by its acknowledgement.
- Cancellation, uncertain transfer/recovery requirement, or completed transfer.

Sequence numbers increase from one. The acknowledgement counter advances only
after a successful protocol reply. A lost reply can mean the submitted operation
was accepted; it is never counted as confirmed or retried. Header intent marks
state inspection as required even if a crash occurs before actual submission.
Transfer completion is not verified boot, successful recovery or data preservation.
Records always identify themselves as replay-only, disable phone-write authority
and automatic resume, and require fresh device checks. They contain no payload
bytes, USB serials or public-ID values.

The native file sink creates a new regular JSONL file without overwriting an
existing one. It flushes and calls `sync_all` for every complete line. A failed
append poisons the sink; partial bytes stay for inspection, and subsequent appends
fail. OS/storage behavior and abrupt power-loss durability have not been tested;
file synchronization alone does not prove crash-safe directory publication.
Empty or partial journals can remain after errors. Callers must handle the returned
error even if the last progress event or saved line is nonterminal. No import,
repair, reconnect, automatic resume or recovery-from-journal API is implemented.

A persistence failure before header submission stops without a simulated write.
After header submission, failure requires state inspection and stops before the
next submission. An acknowledgement received immediately before a journal failure
may not be present on disk; the preceding intent must be treated as uncertain.
The journal's contents never bypass device/image/applicability checks or approve a
write. Future native execution still needs a reviewed admission policy, device and
artifact binding, interruption/reconnection handling, preservation and physical
recovery validation. No new compatibility capability is enabled.

CLI cancellation is observed at existing replay event boundaries. Image
preflight and whole-file fingerprinting do not yet expose cancellation through
that callback. Only transfer acknowledgements are journaled; USB-level
partial-transfer behavior remains separate protocol/adapter work.

Unit tests cover both protocol versions, ordered intents/acknowledgements, source
binding, cancellation, lost final replies and failures at all 26 journal checkpoints
across the two synthetic transfers. Remaining queued requests, including a final
sentinel, prove that no retry or subsequent command was sent. File tests verify
new-file protection, JSONL persistence and sink poisoning. A native CLI smoke run
saved 16 entries for success and 15 for a lost final reply; the latter confirmed
only 20,480 of 24,576 payload bytes and required inspection. Both protected an
existing journal. All fixtures are synthetic; no proprietary images or captured
phone data are distributed.
