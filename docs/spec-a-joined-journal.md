# Joined Spec A replay and interruption journal

`wpi-core::spec_a_unlock_replay::run` now joins emergency entry, one DLOAD loader
upload and the first boot-component programming phase in one replay session.
The programmer connection used for the returning Hello continues directly into
security mode/open/writes/close/reboot; a second Hello is not sent. This does not
implement later UEFI/EFIESP stages, a verified return to Windows or live unlocking.
There is no CLI/IPC/UI execution command or native transport adapter for this API.

The public function requires the image engine's immutable programmer plan,
an immutable entry plan and one pinned loader. It checks that entry FFU digest
and platform agree with the boot package's source, validates transfer ranges
before entry, and binds the journal to six artifact digests:

- Complete source FFU and reference ZIP.
- Saved installed primary GPT and its live-derived candidate.
- Original loader import and decoded loader bytes.

Inputs must already have passed their respective constructors. A report or
journal cannot be deserialized into these objects or used as write authority.
Integrity and shared artifact identity are not OEM authentication, fresh physical
device identity, firmware acceptance or data-preservation evidence. All execution
parameters use concrete replay transports; generic transport helpers are private.

## Checkpoints and progress

Each record has a monotonically increasing sequence, artifact bindings, phase,
step, kind, optional byte address/length, received RAM/boot acknowledgement
counters and safety flags. Source read-only preflight is recorded after its
bookends pass; individual source queries are not journaled. Records then cover:

| Kind | Meaning |
| --- | --- |
| `ready` | Local binding and range checks passed; device preflight has not yet run. |
| `intent` | Persist before submitting a header, zero chunk, RAM command, boot write or control command. |
| `acknowledged` | Persist only after the complete reply passes the applicable checks. |
| `submitted` | The send-only entry reboot returned from the local transport; there is no device acknowledgement. |
| `awaiting_arrival` / `arrival_matched` | Persist the wait and the successful bounded mode/port correlation before continuing. |
| `phase_complete` | Read-only preflight or the loader-to-programmer handoff completed. |
| `transfer_complete` | First boot-phase transfer/reboot acknowledgements saved, without asserting device unlock or boot. |
| `cancelled` / `failed` / `recovery_required` | Terminal outcome when the journal is still writable. |

An intent for the FFU header conservatively requires state inspection even if
a crash happened before actual submission. RAM counters advance after valid
DLOAD replies; those replies do not echo the address or prove memory readback.
Boot-write replies must echo the submitted byte address. If an acknowledgement
was received but its checkpoint could not be saved, the last durable record can
still be an uncertain intent. It must not be retried automatically.

One outer progress sequence covers upload plus boot payload bytes, excluding
entry-header/zero-chunk bytes from those counters. Child phase completions are
suppressed. The final completion event is emitted only after `transfer_complete`
is saved. Cancellation has an explicit handoff boundary before security/open;
after entry submission it requires inspection, even before the first boot write.

Every record keeps fresh checks required, automatic resume disabled, replay-only
true, phone writes disabled, device unlock unverified and preservation unvalidated.
No payload, USB serial, public-ID value, physical-port string or GPT GUID is saved.

## Persistence and failure handling

`spec_a_journal::FileJournal` creates a new regular JSONL file without replacing
an existing file. Every record is bounded to 4 KiB before its newline, written,
flushed and synchronized before execution advances. The existing recovery journal
now shares the same native sink while retaining its 2 KiB limit and public API.
Any serialization, length, write, flush or sync failure poisons that sink. Partial
files remain for inspection; there is no repair, import, continuation or resume API.
The callback form requires a sink whose successful return means durable save.

Persistence failure stops before the next command. No retry, alternate loader,
cleanup write, reset or continued transfer is issued. A failed sink is never
called again for a terminal record. Error reporting retains the underlying save
failure even if a child phase reports cancellation; failure while saving a
terminal outcome is also returned. Callers must handle the returned error.

File synchronization does not establish crash-safe directory publication or
protection against abrupt power loss. Native crash/power-loss behavior has not
been validated. No physical device operation occurred in this milestone.

## Validation scope

The joined fault suite uses the existing synthetic entry/upload fixture and
independent V1 transfer vectors, sharing one framed programmer replay. Five new
tests cover the 90-checkpoint synthetic success path, persistence failure at
every checkpoint, cancellation at every outer event boundary, a lost final
write reply, failure of terminal saves, source-binding contradictions, native
JSONL output protection and sink poisoning. Remaining transcripts and sentinels
prove exactly which requests were consumed, including failures after the final
reply. Tests verify the last durable intent and acknowledgement counters.

These are protocol-composition tests using synthetic transfer regions in a
private test worker. Public callers must supply the image composer's opaque plan;
the existing image tests and local-file comparison cover that plan's derivation.
This is not an end-to-end real-package execution or hardware validation. The
phone remains outside this replay. Separate native adapters, discovery-only arrivals
and [artifact-bound read-only checks](spec-a-session.md) now exist. Native cross-mode
admission, recovery policy and the remaining boot-integrity stages still need
integration, with the owner's data-preservation preference retained.
