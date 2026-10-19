# Artifact-bound Spec A read-only session

The engine can now keep verified unlock inputs and fresh Normal/Flash identity
checks together in one in-memory context. The native CLI defaults to the Normal
part and can explicitly run the mode cycle described below. Neither route sends
a GPT query, programmer upload or storage write.
The joined unlock executor still accepts concrete replay transports only.

## Pinned source and prepared inputs

`EntryPlan` retains its headers and complete source digest from the same hashing
pass. Chunk verification now reads the hash table from those retained headers,
rather than trusting headers reread from a mutable source. GPT/first-payload checks
and the new `EntryPlan::reference` use a bounded reader that hashes each payload
chunk before returning its bytes. The reader caches one verified chunk, supports
bounded seeks and refuses changed or truncated payloads. Changing both a live file's
payload and hash table cannot replace the original pinned table. References retain
the full source digest privately; standalone metadata inspections remain unpinned.

`spec_a_session::Prepared` owns the entry plan, one loader and the image engine's
opaque programmer plan. Construction requires all of the following:

- Entry, reference and package agree on the complete source digest and platform.
- The reference came from that entry's pinned reader after full source verification.
- The package's full original SBL1 digest matches the pinned source SBL1.
- The loader root fingerprint matches that SBL1 reference.
- The source platform matches the initial RM-875 profile, and the saved capacity
  fits the Flash protocol's sector-count field.

The image plan exposes its full original SBL1 digest independently of the shortened
prepared transfer. Six artifact digests bind the context: source FFU, reference ZIP,
saved primary GPT, candidate primary GPT, loader import and decoded loader. The
actual prepared bytes stay owned and immutable. Input paths and JSON reports cannot
recreate this object or authorize a hardware operation. Pinning and certificate
fingerprint equality establish integrity/correlation, not OEM trust or acceptance.

## Device checks

`capture_normal` reads a public ID, manufacturer model, product code, firmware and
a final public ID, with distinct increasing JSON-RPC IDs. A changed public ID,
malformed reply or mismatched model/product/firmware stops immediately. This first
profile is RM-875 / product `059T909` / firmware `3051.50009.1451.1003`; another
variant or firmware requires a separately reviewed profile.

The resulting `NormalSession` privately borrows the prepared context and retains
the public ID. It has no serialization, cloning or import API. Its consuming
`check_flash` operation uses the existing bound preflight: current application and
platform, Normal/Flash public-ID equality, source RRKH, security consistency and
application/ID bookends. A guard rejects missing Spec A protocol/security/capacity
evidence at NOKV before later queries. Capacity must match the saved layout. It
never switches contexts, reads GPT, retries, uploads or writes. Consumption on
failure prevents reusing that baseline for an automatic retry.

The core transport interface supports tests and read-only protocol callers; it
does not prove hardware access, physical-port binding or elapsed-time freshness.
The optional native cycle now connects these checks across modes. It does not
connect them to a write executor or establish a completed physical unlock.

## Native Normal-only command

```sh
wpi check-spec-a-session source.ffu reference.zip saved-primary.bin loader.hex \
  --device-id '<selected-normal-usb-id>' --disk-sectors '<saved-capacity>' \
  --expect-source-sha256 '<source-sha256>' \
  --expect-package-sha256 '<package-sha256>' \
  --expect-primary-sha256 '<saved-primary-sha256>' \
  --expect-loader-sha256 '<loader-import-sha256>'
```

The CLI completes all local preparation before opening the phone. It uses seekable
regular files, bounded loader/GPT reads, streaming source/package verification and
cancellation callbacks. It does not make a full firmware copy. Inputs are pinned
explicitly; a saved report is never accepted in place of verifying the files.

The native phone-operation lock covers the Normal check. The adapter requires the
selected `0421:0661` Normal interface, serial metadata and physical-port binding.
Fresh discovery must retain exactly that descriptor snapshot and one device on
that port before every query and after completion. Its private guard permits only
the five ordered read-only requests, permanently retires on binding/transport
failure and rejects resets, GPT, firmware commands and repeated/out-of-order IDs.
One 30-second session deadline caps the USB transaction deadlines; OS discovery
is not a hard wall-clock-bounded operation. Failure sends no recovery command.

The result exports six artifact digests and check booleans, never a public ID,
USB serial, physical-port value or payload. Normal success leaves fresh Flash
checks pending. Fresh installed GPT, installed originals, OEM/applicability trust,
data preservation, physical recovery and later boot-integrity stages remain
unestablished. All reports retain phone writes disabled, hardware validation false
and automatic resume disabled. Successful checks are not an unlock grant.

## Validation

### Optional artifact-bound native cycle

After verifying the same four local inputs, append the following options to
`check-spec-a-session` to run one CLI-only Windows ARM64 experiment:

```text
--roundtrip --confirm RM875-PREPARED-READONLY-ROUNDTRIP --journal NEW-cycle.jsonl
```

The native phone-operation lock spans the entire cycle. The existing public-ID
mode harness sends the Normal-to-Flash request once and returns with one NOKR
only after its checks pass. It observes a returning BootManager without querying
that retired interface again or adding a recovery reset. Timeouts, cancellation,
identity mismatches and journal failures stop without automatic recovery.

The prepared context now retains its pinned reference. A nonserializable Normal
session is consumed into a Flash session after six fixed, ordered read-only
queries. Every query has fresh descriptor/physical-port checks, a shared deadline
and a strict allowlist. Unknown records on the same physical port also block the
check. The context/source root, protocol, capacity and original public ID must
agree. Returning Normal performs all five queries again and consumes the Flash
session only if the original public ID and the exact prepared context agree.

The CLI synchronizes a new JSONL journal before any mode command and at each
mode-harness event. Reports are redacted and keep storage writes, hardware unlock
validation and automatic resume false. No saved report or journal reconstructs a
session. One [Windows ARM64 hardware cycle](../tests/hardware/lumia-1020-rm875-prepared-cycle.json)
now passed: two mode commands, correlated identity in both modes and on return,
source-root/security/capacity checks, and confirmed Normal USB. The measured
cycle was 57,503 ms, excluding local input preparation. This does not validate
entry, uploads, storage writes or unlock. A failure can require manual restart.
Keep browser phone controls idle during an explicitly selected native cycle.

The [entry preservation audit](spec-a-entry-preservation.md) now models the
begin/end zero chunks against the same prepared layout. Its separately labeled
conservative Data-tail intersection is not an observed write or damage. The
audit is included in Normal-only reports and subsequent cycle headers; it was
added after the recorded cycle and changes no phone request.

### Earlier Normal-only evidence

New tests cover retained headers, verified chunk caching, rewritten live hash
tables, changed/truncated payloads, bounds, source/reference/SBL1 coherence, identity/
root/profile/capacity changes, every query fault/cancellation boundary and the native
request allowlist. The Normal/Flash tests use synthetic private contexts and concrete
replays; they do not execute an actual package or a physical transition. The public
bundle constructor is exercised separately by the local-file/native Normal check.
The image tests also compare the new original-SBL1 digest with source FFU bytes.

On Windows ARM64, adding the command initially exposed a CLI startup stack overflow
before any phone access. Boxed arguments and a separate handler resolved it without
raising stack limits. A subprocess regression test exercises root/session help and
missing required arguments using the process's default stack.

Core/image/protocol/transport tests, the CLI startup test, strict all-target Clippy,
formatting and WASM compilation are covered for this change. The
[sanitized native check record](../tests/hardware/lumia-1020-rm875-session-check.json)
states the exact local-file and device-check scope; no Flash transition, entry,
upload or storage write is part of that check. UI tests were not rerun.
