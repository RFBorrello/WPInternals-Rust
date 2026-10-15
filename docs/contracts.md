# Shared contracts

Rust types in `wpi-types` are the source of truth. They serialize enum values as
snake_case and expose device identity, capabilities, operation previews, and
monotonic progress events. The React adapter mirrors these types in `src/types.ts`.

GPT partition `attributes` is serialized as a decimal **string** because firmware
can set bit 63, which cannot round-trip through a JavaScript JSON number. Native
Rust retains `u64`. Browser byte/sector calculations reject values outside exact
JavaScript integer range instead of silently rounding them.

An OperationPlan is a preview, not authorization. Starting an operation recomputes
the capability gate and validates its inputs. All phone writes remain blocked.
Local file jobs reserve the coordinator before preflight; temporary output files
are published only on success, without overwriting existing native artifacts.

USB VID/PID implies a possible mode only. Model/family information is assigned
only after a device-provided variant is matched to the research catalog. Hardware
verification status remains independent of that match.

RecoveryPreparation wraps a blocked stock-flash plan plus per-check statuses
(`passed`, `failed`, `missing`, `unverified`). Native preparation reads and verifies
the complete local FFU; browser preparation now verifies every SHA-256 chunk and
the full-file fingerprint as well. Metadata-only inspection alone does not supply
that evidence. Browser streaming sessions accept sequential blocks up to 1 MiB;
only a complete, consistent session can produce an artifact identity and chunk
result. `plan.artifacts[].sha256` records the full selected file's digest even if
payload chunks fail. Progress counts actual file bytes, and incomplete/cancelled
sessions cannot publish a checklist. The shared report schema is unchanged.
Authenticity, applicable hardware profiles, backup access and execution stay
blocked independently. Exports redact USB serial and host instance identifiers.
Changing a report cannot bypass the operation coordinator's execution gate.

Inspection adds optional catalog, firmware_version and firmware_version_error
evidence, plus a default-empty firmware_version_sources array naming the observed
partition/file/key locations. PLAT is preferred; a missing PLAT version permits
the corroborated MainOS Nokia package fallback. Metadata errors suppress version
comparison. Old exports without source fields still deserialize.
CatalogReport (wpi-image) has separate signature, hash_table_binding and
signer_trust checks, with valid/invalid/unsupported/missing/unverified states.
RecoveryPreparation maps those to its existing preparation statuses; no new
execution permission is inferred. The browser and native engine use the same
verifier. PLAT-version absence is distinct from a malformed/contradictory value.

ReplayBlockSource is a concrete simulated read-only disk with bounded fixtures.
The backup engine cannot accept native USB or raw block devices. Successful replay
backups produce a `replay_only` manifest and atomically publish a new local image;
interruptions discard temporary outputs and never retry uncertain transfers.

ModeTransitionPreparation wraps a blocked `switch_mode` plan with source/target,
the reviewed route and whether removal is required. Previews redact USB serials
and instance IDs. ReconnectReport has `correlated`, `mismatch` or `unverified`
status and per-field checks, with `recovery_authorized=false` in every case.
Reports do not contain serial values. Matching USB serials only correlates
unauthenticated descriptors. Missing mode-specific fields remain unverified.

Mode replay observations have monotonic elapsed milliseconds and bounded
read-only exchanges. A returning application mode comes from NOKV or normal
JSON-RPC, not from a remembered identity or a USB PID. Permission renewal does
not restart the deadline. `awaiting_reconnect` can emit progress in the same state;
after uncertain command delivery, interruption requires inspection and never retry.

The native hardware experiment has a separate redacted ModeTestPreview and JSONL
ModeTestEvent journal. It cannot consume a caller-supplied preview or OperationPlan
to authorize execution: the selected phone is read again and a fixed, narrow
admission policy is applied. Explicit CLI confirmation permits only the reviewed
mode sequence; it does not grant a capability to firmware-writing orchestration.
The known RM-875 admission profile is now blocked before any mode command after
the first failed cross-mode correlation. Confirmation cannot bypass this blocker.

IdentityProbeReport is a separate CLI-only read-only research report. It contains
public-ID presence, serial/port availability and final FVER-query diagnostics,
not identifier values or cross-mode equality. The local typed PublicId is neither
serializable nor part of DeviceIdentity; Debug is redacted. The presence report
keeps identity_authenticated, mode_change_sent and recovery_authorized false.

The separate public-ID mode experiment holds nonserializable snapshots in memory.
ModeTestEvent.identity_observation records public-ID equality, Normal serial equality
and physical-port checks alongside redacted fresh metadata. Native commands re-read
their own USB handle and enforce the exact profile; caller-provided reports cannot
authorize execution. Results keep identity_authenticated and recovery_authorized
false. General ReconnectReport semantics remain unchanged.
During the return wait only, ModeTestEvent.boot_observation records a fresh
BootManager NOKV result as public_id_verified=false. It cannot become a Snapshot
or authorize a terminal/context/reset request. Final Normal identity still requires
the original public ID, serial, firmware and variant; observing a boot stage never
completes the operation.
An intermediate return interface is queried once, then retired locally. Reusing
its identifier cannot permit another query without a fresh removal or a Normal
USB descriptor; native binding and the final public-ID check still apply.
Retired return waits use native hotplug generations plus a two-second discovery
fallback for missing notifications. Unrelated events or the timer cannot unretire the
same boot generation. Readiness before a protocol request can retry without a new
event. The public-ID preview exposes separate 30-second Flash and 90-second Normal
limits; CLI journal events/outcomes include monotonic elapsed_ms without identity values.
ReconnectDiscovery events record the trigger, enumeration_ms, observed_modes and
source_removal_observed. ReconnectProbe events record observed_mode and readiness
(attempting_read_only_probe or interface_not_ready_no_query_sent). These events
carry no instance IDs or serials and cannot authorize commands. The Normal limit
is an observation bound, not a measured boot time.
