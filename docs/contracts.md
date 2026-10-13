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
the complete local FFU; the browser reports unverified chunk/fingerprint checks.
Authenticity, applicable hardware profiles, backup access and execution stay
blocked independently. Exports redact USB serial and host instance identifiers.
Changing a report cannot bypass the operation coordinator's execution gate.

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
