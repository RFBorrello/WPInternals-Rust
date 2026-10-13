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
