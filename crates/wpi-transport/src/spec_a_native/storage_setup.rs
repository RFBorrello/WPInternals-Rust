//! Manual host-disk state window. Inventory only; no raw handle or mutation.
use super::{boundary, driver_setup, validate, Journal};
use crate::device_binding::Snapshot;
use std::{
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub(super) fn wait<F: FnMut(&str)>(
    storage: &Snapshot,
    instance: &str,
    capacity: u64,
    sink: &mut Journal,
    cancelled: &AtomicBool,
    progress: &mut F,
) -> Result<(), String> {
    boundary(cancelled)?;
    validate(storage)?;
    let started = Instant::now();
    sink.append("awaiting_storage_setup", "Wait for the exact USB-bound disk to be offline/read-only; no attributes changed by controller", None)?;
    progress("Mass-storage checkpoint: up to 10 minutes. No raw disk is open. Leave USB connected. Only the exact bound phone disk can satisfy readiness; no attribute change is automatic.");
    let mut selected: Option<wpi_storage::BoundDiskState> = None;
    driver_setup::poll(
        cancelled,
        || started.elapsed(),
        || {
            validate(storage)?;
            let current = wpi_storage::bound_disk_state(instance, capacity).map_err(super::text)?;
            validate(storage)?;
            let Some(current) = current else {
                if selected.is_some() {
                    return Err("Bound phone disk disappeared after selection; inspect state before further action".into());
                }
                return Ok(false);
            };
            if let Some(previous) = &selected {
                if !previous.same_device(&current) {
                    return Err(
                        "Bound phone disk identity or ancestry changed during manual setup".into(),
                    );
                }
            } else {
                progress(&format!("Private local target: disk {}. If it is not already offline/read-only, run the following reviewed helper in a separate Administrator PowerShell from this repository. It only sets those two host flags. Keep these identifiers private.", current.disk_number()));
                progress(&current.setup_command(instance));
                selected = Some(current.clone());
            }
            Ok(current.ready())
        },
        || std::thread::sleep(Duration::from_millis(250)),
    )?;
    boundary(cancelled)?;
    validate(storage)?;
    sink.append("verified", "Bound phone disk metadata offline/read-only; exclusive raw admission and GPT verification still required", None)
}
