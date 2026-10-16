//! CLI research adapter for an explicitly selected, already exposed FlashApp.
use super::{open_selected, PHONE_ACCESS};
use std::time::{Duration, Instant};
use wpi_core::spec_a_preflight::{Reference, Report};
use wpi_types::DeviceMode;

pub fn run<F: FnMut(&str) -> bool>(
    id: &str,
    reference: &Reference,
    read_primary: bool,
    progress: F,
) -> Result<Report, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    // Refuse Normal before opening or querying any interface. Never enter Flash
    // or BootManager as an implicit side effect of asking for preflight.
    let selected = super::enumerate()?
        .into_iter()
        .find(|d| d.id == id)
        .ok_or("Device disconnected; scan and explicitly select it again")?;
    if selected.mode != DeviceMode::Flash {
        return Err("Read-only Spec A preflight needs an already exposed Flash USB interface. This command does not switch phone modes.".into());
    }
    let (descriptor, mut transport) = open_selected(id)?;
    if descriptor != selected {
        return Err("Device descriptors changed before preflight; inspect device state".into());
    }
    transport.deadline = Some(Instant::now() + Duration::from_secs(30));
    let captured = wpi_protocol::preflight::capture(
        &mut transport,
        reference.root(),
        reference.platform(),
        read_primary,
        progress,
    )
    .map_err(|e| e.to_string())?;
    // No retries or recovery commands on removal or re-enumeration.
    if !super::enumerate()?.iter().any(|d| d == &selected) {
        return Err("Device descriptors changed or disappeared during preflight; discard this session and inspect state".into());
    }
    wpi_core::spec_a_preflight::assess(reference, captured, false).map_err(|e| e.to_string())
}
