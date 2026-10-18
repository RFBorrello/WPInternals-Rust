//! Private local correlation metadata. Never a serialized execution grant.
use super::{
    identity,
    mode_test::{physical_port, PhysicalPort},
};
use nusb::MaybeFuture;
use wpi_types::{DeviceIdentity, DeviceMode};

#[derive(Clone, PartialEq)]
pub(super) struct Snapshot {
    pub(super) descriptor: DeviceIdentity,
    pub(super) port: Option<PhysicalPort>,
}
impl Snapshot {
    pub(super) fn of(info: &nusb::DeviceInfo) -> Self {
        Self {
            descriptor: identity(
                info,
                wpi_core::classify_usb(info.vendor_id(), info.product_id())
                    .unwrap_or(DeviceMode::Unknown),
            ),
            port: physical_port(info),
        }
    }
}
pub(super) fn scan() -> Result<Vec<Snapshot>, String> {
    Ok(nusb::list_devices()
        .wait()
        .map_err(|_| "USB discovery failed")?
        .map(|d| Snapshot::of(&d))
        .collect())
}
pub(super) fn selected(id: &str) -> Result<Snapshot, String> {
    let matches: Vec<_> = scan()?
        .into_iter()
        .filter(|s| s.descriptor.id == id)
        .collect();
    if matches.len() != 1 {
        return Err("Scan and explicitly select one connected recognized USB endpoint".into());
    }
    let snapshot = matches.into_iter().next().unwrap();
    if snapshot.descriptor.mode == DeviceMode::Unknown {
        return Err("Unrecognized USB endpoint".into());
    }
    if snapshot.port.is_none() {
        return Err("Physical USB port binding is unavailable".into());
    }
    Ok(snapshot)
}
