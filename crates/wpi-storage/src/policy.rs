//! Conservative research admission. USB labels do not authenticate a phone.
use crate::StorageCandidate;
use serde::Deserialize;
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct InventoryDisk {
    pub number: u32,
    pub model: String,
    pub pnp_id: String,
    pub serial: String,
    pub size: String,
    pub sector_size: u32,
    pub bus_type: u32,
    pub offline: bool,
    pub read_only: bool,
    pub boot: bool,
    pub system: bool,
}
impl std::fmt::Debug for InventoryDisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InventoryDisk { identity: [redacted] }")
    }
}
pub fn phone_pnp(id: &str) -> bool {
    let upper = id.to_ascii_uppercase();
    let mut parts = upper.split('\\');
    let Some(bus) = parts.next() else {
        return false;
    };
    let Some(device) = parts.next() else {
        return false;
    };
    if !matches!(bus, "USBSTOR" | "SCSI") || parts.next().is_none() {
        return false;
    }
    let tokens: Vec<_> = device.split('&').collect();
    tokens.first() == Some(&"DISK")
        && (tokens.contains(&"VEN_QUALCOMM") && tokens.contains(&"PROD_MMC_STORAGE")
            || tokens.contains(&"VEN_MSFT") && tokens.contains(&"PROD_PHONE_MMC_STOR"))
}
pub fn blockers(d: &InventoryDisk) -> Vec<String> {
    let mut b = Vec::new();
    if !phone_pnp(&d.pnp_id) {
        b.push("Storage identity is not a recognized phone-storage candidate".into());
    }
    if d.bus_type != 7 {
        b.push("Disk must report USB storage transport".into());
    }
    if d.boot || d.system {
        b.push("Host boot/system disks cannot be opened".into());
    }
    if !d.offline {
        b.push("Disk must already be offline; this app does not offline or unmount it".into());
    }
    if !d.read_only {
        b.push("Disk must already be read-only; this app does not set disk attributes".into());
    }
    if d.sector_size != 512 {
        b.push("Only 512-byte logical sectors are supported by this Lumia GPT profile".into());
    }
    if d.size.parse::<u64>().ok().is_none_or(|n| {
        !(1024 * 1024 * 1024..=256 * 1024 * 1024 * 1024).contains(&n) || n % 512 != 0
    }) {
        b.push("Phone-storage capacity is outside the research profile".into());
    }
    if d.serial.trim().is_empty()
        || d.pnp_id.len() > 1024
        || d.serial.len() > 256
        || d.model.len() > 256
    {
        b.push("Storage identity is missing or exceeds bounded lengths".into());
    }
    b
}
pub fn candidate(d: &InventoryDisk) -> StorageCandidate {
    StorageCandidate {
        disk_number: d.number,
        model: d.model.clone(),
        size: d.size.parse().unwrap_or(0),
        sector_size: d.sector_size,
        offline: d.offline,
        read_only: d.read_only,
        blockers: blockers(d),
    }
}
