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
    /// Private Windows PnP ancestry, ordered from the disk's immediate parent.
    #[serde(default)]
    pub ancestors: Vec<String>,
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
    let mut b = identity_blockers(d);
    if !d.offline {
        b.push("Disk must already be offline; this app does not offline or unmount it".into());
    }
    if !d.read_only {
        b.push("Disk must already be read-only; this app does not set disk attributes".into());
    }
    b
}
fn identity_blockers(d: &InventoryDisk) -> Vec<String> {
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

/// Exact, bounded ancestry matching. A disk label, USB VID/PID, serial substring,
/// or a common hub is never sufficient to bind a raw disk to a selected phone.
pub fn bound_candidate<'a>(
    disks: &'a [InventoryDisk],
    usb_instance: &str,
    capacity: u64,
) -> Result<&'a InventoryDisk, &'static str> {
    let disk = bound_metadata(disks, usb_instance, capacity)?
        .ok_or("No admitted raw disk belongs to the selected USB device")?;
    if !disk.offline || !disk.read_only {
        return Err("USB-bound disk read-only/offline admission failed");
    }
    Ok(disk)
}

/// Discovery only: online/writable flags are reported, never raw-access grants.
/// All identity, geometry, host-disk and ancestry checks still apply.
pub fn bound_metadata<'a>(
    disks: &'a [InventoryDisk],
    usb_instance: &str,
    capacity: u64,
) -> Result<Option<&'a InventoryDisk>, &'static str> {
    let parts: Vec<_> = usb_instance.split('\\').collect();
    if parts.len() != 3
        || !parts[0].eq_ignore_ascii_case("USB")
        || !parts[1].to_ascii_uppercase().starts_with("VID_")
        || !parts[1].to_ascii_uppercase().contains("&PID_")
        || parts[2].is_empty()
        || usb_instance.len() > 1024
        || !usb_instance.bytes().all(|b| (0x20..=0x7e).contains(&b))
        || capacity == 0
        || capacity > u64::from(u32::MAX)
    {
        return Err("A complete USB device instance and bounded capacity are required");
    }
    let mut selected = None;
    for disk in disks {
        if disk.ancestors.len() > 16
            || disk
                .ancestors
                .iter()
                .any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err("Invalid or oversized disk ancestry");
        }
        let mut seen = std::collections::BTreeSet::new();
        if disk
            .ancestors
            .iter()
            .any(|s| !seen.insert(s.to_ascii_uppercase()))
        {
            return Err("Cyclic or duplicate disk ancestry");
        }
        if disk
            .ancestors
            .iter()
            .any(|s| s.eq_ignore_ascii_case(usb_instance))
        {
            if selected.is_some() {
                return Err("Multiple disks belong to the selected USB device");
            }
            if !identity_blockers(disk).is_empty()
                || disk.size.parse::<u64>().ok() != Some(capacity * 512)
            {
                return Err("USB-bound disk identity or geometry admission failed");
            }
            selected = Some(disk);
        }
    }
    Ok(selected)
}
