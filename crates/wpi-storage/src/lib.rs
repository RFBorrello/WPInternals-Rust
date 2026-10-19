//! Research-only native read-only mass-storage access. No mode switching, disk
//! attributes, mount state, firmware or phone storage is written by this crate.
use serde::{Deserialize, Serialize};
use std::path::Path;
use wpi_image::{ImageError, Result};
pub mod layout;
pub mod policy;
#[cfg(windows)]
mod windows;
pub use layout::StorageInspection;

/// Query current process token only; never prompts, elevates or changes a disk.
pub fn raw_access_prerequisite() -> Result<()> {
    #[cfg(windows)]
    {
        windows::raw_access_prerequisite()
    }
    #[cfg(not(windows))]
    {
        Err(unsupported())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCandidate {
    pub disk_number: u32,
    pub model: String,
    pub size: u64,
    pub sector_size: u32,
    pub offline: bool,
    pub read_only: bool,
    pub blockers: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Discovery {
    pub host_supported: bool,
    pub hardware_validated: bool,
    pub candidates: Vec<StorageCandidate>,
    pub message: String,
}
pub fn discover() -> Result<Discovery> {
    #[cfg(windows)]
    {
        windows::discover()
    }
    #[cfg(not(windows))]
    {
        Ok(Discovery{host_supported:false,hardware_validated:false,candidates:vec![],message:"Native mass-storage adapter is currently implemented for Windows only; macOS/Linux adapters remain pending. No device state was changed.".into()})
    }
}
pub fn inspect(disk_number: u32) -> Result<StorageInspection> {
    #[cfg(windows)]
    {
        let mut disk = windows::Disk::open(disk_number)?;
        layout::inspect(&mut disk)
    }
    #[cfg(not(windows))]
    {
        let _ = disk_number;
        Err(unsupported())
    }
}

/// Process-local inventory snapshot for a manual disk-state checkpoint. Not
/// serializable, not constructible from disk numbers/reports, never raw access.
#[derive(Clone, Debug)]
pub struct BoundDiskState(policy::InventoryDisk);
impl BoundDiskState {
    pub fn ready(&self) -> bool {
        self.0.offline && self.0.read_only
    }
    pub fn same_device(&self, other: &Self) -> bool {
        let mut left = self.0.clone();
        let mut right = other.0.clone();
        left.offline = true;
        left.read_only = true;
        right.offline = true;
        right.read_only = true;
        left == right
    }
    /// Private local console instructions only; identifiers are hashed and must
    /// be checked against fresh inventory by the explicit operator helper.
    pub fn setup_command(&self, usb_instance: &str) -> String {
        use sha2::{Digest, Sha256};
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        format!("& .\\scripts\\prepare-bound-phone-disk.ps1 -UsbInstance {} -ExpectedPnpSha256 '{:x}' -ExpectedSerialSha256 '{:x}' -CapacityBytes {} -Apply",
            quote(usb_instance), Sha256::digest(self.0.pnp_id.as_bytes()),
            Sha256::digest(self.0.serial.as_bytes()), self.0.size)
    }
    pub fn disk_number(&self) -> u32 {
        self.0.number
    }
}
/// PnP/CIM inventory only. No raw handle, host attribute or phone write.
pub fn bound_disk_state(usb_instance: &str, capacity: u64) -> Result<Option<BoundDiskState>> {
    #[cfg(windows)]
    {
        Ok(windows::bound_metadata(usb_instance, capacity)?.map(BoundDiskState))
    }
    #[cfg(not(windows))]
    {
        let _ = (usb_instance, capacity);
        Err(unsupported())
    }
}

/// Read-only snapshot using a USB instance obtained from the active native
/// session. Raw disk numbers and imported JSON cannot select this capture's
/// source. Windows must already have the disk offline and read-only.
/// `primary` must be the controller's expected in-memory stage layout.
pub fn capture_spec_a_bound<F: FnMut(&str, u64, u64) -> bool>(
    usb_instance: &str,
    capacity: u64,
    primary: &[u8],
    after_nv: bool,
    output: &Path,
    progress: F,
) -> Result<wpi_image::spec_a::entry_snapshot::Report> {
    use sha2::{Digest, Sha256};
    let pin = hex::encode(Sha256::digest(primary));
    let plan = if after_nv {
        wpi_image::spec_a::entry_snapshot::Plan::after_nv(primary, capacity, &pin)?
    } else {
        wpi_image::spec_a::entry_snapshot::Plan::new(primary, capacity, &pin)?
    };
    #[cfg(windows)]
    {
        use wpi_core::backup::ReadOnlySource;
        let mut disk = windows::Disk::open_bound(usb_instance, capacity)?;
        let inspection = layout::inspect(&mut disk)?;
        disk.bind_layout(inspection.gpt_sha256);
        disk.validate()?;
        let mut actual = vec![0; 34 * 512];
        disk.read_at(0, &mut actual)?;
        if actual != primary {
            return Err(ImageError::Invalid(
                "USB-bound disk layout differs from the active stage".into(),
            ));
        }
        let mut report = None;
        wpi_core::artifacts::write_new(output, |writer| {
            report = Some(plan.capture(writer, |at, b| disk.read_at(at, b), progress)?);
            disk.validate()?;
            Ok(())
        })?;
        report.ok_or_else(|| ImageError::Invalid("Bound snapshot did not complete".into()))
    }
    #[cfg(not(windows))]
    {
        let _ = (usb_instance, plan, output, progress);
        Err(unsupported())
    }
}
/// Capture only boot, variable and disk-boundary regions from an ALREADY exposed
/// phone disk. No mode change or disk attribute change; never a write grant.
pub fn capture_spec_a_recovery<F: FnMut(&str, u64, u64) -> bool>(
    disk_number: u32,
    expected_gpt: &str,
    expected_primary: &str,
    output: &Path,
    progress: F,
) -> Result<wpi_image::spec_a::entry_snapshot::Report> {
    for pin in [expected_gpt, expected_primary] {
        if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ImageError::Invalid(
                "Complete storage and primary GPT SHA-256 pins are required before opening a disk"
                    .into(),
            ));
        }
    }
    #[cfg(windows)]
    {
        use wpi_core::backup::ReadOnlySource;
        let mut disk = windows::Disk::open(disk_number)?;
        let inspection = layout::inspect(&mut disk)?;
        if !inspection.gpt_sha256.eq_ignore_ascii_case(expected_gpt) {
            return Err(ImageError::Invalid(
                "Selected storage GPT differs from its pin".into(),
            ));
        }
        disk.bind_layout(inspection.gpt_sha256);
        disk.validate()?;
        let mut primary = vec![0; 34 * 512];
        disk.read_at(0, &mut primary)?;
        let plan = wpi_image::spec_a::entry_snapshot::Plan::new(
            &primary,
            disk.geometry().size / 512,
            expected_primary,
        )?;
        let mut report = None;
        wpi_core::artifacts::write_new(output, |writer| {
            report = Some(plan.capture(writer, |at, bytes| disk.read_at(at, bytes), progress)?);
            disk.validate()?;
            Ok(())
        })?;
        report.ok_or_else(|| ImageError::Invalid("Snapshot did not complete".into()))
    }
    #[cfg(not(windows))]
    {
        let _ = (disk_number, output, progress);
        Err(unsupported())
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageBackup {
    pub experimental: bool,
    pub hardware_validated: bool,
    pub device_identity_authenticated: bool,
    pub gpt_sha256: String,
    pub partition: Option<String>,
    pub image: wpi_core::backup::BackupManifest,
}
pub fn backup<F: FnMut(u64, u64) -> bool>(
    disk_number: u32,
    expected_gpt: &str,
    partition: Option<&str>,
    output: &Path,
    progress: F,
) -> Result<StorageBackup> {
    if expected_gpt.len() != 64 || !expected_gpt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ImageError::Invalid("A complete SHA-256 GPT fingerprint from storage inspection is required before opening a disk".into()));
    }
    #[cfg(windows)]
    {
        let mut disk = windows::Disk::open(disk_number)?;
        let inspection = layout::inspect(&mut disk)?;
        if inspection.gpt_sha256 != expected_gpt || expected_gpt.len() != 64 {
            return Err(ImageError::Invalid("Storage GPT fingerprint changed or was not inspected; stop and inspect the selected disk again".into()));
        }
        let (first, count) = layout::range(&inspection, partition)?;
        disk.bind_layout(inspection.gpt_sha256.clone());
        let image = wpi_core::backup::create(
            &mut disk,
            "native_windows_mass_storage",
            first,
            count,
            output,
            progress,
        )?;
        Ok(StorageBackup {
            experimental: true,
            hardware_validated: false,
            device_identity_authenticated: false,
            gpt_sha256: inspection.gpt_sha256,
            partition: partition.map(str::to_owned),
            image,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (disk_number, expected_gpt, partition, output, progress);
        Err(unsupported())
    }
}
#[cfg(not(windows))]
fn unsupported() -> ImageError {
    ImageError::Unsupported(
        "Native read-only storage access is currently Windows-only; no raw device was opened"
            .into(),
    )
}

#[cfg(test)]
mod bound_state_tests {
    use super::*;
    fn state() -> BoundDiskState {
        BoundDiskState(
            serde_json::from_value(serde_json::json!({
                "number":3,"model":"Synthetic phone",
                "pnp_id":"USBSTOR\\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE\\private-disk",
                "serial":"private-serial","size":"34359738368","sector_size":512,
                "bus_type":7,"offline":false,"read_only":false,"boot":false,"system":false,
                "ancestors":["USB\\VID_05C6&PID_9006\\private-usb"]
            }))
            .unwrap(),
        )
    }
    #[test]
    fn state_flags_can_change_but_disk_identity_cannot() {
        let a = state();
        let mut b = a.clone();
        assert!(!a.ready());
        b.0.offline = true;
        b.0.read_only = true;
        assert!(b.ready() && a.same_device(&b));
        for kind in 0..6 {
            let mut b = a.clone();
            match kind {
                0 => b.0.number += 1,
                1 => b.0.serial.push('X'),
                2 => b.0.pnp_id.push('X'),
                3 => b.0.ancestors.clear(),
                4 => b.0.size = "512".into(),
                _ => b.0.model.push('X'),
            }
            assert!(!a.same_device(&b));
        }
        assert!(!format!("{a:?}").contains("private"));
        let command = a.setup_command("USB\\VID_05C6&PID_9006\\operator's-device");
        assert!(command.contains("operator''s-device"));
        assert!(!command.contains("private-serial") && !command.contains("private-disk"));
    }
}
