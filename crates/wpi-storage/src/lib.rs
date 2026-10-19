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
