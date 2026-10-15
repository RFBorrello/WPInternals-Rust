use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use wpi_image::{ffu::FfuMetadata, filesystem::FilesystemInfo, gpt::Gpt, ImageError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inspection {
    pub format: String,
    pub size: u64,
    pub ffu: Option<FfuMetadata>,
    pub gpt: Option<Gpt>,
    pub filesystem: Option<FilesystemInfo>,
    pub notes: Vec<String>,
    #[serde(default)]
    pub catalog: Option<wpi_image::catalog::CatalogReport>,
    #[serde(default)]
    pub firmware_version: Option<String>,
    #[serde(default)]
    pub firmware_version_error: Option<String>,
}
pub fn inspect<R: Read + Seek>(reader: &mut R) -> wpi_image::Result<Inspection> {
    let size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    let mut prefix = [0u8; 16];
    reader.read_exact(&mut prefix)?;
    let mut report = Inspection {
        format: String::new(),
        size,
        ffu: None,
        gpt: None,
        filesystem: None,
        notes: vec![],
        catalog: None,
        firmware_version: None,
        firmware_version_error: None,
    };
    if &prefix[4..16] == b"SignedImage " {
        let ffu = FfuMetadata::read_headers(reader, size)?;
        let gpt = ffu.gpt(reader)?;
        report.catalog = Some(
            wpi_image::catalog::inspect(reader, &ffu)
                .unwrap_or_else(wpi_image::catalog::unavailable),
        );
        match wpi_image::firmware::read_version(reader, &ffu, &gpt, |_, _| true) {
            Ok(version) => report.firmware_version = version,
            Err(e) => report.firmware_version_error = Some(e.to_string()),
        }
        report.format = "FFU".into();
        report.ffu = Some(ffu);
        report.gpt = Some(gpt);
        report.notes.push(
            "Structure and GPT CRCs checked. Signer trust and phone acceptance remain unverified."
                .into(),
        );
        report.notes.push("Only legacy single-store FFUs are supported. End-relative writes are retained as metadata, not reconstructed into an assumed disk.".into());
    } else {
        reader.seek(SeekFrom::Start(0))?;
        let mut boot = vec![0; 512];
        reader.read_exact(&mut boot)?;
        if boot.starts_with(b"EFI PART") {
            report.format = "GPT".into();
            report.gpt = Some(Gpt::read(reader, size)?);
        } else {
            let mut signature = [0u8; 8];
            reader.seek(SeekFrom::Start(512))?;
            if reader.read_exact(&mut signature).is_ok() && &signature == b"EFI PART" {
                report.format = "GPT / raw disk image".into();
                report.gpt = Some(Gpt::read(reader, size)?);
            } else {
                let fs = wpi_image::filesystem::inspect_boot_sector(&boot)?;
                if fs
                    .total_sectors
                    .checked_mul(fs.bytes_per_sector as u64)
                    .is_none()
                {
                    return Err(ImageError::Invalid("volume geometry overflow".into()));
                }
                report.format = fs.kind.clone();
                report.filesystem = Some(fs);
            }
        }
    }
    Ok(report)
}
