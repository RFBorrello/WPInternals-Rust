//! Narrow, read-only GPT capture during the observed RM-875 BootManager stage.
//! No context switch, timer hold, public-ID query, reset or write request.
use serde::Serialize;
use std::io::Cursor;
#[cfg(not(target_arch = "wasm32"))]
use wpi_image::ImageError;
use wpi_image::{gpt::Gpt, stream};
use wpi_protocol::{flash::FlashInfo, preflight, MessageTransport, ProtocolError};
use wpi_types::DeviceMode;

pub struct Capture {
    bytes: Vec<u8>,
    sectors: u32,
    sha256: String,
    partition_count: usize,
}
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub bytes: usize,
    pub sha256: String,
    pub flash_capacity_sectors: u32,
    pub partition_count: usize,
    pub reference_primary_identical: bool,
    pub primary_gpt_preserved: bool,
    pub backup_gpt_captured: bool,
    pub installed_partitions_preserved: bool,
    pub phone_writes_enabled: bool,
}
fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::Invalid(message.into())
}
pub fn validate_info(info: &FlashInfo) -> wpi_protocol::Result<()> {
    if info.mode != DeviceMode::BootManager
        || (info.protocol_major, info.protocol_minor) != (1, 1)
        || (info.version_major, info.version_minor) != (1, 16)
        || info.transfer_size != Some(2363392)
        || info.platform_id.is_some()
        || info.secure_ffu.is_some()
        || info.secure_boot.is_some()
    {
        return Err(invalid(
            "Unreviewed BootManager profile; no GPT query permitted",
        ));
    }
    Ok(())
}
fn read_info<T: MessageTransport>(t: &mut T) -> wpi_protocol::Result<FlashInfo> {
    let (info, security) = preflight::parse_application(&t.exchange(b"NOKV", 65536)?)?;
    validate_info(&info)?;
    if security.is_some() {
        return Err(invalid("Unexpected BootManager security block"));
    }
    Ok(info)
}
fn parse(bytes: &[u8], sectors: u32) -> wpi_protocol::Result<Gpt> {
    if bytes.len() != preflight::PRIMARY_SIZE || sectors <= 34 {
        return Err(invalid("Invalid primary GPT or fresh Flash capacity"));
    }
    let le32 = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let le64 = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    if le32(524) != 92 || le64(536) != 1 || le64(584) != 2 || le32(592) != 128 || le32(596) != 128 {
        return Err(invalid(
            "Expected a 34-sector primary GPT with 128 entries at LBA 2",
        ));
    }
    let g = Gpt::from_parts(
        &bytes[512..1024],
        &bytes[1024..],
        Some(u64::from(sectors) * 512),
    )
    .map_err(|e| invalid(e.to_string()))?;
    if g.first_usable_sector < 34
        || g.backup_lba != u64::from(sectors) - 1
        || g.last_usable_sector
            .checked_add(33)
            .is_none_or(|last| last > g.backup_lba)
    {
        return Err(invalid(
            "Primary GPT geometry contradicts the fresh Flash capacity",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    if g.partitions.is_empty()
        || g.disk_guid.is_nil()
        || g.partitions.iter().any(|p| {
            p.name.is_empty()
                || !names.insert(p.name.to_ascii_uppercase())
                || p.guid.is_nil()
                || !ids.insert(p.guid)
        })
    {
        return Err(invalid("Empty or ambiguous GPT partition identities"));
    }
    Ok(g)
}
/// The adapter must bind the physical port and source identity, supply capacity
/// from THIS cycle's validated Flash session, and verify returning Normal before
/// publishing. Missing the BootManager window is a failure, never a retry trigger.
pub fn read<T: MessageTransport, F: FnMut(&str) -> bool>(
    t: &mut T,
    sectors: u32,
    mut progress: F,
) -> wpi_protocol::Result<Capture> {
    let mut boundary = |stage| {
        if progress(stage) {
            Ok(())
        } else {
            Err(invalid(
                "BootManager GPT capture cancelled before next query",
            ))
        }
    };
    if sectors <= 34 {
        return Err(invalid("Fresh Flash capacity is missing or invalid"));
    }
    boundary("Verify BootManager")?;
    let first = read_info(t)?;
    boundary("Read primary GPT")?;
    let bytes = preflight::parse_primary_gpt(&t.exchange(b"NOKT", 8 + preflight::PRIMARY_SIZE)?)?;
    let gpt = parse(&bytes, sectors)?;
    boundary("Confirm primary GPT consistency")?;
    let second = preflight::parse_primary_gpt(&t.exchange(b"NOKT", 8 + preflight::PRIMARY_SIZE)?)?;
    if bytes != second {
        return Err(invalid("Primary GPT changed between the two reads"));
    }
    boundary("Recheck BootManager")?;
    let last = read_info(t)?;
    if serde_json::to_value(&first).unwrap() != serde_json::to_value(&last).unwrap() {
        return Err(invalid(
            "BootManager application changed during GPT capture",
        ));
    }
    boundary("Finish primary GPT capture")?;
    let sha256 = stream::sha256(&mut Cursor::new(&bytes)).map_err(|e| invalid(e.to_string()))?;
    Ok(Capture {
        bytes,
        sectors,
        sha256,
        partition_count: gpt.partitions.len(),
    })
}
impl Capture {
    /// Local integrity result only. The caller supplies Normal identity/port
    /// verification; this object carries no phone execution authority.
    pub fn report(&self, reference_sha256: &str) -> Report {
        Report {
            bytes: self.bytes.len(),
            sha256: self.sha256.clone(),
            flash_capacity_sectors: self.sectors,
            partition_count: self.partition_count,
            reference_primary_identical: self.sha256 == reference_sha256,
            primary_gpt_preserved: false,
            backup_gpt_captured: false,
            installed_partitions_preserved: false,
            phone_writes_enabled: false,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save(
        self,
        output: &std::path::Path,
        reference_sha256: &str,
    ) -> wpi_image::Result<Report> {
        use std::io::{Seek, SeekFrom, Write};
        let mut report = self.report(reference_sha256);
        crate::artifacts::write_new(output, |writer| {
            writer.write_all(&self.bytes)?;
            writer.flush()?;
            writer.seek(SeekFrom::Start(0))?;
            if stream::sha256(writer)? != self.sha256 {
                return Err(ImageError::Invalid(
                    "Saved primary GPT digest mismatch".into(),
                ));
            }
            Ok(())
        })?;
        report.primary_gpt_preserved = true;
        Ok(report)
    }
}
#[cfg(not(target_arch = "wasm32"))]
pub fn check_destination(output: &std::path::Path) -> wpi_image::Result<()> {
    if output.file_name().is_none() || output.exists() {
        return Err(ImageError::Invalid("Choose a new primary GPT file".into()));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.as_file().sync_all()?;
    temporary.close()?;
    Ok(())
}
