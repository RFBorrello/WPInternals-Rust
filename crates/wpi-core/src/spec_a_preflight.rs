//! Advisory read-only device/reference comparison. No execution grants.
use serde::Serialize;
use std::io::{Cursor, Read, Seek};
use wpi_image::{ffu::FfuMetadata, gpt::Gpt, spec_a, stream};
use wpi_protocol::preflight::{Capture, GptReadStatus, RootKeyHash};
use wpi_types::{PreparationCheck, PreparationStatus};

pub struct Reference {
    platform: String,
    root: RootKeyHash,
    primary: Vec<u8>,
    summary: ReferenceSummary,
}
#[derive(Debug, Clone, Serialize)]
pub struct ReferenceSummary {
    pub platform: String,
    pub primary_gpt_sha256: String,
    pub sbl1_sha256: String,
    pub source_ffu_size: u64,
    pub full_ffu_integrity_checked: bool,
    pub oem_signer_trusted: bool,
}
impl Reference {
    /// Bounded reference metadata only. This does not replace full source FFU
    /// verification, authenticity/applicability checks or installed originals.
    pub fn read<R: Read + Seek>(source: &mut R) -> wpi_image::Result<Self> {
        let ffu = FfuMetadata::open(source)?;
        if ffu.total_size > 16 * 1024 * 1024 * 1024 {
            return Err(wpi_image::ImageError::Invalid(
                "preflight source exceeds 16 GiB".into(),
            ));
        }
        if ffu.platform_id.is_empty() || !ffu.platform_id.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(wpi_image::ImageError::Invalid(
                "preflight source platform is empty or invalid".into(),
            ));
        }
        let primary = ffu.read_disk(source, 0, spec_a::layout::PRIMARY_SIZE)?;
        let layout = spec_a::layout::prepare(&primary, false)?;
        let sbl1 = layout
            .original
            .partitions
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("SBL1"))
            .unwrap();
        let (start, size) = sbl1.byte_range()?;
        if size > spec_a::MAX_BOOT_IMAGE as u64 {
            return Err(wpi_image::ImageError::Invalid(
                "source SBL1 exceeds limit".into(),
            ));
        }
        let bytes = ffu.read_disk(source, start, size as usize)?;
        let image = spec_a::parse(&bytes, 0x2800)?;
        let mut root = [0; 32];
        for (target, pair) in root
            .iter_mut()
            .zip(image.root_certificate_sha256.as_bytes().as_chunks::<2>().0)
        {
            *target = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        let root =
            RootKeyHash::parse(&root).map_err(|e| wpi_image::ImageError::Invalid(e.to_string()))?;
        let summary = ReferenceSummary {
            platform: ffu.platform_id.clone(),
            primary_gpt_sha256: stream::sha256(&mut Cursor::new(&primary))?,
            sbl1_sha256: stream::sha256(&mut Cursor::new(bytes))?,
            source_ffu_size: ffu.total_size,
            full_ffu_integrity_checked: false,
            oem_signer_trusted: false,
        };
        Ok(Self {
            platform: ffu.platform_id,
            root,
            primary,
            summary,
        })
    }
    pub fn platform(&self) -> &str {
        &self.platform
    }
    pub fn root(&self) -> &RootKeyHash {
        &self.root
    }
    pub fn summary(&self) -> &ReferenceSummary {
        &self.summary
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub source_kind: String,
    pub reference: ReferenceSummary,
    pub flash: wpi_protocol::flash::FlashInfo,
    pub application_security: Option<wpi_protocol::preflight::ApplicationSecurity>,
    pub security: wpi_protocol::preflight::SecurityStatus,
    pub gpt_read_status: GptReadStatus,
    pub observed_primary_sha256: Option<String>,
    pub observed_partition_count: Option<usize>,
    pub checks: Vec<PreparationCheck>,
    pub public_id_bytes_exported: bool,
    pub identity_authenticated: bool,
    pub normal_session_correlated: bool,
    pub mode_changes_sent: bool,
    pub installed_originals_preserved: bool,
    pub backup_gpt_captured: bool,
    pub recovery_authorized: bool,
    pub phone_writes_enabled: bool,
}
fn geometry(g: &Gpt) -> (u64, u64, u64, u64, u32, u32) {
    (
        g.current_lba,
        g.backup_lba,
        g.first_usable_sector,
        g.last_usable_sector,
        g.entry_count,
        g.entry_size,
    )
}

/// The report is advisory, including when all observed comparisons pass.
/// `replay` labels synthetic/imported responses rather than hardware evidence.
pub fn assess(reference: &Reference, capture: Capture, replay: bool) -> wpi_image::Result<Report> {
    use PreparationStatus::*;
    if !capture.matches_reference(reference.root(), reference.platform()) {
        return Err(wpi_image::ImageError::Invalid(
            "capture belongs to a different reference".into(),
        ));
    }
    let capture = capture.into_observation();
    let mut checks = vec![
        PreparationCheck { key: "root_key".into(), label: "Source / device root fingerprint".into(), status: Passed, message: "RRKH matches the last source SBL1 DER certificate fingerprint. This does not authenticate the certificate, programmer or firmware.".into() },
        PreparationCheck { key: "identity_bookends".into(), label: "Single-session identity correlation".into(), status: Passed, message: "The same local public ID answered before and after the read-only queries. No ID bytes are exported; correlation to Normal mode and authenticated identity remain unestablished.".into() },
    ];
    let mut observed_primary_sha256 = None;
    let mut observed_partition_count = None;
    let (status, message) = if let Some(bytes) = &capture.primary_gpt {
        let layout = spec_a::layout::prepare(bytes, false)?;
        if let Some(sectors) = capture.info.emmc_sectors {
            Gpt::from_parts(
                &bytes[512..1024],
                &bytes[1024..],
                Some(u64::from(sectors) * 512),
            )?;
        }
        let original = spec_a::layout::prepare(&reference.primary, false)?.original;
        let observed = layout.original;
        observed_partition_count = Some(observed.partitions.len());
        observed_primary_sha256 = Some(stream::sha256(&mut Cursor::new(bytes))?);
        let same_geometry = geometry(&original) == geometry(&observed);
        let same_parts = serde_json::to_value(&original.partitions).unwrap()
            == serde_json::to_value(&observed.partitions).unwrap();
        let same_disk = original.disk_guid == observed.disk_guid;
        if same_geometry && same_parts && same_disk {
            (Passed, "CRC-checked primary GPT geometry, partition identities, bounds and attributes match the source reference. This does not establish installed partition contents or backup GPT integrity.".into())
        } else {
            (Failed, format!("Live/reference GPT differs: geometry match={same_geometry}, partition entries match={same_parts}, disk GUID match={same_disk}. Do not use reference restore coordinates on this device."))
        }
    } else {
        (Missing, match capture.gpt_status {
            GptReadStatus::ContextSwitchRequired => "Locked FlashApp requires a separately reviewed BootManager context transition for NOKT. This preflight sends none.",
            GptReadStatus::SecurityEvidenceMissing => "NOKV security evidence is absent. No GPT query was sent.",
            _ => "Primary GPT reading was not requested. No GPT query was sent.",
        }.into())
    };
    checks.push(PreparationCheck {
        key: "live_gpt".into(),
        label: "Live / reference primary GPT".into(),
        status,
        message,
    });
    for (key, label, message) in [
        ("normal_identity", "Normal / Flash device correlation", "A fresh Normal-mode public ID and physical-port binding have not been tied to this session."),
        ("installed_originals", "Installed originals and both GPTs", "This report does not preserve installed partition images or either GPT as a recoverable backup. Source FFU originals are reference material only."),
        ("applicability", "Firmware / donor / loader acceptance", "Exact installed firmware, downgrade constraints, donor compatibility, loader acceptance and trusted OEM provenance remain unvalidated."),
        ("recovery", "Validated recovery path", "No recovery path has been hardware validated for this exact device, firmware, host and transport."),
        ("executor", "Reviewed live unlock executor", "Live unlocking remains blocked pending a reviewed executor, replay failure handling and hardware validation."),
    ] {
        checks.push(PreparationCheck { key: key.into(), label: label.into(), status: Unverified, message: message.into() });
    }
    Ok(Report {
        source_kind: if replay {
            "replay_only"
        } else {
            "native_read_only"
        }
        .into(),
        reference: reference.summary.clone(),
        flash: capture.info,
        application_security: capture.application_security,
        security: capture.security,
        gpt_read_status: capture.gpt_status,
        observed_primary_sha256,
        observed_partition_count,
        checks,
        public_id_bytes_exported: false,
        identity_authenticated: false,
        normal_session_correlated: false,
        mode_changes_sent: false,
        installed_originals_preserved: false,
        backup_gpt_captured: false,
        recovery_authorized: false,
        phone_writes_enabled: false,
    })
}
