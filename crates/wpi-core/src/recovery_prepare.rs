//! Offline stock-recovery checklist. No protocol requests or mode changes.
use crate::inspection::Inspection;
use wpi_types::*;

pub enum ChunkIntegrity {
    NotChecked,
    Passed,
    Failed(String),
}

pub fn report(
    device: Option<DeviceIdentity>,
    image: Option<&Inspection>,
    artifact: Option<ArtifactIdentity>,
    integrity: ChunkIntegrity,
    host: Host,
    transport: TransportKind,
) -> RecoveryPreparation {
    use PreparationStatus::*;
    let mut checks = Vec::new();
    let mut check = |key: &str, label: &str, status, message: String| {
        checks.push(PreparationCheck {
            key: key.into(),
            label: label.into(),
            status,
            message,
        });
    };
    let ffu = image.and_then(|i| i.ffu.as_ref());
    check("firmware", "Stock FFU image", if ffu.is_some() { Passed } else if image.is_some() { Failed } else { Missing },
        ffu.map(|f| format!("Legacy FFU parsed for {}. A filename alone does not establish phone applicability.", f.platform_id))
            .unwrap_or_else(|| "Import a local stock FFU. Raw partition and filesystem images cannot be used for stock recovery.".into()));
    check(
        "gpt",
        "Partition bounds",
        if image.and_then(|i| i.gpt.as_ref()).is_some() && ffu.is_some() {
            Passed
        } else {
            Missing
        },
        "FFU inspection must validate the primary GPT CRCs and partition bounds before recovery."
            .into(),
    );
    let valid_identity = artifact.as_ref().is_some_and(|a| {
        a.sha256.len() == 64
            && a.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            && image.is_some_and(|i| a.size == i.size)
            && ffu.is_some_and(|f| a.platform_id.as_deref() == Some(f.platform_id.as_str()))
    });
    check("artifact_identity", "Image fingerprint", if valid_identity { Passed } else { Unverified },
        if valid_identity { "Complete local file SHA-256 recorded for later revalidation." } else { "A complete file fingerprint is not available. The native preparation command can calculate it." }.into());
    let (status, message) = match integrity {
        ChunkIntegrity::NotChecked => (Unverified, "Chunk hashes have not been verified in this preview. Use native preparation to check the complete image.".into()),
        ChunkIntegrity::Passed if ffu.is_some() && valid_identity => (Passed, "FFU SHA-256 chunk table checked; this does not authenticate the signing catalog.".into()),
        ChunkIntegrity::Passed => (Unverified, "Chunk verification requires a parsed FFU and complete artifact identity.".into()),
        ChunkIntegrity::Failed(error) => (Failed, format!("Chunk verification failed: {error}")),
    };
    check("chunk_hashes", "Chunk integrity", status, message);
    for (key, label, evidence) in [
        (
            "catalog_signature",
            "Catalog signature",
            image.and_then(|i| i.catalog.as_ref()).map(|c| &c.signature),
        ),
        (
            "catalog_binding",
            "Signed hash-table binding",
            image
                .and_then(|i| i.catalog.as_ref())
                .map(|c| &c.hash_table_binding),
        ),
        (
            "signing_catalog",
            "Firmware signer trust",
            image
                .and_then(|i| i.catalog.as_ref())
                .map(|c| &c.signer_trust),
        ),
    ] {
        let (status,message)=evidence.map(|e| {
            use wpi_image::catalog::Status;
            (match e.status {Status::Valid=>Passed,Status::Invalid=>Failed,Status::Missing=>Missing,Status::Unsupported|Status::Unverified=>Unverified},e.message.clone())
        }).unwrap_or((Unverified,"Signing-catalog evidence has not been inspected. Chunk hashes alone do not establish authenticity.".into()));
        check(key, label, status, message);
    }
    let image_version = image
        .filter(|i| i.firmware_version_error.is_none())
        .and_then(|i| i.firmware_version.as_deref());
    let version_error = image.and_then(|i| i.firmware_version_error.as_deref());
    check("image_firmware","Firmware version in image",if version_error.is_some(){Failed}else if image_version.is_some(){Passed}else{Missing},
        version_error.map(|e|format!("Image firmware metadata failed: {e}"))
            .or_else(||image_version.map(|v|format!("Image firmware revision is {v}. Sources: {}. This observed metadata does not establish signer trust.", image.map(|i|i.firmware_version_sources.join("; ")).filter(|s|!s.is_empty()).unwrap_or_else(||"unspecified".into()))))
            .unwrap_or_else(||"No supported PLAT or corroborated MainOS firmware revision was found; never infer firmware compatibility from the filename.".into()));
    let (status, message) = firmware_relation(
        image_version,
        device.as_ref().and_then(|d| d.firmware.as_deref()),
    );
    check(
        "firmware_relation",
        "Installed / image firmware",
        status,
        message,
    );
    let identified = device.as_ref().is_some_and(|d| {
        d.variant.as_ref().is_some_and(|s| !s.is_empty())
            && d.firmware.as_ref().is_some_and(|s| !s.is_empty())
            && d.family != BootloaderFamily::Unknown
    });
    check("device_identity", "Phone identity", if identified { Passed } else { Missing },
        if identified { "Read-only model, hardware variant and installed firmware information are available; authenticated identity across mode changes is still required." } else { "Select your Lumia and read its device information. USB labels cannot establish hardware identity." }.into());
    let (status, message) = match (device.as_ref().and_then(|d| d.platform_id.as_deref()), ffu) {
        (Some(platform), Some(ffu)) if platform == ffu.platform_id => (Passed, "Reported phone platform exactly matches the image platform; this alone does not approve recovery.".into()),
        (Some(platform),Some(ffu)) if platform_family(platform,&ffu.platform_id) => (Unverified,"The image platform is a dot-delimited prefix of the observed phone platform, as in upstream matching. This is family evidence only; exact applicability and device acceptance remain unverified.".into()),
        (Some(_), Some(_)) => (Failed, "Phone and image platform IDs differ. Do not use this image for this phone.".into()),
        _ => (Unverified, "The phone platform has not been established. Normal-mode information queries do not read a platform ID.".into()),
    };
    check("platform", "Phone / image platform", status, message);
    check("mode", "Recovery mode", if device.as_ref().is_some_and(|d| d.mode == DeviceMode::Flash) { Passed } else { Missing },
        "Stock recovery requires a validated FlashApp connection and identity checks after reconnection. This preview does not change phone modes.".into());
    check("compatibility", "Validated recovery profile", Unverified, "No stock recovery workflow is hardware validated for this exact variant, firmware, host and transport. Identification evidence does not establish write support.".into());
    check("backup", "Data preservation", Missing, "Native phone backup access is not implemented yet. Preserve recoverable originals and establish a data preservation plan before recovery.".into());
    check("executor", "Recovery execution", Failed, "Stock recovery currently runs only in protocol replay tests. No physical-device executor is enabled.".into());
    let mut plan = crate::operations::prepare(
        Operation::StockFlash,
        device,
        host,
        transport,
        artifact.into_iter().collect(),
    );
    plan.executable = false;
    plan.blockers.extend(
        checks
            .iter()
            .filter(|c| c.status != Passed)
            .map(|c| c.message.clone()),
    );
    plan.steps = vec![
        "Inspect the local FFU, verify chunk hashes and record its SHA-256 fingerprint".into(),
        "Establish phone identity, exact firmware applicability, authenticity and a data preservation plan".into(),
        "Implement and validate mode transitions, reconnection, native recovery execution and interruption handling before enabling recovery".into(),
    ];
    // Preparation exports contain useful model information, not persistent phone identifiers.
    if let Some(d) = plan.device.as_mut() {
        d.serial = None;
        d.id = "selected-device".into();
    }
    RecoveryPreparation { plan, checks }
}

fn platform_family(phone: &str, image: &str) -> bool {
    !image.is_empty()
        && phone
            .strip_prefix(image)
            .is_some_and(|suffix| suffix.starts_with('.'))
}
fn firmware_relation(image: Option<&str>, installed: Option<&str>) -> (PreparationStatus, String) {
    use PreparationStatus::*;
    match (image.and_then(wpi_image::firmware::components),installed.and_then(wpi_image::firmware::components)) {
        (Some(image),Some(phone)) if image==phone =>(Passed,"Observed image and installed firmware versions match. This does not establish recovery support or phone acceptance.".into()),
        (Some(image),Some(phone)) if image[..2]==phone[..2] && image[2..]<phone[2..] =>(Failed,"The image is numerically older within the same firmware branch. No downgrade acceptance/profile is validated; recovery remains blocked.".into()),
        (Some(image),Some(phone)) if image[..2]==phone[..2] =>(Unverified,"The image is numerically newer within the same firmware branch. An upgrade is not approved by version ordering alone.".into()),
        (Some(_),Some(_)) =>(Unverified,"Firmware branches differ. Version numbers alone cannot establish chronology, applicability or rollback acceptance.".into()),
        _=>(Unverified,"Read an image firmware revision and installed phone version before comparing them. Filename versions and unsupported version formats are not applicability evidence.".into()),
    }
}
