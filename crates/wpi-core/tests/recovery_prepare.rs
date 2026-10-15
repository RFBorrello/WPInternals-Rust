use std::io::{Cursor, Write};
use wpi_core::{
    inspection,
    operations::OperationCoordinator,
    recovery_prepare::{report, ChunkIntegrity},
};
use wpi_types::*;
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic.ffu");

fn phone(platform: &str) -> DeviceIdentity {
    DeviceIdentity {
        id: "private-host-id".into(),
        vendor_id: 0x0421,
        product_id: 0x066e,
        manufacturer: None,
        product: None,
        serial: Some("private-serial".into()),
        model: Some("Lumia 1020".into()),
        variant: Some("RM-875".into()),
        firmware: Some("test-firmware".into()),
        platform_id: Some(platform.into()),
        family: BootloaderFamily::SpecA,
        mode: DeviceMode::Flash,
        interfaces: vec![],
    }
}
fn artifact() -> ArtifactIdentity {
    ArtifactIdentity {
        name: "test.ffu".into(),
        size: FFU.len() as u64,
        sha256: "a".repeat(64),
        platform_id: Some("SYNTHETIC.LUMIA.TEST".into()),
    }
}
#[test]
fn successful_offline_checks_never_authorize_recovery_or_export_private_ids() {
    let image = inspection::inspect(&mut Cursor::new(FFU)).unwrap();
    let mut prepared = report(
        Some(phone("SYNTHETIC.LUMIA.TEST")),
        Some(&image),
        Some(artifact()),
        ChunkIntegrity::Passed,
        Host::Windows,
        TransportKind::Usb,
    );
    assert!(!prepared.plan.executable);
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "chunk_hashes" && c.status == PreparationStatus::Passed));
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "signing_catalog" && c.status == PreparationStatus::Unverified));
    let json = serde_json::to_string(&prepared).unwrap();
    assert!(!json.contains("private-serial") && !json.contains("private-host-id"));
    prepared.plan.executable = true;
    prepared.plan.blockers.clear();
    assert!(OperationCoordinator::default()
        .start(&prepared.plan)
        .is_err());
}
#[test]
fn missing_inputs_platform_mismatch_and_browser_integrity_are_explicit() {
    let empty = report(
        None,
        None,
        None,
        ChunkIntegrity::NotChecked,
        Host::Browser,
        TransportKind::WebUsb,
    );
    assert!(empty
        .checks
        .iter()
        .any(|c| c.key == "firmware" && c.status == PreparationStatus::Missing));
    let image = inspection::inspect(&mut Cursor::new(FFU)).unwrap();
    let mismatched = report(
        Some(phone("WRONG.PLATFORM")),
        Some(&image),
        None,
        ChunkIntegrity::NotChecked,
        Host::Browser,
        TransportKind::WebUsb,
    );
    assert!(mismatched
        .checks
        .iter()
        .any(|c| c.key == "platform" && c.status == PreparationStatus::Failed));
    assert!(mismatched
        .checks
        .iter()
        .any(|c| c.key == "chunk_hashes" && c.status == PreparationStatus::Unverified));
}
#[test]
fn native_preparation_verifies_fingerprints_and_reports_corruption_without_modifying_input() {
    let mut input = tempfile::NamedTempFile::new().unwrap();
    input.write_all(FFU).unwrap();
    let mut last = 0;
    let prepared = wpi_core::artifacts::prepare_recovery(
        input.path(),
        None,
        Host::Windows,
        TransportKind::Usb,
        |done, total| {
            assert!(done >= last && done <= total);
            last = done;
            true
        },
    )
    .unwrap();
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "chunk_hashes" && c.status == PreparationStatus::Passed));
    assert_eq!(
        prepared.plan.artifacts[0].sha256,
        wpi_image::stream::sha256(&mut Cursor::new(FFU)).unwrap()
    );
    let mut damaged = FFU.to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    std::fs::write(input.path(), &damaged).unwrap();
    let prepared = wpi_core::artifacts::prepare_recovery(
        input.path(),
        None,
        Host::Windows,
        TransportKind::Usb,
        |_, _| true,
    )
    .unwrap();
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "chunk_hashes" && c.status == PreparationStatus::Failed));
    assert_eq!(std::fs::read(input.path()).unwrap(), damaged);
    assert!(matches!(
        wpi_core::artifacts::prepare_recovery(
            input.path(),
            None,
            Host::Windows,
            TransportKind::Usb,
            |_, _| false
        ),
        Err(wpi_image::ImageError::Cancelled)
    ));
}
#[test]
fn catalog_signature_and_binding_never_promote_embedded_certificate_trust_or_execution() {
    let bytes = include_bytes!("../../../tests/fixtures/synthetic-signed.ffu");
    let mut input = tempfile::NamedTempFile::new().unwrap();
    input.write_all(bytes).unwrap();
    let prepared = wpi_core::artifacts::prepare_recovery(
        input.path(),
        None,
        Host::Windows,
        TransportKind::Usb,
        |_, _| true,
    )
    .unwrap();
    for key in ["catalog_signature", "catalog_binding", "chunk_hashes"] {
        assert!(
            prepared
                .checks
                .iter()
                .any(|c| c.key == key && c.status == PreparationStatus::Passed),
            "{key}"
        );
    }
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "signing_catalog" && c.status == PreparationStatus::Unverified));
    assert!(!prepared.plan.executable);
    let mut damaged = bytes.to_vec();
    let catalog_size = u32::from_le_bytes(damaged[24..28].try_into().unwrap()) as usize;
    damaged[32 + catalog_size] ^= 1;
    std::fs::write(input.path(), &damaged).unwrap();
    let prepared = wpi_core::artifacts::prepare_recovery(
        input.path(),
        None,
        Host::Windows,
        TransportKind::Usb,
        |_, _| true,
    )
    .unwrap();
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "catalog_signature" && c.status == PreparationStatus::Passed));
    assert!(prepared
        .checks
        .iter()
        .any(|c| c.key == "catalog_binding" && c.status == PreparationStatus::Failed));
    assert!(!prepared.plan.executable);
}
#[test]
fn observed_firmware_branch_ordering_blocks_unvalidated_downgrades_without_using_filenames() {
    for (version, status) in [
        (Some("3051.50009.1424.0002"), PreparationStatus::Failed),
        (Some("3051.50009.1451.1003"), PreparationStatus::Passed),
        (Some("3051.50009.1452.1003"), PreparationStatus::Unverified),
        (Some("9999.1.1.1"), PreparationStatus::Unverified),
        (None, PreparationStatus::Unverified),
    ] {
        let mut image = inspection::inspect(&mut Cursor::new(FFU)).unwrap();
        image.firmware_version = version.map(str::to_owned);
        let mut device = phone("SYNTHETIC.LUMIA.TEST");
        device.firmware = Some("3051.50009.1451.1003".into());
        let mut file = artifact();
        file.name = "RM875_9999.9999.9999.9999_signed.ffu".into();
        let result = report(
            Some(device),
            Some(&image),
            Some(file),
            ChunkIntegrity::Passed,
            Host::Windows,
            TransportKind::Usb,
        );
        assert!(result
            .checks
            .iter()
            .any(|c| c.key == "firmware_relation" && c.status == status));
        assert!(!result.plan.executable);
    }
}
#[test]
fn platform_family_prefix_is_advisory_and_cannot_match_an_unrelated_product_number() {
    let image = inspection::inspect(&mut Cursor::new(FFU)).unwrap();
    for (platform, status) in [
        ("SYNTHETIC.LUMIA.TEST.3.2.1", PreparationStatus::Unverified),
        ("SYNTHETIC.LUMIA.TEST2.3", PreparationStatus::Failed),
    ] {
        let result = report(
            Some(phone(platform)),
            Some(&image),
            None,
            ChunkIntegrity::NotChecked,
            Host::Windows,
            TransportKind::Usb,
        );
        assert!(result
            .checks
            .iter()
            .any(|c| c.key == "platform" && c.status == status));
        assert!(!result.plan.executable);
    }
}
