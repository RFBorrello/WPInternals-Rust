use wpi_core::{
    operations::{prepare, OperationCoordinator},
    profiles,
};
use wpi_types::*;
#[test]
fn every_device_write_is_blocked_and_tampered_preview_cannot_bypass() {
    for host in [Host::Windows, Host::Macos, Host::Linux, Host::Browser] {
        for operation in Operation::ALL.into_iter().filter(|o| o.writes_device()) {
            let mut plan = prepare(operation, None, host, TransportKind::Usb, vec![]);
            assert!(!plan.executable);
            plan.executable = true;
            plan.blockers.clear();
            assert!(OperationCoordinator::default().start(&plan).is_err());
        }
    }
}
#[test]
fn no_model_is_claimed_hardware_verified_and_usb_is_not_model_identity() {
    assert!(profiles::known_models()
        .iter()
        .all(|p| !p.hardware_validated));
    assert_eq!(
        profiles::classify_usb(0x05c6, 0x9008),
        Some(DeviceMode::Emergency)
    );
    assert_eq!(profiles::classify_usb(0x1234, 0x9008), None);
}
#[test]
fn session_exclusion_cancellation_and_terminal_states() {
    let coordinator = OperationCoordinator::default();
    let mut session = coordinator
        .reserve_local(Operation::ExtractPartition)
        .unwrap();
    assert!(coordinator.reserve_local(Operation::InspectGpt).is_err());
    session
        .transition(OperationState::Running, 0, 2048, "start")
        .unwrap();
    let token = session.cancellation();
    token.store(true, std::sync::atomic::Ordering::Release);
    assert!(!session.safe_boundary());
    session
        .transition(OperationState::Cancelling, 1024, 2048, "cancel")
        .unwrap();
    session
        .transition(OperationState::Cancelled, 1024, 2048, "cancelled")
        .unwrap();
    assert!(session
        .transition(OperationState::Running, 1024, 2048, "retry")
        .is_err());
    drop(session);
    assert!(coordinator.reserve_local(Operation::InspectGpt).is_ok());
    assert!(coordinator.reserve_local(Operation::StockFlash).is_err());
}
#[test]
fn output_file_is_never_overwritten_and_failed_extraction_is_not_published() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("output.img");
    std::fs::write(&output, b"keep").unwrap();
    assert!(wpi_core::artifacts::write_new(&output, |f| {
        f.write_all(b"replace")?;
        Ok(())
    })
    .is_err());
    assert_eq!(std::fs::read(&output).unwrap(), b"keep");
    let other = dir.path().join("failed.img");
    assert!(wpi_core::artifacts::write_new(&other, |f| {
        f.write_all(b"partial")?;
        Err(wpi_image::ImageError::Cancelled)
    })
    .is_err());
    assert!(!other.exists());
}
