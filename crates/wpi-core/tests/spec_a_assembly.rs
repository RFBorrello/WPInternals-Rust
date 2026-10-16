use std::fs;
use wpi_core::artifacts;
const FFU: &[u8] = include_bytes!("../../../tests/fixtures/synthetic-spec-a-offline.ffu");
#[test]
fn offline_outputs_are_atomic_new_files_and_original_ffu_is_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.ffu");
    fs::write(&source, FFU).unwrap();
    let output = dir.path().join("UEFI.img");
    let report = artifacts::assemble_spec_a(&source, None, "uefi", &output).unwrap();
    assert_eq!(report["phone_writes_enabled"], false);
    assert_eq!(report["signature_removed"], true);
    assert_eq!(fs::read(&source).unwrap(), FFU);
    let saved = fs::read(&output).unwrap();
    assert!(artifacts::assemble_spec_a(&source, None, "uefi", &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), saved);
    assert!(artifacts::assemble_spec_a(&source, None, "uefi", &source).is_err());
    assert_eq!(fs::read(&source).unwrap(), FFU);
}
#[test]
fn missing_donor_bad_bcd_and_unknown_component_publish_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.ffu");
    fs::write(&source, FFU).unwrap();
    let output = dir.path().join("never-published.img");
    for (component, donor) in [
        ("efiesp", None),
        ("efiesp", Some(source.as_path())),
        ("unknown", None),
    ] {
        assert!(artifacts::assemble_spec_a(&source, donor, component, &output).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
#[test]
fn cancellation_before_publication_removes_the_new_temporary_image() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.ffu");
    fs::write(&source, FFU).unwrap();
    let output = dir.path().join("cancelled.img");
    let mut completed = 0;
    let result =
        artifacts::assemble_spec_a_with_progress(&source, None, "uefi", &output, |done, total| {
            if total > 0 && done == total {
                completed += 1;
            }
            completed < 2 // Extraction finishes, then cancel after rebuilding and before publishing.
        });
    assert!(matches!(result, Err(wpi_image::ImageError::Cancelled)));
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}
