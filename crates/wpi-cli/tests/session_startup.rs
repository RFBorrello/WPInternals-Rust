use std::process::Command;

#[test]
fn session_help_and_required_pins_work_on_the_process_default_stack() {
    // A subprocess catches Windows ARM64 CLI startup stack regressions that
    // parser tests on Rust's test-thread stack would miss. No device is selected.
    for args in [
        vec!["--help"],
        vec!["check-spec-a-session", "--help"],
        vec!["plan-spec-a-finish", "--help"],
        vec!["inspect-spec-a-finish-journal", "--help"],
    ] {
        let expected = if args.len() == 1 {
            "check-spec-a-session"
        } else {
            args[0]
        };
        let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains(expected));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
        .arg("check-spec-a-session")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("required"));
}

#[test]
fn unreviewed_roundtrip_confirmation_fails_before_opening_artifacts_or_usb() {
    let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
        .args([
            "check-spec-a-session",
            "missing-source",
            "missing-package",
            "missing-primary",
            "missing-loader",
            "--device-id",
            "not-a-device",
            "--disk-sectors",
            "1",
            "--expect-source-sha256",
            "bad",
            "--expect-package-sha256",
            "bad",
            "--expect-primary-sha256",
            "bad",
            "--expect-loader-sha256",
            "bad",
            "--roundtrip",
            "--confirm",
            "old-or-unreviewed-cycle",
            "--journal",
            "unused.jsonl",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exact RM875-PREPARED-READONLY-ROUNDTRIP")
    );
}
