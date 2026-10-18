use std::process::Command;

#[test]
fn session_help_and_required_pins_work_on_the_process_default_stack() {
    // A subprocess catches Windows ARM64 CLI startup stack regressions that
    // parser tests on Rust's test-thread stack would miss. No device is selected.
    for args in [vec!["--help"], vec!["check-spec-a-session", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("check-spec-a-session"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
        .arg("check-spec-a-session")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("required"));
}
