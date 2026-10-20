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
        vec!["inspect-spec-a-entry-code", "--help"],
        vec!["prepare-spec-a-entry-recovery", "--help"],
        vec!["unlock-spec-a", "--help"],
        vec!["inspect-spec-a-native-journal", "--help"],
        vec!["native-unlock-readiness", "--help"],
        vec!["storage", "capture-spec-a", "--help"],
    ] {
        let expected = if args.len() == 1 {
            "check-spec-a-session"
        } else if args.len() == 3 {
            "capture-spec-a"
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
fn native_unlock_defaults_to_preview_and_requires_explicit_execution_arguments() {
    let executable = env!("CARGO_BIN_EXE_wpi");
    let args = [
        "unlock-spec-a",
        "missing-source",
        "missing-package",
        "missing-primary",
        "missing-loader",
        "missing-donor",
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
    ];
    let output = Command::new(executable)
        .args(args)
        .arg("--execute")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--journal"));
    let output = Command::new(executable)
        .args(args)
        .args([
            "--execute",
            "--device-id",
            "not-a-device",
            "--confirm",
            "unreviewed",
            "--journal",
            "unused.jsonl",
            "--first-snapshot",
            "unused-1.zip",
            "--final-snapshot",
            "unused-2.zip",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no file or device was opened"));
    for (manual, confirmation) in [
        (true, "RM875-EXPERIMENTAL-UNLOCK-WITHOUT-FULL-BACKUP"),
        (
            false,
            "RM875-EXPERIMENTAL-ENTRY-BEFORE-DRIVER-SETUP-WITHOUT-FULL-BACKUP",
        ),
    ] {
        let mut command = Command::new(executable);
        command.args(args).args([
            "--execute",
            "--device-id",
            "not-a-device",
            "--confirm",
            confirmation,
            "--journal",
            "unused.jsonl",
            "--first-snapshot",
            "unused-1.zip",
            "--final-snapshot",
            "unused-2.zip",
        ]);
        if manual {
            command.arg("--manual-emergency-driver-setup");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("no file or device was opened"));
    }
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
#[test]
fn targeted_capture_bad_pins_fail_before_disk_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
        .args([
            "storage",
            "capture-spec-a",
            "4294967295",
            "no-disk-opened.zip",
            "--expect-gpt",
            "invalid",
            "--expect-primary-sha256",
            "invalid",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("required before opening a disk"));
}

#[test]
fn dedicated_gpt_recovery_starts_on_default_stack_and_requires_separate_authorization() {
    let executable = env!("CARGO_BIN_EXE_wpi-gpt-recovery");
    let help = Command::new(executable).arg("--help").output().unwrap();
    assert!(
        help.status.success(),
        "{}",
        String::from_utf8_lossy(&help.stderr)
    );
    assert!(String::from_utf8_lossy(&help.stdout).contains("Preview"));
    let base = [
        "missing-source",
        "missing-package",
        "missing-primary",
        "missing-loader",
        "missing-donor",
        "--disk-sectors",
        "61071360",
        "--expect-source-sha256",
        "bad",
        "--expect-package-sha256",
        "bad",
        "--expect-primary-sha256",
        "bad",
        "--expect-loader-sha256",
        "bad",
    ];
    let missing = Command::new(executable)
        .args(base)
        .arg("--execute")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    for confirmation in [
        "unreviewed",
        "RM875-NATIVE-PREFLIGHT-ONLY",
        "RM875-EXPERIMENTAL-ENTRY-BEFORE-DRIVER-SETUP-WITHOUT-FULL-BACKUP",
    ] {
        let result = Command::new(executable)
            .args(base)
            .args([
                "--execute",
                "--device-id",
                "not-a-device",
                "--confirm",
                confirmation,
                "--journal",
                "unused.jsonl",
                "--expect-port-sha256",
                &"a".repeat(64),
                "--expect-normal-serial-sha256",
                &"b".repeat(64),
            ])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains("no file or device was opened"));
    }
    for forbidden in [
        "--preflight-only",
        "--manual-emergency-driver-setup",
        "--first-snapshot",
    ] {
        let result = Command::new(executable)
            .args(base)
            .arg(forbidden)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn native_preflight_is_exclusive_requires_selection_and_its_own_confirmation() {
    let base = [
        "unlock-spec-a",
        "missing-source",
        "missing-package",
        "missing-primary",
        "missing-loader",
        "missing-donor",
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
    ];
    let selection = [
        "--device-id",
        "not-a-device",
        "--confirm",
        "RM875-NATIVE-PREFLIGHT-ONLY",
        "--journal",
        "unused.jsonl",
    ];
    for extra in [
        vec![],
        vec!["--execute"],
        vec!["--manual-emergency-driver-setup"],
        vec!["--first-snapshot", "unused.zip"],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wpi"));
        command.args(base).arg("--preflight-only");
        if !extra.is_empty() {
            command.args(selection);
        }
        let output = command.args(extra).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for confirmation in [
        "unreviewed",
        "RM875-EXPERIMENTAL-UNLOCK-WITHOUT-FULL-BACKUP",
        "RM875-EXPERIMENTAL-ENTRY-BEFORE-DRIVER-SETUP-WITHOUT-FULL-BACKUP",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
            .args(base)
            .args([
                "--preflight-only",
                "--device-id",
                "not-a-device",
                "--confirm",
                confirmation,
                "--journal",
                "unused.jsonl",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("no file or device was opened"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_wpi"))
        .args(base)
        .arg("--preflight-only")
        .args(selection)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1)); // Accepted options, then fails on missing local input.
    assert!(!String::from_utf8_lossy(&output.stderr).contains("no file or device was opened"));
}
