//! Correlate fresh read-only observations. Never authorizes a write.
use wpi_types::*;

pub fn compare(
    before: &DeviceIdentity,
    after: &DeviceIdentity,
    target: DeviceMode,
) -> ReconnectReport {
    let mut checks = Vec::new();
    let mut mismatch = false;
    let mut correlated = false;
    let mut add = |key: &str, label: &str, status, message: &str| {
        mismatch |= status == PreparationStatus::Failed;
        checks.push(PreparationCheck {
            key: key.into(),
            label: label.into(),
            status,
            message: message.into(),
        });
    };
    let valid_usb = match crate::classify_usb(after.vendor_id, after.product_id) {
        Some(DeviceMode::Normal) => after.mode == DeviceMode::Normal,
        Some(DeviceMode::Flash) => matches!(
            after.mode,
            DeviceMode::Flash | DeviceMode::BootManager | DeviceMode::PhoneInfo
        ),
        _ => false,
    };
    add(
        "usb",
        "Recognized USB interface",
        if valid_usb {
            PreparationStatus::Passed
        } else {
            PreparationStatus::Failed
        },
        "USB IDs identify an interface, not a physical phone.",
    );
    add(
        "mode",
        "Observed application mode",
        if after.mode == target && target != DeviceMode::Unknown {
            PreparationStatus::Passed
        } else {
            PreparationStatus::Failed
        },
        "A fresh application-level probe must establish the expected mode.",
    );
    match (present(before.serial.as_deref()), present(after.serial.as_deref())) {
        (Some(a), Some(b)) if a == b => {
            correlated = true;
            add("serial", "USB serial correlation", PreparationStatus::Passed, "USB serials match locally. This is not cryptographic authentication.");
        }
        (Some(_), Some(_)) => add("serial", "USB serial correlation", PreparationStatus::Failed, "USB serials differ. Do not continue with this device."),
        _ => add("serial", "USB serial correlation", PreparationStatus::Unverified, "A nonempty USB serial is missing. Model and firmware equality cannot identify the same physical phone."),
    }
    for (key, label, a, b) in [
        (
            "variant",
            "Hardware variant",
            before.variant.as_deref(),
            after.variant.as_deref(),
        ),
        (
            "firmware",
            "Installed firmware",
            before.firmware.as_deref(),
            after.firmware.as_deref(),
        ),
        (
            "platform",
            "Platform",
            before.platform_id.as_deref(),
            after.platform_id.as_deref(),
        ),
    ] {
        let (status, message) = match (present(a), present(b)) {
            (Some(a), Some(b)) if a == b => (PreparationStatus::Passed, "Fresh observations agree."),
            (Some(_), Some(_)) => (PreparationStatus::Failed, "Fresh observations contradict the remembered phone; stop and inspect device state."),
            _ => (PreparationStatus::Unverified, "This field is unavailable in one of the modes; it was not copied from the remembered phone."),
        };
        add(key, label, status, message);
    }
    if before.family != BootloaderFamily::Unknown && after.family != BootloaderFamily::Unknown {
        add(
            "family",
            "Bootloader family",
            if before.family == after.family {
                PreparationStatus::Passed
            } else {
                PreparationStatus::Failed
            },
            "Known family observations must agree.",
        );
    }
    let source_known = before.variant.as_deref().is_some_and(|v| {
        crate::known_models()
            .iter()
            .any(|p| p.variants.contains(&v) && p.family == before.family)
    }) && present(before.firmware.as_deref()).is_some();
    add(
        "baseline",
        "Remembered phone information",
        if source_known {
            PreparationStatus::Passed
        } else {
            PreparationStatus::Unverified
        },
        "A recognized variant, family and firmware are required as the baseline.",
    );
    ReconnectReport {
        status: if mismatch {
            ReconnectStatus::Mismatch
        } else if correlated && source_known {
            ReconnectStatus::Correlated
        } else {
            ReconnectStatus::Unverified
        },
        expected_mode: target,
        observed_mode: after.mode,
        checks,
        recovery_authorized: false,
    }
}

fn present(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.trim().is_empty() && s.len() <= 4096)
}

pub fn prepare(
    device: Option<DeviceIdentity>,
    target: DeviceMode,
    protocol_major: Option<u8>,
    host: Host,
    transport: TransportKind,
) -> ModeTransitionPreparation {
    let source = device.as_ref().map_or(DeviceMode::Unknown, |d| d.mode);
    let route = device
        .as_ref()
        .and_then(|d| wpi_protocol::mode::command(d.mode, target, d.family, protocol_major).ok());
    let mut plan =
        crate::operations::prepare(Operation::SwitchMode, device, host, transport, vec![]);
    if route.is_none() {
        plan.blockers
            .push("No reviewed route for these modes, family and protocol version.".into());
    }
    if plan
        .device
        .as_ref()
        .and_then(|d| present(d.serial.as_deref()))
        .is_none()
    {
        plan.blockers.push(
            "USB serial correlation is unavailable; never choose the first arriving phone.".into(),
        );
    }
    plan.blockers.push("Mode transitions are implemented only in replay. A native executor and hardware validation are still required.".into());
    plan.steps = vec!["Re-read the selected phone information before sending a single mode-change request".into(), "Observe disconnection when required, renew USB permission and probe the returning interface".into(), "Compare local identity evidence; stop on ambiguity, missing identity, timeout or cancellation without retrying the command".into()];
    // Export only nonidentifying baseline metadata.
    if let Some(d) = plan.device.as_mut() {
        d.serial = None;
        d.id = "selected-device".into();
    }
    ModeTransitionPreparation {
        plan,
        source,
        target,
        route: route.as_ref().map(|r| r.name.into()),
        requires_disconnect: route.is_some_and(|r| r.requires_disconnect),
    }
}
