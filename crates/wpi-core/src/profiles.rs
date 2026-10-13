use serde::Serialize;
use wpi_types::*;

#[derive(Debug, Clone, Serialize)]
pub struct ModelProfile {
    pub model: &'static str,
    pub variants: &'static [&'static str],
    pub family: BootloaderFamily,
    pub hardware_validated: bool,
}
pub fn known_models() -> Vec<ModelProfile> {
    vec![
        ModelProfile {
            model: "Lumia 1020",
            variants: &["RM-875", "RM-876", "RM-877"],
            family: BootloaderFamily::SpecA,
            hardware_validated: false,
        },
        ModelProfile {
            model: "Lumia 730",
            variants: &["RM-1040"],
            family: BootloaderFamily::SpecB,
            hardware_validated: false,
        },
        ModelProfile {
            model: "Lumia 800",
            variants: &["RM-801", "RM-802"],
            family: BootloaderFamily::Wp7,
            hardware_validated: false,
        },
        ModelProfile {
            model: "Lumia 710",
            variants: &["RM-803", "RM-809"],
            family: BootloaderFamily::Wp7,
            hardware_validated: false,
        },
    ]
}
/// USB PIDs identify a mode, never prove a phone's model or bootloader family.
pub fn classify_usb(vendor: u16, product: u16) -> Option<DeviceMode> {
    match (vendor, product) {
        (0x0421 | 0x045e, 0x0661 | 0x06fc | 0x0a00) => Some(DeviceMode::Normal),
        (0x0421 | 0x045e, 0x0660 | 0x0713 | 0x0a01) => Some(DeviceMode::MassStorage),
        (0x0421 | 0x045e, 0x066e | 0x0714 | 0x0a02 | 0x05ee) => Some(DeviceMode::Flash),
        (0x05c6, 0x9008 | 0xf006) => Some(DeviceMode::Emergency),
        (0x05c6 | 0x045e, 0x9006) => Some(DeviceMode::MassStorage),
        _ => None,
    }
}
pub fn apply_variant(device: &mut DeviceIdentity, variant: &str) {
    device.variant = Some(variant.to_owned());
    device.family = BootloaderFamily::Unknown;
    device.model = None;
    if let Some(profile) = known_models()
        .iter()
        .find(|p| p.variants.iter().any(|v| v.eq_ignore_ascii_case(variant)))
    {
        device.family = profile.family;
        device.model = Some(profile.model.to_owned());
    }
}
pub fn capabilities(
    device: Option<&DeviceIdentity>,
    host: Host,
    transport: TransportKind,
) -> CapabilityReport {
    let capabilities = Operation::ALL.into_iter().map(|operation| {
        let (status, executable, reason) = if operation == Operation::PatchFiles && host == Host::Browser {
            (SupportStatus::Unsupported, false, "Offline catalog patching is currently available through the native CLI, not the browser adapter.")
        } else if operation.offline() {
            (SupportStatus::Experimental, true, "Implemented for supported local file formats; no phone write is involved.")
        } else if operation == Operation::DeviceInfo {
            match device {
                Some(d) if d.mode == DeviceMode::Normal && matches!(transport, TransportKind::Usb | TransportKind::WebUsb) =>
                    (SupportStatus::Experimental, true, "Read-only Nokia Care Suite queries require vendor interface 3. Native and user-reported browser identification succeeded on one RM-875; repeatability and broader hardware validation remain pending."),
                Some(d) if matches!(d.mode, DeviceMode::Flash | DeviceMode::BootManager | DeviceMode::PhoneInfo) && matches!(transport, TransportKind::Usb | TransportKind::WebUsb) =>
                    (SupportStatus::Experimental, true, "Read-only NOKV probe available; hardware behavior has not yet been validated."),
                Some(d) if d.mode == DeviceMode::Emergency => (SupportStatus::Unsupported, false, "Emergency devices are enumerated only; no Sahara handshake is sent."),
                Some(_) => (SupportStatus::Unknown, false, "USB descriptors are available; an application-level probe is not implemented for this mode."),
                None => (SupportStatus::Unknown, false, "Connect a device to determine available information queries."),
            }
        } else if host == Host::Browser && matches!(operation, Operation::Backup | Operation::Restore) {
            (SupportStatus::Unsupported, false, "Raw storage access requires the desktop app.")
        } else {
            (SupportStatus::Unknown, false, "Device workflow is not implemented and hardware-validated in this release; execution is blocked.")
        };
        Capability { operation, status, executable, reason: reason.into(), requirements: if executable { vec![] } else { vec!["A complete implementation and recorded validation for the exact device, firmware, host and transport".into()] } }
    }).collect();
    CapabilityReport {
        device_id: device.map(|d| d.id.clone()),
        host,
        transport,
        capabilities,
    }
}
pub fn current_host() -> Host {
    if cfg!(target_arch = "wasm32") {
        Host::Browser
    } else if cfg!(target_os = "windows") {
        Host::Windows
    } else if cfg!(target_os = "macos") {
        Host::Macos
    } else {
        Host::Linux
    }
}
