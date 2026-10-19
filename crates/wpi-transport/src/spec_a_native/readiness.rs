//! Read-only host prerequisites. Historical driver bindings are availability
//! evidence, never device identity or proof that a future endpoint will open.
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize)]
pub struct Readiness {
    pub supported_experiment_host: bool,
    pub administrator_ready: bool,
    pub known_emergency_endpoint_count: u32,
    pub known_winusb_bindings: u32,
    pub usable_winusb_bindings: u32,
    pub present_emergency_endpoint_count: u32,
    pub endpoints: Vec<Endpoint>,
    pub prerequisites_met: bool,
    pub phone_contacted: bool,
    pub driver_changes_sent: bool,
    pub hardware_validated: bool,
    pub messages: Vec<&'static str>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bindings {
    endpoints: Vec<Endpoint>,
}
/// Sanitized PnP facts only. No instance ID, serial, path, GUID or device label.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub product_id: u16,
    pub present: bool,
    pub setup_class: SetupClass,
    pub service: Service,
    pub problem_code: Option<u32>,
    pub protected_class: bool,
    pub winusb_compatible_id: bool,
    pub interface_guid_registered: bool,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupClass {
    UsbDevice,
    Hid,
    Ports,
    Other,
    Unknown,
}
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Winusb,
    Hidusb,
    Serial,
    Other,
    None,
}
impl Endpoint {
    fn usable_binding(&self) -> bool {
        self.service == Service::Winusb
            && self.setup_class == SetupClass::UsbDevice
            && !self.protected_class
            && self.interface_guid_registered
            // A historical devnode need not have a current problem code. A
            // present devnode must positively report no configuration problem.
            && (!self.present || self.problem_code == Some(0))
    }
}
#[cfg(any(windows, test))]
fn parse(bytes: &[u8]) -> Result<Bindings, String> {
    let b: Bindings =
        serde_json::from_slice(bytes).map_err(|_| "Invalid emergency driver readiness metadata")?;
    if b.endpoints.len() > 64
        || b.endpoints
            .iter()
            .any(|e| !matches!(e.product_id, 0x9008 | 0xf006))
    {
        return Err("Invalid emergency driver readiness inventory".into());
    }
    Ok(b)
}
pub fn inspect() -> Result<Readiness, String> {
    let supported = cfg!(all(target_os = "windows", target_arch = "aarch64"));
    let admin = wpi_storage::raw_access_prerequisite().is_ok();
    let bindings = bindings()?;
    Ok(report(supported, admin, bindings))
}
fn report(supported: bool, admin: bool, bindings: Bindings) -> Readiness {
    let known = bindings.endpoints.len() as u32;
    let winusb = bindings
        .endpoints
        .iter()
        .filter(|e| e.service == Service::Winusb)
        .count() as u32;
    let usable = bindings
        .endpoints
        .iter()
        .filter(|e| e.usable_binding())
        .count() as u32;
    let present = bindings.endpoints.iter().filter(|e| e.present).count() as u32;
    let mut messages = vec!["Historical WinUSB binding availability is not authentication or positive validation of the future emergency/programmer endpoint."];
    if !supported {
        messages.push("The initial native unlock experiment supports Windows ARM64 only.");
    }
    if !admin {
        messages.push("Run the reviewed native CLI from an Administrator terminal before any mode change; no elevation was attempted.");
    }
    if usable == 0 {
        messages.push("No usable historical emergency WinUSB binding with a registered interface GUID was found. Verify the actual phone endpoint before choosing a binding; no driver was installed or changed.");
    }
    if bindings.endpoints.iter().any(|e| {
        e.protected_class || e.setup_class == SetupClass::Hid || e.service == Service::Hidusb
    }) {
        messages.push("A matching VID/PID has protected/HID-class metadata. Leave its class driver intact; VID/PID alone is not evidence that it is the phone's bulk emergency endpoint.");
    }
    if bindings
        .endpoints
        .iter()
        .any(|e| e.setup_class == SetupClass::Ports || e.service == Service::Serial)
    {
        messages.push("A matching endpoint uses serial access. The native unlock controller has no serial fallback; do not replace a class driver based only on this report.");
    }
    if bindings
        .endpoints
        .iter()
        .any(|e| e.service == Service::Winusb && !e.interface_guid_registered)
    {
        messages.push("A WinUSB service without a registered device interface GUID is insufficient for application discovery.");
    }
    messages.push("A future phone disk must already be offline/read-only before capture; this check changes no disk attributes.");
    Readiness {
        supported_experiment_host: supported,
        administrator_ready: admin,
        known_emergency_endpoint_count: known,
        known_winusb_bindings: winusb,
        usable_winusb_bindings: usable,
        present_emergency_endpoint_count: present,
        endpoints: bindings.endpoints,
        prerequisites_met: supported && admin && usable > 0,
        phone_contacted: false,
        driver_changes_sent: false,
        hardware_validated: false,
        messages,
    }
}
#[cfg(not(windows))]
fn bindings() -> Result<Bindings, String> {
    Ok(Bindings {
        endpoints: Vec::new(),
    })
}
#[cfg(windows)]
fn bindings() -> Result<Bindings, String> {
    use std::{
        io::Read,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut directory = vec![0u16; 32768];
    // SAFETY: the supplied output buffer is writable for the exact element count.
    let n =
        unsafe { GetWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if n == 0 || n >= directory.len() {
        return Err("Cannot locate native Windows system directory".into());
    }
    let executable = std::path::PathBuf::from(String::from_utf16_lossy(&directory[..n]))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script = include_str!("readiness.ps1");
    let mut child = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(super::text)?;
    let pipe = child
        .stdout
        .take()
        .ok_or("Driver readiness output unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.take(65537).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(match other {
                    Err(e) => e.to_string(),
                    _ => "Emergency driver readiness timed out".into(),
                });
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "Driver readiness reader failed")?
        .map_err(super::text)?;
    if !result?.success() || bytes.len() > 65536 {
        return Err("Emergency driver readiness failed; no phone command was sent".into());
    }
    parse(&bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn driver_inventory_fails_closed_for_unknown_truncated_or_impossible_metadata() {
        assert!(parse(br#"{"endpoints":[]}"#).unwrap().endpoints.is_empty());
        for bytes in [
            br#"{"known":1,"winusb":1}"#.as_slice(),
            br#"{"endpoints":[],"guess":true}"#,
            br#"{"endpoints":[],"instance_id":"private"}"#,
            br#"{"endpoints":[{}]}"#,
            br#"{"endpoints":null}"#,
            br#"{"endpoints":[]"#,
        ] {
            assert!(parse(bytes).is_err());
        }
    }

    fn endpoint() -> Endpoint {
        Endpoint {
            product_id: 0x9008,
            present: false,
            setup_class: SetupClass::UsbDevice,
            service: Service::Winusb,
            problem_code: None,
            protected_class: false,
            winusb_compatible_id: false,
            interface_guid_registered: true,
        }
    }
    fn with(e: Endpoint) -> Readiness {
        report(true, true, Bindings { endpoints: vec![e] })
    }
    #[test]
    fn winusb_service_alone_does_not_admit_unknown_protected_or_unregistered_interfaces() {
        assert!(with(endpoint()).prerequisites_met);
        for class in [
            SetupClass::Hid,
            SetupClass::Ports,
            SetupClass::Other,
            SetupClass::Unknown,
        ] {
            let mut e = endpoint();
            e.setup_class = class;
            assert!(!with(e).prerequisites_met);
        }
        let mut e = endpoint();
        e.protected_class = true;
        assert!(!with(e).prerequisites_met);
        let mut e = endpoint();
        e.interface_guid_registered = false;
        assert!(!with(e).prerequisites_met);
        let mut e = endpoint();
        e.service = Service::Hidusb;
        assert!(!with(e).prerequisites_met);
    }
    #[test]
    fn present_problem_codes_fail_closed_and_success_never_claims_hardware_validation() {
        for code in [None, Some(10), Some(28), Some(45)] {
            let mut e = endpoint();
            e.present = true;
            e.problem_code = code;
            assert!(!with(e).prerequisites_met);
        }
        let mut e = endpoint();
        e.present = true;
        e.problem_code = Some(0);
        let r = with(e);
        assert!(r.prerequisites_met);
        assert_eq!(r.present_emergency_endpoint_count, 1);
        assert!(!r.phone_contacted && !r.driver_changes_sent && !r.hardware_validated);
        assert!(
            !report(
                false,
                true,
                Bindings {
                    endpoints: vec![endpoint()]
                }
            )
            .prerequisites_met
        );
        assert!(
            !report(
                true,
                false,
                Bindings {
                    endpoints: vec![endpoint()]
                }
            )
            .prerequisites_met
        );
    }
    #[test]
    fn bounded_inventory_rejects_unexpected_products_and_private_metadata() {
        let mut e = endpoint();
        e.product_id = 0x0661;
        assert!(
            parse(&serde_json::to_vec(&serde_json::json!({"endpoints": [e]})).unwrap()).is_err()
        );
        let entries: Vec<_> = (0..65).map(|_| endpoint()).collect();
        assert!(
            parse(&serde_json::to_vec(&serde_json::json!({"endpoints": entries})).unwrap())
                .is_err()
        );
        let mut e = serde_json::to_value(endpoint()).unwrap();
        e["instance_id"] = "private".into();
        assert!(
            parse(&serde_json::to_vec(&serde_json::json!({"endpoints": [e]})).unwrap()).is_err()
        );
    }
}
