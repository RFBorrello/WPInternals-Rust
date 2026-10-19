//! Read-only host prerequisites. Historical driver bindings are availability
//! evidence, never device identity or proof that a future endpoint will open.
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize)]
pub struct Readiness {
    pub supported_experiment_host: bool,
    pub administrator_ready: bool,
    pub known_emergency_endpoint_count: u32,
    pub known_winusb_bindings: u32,
    pub prerequisites_met: bool,
    pub phone_contacted: bool,
    pub driver_changes_sent: bool,
    pub hardware_validated: bool,
    pub messages: Vec<&'static str>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bindings {
    known: u32,
    winusb: u32,
}
#[cfg(any(windows, test))]
fn parse(bytes: &[u8]) -> Result<Bindings, String> {
    let b: Bindings =
        serde_json::from_slice(bytes).map_err(|_| "Invalid emergency driver readiness metadata")?;
    if b.known > 64 || b.winusb > b.known {
        return Err("Invalid emergency driver readiness counts".into());
    }
    Ok(b)
}
pub fn inspect() -> Result<Readiness, String> {
    let supported = cfg!(all(target_os = "windows", target_arch = "aarch64"));
    let admin = wpi_storage::raw_access_prerequisite().is_ok();
    let bindings = bindings()?;
    let mut messages = vec!["Historical WinUSB binding availability is not authentication or positive validation of the future emergency/programmer endpoint."];
    if !supported {
        messages.push("The initial native unlock experiment supports Windows ARM64 only.");
    }
    if !admin {
        messages.push("Run the reviewed native CLI from an Administrator terminal before any mode change; no elevation was attempted.");
    }
    if bindings.winusb == 0 {
        messages.push("No known Qualcomm emergency endpoint has a WinUSB binding. Set up native ARM64 WinUSB access before emergency entry; no driver was installed or changed.");
    }
    messages.push("A future phone disk must already be offline/read-only before capture; this check changes no disk attributes.");
    Ok(Readiness {
        supported_experiment_host: supported,
        administrator_ready: admin,
        known_emergency_endpoint_count: bindings.known,
        known_winusb_bindings: bindings.winusb,
        prerequisites_met: supported && admin && bindings.winusb > 0,
        phone_contacted: false,
        driver_changes_sent: false,
        hardware_validated: false,
        messages,
    })
}
#[cfg(not(windows))]
fn bindings() -> Result<Bindings, String> {
    Ok(Bindings {
        known: 0,
        winusb: 0,
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
    let script = r#"
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $devices = @(Get-PnpDevice | Where-Object { $_.InstanceId -match '^USB\\VID_05C6&PID_(9008|F006)' } | Select-Object -First 65)
        if ($devices.Count -gt 64) { throw 'Emergency device inventory exceeds bound' }
        $winusb = 0
        foreach ($device in $devices) {
            $service = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_Service'
            if ($service.Data -eq 'WinUSB') { $winusb++ }
        }
        @{ known = $devices.Count; winusb = $winusb } | ConvertTo-Json -Compress
    "#;
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
        pipe.take(8193).read_to_end(&mut bytes).map(|_| bytes)
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
    if !result?.success() || bytes.len() > 8192 {
        return Err("Emergency driver readiness failed; no phone command was sent".into());
    }
    parse(&bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn driver_counts_fail_closed_for_unknown_truncated_or_impossible_metadata() {
        assert_eq!(parse(br#"{"known":1,"winusb":0}"#).unwrap().winusb, 0);
        assert_eq!(parse(br#"{"known":1,"winusb":1}"#).unwrap().winusb, 1);
        for bytes in [
            br#"{"known":0,"winusb":1}"#.as_slice(),
            br#"{"known":65,"winusb":1}"#,
            br#"{"known":1}"#,
            br#"{"known":1,"winusb":1,"guess":true}"#,
            br#"{"known":1,"winusb":1"#,
        ] {
            assert!(parse(bytes).is_err());
        }
    }
}
