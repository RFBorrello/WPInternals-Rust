//! Explicit read-only identity research. No mode change or production gate bypass.
use super::{open_selected, probe_session, PHONE_ACCESS};
use serde::Serialize;
use std::time::{Duration, Instant};
use wpi_protocol::{flash, identity, MessageTransport};
use wpi_types::*;

#[derive(Debug, Serialize)]
pub struct IdentityProbeReport {
    pub device: DeviceIdentity,
    pub info: Option<flash::FlashInfo>,
    pub public_id_available: bool,
    pub public_id_bytes_exported: bool,
    pub physical_port_binding_available: bool,
    pub usb_serial_available: bool,
    pub firmware_query: Option<FirmwareQueryReport>,
    pub identity_authenticated: bool,
    pub mode_change_sent: bool,
    pub recovery_authorized: bool,
}
#[derive(Debug, Serialize)]
pub struct FirmwareQueryReport {
    pub successful: bool,
    pub error: Option<String>,
    pub response_length: Option<usize>,
    pub response_signature: Option<String>,
}

/// Reads one public ID, discards its bytes and exports presence only.
/// A Flash-mode query requires explicit caller selection, not correlation by a model label.
pub fn run(id: &str) -> Result<IdentityProbeReport, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let physical_port_binding_available = super::mode_test::port_available(id)?;
    let (mut device, mut transport) = open_selected(id)?;
    transport.deadline = Some(Instant::now() + Duration::from_secs(20));
    let (info, firmware_query) = match device.mode {
        DeviceMode::Normal => {
            let normal = probe_session(device, &mut transport, true)?;
            device = normal.device;
            let _local_id = identity::read_normal(&mut transport, 3).map_err(|e| e.to_string())?;
            (None, None)
        }
        DeviceMode::Flash => {
            let info = flash::read_info(&mut transport).map_err(|e| e.to_string())?;
            if info.mode != DeviceMode::Flash {
                return Err("Public-ID inspection currently requires Normal or FlashApp, not BootManager/PhoneInfo".into());
            }
            device.mode = info.mode;
            device.platform_id = info.platform_id.clone();
            let _local_id = identity::read_flash(&mut transport).map_err(|e| e.to_string())?;
            // This is the final query: a failed FVER never leads to another query or command.
            let (firmware, query) = read_firmware(&mut transport);
            device.firmware = firmware;
            (Some(info), Some(query))
        }
        _ => return Err("Unsupported public-ID transport mode".into()),
    };
    let usb_serial_available = device
        .serial
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    device.serial = None;
    device.id = "selected-device".into();
    Ok(IdentityProbeReport {
        device,
        info,
        firmware_query,
        public_id_available: true,
        public_id_bytes_exported: false,
        physical_port_binding_available,
        usb_serial_available,
        identity_authenticated: false,
        mode_change_sent: false,
        recovery_authorized: false,
    })
}
fn read_firmware<T: MessageTransport>(transport: &mut T) -> (Option<String>, FirmwareQueryReport) {
    let response = transport.exchange(
        &flash::parameter_request("FVER").expect("fixed parameter"),
        65536,
    );
    let response_length = response.as_ref().ok().map(Vec::len);
    // Only the six-byte command signature is recorded; never the parameter payload.
    let response_signature = response.as_ref().ok().map(|bytes| {
        bytes
            .iter()
            .take(6)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
    let value = response
        .and_then(|r| flash::parse_parameter(&r))
        .and_then(|v| {
            String::from_utf8(v).map_err(|_| {
                wpi_protocol::ProtocolError::Invalid("non-UTF8 firmware parameter".into())
            })
        })
        .and_then(|v| {
            let v = v.trim_matches('\0');
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic()) {
                Err(wpi_protocol::ProtocolError::Invalid(
                    "empty or invalid firmware parameter".into(),
                ))
            } else {
                Ok(v.to_owned())
            }
        });
    let (firmware, error) = match value {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e.to_string())),
    };
    (
        firmware.clone(),
        FirmwareQueryReport {
            successful: firmware.is_some(),
            error,
            response_length,
            response_signature,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wpi_protocol::replay::{Exchange, ReplayTransport};
    #[test]
    fn firmware_failures_preserve_diagnostics_and_never_retry() {
        for response in [b"NOKU".to_vec(), b"BADHDR".to_vec(), vec![], {
            let mut r = vec![0; 17];
            r[..6].copy_from_slice(b"NOKXFR");
            r
        }] {
            let mut replay = ReplayTransport::new(vec![Exchange {
                request: flash::parameter_request("FVER").unwrap(),
                response: response.clone(),
                error: None,
            }]);
            let (fw, report) = read_firmware(&mut replay);
            assert!(fw.is_none());
            assert!(!report.successful);
            assert!(report.error.is_some());
            assert_eq!(report.response_length, Some(response.len()));
            assert!(replay.finished());
        }
        let mut replay = ReplayTransport::new(vec![Exchange {
            request: flash::parameter_request("FVER").unwrap(),
            response: vec![],
            error: Some("disconnected".into()),
        }]);
        let (_, report) = read_firmware(&mut replay);
        assert!(report.error.unwrap().contains("disconnected"));
        assert!(report.response_length.is_none());
        assert!(replay.finished());
    }
    #[test]
    fn valid_firmware_payload_is_not_in_diagnostic_signature() {
        let mut response = vec![0; 17];
        response[..6].copy_from_slice(b"NOKXFR");
        response[16] = 5;
        response.extend_from_slice(b"TEST\0");
        let mut replay = ReplayTransport::new(vec![Exchange {
            request: flash::parameter_request("FVER").unwrap(),
            response,
            error: None,
        }]);
        let (fw, report) = read_firmware(&mut replay);
        assert_eq!(fw.as_deref(), Some("TEST"));
        assert!(report.successful);
        assert_eq!(report.response_signature.as_deref(), Some("4e4f4b584652"));
        assert!(report.error.is_none());
        assert!(replay.finished());
    }
}
