//! Native adapters; raw block devices are intentionally never opened by an arbitrary path.
use nusb::MaybeFuture;
use serde::Serialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use wpi_protocol::{MessageTransport, ProtocolError};
use wpi_types::*;
pub mod identity_probe;
pub mod mode_test;
static PHONE_ACCESS: Mutex<()> = Mutex::new(());

pub fn enumerate() -> Result<Vec<DeviceIdentity>, String> {
    let devices = nusb::list_devices()
        .wait()
        .map_err(|e| format!("USB discovery failed: {e}"))?;
    Ok(devices
        .filter_map(|info| {
            let mode = wpi_core::classify_usb(info.vendor_id(), info.product_id())?;
            Some(identity(&info, mode))
        })
        .collect())
}
fn identity(info: &nusb::DeviceInfo, mode: DeviceMode) -> DeviceIdentity {
    DeviceIdentity {
        id: format!("{:?}", info.id()),
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        manufacturer: info.manufacturer_string().map(str::to_owned),
        product: info.product_string().map(str::to_owned),
        serial: info.serial_number().map(str::to_owned),
        model: None,
        variant: None,
        firmware: None,
        platform_id: None,
        family: BootloaderFamily::Unknown,
        mode,
        interfaces: info
            .interfaces()
            .map(|i| UsbInterface {
                number: i.interface_number(),
                class: i.class(),
                subclass: i.subclass(),
                protocol: i.protocol(),
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub device: DeviceIdentity,
    pub info: Option<wpi_protocol::flash::FlashInfo>,
    pub normal: Option<wpi_protocol::normal::NormalInfo>,
    pub firmware: Option<String>,
}

pub fn probe(id: &str) -> Result<ProbeResult, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let (identity, mut transport) = open_selected(id)?;
    probe_session(identity, &mut transport, false)
}
fn open_selected(id: &str) -> Result<(DeviceIdentity, UsbMessages), String> {
    let info = nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .find(|d| format!("{:?}", d.id()) == id)
        .ok_or("Device disconnected; scan and select it again")?;
    let mode = wpi_core::classify_usb(info.vendor_id(), info.product_id())
        .ok_or("Not a recognized Lumia interface")?;
    if !matches!(mode, DeviceMode::Flash | DeviceMode::Normal) {
        return Err(
            "This release probes only Lumia normal/flash interfaces. Emergency mode is enumeration-only."
                .into(),
        );
    }
    let device_identity = identity(&info, mode);
    let device = info.open().wait().map_err(|e| {
        format!("Cannot open device: {e}. Check WinUSB binding or USB permissions.")
    })?;
    if device.active_configuration().is_err() {
        // Do not change the configuration on Windows or guess a configuration value.
        #[cfg(not(target_os = "windows"))]
        {
            let value = device
                .configurations()
                .next()
                .ok_or("No USB configuration descriptors")?
                .configuration_value();
            device
                .set_configuration(value)
                .wait()
                .map_err(|e| e.to_string())?;
        }
    }
    let configuration = device.active_configuration().map_err(|e| e.to_string())?;
    let candidate = configuration
        .interface_alt_settings()
        .filter(|i| {
            i.alternate_setting() == 0
                && i.class() == 0xff
                && (mode != DeviceMode::Normal || i.interface_number() == 3)
        })
        .find_map(|i| {
            let input = i.endpoints().find(|e| {
                e.transfer_type() == nusb::descriptors::TransferType::Bulk
                    && e.address() & 0x80 != 0
            })?;
            let output = i.endpoints().find(|e| {
                e.transfer_type() == nusb::descriptors::TransferType::Bulk
                    && e.address() & 0x80 == 0
            })?;
            Some((i.interface_number(), input.address(), output.address()))
        })
        .ok_or("No vendor-specific bulk interface; refusing to claim a protected USB class")?;
    let interface = device
        .claim_interface(candidate.0)
        .wait()
        .map_err(|e| format!("Cannot claim USB interface: {e}"))?;
    let transport =
        UsbMessages::new(interface, candidate.1, candidate.2).map_err(|e| e.to_string())?;
    Ok((device_identity, transport))
}
fn probe_session(
    mut device_identity: DeviceIdentity,
    transport: &mut UsbMessages,
    strict_firmware: bool,
) -> Result<ProbeResult, String> {
    if device_identity.mode == DeviceMode::Normal {
        let normal = wpi_protocol::normal::read_info(transport).map_err(|e| e.to_string())?;
        let variant = normal
            .manufacturer_model
            .split('_')
            .next()
            .unwrap_or_default();
        wpi_core::profiles::apply_variant(&mut device_identity, variant);
        device_identity.firmware = Some(normal.firmware.clone());
        return Ok(ProbeResult {
            device: device_identity,
            info: None,
            firmware: Some(normal.firmware.clone()),
            normal: Some(normal),
        });
    }
    let flash = wpi_protocol::flash::read_info(transport).map_err(|e| e.to_string())?;
    device_identity.mode = flash.mode;
    device_identity.platform_id = flash.platform_id.clone();
    // Reading FVER does not switch contexts. Do not query phone-info variables by
    // silently sending a context switch (upstream's extended info does that).
    let firmware = if flash.mode == DeviceMode::Flash {
        let value = transport
            .exchange(
                &wpi_protocol::flash::parameter_request("FVER").map_err(|e| e.to_string())?,
                65536,
            )
            .and_then(|r| wpi_protocol::flash::parse_parameter(&r));
        if strict_firmware {
            Some(
                String::from_utf8_lossy(&value.map_err(|e| e.to_string())?)
                    .trim_matches('\0')
                    .to_owned(),
            )
        } else {
            value
                .ok()
                .map(|s| String::from_utf8_lossy(&s).trim_matches('\0').to_owned())
        }
    } else {
        None
    };
    device_identity.firmware = firmware.clone();
    Ok(ProbeResult {
        device: device_identity,
        info: Some(flash),
        normal: None,
        firmware,
    })
}

pub struct UsbMessages {
    input: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::In>,
    output: nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::Out>,
    deadline: Option<Instant>,
}
impl UsbMessages {
    pub fn new(interface: nusb::Interface, input: u8, output: u8) -> Result<Self, nusb::Error> {
        use nusb::transfer::{Bulk, In, Out};
        Ok(Self {
            input: interface.endpoint::<Bulk, In>(input)?,
            output: interface.endpoint::<Bulk, Out>(output)?,
            deadline: None,
        })
    }
    fn timeout(&self) -> wpi_protocol::Result<Duration> {
        let timeout = self.deadline.map_or(Duration::from_secs(5), |d| {
            d.saturating_duration_since(Instant::now())
                .min(Duration::from_secs(5))
        });
        if timeout.is_zero() {
            return Err(ProtocolError::Transport(
                "USB operation deadline expired".into(),
            ));
        }
        Ok(timeout)
    }
    /// One OUT transfer only. A short completion is an error, never a remainder retry.
    fn send_once(&mut self, request: &[u8]) -> wpi_protocol::Result<()> {
        use nusb::transfer::Buffer;
        if request.is_empty() || request.len() > 65536 {
            return Err(ProtocolError::Invalid(
                "invalid native request bound".into(),
            ));
        }
        let timeout = self.timeout()?;
        self.output.submit(Buffer::from(request.to_vec()));
        let result = self.output.wait_next_complete(timeout);
        if let Some(result) = result {
            result
                .status
                .map_err(|e| ProtocolError::Transport(e.to_string()))?;
            if result.actual_len != request.len() {
                return Err(ProtocolError::Transport(
                    "Incomplete USB OUT transfer; no retry was sent".into(),
                ));
            }
            Ok(())
        } else {
            self.output.cancel_all();
            Err(ProtocolError::Transport(
                "USB OUT timed out; delivery is uncertain and must not be retried".into(),
            ))
        }
    }
}
impl MessageTransport for UsbMessages {
    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response: usize,
    ) -> wpi_protocol::Result<Vec<u8>> {
        if maximum_response == 0 || maximum_response > 1024 * 1024 {
            return Err(ProtocolError::Invalid("invalid response bound".into()));
        }
        self.send_once(request)?;
        let timeout = self.timeout()?;
        let packet = self.input.max_packet_size();
        if packet == 0 {
            return Err(ProtocolError::Invalid("USB IN packet size is zero".into()));
        }
        let length = maximum_response.div_ceil(packet) * packet;
        self.input.submit(nusb::transfer::Buffer::new(length));
        let result = self.input.wait_next_complete(timeout).ok_or_else(|| {
            self.input.cancel_all();
            ProtocolError::Transport("USB IN timed out; inspect state before retrying".into())
        })?;
        result
            .status
            .map_err(|e| ProtocolError::Transport(e.to_string()))?;
        if result.actual_len == 0 {
            return Err(ProtocolError::Transport("device disconnected".into()));
        }
        if result.actual_len > maximum_response {
            return Err(ProtocolError::Invalid("USB response exceeds bound".into()));
        }
        Ok(result.buffer.into_vec())
    }
}

#[derive(Debug, Serialize)]
pub struct SerialCandidate {
    pub port: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
}
pub fn serial_candidates() -> Result<Vec<SerialCandidate>, String> {
    Ok(serialport::available_ports()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter_map(|p| {
            if let serialport::SerialPortType::UsbPort(usb) = p.port_type {
                wpi_core::classify_usb(usb.vid, usb.pid)?;
                Some(SerialCandidate {
                    port: p.port_name,
                    vendor_id: usb.vid,
                    product_id: usb.pid,
                    serial: usb.serial_number,
                })
            } else {
                None
            }
        })
        .collect())
}
