//! Native adapters; raw block devices are intentionally never opened by an arbitrary path.
use nusb::MaybeFuture;
use serde::Serialize;
use std::{sync::Mutex, time::Instant};
use wpi_protocol::MessageTransport;
use wpi_types::*;
pub mod arrival;
mod device_binding;
pub mod emergency_probe;
pub mod identity_probe;
pub mod mode_test;
pub mod serial_probe;
pub mod spec_a_preflight;
pub mod spec_a_session;
mod usb_session;
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
            "This probe supports only Lumia normal/flash interfaces. Use the explicitly selected read-only emergency probe for an already exposed emergency interface."
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

/// Native single-message USB adapter. An uncertain transfer permanently retires
/// this handle; callers must inspect device state before opening another session.
pub struct UsbMessages {
    session: usb_session::Session<usb_session::NativeIo>,
    deadline: Option<Instant>,
}
impl UsbMessages {
    pub fn new(interface: nusb::Interface, input: u8, output: u8) -> Result<Self, nusb::Error> {
        Ok(Self {
            session: usb_session::Session::new(usb_session::NativeIo::new(
                interface, input, output,
            )?),
            deadline: None,
        })
    }
    /// One OUT transfer only. A short completion is an error, never a remainder retry.
    fn send_once(&mut self, request: &[u8]) -> wpi_protocol::Result<()> {
        self.session.send_once(request, self.deadline)
    }
}
impl MessageTransport for UsbMessages {
    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response: usize,
    ) -> wpi_protocol::Result<Vec<u8>> {
        self.session
            .exchange(request, maximum_response, self.deadline)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
