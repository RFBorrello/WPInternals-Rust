//! Explicit read-only queries for an ALREADY exposed Qualcomm emergency endpoint.
//! USB descriptors/port correlate one session; they do not identify a Lumia or authorize writes.
use super::{
    identity,
    mode_test::{physical_port, PhysicalPort},
    usb_session, PHONE_ACCESS,
};
use nusb::MaybeFuture;
use serde::Serialize;
use std::time::{Duration, Instant};
use wpi_protocol::qualcomm::{dload, v1};
use wpi_types::{DeviceIdentity, DeviceMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Dload,
    ProgrammerV1,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub protocol: Protocol,
    pub vendor_id: u16,
    pub product_id: u16,
    pub requests_sent: usize,
    pub protocol_response_validated: bool,
    pub root_key_available: bool,
    pub descriptors_matched: bool,
    pub physical_port_matched: bool,
    pub identity_authenticated: bool,
    pub lumia_model_identified: bool,
    pub mode_change_sent: bool,
    pub programmer_uploaded: bool,
    pub phone_writes_enabled: bool,
    pub unlock_verified: bool,
    pub data_preservation_validated: bool,
}

#[derive(Clone, PartialEq)]
struct Snapshot {
    descriptor: DeviceIdentity,
    port: Option<PhysicalPort>,
}
impl Snapshot {
    fn of(info: &nusb::DeviceInfo) -> Option<Self> {
        Some(Self {
            descriptor: identity(
                info,
                wpi_core::classify_usb(info.vendor_id(), info.product_id())?,
            ),
            port: physical_port(info),
        })
    }
}
fn admit(selected: &Snapshot) -> Result<(), String> {
    if selected.descriptor.mode != DeviceMode::Emergency
        || selected.descriptor.vendor_id != 0x05c6
        || !matches!(selected.descriptor.product_id, 0x9008 | 0xf006)
    {
        return Err("Select an already exposed recognized emergency USB endpoint; no mode change will be sent".into());
    }
    if selected.port.is_none() {
        return Err("Physical USB port binding is unavailable; no probe will be sent".into());
    }
    Ok(())
}
fn validate(selected: &Snapshot, current: &[Snapshot]) -> Result<(), String> {
    admit(selected)?;
    let by_id: Vec<_> = current
        .iter()
        .filter(|s| s.descriptor.id == selected.descriptor.id)
        .collect();
    if by_id.len() != 1
        || by_id[0] != selected
        || current.iter().filter(|s| s.port == selected.port).count() != 1
    {
        return Err("Selected USB descriptors or physical port changed, disappeared or became ambiguous; inspect device state before selecting again".into());
    }
    Ok(())
}
fn validate_now(selected: &Snapshot) -> Result<(), String> {
    let current: Vec<_> = nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .filter_map(|d| Snapshot::of(&d))
        .collect();
    validate(selected, &current)
}

struct Interface {
    number: u8,
    alternate: u8,
    class: u8,
    /// Address and whether this endpoint is bulk.
    endpoints: Vec<(u8, bool)>,
}
fn select_interface(interfaces: &[Interface]) -> Result<(u8, u8, u8), String> {
    let mut candidates = vec![];
    for i in interfaces
        .iter()
        .filter(|i| i.alternate == 0 && i.class == 0xff)
    {
        let inputs: Vec<_> = i
            .endpoints
            .iter()
            .filter(|(a, bulk)| *bulk && a & 0x80 != 0)
            .collect();
        let outputs: Vec<_> = i
            .endpoints
            .iter()
            .filter(|(a, bulk)| *bulk && a & 0x80 == 0)
            .collect();
        if inputs.len() > 1 || outputs.len() > 1 {
            return Err("Ambiguous emergency bulk endpoints; no interface was claimed".into());
        }
        if let ([input], [output]) = (inputs.as_slice(), outputs.as_slice()) {
            if input.0 & 0x0f == 0
                || output.0 & 0x0f == 0
                || input.0 & 0x70 != 0
                || output.0 & 0x70 != 0
            {
                return Err("Invalid emergency bulk endpoint address".into());
            }
            candidates.push((i.number, input.0, output.0));
        }
    }
    if candidates.len() != 1 {
        return Err("Need exactly one vendor-specific bulk interface; protected USB classes and ambiguous interfaces are not claimed. A serial-only driver needs a separate serial adapter".into());
    }
    Ok(candidates[0])
}

/// No protocol guessing/fallback. DLOAD sends alive + root query; V1 sends Hello only.
/// Private query construction prevents arbitrary commands from reaching this adapter.
fn queries<C, X>(protocol: Protocol, mut check: C, mut exchange: X) -> Result<(usize, bool), String>
where
    C: FnMut() -> Result<(), String>,
    X: FnMut(&[u8]) -> wpi_protocol::Result<Vec<u8>>,
{
    check()?;
    let result = match protocol {
        Protocol::Dload => {
            let alive =
                exchange(&dload::alive().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            dload::check_ack(&alive).map_err(|e| e.to_string())?;
            check()?;
            let root = exchange(&dload::root_key().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            let _root = dload::parse_root(&root).map_err(|e| e.to_string())?;
            (2, true)
        }
        Protocol::ProgrammerV1 => {
            let reply = exchange(&v1::hello()).map_err(|e| e.to_string())?;
            v1::check_ack(&reply, v1::Ack::Hello).map_err(|e| e.to_string())?;
            (1, false)
        }
    };
    check()?;
    Ok(result)
}

pub fn run(id: &str, protocol: Protocol) -> Result<Report, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let selected_infos: Vec<_> = nusb::list_devices()
        .wait()
        .map_err(|e| e.to_string())?
        .filter(|d| format!("{:?}", d.id()) == id)
        .collect();
    if selected_infos.len() != 1 {
        return Err("Scan and explicitly select one connected emergency endpoint".into());
    }
    let info = &selected_infos[0];
    let selected = Snapshot::of(info).ok_or("Unrecognized USB endpoint")?;
    admit(&selected)?;
    validate_now(&selected)?;
    let device = info.open().wait().map_err(|_| "Cannot open selected emergency USB endpoint; check native WinUSB binding or USB permissions")?;
    // Read descriptors only; do not set a configuration, alternate setting or kernel driver.
    let configuration = device.active_configuration().map_err(|_| {
        "Emergency USB configuration is unavailable; no configuration change was attempted"
    })?;
    let interfaces: Vec<_> = configuration
        .interface_alt_settings()
        .map(|i| Interface {
            number: i.interface_number(),
            alternate: i.alternate_setting(),
            class: i.class(),
            endpoints: i
                .endpoints()
                .map(|e| {
                    (
                        e.address(),
                        e.transfer_type() == nusb::descriptors::TransferType::Bulk,
                    )
                })
                .collect(),
        })
        .collect();
    let (number, input, output) = select_interface(&interfaces)?;
    validate_now(&selected)?;
    let interface = device
        .claim_interface(number)
        .wait()
        .map_err(|_| "Cannot claim selected emergency bulk interface; no probe was sent")?;
    let io = usb_session::NativeIo::new(interface, input, output)
        .map_err(|_| "Cannot open emergency bulk endpoints; no probe was sent")?;
    let mut session = usb_session::Session::new(io);
    let deadline = Instant::now() + Duration::from_secs(15);
    let (requests_sent, root_key_available) = queries(
        protocol,
        || validate_now(&selected),
        |request| session.exchange_framed(request, v1::MAX_REPLY_FRAME, Some(deadline)),
    )?;
    Ok(Report {
        protocol,
        vendor_id: selected.descriptor.vendor_id,
        product_id: selected.descriptor.product_id,
        requests_sent,
        protocol_response_validated: true,
        root_key_available,
        descriptors_matched: true,
        physical_port_matched: true,
        identity_authenticated: false,
        lumia_model_identified: false,
        mode_change_sent: false,
        programmer_uploaded: false,
        phone_writes_enabled: false,
        unlock_verified: false,
        data_preservation_validated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, collections::VecDeque};
    use wpi_protocol::{qualcomm::encode_hdlc, ProtocolError};
    fn snapshot() -> Snapshot {
        let mut descriptor: DeviceIdentity = serde_json::from_value(serde_json::json!({
            "id":"selected", "vendor_id":0x05c6,"product_id":0x9008,
            "manufacturer":null,"product":null,"serial":"private-serial",
            "model":null,"variant":null,"firmware":null,"platform_id":null,
            "family":"unknown","mode":"emergency","interfaces":[]
        }))
        .unwrap();
        descriptor.serial = Some("private-serial".into());
        #[cfg(target_os = "windows")]
        let port = PhysicalPort::Windows {
            hub: "private-hub".into(),
            number: 1,
        };
        #[cfg(not(target_os = "windows"))]
        let port = PhysicalPort::Native {
            bus: "private-bus".into(),
            chain: vec![1],
        };
        Snapshot {
            descriptor,
            port: Some(port),
        }
    }
    #[test]
    fn fresh_binding_rejects_changes_absence_and_ambiguity() {
        let selected = snapshot();
        validate(&selected, std::slice::from_ref(&selected)).unwrap();
        assert!(validate(&selected, &[]).is_err());
        assert!(validate(&selected, &[selected.clone(), selected.clone()]).is_err());
        let mut changed = selected.clone();
        changed.descriptor.serial = Some("changed".into());
        assert!(validate(&selected, &[changed]).is_err());
        let mut changed = selected.clone();
        changed.port = None;
        assert!(validate(&selected, std::slice::from_ref(&changed)).is_err());
        assert!(admit(&changed).is_err());
        for (vid, pid, mode) in [
            (0x0421, 0x0661, DeviceMode::Normal),
            (0x0421, 0x066e, DeviceMode::Flash),
            (0x05c6, 0x9006, DeviceMode::MassStorage),
            (0x1234, 0x9008, DeviceMode::Emergency),
        ] {
            let mut changed = selected.clone();
            changed.descriptor.vendor_id = vid;
            changed.descriptor.product_id = pid;
            changed.descriptor.mode = mode;
            assert!(admit(&changed).is_err());
        }
        let mut duplicate_port = selected.clone();
        duplicate_port.descriptor.id = "another".into();
        assert!(validate(&selected, &[selected.clone(), duplicate_port]).is_err());
    }
    fn interface(number: u8) -> Interface {
        Interface {
            number,
            alternate: 0,
            class: 0xff,
            endpoints: vec![(0x81, true), (0x01, true)],
        }
    }
    #[test]
    fn endpoint_selection_requires_one_vendor_bulk_pair() {
        assert_eq!(select_interface(&[interface(2)]).unwrap(), (2, 0x81, 1));
        assert!(select_interface(&[]).is_err());
        assert!(select_interface(&[interface(1), interface(2)]).is_err());
        for class in [2, 8, 0x0a] {
            let mut i = interface(1);
            i.class = class;
            assert!(select_interface(&[i]).is_err());
        }
        let mut i = interface(1);
        i.alternate = 1;
        assert!(select_interface(&[i]).is_err());
        let mut i = interface(1);
        i.endpoints.push((0x82, true));
        assert!(select_interface(&[i]).is_err());
        let mut i = interface(1);
        i.endpoints[0].1 = false;
        assert!(select_interface(&[i]).is_err());
        let mut i = interface(1);
        i.endpoints[0].0 = 0x80;
        assert!(select_interface(&[i]).is_err());
    }
    fn replies() -> VecDeque<wpi_protocol::Result<Vec<u8>>> {
        let mut root = vec![0x18, 1, 0];
        root.extend_from_slice(&[0x55; 32]);
        [encode_hdlc(&[2]), encode_hdlc(&root)].into()
    }
    #[test]
    fn only_explicit_read_only_queries_are_sent_and_binding_is_bookended() {
        for protocol in [Protocol::Dload, Protocol::ProgrammerV1] {
            let count = Cell::new(0);
            let mut requests = vec![];
            let mut replies = replies();
            let (sent, root) = queries(
                protocol,
                || {
                    count.set(count.get() + 1);
                    Ok(())
                },
                |r| {
                    requests.push(r.to_vec());
                    replies.pop_front().unwrap()
                },
            )
            .unwrap();
            if protocol == Protocol::Dload {
                assert_eq!(
                    requests,
                    [dload::alive().unwrap(), dload::root_key().unwrap()]
                );
                assert_eq!((sent, root, count.get()), (2, true, 3));
            } else {
                assert_eq!(requests, [v1::hello()]);
                assert_eq!((sent, root, count.get()), (1, false, 2));
            }
        }
    }
    #[test]
    fn binding_failure_at_every_boundary_stops_without_fallback() {
        for protocol in [Protocol::Dload, Protocol::ProgrammerV1] {
            let boundaries = if protocol == Protocol::Dload { 3 } else { 2 };
            for fail_at in 0..boundaries {
                let checks = Cell::new(0);
                let mut sent = 0;
                let mut replies = replies();
                assert!(queries(
                    protocol,
                    || {
                        let current = checks.get();
                        checks.set(current + 1);
                        if current == fail_at {
                            Err("changed binding".into())
                        } else {
                            Ok(())
                        }
                    },
                    |_| {
                        sent += 1;
                        replies.pop_front().unwrap()
                    }
                )
                .is_err());
                assert_eq!(sent, fail_at);
            }
        }
    }
    #[test]
    fn query_faults_or_invalid_root_never_retry_or_try_another_protocol() {
        for fail_at in 0..2 {
            for invalid in [false, true] {
                let mut sent = 0;
                let mut replies = replies();
                let result = queries(
                    Protocol::Dload,
                    || Ok(()),
                    |_| {
                        let at = sent;
                        sent += 1;
                        let reply = replies.pop_front().unwrap();
                        if at != fail_at {
                            return reply;
                        }
                        if invalid {
                            encode_hdlc(&[0x18, 1, 0])
                        } else {
                            Err(ProtocolError::Transport("disconnect".into()))
                        }
                    },
                );
                assert!(result.is_err());
                assert_eq!(sent, fail_at + 1);
            }
        }
        let mut sent = 0;
        assert!(queries(
            Protocol::ProgrammerV1,
            || Ok(()),
            |_| {
                sent += 1;
                encode_hdlc(&[0x18])
            }
        )
        .is_err());
        assert_eq!(sent, 1);
    }

    #[test]
    fn pinned_reference_queries_pass_through_fragmented_transaction_adapter() {
        struct Pipe {
            requests: VecDeque<Vec<u8>>,
            fragments: VecDeque<Vec<u8>>,
        }
        impl usb_session::Io for Pipe {
            fn packet_size(&self) -> usize {
                64
            }
            fn write(&mut self, bytes: &[u8], _: Duration) -> wpi_protocol::Result<usize> {
                assert_eq!(
                    bytes,
                    self.requests.pop_front().expect("unreviewed command")
                );
                Ok(bytes.len())
            }
            fn read(&mut self, length: usize, _: Duration) -> wpi_protocol::Result<Vec<u8>> {
                let fragment = self.fragments.pop_front().expect("excess read");
                assert!(fragment.len() <= length);
                Ok(fragment)
            }
            fn cancel(&mut self) {
                panic!("reference success must not cancel");
            }
        }
        for (protocol, fixture, count) in [
            (
                Protocol::Dload,
                include_str!("../../../tests/fixtures/spec-a-dload.json"),
                2,
            ),
            (
                Protocol::ProgrammerV1,
                include_str!("../../../tests/fixtures/spec-a-programmer-v1.json"),
                1,
            ),
        ] {
            let fixture: serde_json::Value = serde_json::from_str(fixture).unwrap();
            assert_eq!(
                fixture["reference_commit"],
                "d8fd0aa516b16dc094df0422a3adc525af005c29"
            );
            let exchanges = fixture["exchanges"].as_array().unwrap();
            for fragment_length in [1, 3, 64] {
                let mut requests = VecDeque::new();
                let mut fragments = VecDeque::new();
                for exchange in exchanges.iter().take(count) {
                    let request: Vec<u8> =
                        serde_json::from_value(exchange["request"].clone()).unwrap();
                    let response: Vec<u8> =
                        serde_json::from_value(exchange["response"].clone()).unwrap();
                    requests.push_back(request);
                    fragments.extend(response.chunks(fragment_length).map(|c| c.to_vec()));
                }
                let mut session = usb_session::Session::new(Pipe {
                    requests,
                    fragments,
                });
                let result = queries(
                    protocol,
                    || Ok(()),
                    |r| session.exchange_framed(r, v1::MAX_REPLY_FRAME, None),
                )
                .unwrap();
                assert_eq!(result, (count, protocol == Protocol::Dload));
                // An unexpected extra request/read panics in Pipe; transcript commands
                // include no loader, security, partition, reboot or write operations.
            }
        }
    }
}
