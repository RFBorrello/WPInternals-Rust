//! Fixed read-only emergency queries over a freshly correlated native serial port.
use super::{
    device_binding::{self, Snapshot},
    emergency_probe::{self, Protocol, Report},
    usb_session::{Io, Session},
    SerialCandidate, PHONE_ACCESS,
};
use serde::Serialize;
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};
use wpi_protocol::{qualcomm::v1::MAX_REPLY_FRAME, ProtocolError};

#[derive(Debug, Serialize)]
pub struct SerialReport {
    pub probe: Report,
    pub transport: &'static str,
    pub serial_metadata_matched: bool,
    pub port_name_exported: bool,
}

fn correlate<'a>(
    name: &str,
    usb: &Snapshot,
    ports: &'a [SerialCandidate],
) -> Result<&'a SerialCandidate, String> {
    emergency_probe::admit(usb)?;
    let serial = usb
        .descriptor
        .serial
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or("USB serial metadata is missing; cannot bind a serial port to this USB device")?;
    let selected: Vec<_> = ports.iter().filter(|p| p.port == name).collect();
    if selected.len() != 1 {
        return Err("Select exactly one currently enumerated recognized USB serial port; arbitrary paths are not opened".into());
    }
    let matches = |p: &&SerialCandidate| {
        p.vendor_id == usb.descriptor.vendor_id
            && p.product_id == usb.descriptor.product_id
            && p.serial.as_deref() == Some(serial)
    };
    if !matches(&selected[0]) || ports.iter().filter(matches).count() != 1 {
        return Err(
            "Serial-to-USB metadata is missing, different or ambiguous; no serial port was opened"
                .into(),
        );
    }
    Ok(selected[0])
}
fn validate(
    usb: &Snapshot,
    port: &SerialCandidate,
    devices: &[Snapshot],
    ports: &[SerialCandidate],
) -> Result<(), String> {
    emergency_probe::validate(usb, devices)?;
    if devices
        .iter()
        .filter(|s| {
            s.descriptor.vendor_id == usb.descriptor.vendor_id
                && s.descriptor.product_id == usb.descriptor.product_id
                && s.descriptor.serial == usb.descriptor.serial
        })
        .count()
        != 1
    {
        return Err(
            "Multiple USB devices share the serial metadata; cannot bind the selected serial port"
                .into(),
        );
    }
    if correlate(&port.port, usb, ports)? != port {
        return Err("Selected serial port metadata changed; inspect device state".into());
    }
    Ok(())
}
fn validate_now(usb: &Snapshot, port: &SerialCandidate) -> Result<(), String> {
    validate(
        usb,
        port,
        &device_binding::scan()?,
        &super::serial_candidates()?,
    )
}

/// Synchronous calls only: no write_all, flush, buffer purge, line toggles or retry.
trait Port {
    fn timeout(&mut self, value: Duration) -> Result<(), ()>;
    fn pending(&self) -> Result<u32, ()>;
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize>;
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize>;
}
struct NativePort(Box<dyn serialport::SerialPort>);
impl Port for NativePort {
    fn timeout(&mut self, value: Duration) -> Result<(), ()> {
        self.0.set_timeout(value).map_err(|_| ())
    }
    fn pending(&self) -> Result<u32, ()> {
        self.0.bytes_to_read().map_err(|_| ())
    }
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes)
    }
}
struct SerialIo<P> {
    port: Option<P>,
}
impl<P: Port> SerialIo<P> {
    fn new(port: P) -> wpi_protocol::Result<Self> {
        // Reject pending data observed after open instead of discarding it and
        // treating a later fragment as an apparent reply. OS open behavior varies.
        if port
            .pending()
            .map_err(|_| error("Cannot inspect serial input queue"))?
            != 0
        {
            return Err(error("Serial input already contains data; inspect state instead of purging or guessing a protocol"));
        }
        Ok(Self { port: Some(port) })
    }
    fn port(&mut self, timeout: Duration) -> wpi_protocol::Result<&mut P> {
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| error("Serial handle is closed"))?;
        port.timeout(timeout)
            .map_err(|_| error("Cannot set bounded serial timeout"))?;
        Ok(port)
    }
}
fn error(message: &str) -> ProtocolError {
    ProtocolError::Transport(message.into())
}
impl<P: Port> Io for SerialIo<P> {
    fn packet_size(&self) -> usize {
        256
    }
    fn write(&mut self, bytes: &[u8], timeout: Duration) -> wpi_protocol::Result<usize> {
        self.port(timeout)?
            .write(bytes)
            .map_err(|_| error("Serial output failed; delivery is uncertain"))
    }
    fn read(&mut self, length: usize, timeout: Duration) -> wpi_protocol::Result<Vec<u8>> {
        if length == 0 || length > MAX_REPLY_FRAME {
            return Err(error("Invalid serial read allocation"));
        }
        let mut bytes = vec![0; length];
        let count = self
            .port(timeout)?
            .read(&mut bytes)
            .map_err(|_| error("Serial input failed or timed out; command outcome is uncertain"))?;
        if count > length {
            return Err(error("Invalid serial completion length"));
        }
        bytes.truncate(count);
        Ok(bytes)
    }
    fn cancel(&mut self) {
        // Close instead of clearing queues or attempting cleanup commands. Already
        // accepted driver output cannot be unsent by retiring this handle.
        self.port.take();
    }
}

pub fn run(name: &str, usb_id: &str, protocol: Protocol) -> Result<SerialReport, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let usb = device_binding::selected(usb_id)?;
    emergency_probe::admit(&usb)?;
    let ports = super::serial_candidates()?;
    let port = correlate(name, &usb, &ports)?.clone();
    validate_now(&usb, &port)?;
    // Pinned upstream QualcommSerial uses 115200. Opening a serial device configures
    // its line settings; preserve DTR where the OS permits instead of toggling it.
    let native = serialport::new(&port.port, 115200)
        .data_bits(serialport::DataBits::Eight).parity(serialport::Parity::None)
        .stop_bits(serialport::StopBits::One).flow_control(serialport::FlowControl::None)
        .preserve_dtr_on_open().timeout(Duration::from_secs(5)).open()
        .map_err(|_| "Cannot exclusively open the selected native serial port; check class driver and OS permissions")?;
    let mut session = Session::new(SerialIo::new(NativePort(native)).map_err(|e| e.to_string())?);
    let deadline = Instant::now() + Duration::from_secs(15);
    let (sent, root) = emergency_probe::queries(
        protocol,
        || validate_now(&usb, &port),
        |r| session.exchange_framed(r, MAX_REPLY_FRAME, Some(deadline)),
    )?;
    Ok(SerialReport {
        probe: emergency_probe::report(&usb, protocol, sent, root),
        transport: "native_serial",
        serial_metadata_matched: true,
        port_name_exported: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode_test::PhysicalPort;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    use wpi_types::{BootloaderFamily, DeviceIdentity, DeviceMode};
    fn usb() -> Snapshot {
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
            port: Some(port),
            descriptor: DeviceIdentity {
                id: "selected".into(),
                vendor_id: 0x05c6,
                product_id: 0x9008,
                manufacturer: None,
                product: None,
                serial: Some("private-serial".into()),
                model: None,
                variant: None,
                firmware: None,
                platform_id: None,
                family: BootloaderFamily::Unknown,
                mode: DeviceMode::Emergency,
                interfaces: vec![],
            },
        }
    }
    fn candidate() -> SerialCandidate {
        SerialCandidate {
            port: "enumerated-port".into(),
            vendor_id: 0x05c6,
            product_id: 0x9008,
            serial: Some("private-serial".into()),
        }
    }
    #[test]
    fn only_unique_nonblank_serial_and_fresh_usb_port_can_bind() {
        let usb = usb();
        let port = candidate();
        validate(
            &usb,
            &port,
            std::slice::from_ref(&usb),
            std::slice::from_ref(&port),
        )
        .unwrap();
        assert!(correlate("arbitrary-path", &usb, std::slice::from_ref(&port)).is_err());
        assert!(correlate(&port.port, &usb, &[]).is_err());
        for serial in [
            None,
            Some("".into()),
            Some(" ".into()),
            Some("different".into()),
        ] {
            let mut changed = usb.clone();
            changed.descriptor.serial = serial;
            assert!(correlate(&port.port, &changed, std::slice::from_ref(&port)).is_err());
        }
        let mut duplicate = port.clone();
        duplicate.port = "second-port".into();
        assert!(correlate(&port.port, &usb, &[port.clone(), duplicate]).is_err());
        let mut changed = usb.clone();
        changed.port = None;
        assert!(validate(&usb, &port, &[changed], std::slice::from_ref(&port)).is_err());
        let mut changed = port.clone();
        changed.serial = None;
        assert!(validate(&usb, &port, std::slice::from_ref(&usb), &[changed]).is_err());
        let mut other = usb.clone();
        other.descriptor.id = "other-device".into();
        #[cfg(target_os = "windows")]
        {
            other.port = Some(PhysicalPort::Windows {
                hub: "other-hub".into(),
                number: 2,
            });
        }
        #[cfg(not(target_os = "windows"))]
        {
            other.port = Some(PhysicalPort::Native {
                bus: "other-bus".into(),
                chain: vec![2],
            });
        }
        assert!(validate(
            &usb,
            &port,
            &[usb.clone(), other],
            std::slice::from_ref(&port)
        )
        .is_err());
    }
    #[derive(Default)]
    struct State {
        pending: u32,
        fail_pending: bool,
        fail_timeout: bool,
        drops: usize,
        timeouts: Vec<Duration>,
        requests: Vec<Vec<u8>>,
        output: VecDeque<std::io::Result<usize>>,
        input: VecDeque<std::io::Result<Vec<u8>>>,
        reads: usize,
    }
    struct Fake(Rc<RefCell<State>>);
    impl Drop for Fake {
        fn drop(&mut self) {
            self.0.borrow_mut().drops += 1;
        }
    }
    impl Port for Fake {
        fn timeout(&mut self, t: Duration) -> Result<(), ()> {
            let mut s = self.0.borrow_mut();
            s.timeouts.push(t);
            if s.fail_timeout {
                Err(())
            } else {
                Ok(())
            }
        }
        fn pending(&self) -> Result<u32, ()> {
            let s = self.0.borrow();
            if s.fail_pending {
                Err(())
            } else {
                Ok(s.pending)
            }
        }
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let mut s = self.0.borrow_mut();
            s.requests.push(b.to_vec());
            s.output.pop_front().expect("extra serial write")
        }
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let mut s = self.0.borrow_mut();
            s.reads += 1;
            let bytes = s.input.pop_front().expect("extra serial read")?;
            assert!(bytes.len() <= b.len());
            b[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }
    fn fail() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "injected")
    }
    #[test]
    fn unsolicited_input_or_uninspectable_queue_closes_before_commands() {
        for (pending, fail_pending) in [(1, false), (0, true)] {
            let state = Rc::new(RefCell::new(State {
                pending,
                fail_pending,
                ..State::default()
            }));
            assert!(SerialIo::new(Fake(state.clone())).is_err());
            assert_eq!(state.borrow().drops, 1);
            assert!(state.borrow().requests.is_empty());
        }
    }
    #[test]
    fn serial_short_output_error_and_timeout_setup_retire_without_remainder() {
        for case in 0..4 {
            let state = Rc::new(RefCell::new(State::default()));
            {
                let mut s = state.borrow_mut();
                s.fail_timeout = case == 3;
                s.output
                    .push_back(if case == 2 { Err(fail()) } else { Ok(case) });
            }
            let mut session = Session::new(SerialIo::new(Fake(state.clone())).unwrap());
            assert!(session
                .exchange_framed(&[6, 7], MAX_REPLY_FRAME, None)
                .is_err());
            let before = state.borrow().requests.len();
            assert!(session
                .exchange_framed(&[6, 7], MAX_REPLY_FRAME, None)
                .is_err());
            let s = state.borrow();
            assert_eq!(s.requests.len(), before);
            assert_eq!(s.reads, 0);
            assert_eq!(s.drops, 1);
            assert_eq!(before, usize::from(case != 3));
        }
    }
    #[test]
    fn serial_partial_reply_disconnect_or_empty_read_closes_without_retry() {
        for empty in [false, true] {
            let state = Rc::new(RefCell::new(State::default()));
            {
                let mut s = state.borrow_mut();
                s.output.push_back(Ok(1));
                s.input.push_back(Ok(vec![0x7e]));
                s.input
                    .push_back(if empty { Ok(vec![]) } else { Err(fail()) });
            }
            let mut session = Session::new(SerialIo::new(Fake(state.clone())).unwrap());
            assert!(session
                .exchange_framed(&[6], MAX_REPLY_FRAME, None)
                .is_err());
            assert!(session
                .exchange_framed(&[6], MAX_REPLY_FRAME, None)
                .is_err());
            let s = state.borrow();
            assert_eq!(s.requests, [vec![6]]);
            assert_eq!(s.reads, 2);
            assert_eq!(s.drops, 1);
        }
    }
    #[test]
    fn pinned_read_only_queries_cross_serial_reads_without_flush_or_retry() {
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
            let exchanges = fixture["exchanges"].as_array().unwrap();
            let state = Rc::new(RefCell::new(State::default()));
            let mut expected = vec![];
            {
                let mut s = state.borrow_mut();
                for e in exchanges.iter().take(count) {
                    let request: Vec<u8> = serde_json::from_value(e["request"].clone()).unwrap();
                    let reply: Vec<u8> = serde_json::from_value(e["response"].clone()).unwrap();
                    s.output.push_back(Ok(request.len()));
                    expected.push(request);
                    s.input.extend(reply.chunks(1).map(|c| Ok(c.to_vec())));
                }
            }
            {
                let mut session = Session::new(SerialIo::new(Fake(state.clone())).unwrap());
                assert_eq!(
                    emergency_probe::queries(
                        protocol,
                        || Ok(()),
                        |r| session.exchange_framed(r, MAX_REPLY_FRAME, None)
                    )
                    .unwrap(),
                    (count, protocol == Protocol::Dload)
                );
            }
            let s = state.borrow();
            assert_eq!(s.requests, expected);
            assert!(s.input.is_empty());
            assert!(s.output.is_empty());
            assert_eq!(s.drops, 1);
            assert!(s
                .timeouts
                .iter()
                .all(|t| !t.is_zero() && *t <= Duration::from_secs(5)));
        }
    }
}
