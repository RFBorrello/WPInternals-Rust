//! Native Normal-only artifact/session check. No transition, wait or hardware writer.
use super::{
    device_binding::{self, Snapshot},
    open_selected, PHONE_ACCESS,
};
use serde::Serialize;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use wpi_core::spec_a_session::{self as session, Prepared};
use wpi_protocol::{identity, normal, MessageTransport, ProtocolError};
use wpi_types::DeviceMode;

#[derive(Debug, Serialize)]
pub struct Report {
    pub session: session::Report,
    pub transport: &'static str,
    pub usb_descriptor_bookends_match: bool,
    pub physical_port_matches: bool,
    pub normal_queries_sent: usize,
    pub mode_changes_sent: bool,
}
fn validate(expected: &Snapshot, current: &[Snapshot]) -> Result<(), String> {
    if expected.descriptor.mode != DeviceMode::Normal
        || expected.descriptor.vendor_id != 0x0421
        || expected.descriptor.product_id != 0x0661
        || expected.port.is_none()
        || expected
            .descriptor
            .serial
            .as_deref()
            .is_none_or(|s| s.trim().is_empty())
    {
        return Err("Select the reviewed Normal USB profile with serial metadata and physical-port binding; no mode change is sent".into());
    }
    let selected: Vec<_> = current
        .iter()
        .filter(|s| s.descriptor.id == expected.descriptor.id)
        .collect();
    if selected.len() != 1
        || selected[0] != expected
        || current.iter().filter(|s| s.port == expected.port).count() != 1
    {
        return Err(
            "Selected Normal USB descriptors or physical port changed or became ambiguous".into(),
        );
    }
    Ok(())
}
struct Guard<T, C> {
    transport: T,
    check: C,
    next: usize,
    failed: bool,
}
impl<T, C: FnMut() -> Result<(), String>> Guard<T, C> {
    fn check(&mut self) -> Result<(), String> {
        if self.failed {
            return Err(
                "Read-only session retired; fresh preparation and identity checks are required"
                    .into(),
            );
        }
        let result = (self.check)();
        self.failed |= result.is_err();
        result
    }
}
fn request(at: usize) -> Option<Vec<u8>> {
    match at {
        0 => Some(identity::normal_request(0)),
        1 => normal::request(1, "ReadManufacturerModelName").ok(),
        2 => normal::request(2, "ReadProductCode").ok(),
        3 => normal::request(3, "ReadSwVersion").ok(),
        4 => Some(identity::normal_request(4)),
        _ => None,
    }
}
impl<T: MessageTransport, C: FnMut() -> Result<(), String>> MessageTransport for Guard<T, C> {
    fn exchange(&mut self, bytes: &[u8], maximum_response: usize) -> wpi_protocol::Result<Vec<u8>> {
        self.check().map_err(ProtocolError::Transport)?;
        if maximum_response == 0
            || maximum_response > 65536
            || request(self.next).as_deref() != Some(bytes)
        {
            self.failed = true;
            return Err(ProtocolError::Unsupported);
        }
        self.next += 1;
        let result = self.transport.exchange(bytes, maximum_response);
        self.failed |= result.is_err();
        result
    }
}
pub fn check_normal<F: FnMut(&str)>(
    id: &str,
    prepared: &Prepared,
    cancelled: &AtomicBool,
    mut progress: F,
) -> Result<Report, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    if cancelled.load(Ordering::Acquire) {
        return Err("Cancelled before USB selection".into());
    }
    let selected = device_binding::selected(id)?;
    validate(&selected, &device_binding::scan()?)?;
    let (descriptor, mut transport) = open_selected(id)?;
    if descriptor != selected.descriptor {
        return Err("Normal descriptors changed while opening the selected interface".into());
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    transport.deadline = Some(deadline);
    let mut guard = Guard {
        transport,
        next: 0,
        failed: false,
        check: || {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("Normal session cancelled or expired".into());
            }
            validate(&selected, &device_binding::scan()?)?;
            if Instant::now() >= deadline {
                return Err("Normal discovery exceeded the session deadline".into());
            }
            Ok(())
        },
    };
    let baseline = session::capture_normal(prepared, &mut guard, |stage| {
        progress(stage);
        !cancelled.load(Ordering::Acquire)
    })?;
    guard.check()?;
    Ok(Report {
        session: baseline.report(),
        transport: "native_usb",
        usb_descriptor_bookends_match: true,
        physical_port_matches: true,
        normal_queries_sent: guard.next,
        mode_changes_sent: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use wpi_protocol::replay::{Exchange, ReplayTransport};
    fn exchanges() -> Vec<Exchange> {
        (0..5)
            .map(|at| Exchange {
                request: request(at).unwrap(),
                response: vec![at as u8],
                error: None,
            })
            .collect()
    }
    #[test]
    fn guard_allows_only_five_ordered_read_only_queries_and_retires_on_any_failure() {
        let steps = exchanges();
        for fail_at in 0..5 {
            let checks = Cell::new(0);
            let mut guard = Guard {
                transport: ReplayTransport::new(steps.clone()),
                next: 0,
                failed: false,
                check: || {
                    let at = checks.get();
                    checks.set(at + 1);
                    if at == fail_at {
                        Err("changed physical port".into())
                    } else {
                        Ok(())
                    }
                },
            };
            for e in &steps[..fail_at] {
                guard.exchange(&e.request, 65536).unwrap();
            }
            assert!(guard.exchange(&steps[fail_at].request, 65536).is_err());
            assert!(guard.exchange(&steps[fail_at].request, 65536).is_err());
            assert_eq!(checks.get(), fail_at + 1);
            for e in &steps[fail_at..] {
                assert_eq!(
                    guard.transport.exchange(&e.request, 65536).unwrap(),
                    e.response
                );
            }
        }
        for invalid in [
            b"NOKR".to_vec(),
            b"NOKT".to_vec(),
            b"NOKXFS".to_vec(),
            identity::normal_request(4),
        ] {
            let mut guard = Guard {
                transport: ReplayTransport::new(steps.clone()),
                next: 0,
                failed: false,
                check: || Ok(()),
            };
            assert!(guard.exchange(&invalid, 65536).is_err());
            assert!(guard.exchange(&steps[0].request, 65536).is_err());
            assert_eq!(guard.next, 0);
            guard.transport.exchange(&steps[0].request, 65536).unwrap();
        }
    }
    #[test]
    fn protocol_error_retires_guard_without_retry_or_consuming_later_queries() {
        let steps = exchanges();
        for at in 0..5 {
            let mut broken = steps.clone();
            broken[at].error = Some("lost reply".into());
            let mut guard = Guard {
                transport: ReplayTransport::new(broken),
                next: 0,
                failed: false,
                check: || Ok(()),
            };
            for e in &steps[..at] {
                guard.exchange(&e.request, 65536).unwrap();
            }
            assert!(guard.exchange(&steps[at].request, 65536).is_err());
            assert!(guard.exchange(&steps[at].request, 65536).is_err());
            for e in &steps[at + 1..] {
                assert_eq!(
                    guard.transport.exchange(&e.request, 65536).unwrap(),
                    e.response
                );
            }
            assert!(guard.transport.finished());
        }
    }
}
