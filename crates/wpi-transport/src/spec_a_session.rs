//! Native read-only artifact/session checks. Public Normal-only probe; private
//! mode-harness handoffs retain one operation lock. No storage writer.
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
    requests: Vec<Vec<u8>>,
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
fn flash_requests() -> Result<Vec<Vec<u8>>, String> {
    Ok(vec![
        b"NOKV".to_vec(),
        identity::flash_request(),
        wpi_protocol::flash::parameter_request("RRKH").map_err(|e| e.to_string())?,
        wpi_protocol::flash::parameter_request("SS").map_err(|e| e.to_string())?,
        b"NOKV".to_vec(),
        identity::flash_request(),
    ])
}
impl<T: MessageTransport, C: FnMut() -> Result<(), String>> MessageTransport for Guard<T, C> {
    fn exchange(&mut self, bytes: &[u8], maximum_response: usize) -> wpi_protocol::Result<Vec<u8>> {
        self.check().map_err(ProtocolError::Transport)?;
        if maximum_response == 0
            || maximum_response > 65536
            || self.requests.get(self.next).map(Vec::as_slice) != Some(bytes)
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
    progress: F,
) -> Result<Report, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let (baseline, count) = capture_normal_bound(id, prepared, cancelled, progress)?;
    Ok(Report {
        session: baseline.report(),
        transport: "native_usb",
        usb_descriptor_bookends_match: true,
        physical_port_matches: true,
        normal_queries_sent: count,
        mode_changes_sent: false,
    })
}
/// Caller must retain PHONE_ACCESS across the whole multi-mode session.
pub(super) fn capture_normal_bound<'a, F: FnMut(&str)>(
    id: &str,
    prepared: &'a Prepared,
    cancelled: &AtomicBool,
    mut progress: F,
) -> Result<(session::NormalSession<'a>, usize), String> {
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
        requests: (0..5).filter_map(request).collect(),
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
    Ok((baseline, guard.next))
}

pub(super) fn capture_flash_bound<'a>(
    id: &str,
    baseline: session::NormalSession<'a>,
    serial: &str,
    port: &super::mode_test::PhysicalPort,
    cancelled: &AtomicBool,
) -> Result<session::FlashSession<'a>, String> {
    let selected = device_binding::selected(id)?;
    if selected.descriptor.mode != DeviceMode::Flash
        || selected.descriptor.vendor_id != 0x0421
        || selected.descriptor.product_id != 0x066e
        || selected.port.as_ref() != Some(port)
        || selected
            .descriptor
            .serial
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .is_some_and(|s| s != serial)
    {
        return Err(
            "Flash endpoint contradicts the Normal physical-port or available serial binding"
                .into(),
        );
    }
    let (descriptor, mut transport) = open_selected(id)?;
    if descriptor != selected.descriptor {
        return Err("Flash descriptors changed during open".into());
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    transport.deadline = Some(deadline);
    let mut guard = Guard {
        transport,
        next: 0,
        failed: false,
        requests: flash_requests()?,
        check: || {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("Prepared Flash checks cancelled or expired".into());
            }
            let current = device_binding::scan()?;
            let matches: Vec<_> = current
                .iter()
                .filter(|s| s.descriptor.id == selected.descriptor.id)
                .collect();
            if matches.len() != 1
                || matches[0] != &selected
                || current.iter().filter(|s| s.port == selected.port).count() != 1
                || Instant::now() >= deadline
            {
                return Err("Prepared Flash descriptors, physical port or deadline changed".into());
            }
            Ok(())
        },
    };
    let flash = baseline.into_flash(&mut guard, |_| !cancelled.load(Ordering::Acquire))?;
    guard.check()?;
    Ok(flash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use wpi_protocol::replay::{Exchange, ReplayTransport};
    #[test]
    fn prepared_flash_allowlist_retires_at_each_binding_failure_and_rejects_gpt_or_reset() {
        let requests = flash_requests().unwrap();
        let steps: Vec<_> = requests
            .iter()
            .map(|r| Exchange {
                request: r.clone(),
                response: vec![1],
                error: None,
            })
            .collect();
        for at in 0..6 {
            let mut checks = 0;
            let mut guard = Guard {
                transport: ReplayTransport::new(steps.clone()),
                next: 0,
                failed: false,
                requests: requests.clone(),
                check: || {
                    let now = checks;
                    checks += 1;
                    if now == at {
                        Err("physical port changed".into())
                    } else {
                        Ok(())
                    }
                },
            };
            for r in &requests[..at] {
                guard.exchange(r, 65536).unwrap();
            }
            assert!(guard.exchange(&requests[at], 65536).is_err());
            assert!(guard.exchange(&requests[at], 65536).is_err());
            for later in &steps[at..] {
                assert_eq!(
                    guard.transport.exchange(&later.request, 65536).unwrap(),
                    later.response
                );
            }
            assert!(guard.transport.finished());
        }
        for request in [b"NOKT".as_slice(), b"NOKR", b"NOKF", b"NOKXFS"] {
            let mut guard = Guard {
                transport: ReplayTransport::new(steps.clone()),
                next: 0,
                failed: false,
                requests: requests.clone(),
                check: || Ok(()),
            };
            assert!(guard.exchange(request, 65536).is_err());
            assert_eq!(guard.next, 0);
        }
    }
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
                requests: (0..5).filter_map(request).collect(),
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
                requests: (0..5).filter_map(request).collect(),
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
                requests: (0..5).filter_map(request).collect(),
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
