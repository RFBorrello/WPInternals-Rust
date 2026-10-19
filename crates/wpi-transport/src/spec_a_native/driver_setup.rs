//! Process-local manual setup checkpoint. This module never changes a driver,
//! claims an interface, sends a protocol request, or grants crash-resume rights.
use super::Journal;
#[cfg(any(windows, test))]
use super::{boundary, readiness};
use crate::device_binding::Snapshot;
use std::sync::atomic::AtomicBool;
#[cfg(any(windows, test))]
use std::time::Duration;

pub(super) const TIMEOUT_SECONDS: u64 = 600;

#[cfg(any(windows, test))]
fn eligible(endpoint: &readiness::Endpoint) -> Result<bool, String> {
    use readiness::{BindingTarget, Service, SetupClass};
    if endpoint.product_id != 0x9008
        || endpoint.binding_target != BindingTarget::WholeDevice
        || endpoint.protected_class
        || !matches!(
            endpoint.setup_class,
            SetupClass::UsbDevice | SetupClass::Unknown
        )
    {
        return Err("First-time setup refuses protected, HID, serial, composite or unknown targets; no driver was changed".into());
    }
    if !endpoint.present {
        return Ok(false);
    }
    if endpoint.usable_binding() {
        return Ok(true);
    }
    if endpoint.service == Service::None && endpoint.problem_code == Some(28) {
        return Ok(false); // CM_PROB_FAILED_INSTALL: no driver selected yet.
    }
    Err("Selected emergency endpoint has an incompatible driver or device error; inspect it before choosing a binding".into())
}

/// A temporarily absent device is allowed during manual driver installation.
/// A different device on the port or movement to another port is never allowed.
#[cfg(any(windows, test))]
fn present(selected: &Snapshot, current: &[Snapshot]) -> Result<bool, String> {
    crate::emergency_probe::admit(selected)?;
    if selected.descriptor.product_id != 0x9008 {
        return Err(
            "First-time setup is limited to the observed 05c6:9008 endpoint; F006 is excluded"
                .into(),
        );
    }
    let by_id: Vec<_> = current
        .iter()
        .filter(|s| s.descriptor.id == selected.descriptor.id)
        .collect();
    let by_port: Vec<_> = current.iter().filter(|s| s.port == selected.port).collect();
    match (by_id.as_slice(), by_port.as_slice()) {
        ([], []) => Ok(false),
        ([id], [port]) if **id == *selected && **port == *selected => Ok(true),
        _ => Err(
            "Emergency setup target changed, moved or became ambiguous; no interface was claimed"
                .into(),
        ),
    }
}

/// Two consecutive ready observations. Metadata-only polling is repeatable;
/// opening USB and protocol queries are deliberately outside this loop.
#[cfg(any(windows, test))]
fn poll<N, P, S>(
    cancelled: &AtomicBool,
    mut elapsed: N,
    mut probe: P,
    mut pause: S,
) -> Result<(), String>
where
    N: FnMut() -> Duration,
    P: FnMut() -> Result<bool, String>,
    S: FnMut(),
{
    let limit = Duration::from_secs(TIMEOUT_SECONDS);
    let mut ready = 0;
    loop {
        boundary(cancelled)?;
        if elapsed() >= limit {
            return Err("Manual emergency driver setup timed out; no upload, retry or reset was sent by the checkpoint".into());
        }
        let observed = probe()?;
        boundary(cancelled)?;
        if elapsed() >= limit {
            return Err("Emergency driver metadata arrived after the setup deadline".into());
        }
        ready = if observed { ready + 1 } else { 0 };
        if ready == 2 {
            return Ok(());
        }
        pause();
    }
}

#[cfg(windows)]
pub(super) fn wait<F: FnMut(&str)>(
    selected: &Snapshot,
    sink: &mut Journal,
    cancelled: &AtomicBool,
    progress: &mut F,
) -> Result<(), String> {
    use nusb::MaybeFuture;
    use std::time::Instant;
    let started = Instant::now();
    boundary(cancelled)?;
    let inventory = || -> Result<Vec<nusb::DeviceInfo>, String> {
        Ok(nusb::list_devices().wait().map_err(super::text)?.collect())
    };
    let all = inventory()?;
    let snapshots: Vec<_> = all.iter().map(Snapshot::of).collect();
    if !present(selected, &snapshots)? {
        return Err("Emergency setup target disappeared before checkpoint admission".into());
    }
    let info = all
        .iter()
        .find(|d| Snapshot::of(d) == *selected)
        .ok_or("Selected emergency setup metadata unavailable")?;
    if !matches!(info.class(), 0 | 0xff) {
        return Err("First-time setup refuses a protected USB device class".into());
    }
    let instance = info
        .instance_id()
        .to_str()
        .ok_or("Invalid Windows instance ID encoding")?
        .to_owned();
    let initial = readiness::selected_binding(&instance)?
        .ok_or("Selected emergency PnP record unavailable")?;
    eligible(&initial)?;
    crate::emergency_probe::check_setup_descriptors(selected)?;
    boundary(cancelled)?;
    sink.append(
        "awaiting_driver_setup",
        "Manual setup for the session-bound emergency endpoint; storage may already have changed",
        None,
    )?;
    progress("Manual driver checkpoint: up to 10 minutes. If needed, configure only the actual observed target using the reviewed in-box WinUSB route. No driver is installed by this process. It continues automatically after two ready observations and fresh descriptor/protocol checks. Ctrl+C stops without reset or rollback.");
    // Needed for exact Device Manager selection. Local console only: never
    // persisted in the JSON journal, preview or completion report.
    progress(&format!(
        "Private local Device Manager instance target: {instance}"
    ));
    poll(
        cancelled,
        || started.elapsed(),
        || {
            let all = inventory()?;
            if !present(selected, &all.iter().map(Snapshot::of).collect::<Vec<_>>())? {
                return Ok(false);
            }
            let ready = match readiness::selected_binding(&instance)? {
                Some(endpoint) => eligible(&endpoint)?,
                None => false,
            };
            let all = inventory()?;
            Ok(present(selected, &all.iter().map(Snapshot::of).collect::<Vec<_>>())? && ready)
        },
        || std::thread::sleep(Duration::from_millis(250)),
    )?;
    boundary(cancelled)?;
    crate::emergency_probe::check_setup_descriptors(selected)?;
    boundary(cancelled)?;
    if started.elapsed() >= Duration::from_secs(TIMEOUT_SECONDS) {
        return Err("Emergency descriptor checks finished after the setup deadline".into());
    }
    sink.append(
        "verified",
        "Selected emergency binding metadata ready; protocol/root verification still required",
        None,
    )
}

#[cfg(not(windows))]
pub(super) fn wait<F: FnMut(&str)>(
    _selected: &Snapshot,
    _sink: &mut Journal,
    _cancelled: &AtomicBool,
    _progress: &mut F,
) -> Result<(), String> {
    Err("Manual emergency driver setup supports Windows only".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use readiness::{BindingTarget, Endpoint, Service, SetupClass};
    use std::{cell::Cell, collections::VecDeque, sync::atomic::Ordering};
    fn endpoint() -> Endpoint {
        Endpoint {
            product_id: 0x9008,
            binding_target: BindingTarget::WholeDevice,
            present: true,
            setup_class: SetupClass::UsbDevice,
            service: Service::Winusb,
            problem_code: Some(0),
            protected_class: false,
            winusb_compatible_id: false,
            interface_guid_registered: false,
        }
    }
    fn snapshot() -> Snapshot {
        use crate::mode_test::PhysicalPort;
        let descriptor = serde_json::from_value(serde_json::json!({
            "id":"selected", "vendor_id":0x05c6,"product_id":0x9008,
            "manufacturer":null,"product":null,"serial":"private-serial",
            "model":null,"variant":null,"firmware":null,"platform_id":null,
            "family":"unknown","mode":"emergency","interfaces":[]
        }))
        .unwrap();
        #[cfg(windows)]
        let port = PhysicalPort::Windows {
            hub: "private-hub".into(),
            number: 1,
        };
        #[cfg(not(windows))]
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
    fn setup_retains_exact_target_across_absence_but_rejects_substitution_or_movement() {
        let selected = snapshot();
        assert!(present(&selected, std::slice::from_ref(&selected)).unwrap());
        assert!(!present(&selected, &[]).unwrap());
        let mut changed = selected.clone();
        changed.port = None;
        assert!(present(&selected, &[changed]).is_err());
        for field in ["id", "serial", "mode"] {
            let mut changed = selected.clone();
            match field {
                "id" => changed.descriptor.id = "other".into(),
                "serial" => changed.descriptor.serial = Some("changed".into()),
                _ => changed.descriptor.mode = wpi_types::DeviceMode::Unknown,
            }
            assert!(present(&selected, &[changed]).is_err());
        }
        assert!(present(&selected, &[selected.clone(), selected.clone()]).is_err());
        let mut f006 = selected.clone();
        f006.descriptor.product_id = 0xf006;
        assert!(present(&f006, &[]).is_err());
        let mut missing_port = selected;
        missing_port.port = None;
        assert!(present(&missing_port, &[]).is_err());
    }
    #[test]
    fn only_unbound_or_healthy_whole_device_9008_can_enter_manual_setup() {
        assert!(eligible(&endpoint()).unwrap());
        let mut e = endpoint();
        e.service = Service::None;
        e.setup_class = SetupClass::Unknown;
        e.problem_code = Some(28);
        assert!(!eligible(&e).unwrap());
        for class in [SetupClass::Hid, SetupClass::Ports, SetupClass::Other] {
            let mut e = endpoint();
            e.setup_class = class;
            assert!(eligible(&e).is_err());
        }
        for service in [
            Service::Hidusb,
            Service::Serial,
            Service::Other,
            Service::None,
        ] {
            let mut e = endpoint();
            e.service = service;
            assert!(eligible(&e).is_err());
        }
        for code in [None, Some(10), Some(28), Some(45)] {
            let mut e = endpoint();
            e.problem_code = code;
            assert!(eligible(&e).is_err());
        }
        let mut e = endpoint();
        e.protected_class = true;
        assert!(eligible(&e).is_err());
        let mut e = endpoint();
        e.product_id = 0xf006;
        assert!(eligible(&e).is_err());
        for target in [BindingTarget::CompositeInterface, BindingTarget::Unknown] {
            let mut e = endpoint();
            e.binding_target = target;
            assert!(eligible(&e).is_err());
        }
    }
    #[test]
    fn metadata_must_be_ready_twice_and_absence_resets_stability() {
        let cancelled = AtomicBool::new(false);
        let mut observations = VecDeque::from([false, true, false, true, true]);
        let calls = Cell::new(0);
        poll(
            &cancelled,
            || Duration::ZERO,
            || {
                calls.set(calls.get() + 1);
                Ok(observations.pop_front().unwrap())
            },
            || {},
        )
        .unwrap();
        assert_eq!(calls.get(), 5);
    }
    #[test]
    fn errors_cancellation_and_deadlines_stop_before_another_metadata_probe() {
        let cancelled = AtomicBool::new(true);
        assert!(poll(&cancelled, || Duration::ZERO, || panic!("no probe"), || {}).is_err());
        cancelled.store(false, Ordering::Release);
        assert!(poll(
            &cancelled,
            || Duration::from_secs(600),
            || panic!("expired"),
            || {}
        )
        .is_err());
        assert!(poll(
            &cancelled,
            || Duration::ZERO,
            || Err("metadata failure".into()),
            || panic!("no retry")
        )
        .is_err());
        assert!(poll(
            &cancelled,
            || Duration::ZERO,
            || {
                cancelled.store(true, Ordering::Release);
                Ok(true)
            },
            || panic!("no retry")
        )
        .is_err());
        cancelled.store(false, Ordering::Release);
        let elapsed = Cell::new(Duration::ZERO);
        assert!(poll(
            &cancelled,
            || elapsed.get(),
            || {
                elapsed.set(Duration::from_secs(600));
                Ok(true)
            },
            || panic!("late probe")
        )
        .is_err());
    }
}
