//! Bounded discovery-only observation. No interface opens, queries or mode commands.
use super::{
    device_binding::{self, Snapshot},
    PHONE_ACCESS,
};
use serde::Serialize;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use wpi_types::DeviceMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    WaitingRemoval,
    Removed,
    Candidate,
    Arrived,
    TimedOut,
    Cancelled,
}
#[derive(Debug, Serialize)]
pub struct Event {
    pub stage: Stage,
    pub elapsed_ms: u64,
    pub observations: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub outcome: Stage,
    pub expected_usb_mode: DeviceMode,
    pub source_disappearance_observed: bool,
    pub arrival_confirmed_by_discovery: bool,
    pub observations: usize,
    pub elapsed_ms: u64,
    pub phone_queries_sent: bool,
    pub mode_changes_sent: bool,
    pub protocol_detected: bool,
    pub identity_authenticated: bool,
    pub phone_writes_enabled: bool,
}

trait Driver {
    fn now(&self) -> Instant;
    fn scan(&mut self) -> Result<Vec<Snapshot>, String>;
    fn pause(&mut self, duration: Duration);
}
struct Native;
impl Driver for Native {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn scan(&mut self) -> Result<Vec<Snapshot>, String> {
        device_binding::scan()
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
fn advance(
    source: &Snapshot,
    expected: DeviceMode,
    current: &[Snapshot],
    stage: &mut Stage,
    candidate: &mut Option<Snapshot>,
) -> Result<(), String> {
    if current
        .iter()
        .any(|s| s.descriptor.id == source.descriptor.id && s.port != source.port)
    {
        return Err("Selected USB endpoint moved or lost its physical-port binding".into());
    }
    let on_port: Vec<_> = current.iter().filter(|s| s.port == source.port).collect();
    if on_port.len() > 1 {
        return Err("Physical USB port has ambiguous records; observation stopped".into());
    }
    match *stage {
        Stage::WaitingRemoval => match on_port.first() {
            None => *stage = Stage::Removed,
            Some(observed) if *observed == source => {}
            _ => return Err(
                "USB endpoint changed before disappearance was observed; no arrival was accepted"
                    .into(),
            ),
        },
        Stage::Removed => {
            if let Some(observed) = on_port.first() {
                if observed.descriptor.mode != expected {
                    return Err(
                        "Unexpected USB mode on the selected physical port; observation stopped"
                            .into(),
                    );
                }
                if let Some(serial) = source
                    .descriptor
                    .serial
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                {
                    let returning = observed
                        .descriptor
                        .serial
                        .as_deref()
                        .filter(|s| !s.trim().is_empty());
                    if returning.is_some_and(|s| s != serial)
                        || (expected == DeviceMode::Normal && returning != Some(serial))
                    {
                        return Err(
                            "Returning USB serial metadata differs or is missing for Normal mode"
                                .into(),
                        );
                    }
                }
                *candidate = Some((*observed).clone());
                *stage = Stage::Candidate;
            }
        }
        Stage::Candidate => {
            if on_port.first().copied() != candidate.as_ref() {
                return Err("Arrival candidate changed or disappeared before confirmation".into());
            }
            *stage = Stage::Arrived;
        }
        _ => return Err("Arrival observer is already terminal".into()),
    }
    Ok(())
}
fn observe<D: Driver, C: FnMut() -> bool, E: FnMut(Event)>(
    driver: &mut D,
    source: &Snapshot,
    expected: DeviceMode,
    timeout: Duration,
    mut cancelled: C,
    mut emit: E,
) -> Result<Report, String> {
    if source.port.is_none()
        || !matches!(
            expected,
            DeviceMode::Normal | DeviceMode::Flash | DeviceMode::Emergency
        )
        || timeout < Duration::from_secs(1)
        || timeout > Duration::from_secs(30)
    {
        return Err("Need a physical-port binding, a Normal/Flash/Emergency USB target and a timeout from 1 to 30 seconds".into());
    }
    let start = driver.now();
    let deadline = start + timeout;
    let mut stage = Stage::WaitingRemoval;
    let mut candidate = None;
    let mut observations = 0;
    let mut disappeared = false;
    let mut last_emitted = None;
    loop {
        if cancelled() {
            stage = Stage::Cancelled;
        } else if driver.now() >= deadline {
            stage = Stage::TimedOut;
        }
        if last_emitted != Some(stage) {
            emit(Event {
                stage,
                elapsed_ms: driver.now().saturating_duration_since(start).as_millis() as u64,
                observations,
            });
            last_emitted = Some(stage);
        }
        if matches!(stage, Stage::Arrived | Stage::TimedOut | Stage::Cancelled) {
            break;
        }
        // Cancellation is rechecked after a callback, before another OS scan.
        if cancelled() {
            stage = Stage::Cancelled;
            continue;
        }
        let current = driver.scan()?;
        observations += 1;
        if cancelled() {
            stage = Stage::Cancelled;
            continue;
        }
        if driver.now() >= deadline {
            stage = Stage::TimedOut;
            continue;
        }
        let previous = stage;
        advance(source, expected, &current, &mut stage, &mut candidate)?;
        disappeared |= stage == Stage::Removed;
        if stage == Stage::Arrived {
            continue;
        }
        if stage != previous {
            emit(Event {
                stage,
                elapsed_ms: driver.now().saturating_duration_since(start).as_millis() as u64,
                observations,
            });
            last_emitted = Some(stage);
            if cancelled() {
                stage = Stage::Cancelled;
                continue;
            }
        }
        driver.pause(
            Duration::from_millis(250).min(deadline.saturating_duration_since(driver.now())),
        );
    }
    Ok(Report {
        outcome: stage,
        expected_usb_mode: expected,
        source_disappearance_observed: disappeared,
        arrival_confirmed_by_discovery: stage == Stage::Arrived,
        observations,
        elapsed_ms: driver.now().saturating_duration_since(start).as_millis() as u64,
        phone_queries_sent: false,
        mode_changes_sent: false,
        protocol_detected: false,
        identity_authenticated: false,
        phone_writes_enabled: false,
    })
}

pub fn run<E: FnMut(Event)>(
    id: &str,
    expected: DeviceMode,
    timeout: Duration,
    cancelled: &AtomicBool,
    emit: E,
) -> Result<Report, String> {
    let _access = PHONE_ACCESS
        .try_lock()
        .map_err(|_| "Another native phone operation is active")?;
    let source = device_binding::selected(id)?;
    observe(
        &mut Native,
        &source,
        expected,
        timeout,
        || cancelled.load(Ordering::Acquire),
        emit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode_test::PhysicalPort;
    use std::{cell::Cell, collections::VecDeque};
    use wpi_types::{BootloaderFamily, DeviceIdentity};
    fn source() -> Snapshot {
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
                id: "source".into(),
                vendor_id: 0x0421,
                product_id: 0x0661,
                serial: Some("private-serial".into()),
                mode: DeviceMode::Normal,
                manufacturer: None,
                product: None,
                model: None,
                variant: None,
                firmware: None,
                platform_id: None,
                family: BootloaderFamily::Unknown,
                interfaces: vec![],
            },
        }
    }
    fn target() -> Snapshot {
        let mut s = source();
        s.descriptor.id = "arrival".into();
        s.descriptor.vendor_id = 0x05c6;
        s.descriptor.product_id = 0x9008;
        s.descriptor.mode = DeviceMode::Emergency;
        s.descriptor.serial = None;
        s
    }
    struct Fake {
        now: Instant,
        scans: VecDeque<Result<Vec<Snapshot>, String>>,
        last: Vec<Snapshot>,
        calls: usize,
        scan_elapsed: Duration,
    }
    impl Fake {
        fn new(scans: Vec<Vec<Snapshot>>) -> Self {
            Self {
                now: Instant::now(),
                scans: scans.into_iter().map(Ok).collect(),
                last: vec![],
                calls: 0,
                scan_elapsed: Duration::ZERO,
            }
        }
    }
    impl Driver for Fake {
        fn now(&self) -> Instant {
            self.now
        }
        fn scan(&mut self) -> Result<Vec<Snapshot>, String> {
            self.calls += 1;
            self.now += self.scan_elapsed;
            if let Some(s) = self.scans.pop_front() {
                self.last = s?;
            }
            Ok(self.last.clone())
        }
        fn pause(&mut self, d: Duration) {
            assert!(d <= Duration::from_millis(250));
            self.now += d;
        }
    }
    fn run_fake(driver: &mut Fake) -> Result<Report, String> {
        observe(
            driver,
            &source(),
            DeviceMode::Emergency,
            Duration::from_secs(1),
            || false,
            |_| {},
        )
    }
    #[test]
    fn requires_disappearance_and_two_equal_arrival_snapshots_without_queries() {
        let mut driver = Fake::new(vec![vec![source()], vec![], vec![target()], vec![target()]]);
        let mut events = vec![];
        let r = observe(
            &mut driver,
            &source(),
            DeviceMode::Emergency,
            Duration::from_secs(1),
            || false,
            |e| events.push(e.stage),
        )
        .unwrap();
        assert_eq!(r.outcome, Stage::Arrived);
        assert_eq!(r.observations, 4);
        assert!(r.source_disappearance_observed);
        assert_eq!(
            events,
            [
                Stage::WaitingRemoval,
                Stage::Removed,
                Stage::Candidate,
                Stage::Arrived
            ]
        );
        let json = serde_json::to_string(&r).unwrap();
        for private in ["private-serial", "private-hub", "private-bus"] {
            assert!(!json.contains(private));
        }
        assert!(
            !r.phone_queries_sent
                && !r.mode_changes_sent
                && !r.protocol_detected
                && !r.identity_authenticated
                && !r.phone_writes_enabled
        );
    }
    #[test]
    fn wrong_mode_unknown_device_ambiguity_and_unstable_candidate_stop() {
        let mut unknown = target();
        unknown.descriptor.mode = DeviceMode::Unknown;
        let mut changed = target();
        changed.descriptor.id = "replacement".into();
        for snapshots in [
            vec![vec![source()], vec![target()]],
            vec![vec![], vec![unknown]],
            vec![vec![], vec![target(), target()]],
            vec![vec![], vec![target()], vec![]],
            vec![vec![], vec![target()], vec![changed]],
            vec![vec![source(), source()]],
        ] {
            let mut driver = Fake::new(snapshots);
            assert!(run_fake(&mut driver).is_err());
            assert!(driver.calls <= 3);
        }
    }
    #[test]
    fn unchanged_phone_or_unrelated_arrival_times_out_without_extending_deadline() {
        let mut elsewhere = target();
        #[cfg(target_os = "windows")]
        {
            elsewhere.port = Some(PhysicalPort::Windows {
                hub: "another-hub".into(),
                number: 2,
            });
        }
        #[cfg(not(target_os = "windows"))]
        {
            elsewhere.port = Some(PhysicalPort::Native {
                bus: "other".into(),
                chain: vec![2],
            });
        }
        for snapshots in [vec![vec![source()]], vec![vec![], vec![elsewhere]]] {
            let mut driver = Fake::new(snapshots);
            let r = run_fake(&mut driver).unwrap();
            assert_eq!(r.outcome, Stage::TimedOut);
            assert_eq!(r.elapsed_ms, 1000);
            assert!(!r.arrival_confirmed_by_discovery);
            assert!(driver.calls <= 5);
        }
    }
    #[test]
    fn cancellation_before_scan_or_after_removal_never_observes_again() {
        for initial in [true, false] {
            let cancelled = Cell::new(initial);
            let mut driver = Fake::new(vec![vec![], vec![target()]]);
            let r = observe(
                &mut driver,
                &source(),
                DeviceMode::Emergency,
                Duration::from_secs(1),
                || cancelled.get(),
                |e| {
                    if e.stage == Stage::Removed {
                        cancelled.set(true);
                    }
                },
            )
            .unwrap();
            assert_eq!(r.outcome, Stage::Cancelled);
            assert_eq!(driver.calls, usize::from(!initial));
        }
    }
    #[test]
    fn normal_return_requires_consistent_available_serial_and_port() {
        for serial in [None, Some("changed".into())] {
            let mut returning = source();
            returning.descriptor.serial = serial;
            let mut driver = Fake::new(vec![vec![], vec![returning]]);
            assert!(observe(
                &mut driver,
                &source(),
                DeviceMode::Normal,
                Duration::from_secs(1),
                || false,
                |_| {}
            )
            .is_err());
        }
        let mut moved = source();
        moved.port = None;
        let mut driver = Fake::new(vec![vec![moved]]);
        assert!(run_fake(&mut driver).is_err());
    }
    #[test]
    fn invalid_options_and_discovery_errors_never_retry() {
        for (mode, secs) in [
            (DeviceMode::MassStorage, 1),
            (DeviceMode::Emergency, 0),
            (DeviceMode::Emergency, 31),
        ] {
            let mut driver = Fake::new(vec![]);
            assert!(observe(
                &mut driver,
                &source(),
                mode,
                Duration::from_secs(secs),
                || false,
                |_| {}
            )
            .is_err());
            assert_eq!(driver.calls, 0);
        }
        let mut driver = Fake::new(vec![]);
        driver.scans.push_back(Err("discovery failed".into()));
        assert!(run_fake(&mut driver).is_err());
        assert_eq!(driver.calls, 1);
    }
    #[test]
    fn late_discovery_cannot_confirm_arrival() {
        let mut driver = Fake::new(vec![vec![], vec![target()], vec![target()]]);
        driver.scan_elapsed = Duration::from_millis(400);
        let r = run_fake(&mut driver).unwrap();
        assert_eq!(r.outcome, Stage::TimedOut);
        assert!(!r.arrival_confirmed_by_discovery);
        assert_eq!(driver.calls, 2);
    }
}
