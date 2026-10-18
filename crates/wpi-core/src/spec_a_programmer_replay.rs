//! Rehearse the V1 programmer transfer phase of Spec A unlocking, after loader
//! entry. Derived from WPInternals 2.9.2 QualcommFlasher.cs (Rene Lergner, MIT).
//! Concrete replay only: not an unlock executor, admission policy or write grant.
use wpi_protocol::{qualcomm::v1, replay::ReplayTransport, MessageTransport};
use wpi_types::{Operation, OperationEvent, OperationState};

/// Borrowed immutable bytes in caller-selected order. This phase does not
/// authenticate artifacts or derive placement from a phone GPT.
pub struct Region<'a> {
    pub start_bytes: u32,
    pub data: &'a [u8],
}

/// Compose only immutable regions from the image engine's verified, in-memory
/// replay plan. Advisory JSON reports cannot be passed to this API.
pub fn run_plan<F: FnMut(&OperationEvent) -> bool>(
    plan: &wpi_image::spec_a::programmer_plan::Plan,
    transport: &mut ReplayTransport,
    event: F,
) -> Result<(), Error> {
    let regions: Vec<_> = plan
        .regions()
        .iter()
        .map(|r| Region {
            start_bytes: r.start_bytes(),
            data: r.bytes(),
        })
        .collect();
    run(&regions, transport, event)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Programmer replay preflight: {0}")]
    Preflight(String),
    #[error("Programmer replay cancelled before session submission")]
    Cancelled,
    #[error("Programmer replay interrupted during {phase}; inspect state: {detail}")]
    Interrupted {
        phase: &'static str,
        acknowledged_bytes: u64,
        write_attempted: bool,
        detail: String,
    },
}

fn validate(regions: &[Region<'_>]) -> Result<u64, Error> {
    if regions.is_empty() || regions.len() > 32 {
        return Err(Error::Preflight("requires 1–32 regions".into()));
    }
    let mut ranges = Vec::with_capacity(regions.len());
    let mut total = 0;
    for region in regions {
        let start = u64::from(region.start_bytes);
        let length = region.data.len() as u64;
        let end = start + length;
        if length == 0 || length > 16 * 1024 * 1024 || end > u64::from(u32::MAX) + 1 {
            return Err(Error::Preflight("invalid or oversized region".into()));
        }
        total += length;
        ranges.push((start, end));
    }
    if total > 64 * 1024 * 1024 {
        return Err(Error::Preflight("replay exceeds 64 MiB".into()));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|r| r[0].1 > r[1].0) {
        return Err(Error::Preflight("overlapping replay regions".into()));
    }
    Ok(total)
}

/// No native transport can be passed. No retries, cleanup writes or automatic
/// reconnect. A failed reply can follow an accepted command. Completion means
/// the simulated transfer/reboot was acknowledged, not that a phone is unlocked.
pub fn run<F: FnMut(&OperationEvent) -> bool>(
    regions: &[Region<'_>],
    transport: &mut ReplayTransport,
    event: F,
) -> Result<(), Error> {
    let total = validate(regions)?;
    let mut session = Session {
        transport,
        event,
        sequence: 0,
        total,
        done: 0,
        started: false,
        write_attempted: false,
    };
    session.submit("hello", &v1::hello(), v1::Ack::Hello, 0)?;
    session.submit(
        "security mode",
        v1::SECURITY_MODE_ZERO,
        v1::Ack::SecurityMode,
        0,
    )?;
    session.submit("open", v1::OPEN_BOOT_PARTITION, v1::Ack::Open, 0)?;
    for region in regions {
        let mut address = u64::from(region.start_bytes);
        for chunk in region.data.chunks(v1::MAX_WRITE_BYTES) {
            // Preflight proves all chunk starts fit u32, including a region
            // ending exactly at the exclusive 32-bit address-space boundary.
            let address_bytes = address as u32;
            let request = v1::write(address_bytes, chunk)
                .map_err(|e| session.stop("write encoding", e.to_string()))?;
            session.submit(
                "write",
                &request,
                v1::Ack::Write(address_bytes),
                chunk.len(),
            )?;
            address += chunk.len() as u64;
        }
    }
    session.submit("close", v1::CLOSE_PARTITION, v1::Ack::Close, 0)?;
    session.submit("reboot", v1::REBOOT, v1::Ack::Reboot, 0)?;
    session.notify(
        OperationState::Completed,
        "Replay programmer transfer acknowledged; device unlock is not established",
    );
    Ok(())
}

struct Session<'a, F> {
    transport: &'a mut ReplayTransport,
    event: F,
    sequence: u64,
    total: u64,
    done: u64,
    started: bool,
    write_attempted: bool,
}
impl<F: FnMut(&OperationEvent) -> bool> Session<'_, F> {
    fn notify(&mut self, state: OperationState, message: &str) -> bool {
        self.sequence += 1;
        (self.event)(&OperationEvent {
            sequence: self.sequence,
            operation: Operation::UnlockBootloader,
            state,
            completed_bytes: self.done,
            total_bytes: self.total,
            message: message.into(),
        })
    }

    fn stop(&mut self, phase: &'static str, detail: String) -> Error {
        if !self.started {
            self.notify(
                OperationState::Cancelled,
                "Replay cancelled before submission",
            );
            return Error::Cancelled;
        }
        self.notify(
            OperationState::RecoveryRequired,
            &format!("Replay {phase}: {detail}"),
        );
        Error::Interrupted {
            phase,
            acknowledged_bytes: self.done,
            write_attempted: self.write_attempted,
            detail,
        }
    }

    fn submit(
        &mut self,
        phase: &'static str,
        request: &[u8],
        ack: v1::Ack,
        write_bytes: usize,
    ) -> Result<(), Error> {
        if !self.notify(
            OperationState::Running,
            &format!("Replay programmer {phase}"),
        ) {
            return Err(self.stop(phase, "cancelled at command boundary".into()));
        }
        self.started = true;
        self.write_attempted |= write_bytes != 0;
        let result = self
            .transport
            .exchange(request, v1::MAX_REPLY_FRAME)
            .and_then(|r| v1::check_ack(&r, ack));
        if let Err(error) = result {
            return Err(self.stop(phase, error.to_string()));
        }
        self.done += write_bytes as u64;
        Ok(())
    }
}
