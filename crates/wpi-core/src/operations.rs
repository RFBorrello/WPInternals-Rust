use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use thiserror::Error;
use wpi_types::*;

#[derive(Debug, Error)]
pub enum OperationError {
    #[error("Another operation is already active")]
    Busy,
    #[error("Operation blocked: {0}")]
    Blocked(String),
    #[error("Invalid state transition from {0:?} to {1:?}")]
    Transition(OperationState, OperationState),
}
pub fn prepare(
    operation: Operation,
    device: Option<DeviceIdentity>,
    host: Host,
    transport: TransportKind,
    artifacts: Vec<ArtifactIdentity>,
) -> OperationPlan {
    let report = crate::capabilities(device.as_ref(), host, transport);
    let capability = report
        .capabilities
        .iter()
        .find(|c| c.operation == operation)
        .unwrap();
    let mut blockers = if capability.executable {
        vec![]
    } else {
        vec![capability.reason.clone()]
    };
    if !operation.offline() && device.is_none() {
        blockers.push("No device selected".into());
    }
    if operation.offline() && operation != Operation::PatchFiles && artifacts.is_empty() {
        blockers.push("Select a local artifact".into());
    }
    for artifact in &artifacts {
        if artifact.sha256.len() != 64 || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            blockers.push(format!("{} has no valid SHA-256 identity", artifact.name));
        }
    }
    OperationPlan {
        operation,
        device,
        host,
        transport,
        artifacts,
        executable: blockers.is_empty(),
        blockers,
        steps: vec![
            "Revalidate the selected device and artifact identities".into(),
            "Check supported format, bounds and operation preconditions".into(),
            "Execute with bounded streaming and safe cancellation boundaries".into(),
        ],
    }
}

#[derive(Default, Clone)]
pub struct OperationCoordinator {
    active: Arc<Mutex<bool>>,
}
pub struct OperationSession {
    active: Arc<Mutex<bool>>,
    cancelled: Arc<AtomicBool>,
    state: OperationState,
    sequence: u64,
    operation: Operation,
    completed: u64,
}
impl OperationCoordinator {
    /// Reserves an offline job before opening/validating its artifacts.
    pub fn reserve_local(&self, operation: Operation) -> Result<OperationSession, OperationError> {
        if !operation.offline() {
            return Err(OperationError::Blocked(
                "only offline jobs can use a local reservation".into(),
            ));
        }
        self.acquire(operation)
    }
    pub fn start(&self, plan: &OperationPlan) -> Result<OperationSession, OperationError> {
        if !plan.executable {
            return Err(OperationError::Blocked(plan.blockers.join("; ")));
        }
        // Recompute the gate: callers cannot make an unsupported device write executable
        // by deserializing or modifying a public OperationPlan.
        let gate = crate::capabilities(plan.device.as_ref(), plan.host, plan.transport);
        if !gate
            .capabilities
            .iter()
            .any(|c| c.operation == plan.operation && c.executable)
        {
            return Err(OperationError::Blocked(
                "capability gate rejected execution".into(),
            ));
        }
        let checked = prepare(
            plan.operation,
            plan.device.clone(),
            plan.host,
            plan.transport,
            plan.artifacts.clone(),
        );
        if !checked.executable {
            return Err(OperationError::Blocked(checked.blockers.join("; ")));
        }
        self.acquire(plan.operation)
    }
    fn acquire(&self, operation: Operation) -> Result<OperationSession, OperationError> {
        let mut active = self.active.lock().map_err(|_| OperationError::Busy)?;
        if *active {
            return Err(OperationError::Busy);
        }
        *active = true;
        Ok(OperationSession {
            active: self.active.clone(),
            cancelled: Arc::new(AtomicBool::new(false)),
            state: OperationState::Prepared,
            sequence: 0,
            operation,
            completed: 0,
        })
    }
}
impl OperationSession {
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
    pub fn safe_boundary(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
    }
    pub fn transition(
        &mut self,
        state: OperationState,
        done: u64,
        total: u64,
        message: impl Into<String>,
    ) -> Result<OperationEvent, OperationError> {
        use OperationState::*;
        let legal = matches!(
            (self.state, state),
            (Prepared, Running | Failed | Cancelled)
                | (
                    Running,
                    Running
                        | AwaitingReconnect
                        | Cancelling
                        | Completed
                        | RecoveryRequired
                        | Failed
                )
                | (
                    AwaitingReconnect,
                    Running | RecoveryRequired | Failed | Cancelling
                )
                | (Cancelling, Cancelled | RecoveryRequired | Failed)
        );
        if !legal || done > total || done < self.completed {
            return Err(OperationError::Transition(self.state, state));
        }
        self.state = state;
        self.completed = done;
        self.sequence += 1;
        Ok(OperationEvent {
            sequence: self.sequence,
            operation: self.operation,
            state,
            completed_bytes: done,
            total_bytes: total,
            message: message.into(),
        })
    }
}
impl Drop for OperationSession {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            *active = false;
        }
    }
}
