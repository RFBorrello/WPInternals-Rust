//! Mode transitions restricted to concrete replay transports. No physical USB access.
use serde::{Deserialize, Serialize};
use wpi_protocol::{
    flash, normal,
    replay::{Exchange, ReplayTransport},
    MessageTransport,
};
use wpi_types::*;

const DEADLINE_MS: u32 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayObservation {
    /// Monotonic elapsed time from the simulated command, never a wall-clock timestamp.
    pub elapsed_ms: u32,
    pub observation: Observation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation {
    Disconnected,
    PermissionRequired,
    Connected {
        devices: Vec<DeviceIdentity>,
        probe: Vec<Exchange>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("Mode-transition preflight: {0}")]
    Preflight(String),
    #[error("Replay cancelled before sending the mode-change command")]
    Cancelled,
    #[error("Inspect device state before continuing; never retry the mode-change command: {0}")]
    RecoveryRequired(String),
}

/// Replays a fresh source probe, one command, and bounded returning-device observations.
/// Matching USB serials only correlates identity; it never authorizes recovery writes.
pub fn run<F: FnMut(&OperationEvent) -> bool>(
    baseline: &DeviceIdentity,
    target: DeviceMode,
    transport: &mut ReplayTransport,
    observations: Vec<ReplayObservation>,
    mut event: F,
) -> Result<ReconnectReport, TransitionError> {
    validate_observations(&observations)?;
    if crate::reconnect::compare(baseline, baseline, baseline.mode).status
        != ReconnectStatus::Correlated
    {
        return Err(TransitionError::Preflight(
            "a known phone baseline with a local USB serial is required".into(),
        ));
    }
    let mut sequence = 0;
    let mut notify = |state, message: &str| {
        sequence += 1;
        event(&OperationEvent {
            sequence,
            operation: Operation::SwitchMode,
            state,
            completed_bytes: 0,
            total_bytes: 0,
            message: message.into(),
        })
    };
    if !notify(
        OperationState::Running,
        "Replay source preflight; no physical phone is contacted",
    ) {
        notify(
            OperationState::Cancelling,
            "Cancellation requested before the simulated command",
        );
        notify(
            OperationState::Cancelled,
            "Cancelled before the simulated command",
        );
        return Err(TransitionError::Cancelled);
    }
    let (fresh, protocol) = probe(baseline.clone(), transport).map_err(|e| {
        notify(OperationState::Failed, &e);
        TransitionError::Preflight(e)
    })?;
    if crate::reconnect::compare(baseline, &fresh, baseline.mode).status
        != ReconnectStatus::Correlated
    {
        notify(
            OperationState::Failed,
            "Fresh source identity contradicts or cannot correlate the baseline",
        );
        return Err(TransitionError::Preflight(
            "fresh source identity did not correlate".into(),
        ));
    }
    let command = wpi_protocol::mode::command(fresh.mode, target, baseline.family, protocol)
        .map_err(|e| {
            notify(OperationState::Failed, &e.to_string());
            TransitionError::Preflight(e.to_string())
        })?;
    if !notify(
        OperationState::Running,
        "Source revalidated; safe cancellation boundary before command",
    ) {
        notify(
            OperationState::Cancelling,
            "Cancellation requested before the simulated command",
        );
        notify(
            OperationState::Cancelled,
            "Cancelled before the simulated command",
        );
        return Err(TransitionError::Cancelled);
    }
    // A failed transfer can have reached the phone. Do not retry it or issue another reset.
    let sent = match command.status_signature {
        Some(signature) => transport
            .exchange(&command.request, 65536)
            .and_then(|r| flash::check_status(&r, signature)),
        None => transport.send(&command.request),
    };
    let uncertain = sent.is_err();
    if !notify(
        OperationState::AwaitingReconnect,
        if uncertain {
            "Command delivery uncertain; inspect the next observation without retry"
        } else {
            "Command sent once; awaiting a fresh application-level observation"
        },
    ) {
        notify(
            OperationState::RecoveryRequired,
            "Cancelled after command delivery; inspect state manually",
        );
        return Err(TransitionError::RecoveryRequired(
            "cancelled after command delivery".into(),
        ));
    }
    let mut removed = !command.requires_disconnect;
    for observation in observations {
        if observation.elapsed_ms >= DEADLINE_MS {
            break;
        }
        if !notify(
            OperationState::AwaitingReconnect,
            "Replay observation boundary",
        ) {
            notify(
                OperationState::RecoveryRequired,
                "Cancelled while waiting; inspect state manually",
            );
            return Err(TransitionError::RecoveryRequired(
                "cancelled while waiting".into(),
            ));
        }
        match observation.observation {
            Observation::Disconnected => removed = true,
            Observation::PermissionRequired => {
                if !notify(
                    OperationState::AwaitingReconnect,
                    "Renew device selection permission; the original deadline is unchanged",
                ) {
                    notify(
                        OperationState::RecoveryRequired,
                        "Cancelled during permission renewal; inspect state manually",
                    );
                    return Err(TransitionError::RecoveryRequired(
                        "cancelled during permission renewal".into(),
                    ));
                }
            }
            Observation::Connected {
                devices,
                probe: exchanges,
            } => {
                if !removed {
                    // Stale enumeration before actual removal is never considered an arrival.
                    continue;
                }
                if devices.len() != 1 {
                    notify(
                        OperationState::RecoveryRequired,
                        "No unique returning phone; explicit selection is required",
                    );
                    return Err(TransitionError::RecoveryRequired(
                        "ambiguous returning devices".into(),
                    ));
                }
                let mut replay = ReplayTransport::new(exchanges);
                let (returned, _) = probe(devices.into_iter().next().unwrap(), &mut replay)
                    .map_err(|e| {
                        notify(OperationState::RecoveryRequired, &e);
                        TransitionError::RecoveryRequired(e)
                    })?;
                if !replay.finished() {
                    notify(
                        OperationState::RecoveryRequired,
                        "Unexpected extra replay exchanges",
                    );
                    return Err(TransitionError::RecoveryRequired(
                        "unexpected extra replay exchanges".into(),
                    ));
                }
                let report = crate::reconnect::compare(baseline, &returned, target);
                if report.status != ReconnectStatus::Correlated {
                    notify(
                        OperationState::RecoveryRequired,
                        "Returning phone identity or mode did not correlate",
                    );
                    return Err(TransitionError::RecoveryRequired(
                        "returning phone identity or mode did not correlate".into(),
                    ));
                }
                // Completion is a replay result, never a live execution capability.
                if !notify(
                    OperationState::Running,
                    "Returning phone correlated from fresh observations",
                ) {
                    notify(
                        OperationState::RecoveryRequired,
                        "Cancelled after observation; inspect state manually",
                    );
                    return Err(TransitionError::RecoveryRequired(
                        "cancelled after observation".into(),
                    ));
                }
                notify(
                    OperationState::Completed,
                    if uncertain {
                        "Replay correlated after uncertain delivery; no command retry and no write authorization"
                    } else {
                        "Mode transition replay complete; no physical phone contacted and no write authorization"
                    },
                );
                return Ok(report);
            }
        }
    }
    notify(
        OperationState::RecoveryRequired,
        "Reconnect deadline exhausted; inspect state before recovery",
    );
    Err(TransitionError::RecoveryRequired(
        "reconnect timed out".into(),
    ))
}

fn validate_observations(observations: &[ReplayObservation]) -> Result<(), TransitionError> {
    if observations.len() > 64
        || observations
            .windows(2)
            .any(|w| w[0].elapsed_ms > w[1].elapsed_ms)
    {
        return Err(TransitionError::Preflight(
            "too many or nonmonotonic observations".into(),
        ));
    }
    for o in observations {
        if let Observation::Connected { devices, probe } = &o.observation {
            if devices.len() > 8
                || probe.len() > 8
                || probe
                    .iter()
                    .any(|e| e.request.len() > 65536 || e.response.len() > 65536)
            {
                return Err(TransitionError::Preflight(
                    "replay observation exceeds bounds".into(),
                ));
            }
        }
    }
    Ok(())
}

fn probe(
    mut device: DeviceIdentity,
    transport: &mut ReplayTransport,
) -> Result<(DeviceIdentity, Option<u8>), String> {
    let enumeration_mode =
        crate::classify_usb(device.vendor_id, device.product_id).ok_or("unexpected USB device")?;
    // Never inherit remembered application fields into a returning interface.
    device.model = None;
    device.variant = None;
    device.firmware = None;
    device.platform_id = None;
    device.family = BootloaderFamily::Unknown;
    match enumeration_mode {
        DeviceMode::Normal => {
            let info = normal::read_info(transport).map_err(|e| e.to_string())?;
            crate::profiles::apply_variant(
                &mut device,
                info.manufacturer_model
                    .split('_')
                    .next()
                    .unwrap_or_default(),
            );
            device.firmware = Some(info.firmware);
            device.mode = DeviceMode::Normal;
            Ok((device, None))
        }
        DeviceMode::Flash => {
            let info = flash::read_info(transport).map_err(|e| e.to_string())?;
            device.mode = info.mode;
            device.platform_id = info.platform_id;
            if info.mode == DeviceMode::Flash {
                let value = transport
                    .exchange(
                        &flash::parameter_request("FVER").map_err(|e| e.to_string())?,
                        65536,
                    )
                    .and_then(|r| flash::parse_parameter(&r))
                    .map_err(|e| e.to_string())?;
                device.firmware = Some(String::from_utf8_lossy(&value).trim_matches('\0').into());
            }
            Ok((device, Some(info.protocol_major)))
        }
        _ => Err("returning mode has no read-only application probe".into()),
    }
}
