#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tauri::{Emitter, State};
use wpi_core::{
    artifacts,
    inspection::Inspection,
    operations::{OperationCoordinator, OperationSession},
    profiles,
};
use wpi_types::*;

#[derive(Default)]
struct DesktopState {
    coordinator: OperationCoordinator,
    cancellation: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}
#[tauri::command]
fn prepare_mode(
    device: Option<DeviceIdentity>,
    target: DeviceMode,
    protocol_major: Option<u8>,
) -> ModeTransitionPreparation {
    wpi_core::reconnect::prepare(
        device,
        target,
        protocol_major,
        profiles::current_host(),
        TransportKind::Usb,
    )
}
#[tauri::command]
fn check_reconnect(
    before: DeviceIdentity,
    after: DeviceIdentity,
    target: DeviceMode,
) -> ReconnectReport {
    wpi_core::reconnect::compare(&before, &after, target)
}
#[tauri::command]
fn startup() -> serde_json::Value {
    serde_json::json!({"models":profiles::known_models(),"capabilities":profiles::capabilities(None,profiles::current_host(),TransportKind::Usb)})
}
#[tauri::command]
fn capabilities(device: Option<DeviceIdentity>) -> CapabilityReport {
    profiles::capabilities(
        device.as_ref(),
        profiles::current_host(),
        TransportKind::Usb,
    )
}
#[tauri::command]
async fn devices() -> Result<Vec<DeviceIdentity>, String> {
    tauri::async_runtime::spawn_blocking(wpi_transport::enumerate)
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn probe(
    id: String,
    state: State<'_, DesktopState>,
) -> Result<wpi_transport::ProbeResult, String> {
    let coordinator = state.coordinator.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let device = wpi_transport::enumerate()?
            .into_iter()
            .find(|d| d.id == id)
            .ok_or("Device disconnected")?;
        let plan = wpi_core::operations::prepare(
            Operation::DeviceInfo,
            Some(device),
            profiles::current_host(),
            TransportKind::Usb,
            vec![],
        );
        let _session = coordinator.start(&plan).map_err(|e| e.to_string())?;
        wpi_transport::probe(&id)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn inspect_file(path: String, state: State<'_, DesktopState>) -> Result<Inspection, String> {
    let session = state
        .coordinator
        .reserve_local(Operation::InspectFirmware)
        .map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _session = session;
        artifacts::inspect_file(&PathBuf::from(path)).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn build_spec_a_package(
    input: String,
    donor: String,
    sbl3: Option<String>,
    loaders: Vec<String>,
    output: String,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<wpi_image::spec_a::package::Report, String> {
    let mut session = state
        .coordinator
        .reserve_local(Operation::InspectFirmware)
        .map_err(|e| e.to_string())?;
    *state
        .cancellation
        .lock()
        .map_err(|_| "Operation state lock failed")? = Some(session.cancellation());
    let registry = state.cancellation.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let paths: Vec<_> = loaders.into_iter().map(PathBuf::from).collect();
        let mut last_stage = String::new();
        let mut last_progress = std::time::Instant::now();
        let result = artifacts::build_spec_a_package(
            std::path::Path::new(&input),
            std::path::Path::new(&donor),
            sbl3.as_deref().map(std::path::Path::new),
            &paths,
            std::path::Path::new(&output),
            |stage, done, total| {
                if stage != last_stage
                    || done == total
                    || last_progress.elapsed().as_millis() >= 100
                {
                    emit(
                        &app,
                        &mut session,
                        OperationState::Running,
                        done,
                        total,
                        stage,
                    );
                    last_stage = stage.to_string();
                    last_progress = std::time::Instant::now();
                }
                session.safe_boundary()
            },
        );
        match &result {
            Ok(report) => emit(
                &app,
                &mut session,
                OperationState::Completed,
                report.size,
                report.size,
                "Offline package saved; device writes remain blocked",
            ),
            Err(wpi_image::ImageError::Cancelled) => {
                emit(
                    &app,
                    &mut session,
                    OperationState::Cancelling,
                    0,
                    0,
                    "Cancelling offline package",
                );
                emit(
                    &app,
                    &mut session,
                    OperationState::Cancelled,
                    0,
                    0,
                    "Package discarded",
                );
            }
            Err(error) => emit(
                &app,
                &mut session,
                OperationState::Failed,
                0,
                0,
                &error.to_string(),
            ),
        }
        if let Ok(mut current) = registry.lock() {
            *current = None;
        }
        result.map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn assemble_spec_a(
    input: String,
    donor: Option<String>,
    component: String,
    output: String,
    state: State<'_, DesktopState>,
) -> Result<serde_json::Value, String> {
    let session = state
        .coordinator
        .reserve_local(Operation::InspectFirmware)
        .map_err(|e| e.to_string())?;
    *state
        .cancellation
        .lock()
        .map_err(|_| "Operation state lock failed")? = Some(session.cancellation());
    let registry = state.cancellation.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let result = artifacts::assemble_spec_a_with_progress(
            std::path::Path::new(&input),
            donor.as_deref().map(std::path::Path::new),
            &component,
            std::path::Path::new(&output),
            |_, _| session.safe_boundary(),
        );
        if let Ok(mut current) = registry.lock() {
            *current = None;
        }
        result.map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn prepare_spec_a(
    input: String,
    sbl3: Option<String>,
    loaders: Vec<String>,
    donor: Option<String>,
    state: State<'_, DesktopState>,
) -> Result<wpi_image::spec_a::Preparation, String> {
    let session = state
        .coordinator
        .reserve_local(Operation::InspectFirmware)
        .map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _session = session;
        let loaders: Vec<_> = loaders.into_iter().map(PathBuf::from).collect();
        artifacts::prepare_spec_a(
            &PathBuf::from(input),
            sbl3.as_deref().map(std::path::Path::new),
            &loaders,
            donor.as_deref().map(std::path::Path::new),
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn prepare_recovery(
    input: String,
    device: Option<DeviceIdentity>,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<RecoveryPreparation, String> {
    let mut session = state
        .coordinator
        .reserve_local(Operation::InspectFirmware)
        .map_err(|e| e.to_string())?;
    *state
        .cancellation
        .lock()
        .map_err(|_| "Operation state lock failed")? = Some(session.cancellation());
    let registry = state.cancellation.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut last = (0, 0);
        emit(
            &app,
            &mut session,
            OperationState::Running,
            0,
            0,
            "Checking local recovery artifacts",
        );
        let result = artifacts::prepare_recovery(
            &PathBuf::from(input),
            device,
            profiles::current_host(),
            TransportKind::Usb,
            |done, total| {
                last = (done, total);
                emit(
                    &app,
                    &mut session,
                    OperationState::Running,
                    done,
                    total,
                    "Verifying local firmware",
                );
                session.safe_boundary()
            },
        );
        match &result {
            Ok(_) => emit(
                &app,
                &mut session,
                OperationState::Completed,
                last.0,
                last.1,
                "Checklist ready; device recovery remains blocked",
            ),
            Err(wpi_image::ImageError::Cancelled) => {
                emit(
                    &app,
                    &mut session,
                    OperationState::Cancelling,
                    last.0,
                    last.1,
                    "Cancellation requested",
                );
                emit(
                    &app,
                    &mut session,
                    OperationState::Cancelled,
                    last.0,
                    last.1,
                    "Offline preparation cancelled",
                );
            }
            Err(error) => emit(
                &app,
                &mut session,
                OperationState::Failed,
                last.0,
                last.1,
                &error.to_string(),
            ),
        }
        if let Ok(mut current) = registry.lock() {
            *current = None;
        }
        result.map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn convert_gpt(
    input: String,
    output: String,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    let session = state
        .coordinator
        .reserve_local(Operation::ConvertGpt)
        .map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _session = session;
        artifacts::convert_gpt(&PathBuf::from(input), &PathBuf::from(output))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn extract_partition(
    input: String,
    partition: String,
    output: String,
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
) -> Result<(), String> {
    let mut session = state
        .coordinator
        .reserve_local(Operation::ExtractPartition)
        .map_err(|e| e.to_string())?;
    let cancellation = session.cancellation();
    *state
        .cancellation
        .lock()
        .map_err(|_| "Operation state lock failed")? = Some(cancellation);
    let registry = state.cancellation.clone();
    tauri::async_runtime::spawn_blocking(move || {
        emit(
            &app,
            &mut session,
            OperationState::Running,
            0,
            0,
            "Validating source image",
        );
        let mut last = (0, 0);
        let result = artifacts::extract_partition(
            &PathBuf::from(input),
            &partition,
            &PathBuf::from(output),
            |done, total| {
                last = (done, total);
                emit(
                    &app,
                    &mut session,
                    OperationState::Running,
                    done,
                    total,
                    "Extracting local partition",
                );
                session.safe_boundary()
            },
        );
        match &result {
            Ok(()) => emit(
                &app,
                &mut session,
                OperationState::Completed,
                last.0,
                last.1,
                "Partition saved",
            ),
            Err(wpi_image::ImageError::Cancelled) => {
                emit(
                    &app,
                    &mut session,
                    OperationState::Cancelling,
                    last.0,
                    last.1,
                    "Cancellation requested",
                );
                emit(
                    &app,
                    &mut session,
                    OperationState::Cancelled,
                    last.0,
                    last.1,
                    "Cancelled; output was not published",
                );
            }
            Err(error) => emit(
                &app,
                &mut session,
                OperationState::Failed,
                last.0,
                last.1,
                &error.to_string(),
            ),
        }
        if let Ok(mut current) = registry.lock() {
            *current = None;
        }
        result.map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
fn emit(
    app: &tauri::AppHandle,
    session: &mut OperationSession,
    state: OperationState,
    done: u64,
    total: u64,
    message: &str,
) {
    if let Ok(event) = session.transition(state, done, total, message) {
        let _ = app.emit("operation-progress", event);
    }
}
#[tauri::command]
fn cancel_operation(state: State<'_, DesktopState>) -> Result<(), String> {
    if let Some(token) = state
        .cancellation
        .lock()
        .map_err(|_| "Operation state lock failed")?
        .as_ref()
    {
        token.store(true, Ordering::Release);
    }
    Ok(())
}
#[tauri::command]
async fn storage_discovery(
    state: State<'_, DesktopState>,
) -> Result<wpi_storage::Discovery, String> {
    let session = state
        .coordinator
        .reserve_storage_read()
        .map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _session = session;
        wpi_storage::discover().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DesktopState::default())
        .invoke_handler(tauri::generate_handler![
            prepare_mode,
            check_reconnect,
            startup,
            capabilities,
            devices,
            probe,
            inspect_file,
            prepare_recovery,
            prepare_spec_a,
            assemble_spec_a,
            build_spec_a_package,
            convert_gpt,
            extract_partition,
            cancel_operation,
            storage_discovery
        ])
        .run(tauri::generate_context!())
        .expect("failed to run WPInternals Rust");
}
