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
fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(DesktopState::default())
        .invoke_handler(tauri::generate_handler![
            startup,
            capabilities,
            devices,
            probe,
            inspect_file,
            convert_gpt,
            extract_partition,
            cancel_operation
        ])
        .run(tauri::generate_context!())
        .expect("failed to run WPInternals Rust");
}
