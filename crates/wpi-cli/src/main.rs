use clap::{Parser, Subcommand};
use std::{error::Error, path::PathBuf};
use wpi_core::{artifacts, profiles};
use wpi_types::*;

#[derive(Parser)]
#[command(
    name = "wpi",
    version,
    about = "Local Lumia firmware and device tools. Device writes remain gated pending hardware validation."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// List recognized USB interfaces without opening them.
    Devices {
        #[arg(long)]
        serial: bool,
    },
    /// Read normal-mode model/product/firmware or flash-mode NOKV/FVER information.
    Probe { id: String },
    /// Read a local public ID without exporting its bytes. Sends no mode change.
    IdentityProbe { id: String },
    /// Read phone information and preview a mode change. Never sends a mode-change command.
    PrepareMode {
        id: String,
        #[arg(value_parser = parse_mode)]
        target: DeviceMode,
    },
    /// Compare a local probe JSON baseline with a fresh read-only probe. Never authorizes writes.
    CheckReconnect {
        baseline: PathBuf,
        id: String,
        #[arg(value_parser = parse_mode)]
        target: DeviceMode,
    },
    /// Run a synthetic mode-transition scenario using replay only. No USB access.
    ReplayMode { input: PathBuf },
    /// Preview a narrowly scoped native mode experiment. Execution requires explicit confirmation.
    ModeTest {
        id: String,
        #[arg(long, requires_all = ["confirm", "report"])]
        execute: bool,
        #[arg(long, requires = "execute")]
        confirm: Option<String>,
        /// New local JSONL journal. Existing files are never overwritten.
        #[arg(long, requires = "execute")]
        report: Option<PathBuf>,
    },
    /// Preview a public-ID/physical-port mode experiment; never writes firmware.
    ModePublicIdTest {
        id: String,
        #[arg(long, requires_all = ["confirm", "report"])]
        execute: bool,
        #[arg(long, requires = "execute")]
        confirm: Option<String>,
        #[arg(long, requires = "execute")]
        report: Option<PathBuf>,
    },
    /// Inspect a legacy FFU, GPT/raw disk image, or FAT/NTFS boot sector.
    Inspect { input: PathBuf },
    /// Verify a local FFU and generate an advisory recovery checklist. Never starts recovery.
    PrepareRecovery {
        input: PathBuf,
        #[arg(long)]
        device_id: Option<String>,
    },
    /// Check FFU SHA-256 chunk hashes (does not authenticate its signing catalog).
    Verify { input: PathBuf },
    /// Extract a named partition into a new local file, using bounded memory.
    Extract {
        input: PathBuf,
        partition: String,
        output: PathBuf,
    },
    /// Export GPT information to the upstream Partitions.xml format.
    ConvertGpt { input: PathBuf, output: PathBuf },
    /// List upstream patch definitions and supported firmware versions.
    Patches,
    /// Patch extracted files into a NEW directory; source files are preserved.
    PatchFiles {
        input: PathBuf,
        output: PathBuf,
        definition: String,
        #[arg(long)]
        reverse: bool,
    },
    /// Inspect a FAT/NTFS filesystem boot sector.
    Filesystem { input: PathBuf },
    /// List a directory in a FAT or NTFS partition image without host mounting.
    Files {
        input: PathBuf,
        #[arg(default_value = "")]
        path: String,
    },
    /// Extract a file from a FAT or NTFS partition image.
    ExtractFile {
        input: PathBuf,
        path: String,
        output: PathBuf,
    },
    /// Apply a catalog patch to a NEW copy of a FAT partition image.
    PatchFat {
        input: PathBuf,
        output: PathBuf,
        definition: String,
        #[arg(long)]
        reverse: bool,
    },
    /// Show model research targets; none are hardware verified yet.
    Models,
    /// Show implemented and blocked capabilities for this host.
    Capabilities,
    /// Prepare a preview. Never executes a device operation.
    Plan {
        #[arg(value_parser = parse_operation)]
        operation: Operation,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
    },
}
fn parse_operation(s: &str) -> Result<Operation, String> {
    serde_json::from_value(serde_json::Value::String(s.into())).map_err(|_| {
        "Use a snake_case operation such as stock_flash, unlock_bootloader, or inspect_firmware"
            .into()
    })
}
fn parse_mode(s: &str) -> Result<DeviceMode, String> {
    serde_json::from_value(serde_json::Value::String(s.into()))
        .map_err(|_| "Use normal, flash, boot_manager or phone_info".into())
}
fn read_json(path: &std::path::Path) -> Result<serde_json::Value, Box<dyn Error>> {
    use std::io::Read;
    let file = artifacts::open_artifact(path)?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("JSON input exceeds 1 MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
#[derive(serde::Deserialize)]
struct ModeScenario {
    baseline: DeviceIdentity,
    target: DeviceMode,
    exchanges: Vec<wpi_protocol::replay::Exchange>,
    observations: Vec<wpi_core::mode_replay::ReplayObservation>,
}
fn print<T: serde::Serialize>(value: T) -> Result<(), Box<dyn Error>> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn execute_experiment<T: serde::Serialize>(
    confirmation: Option<String>,
    report: Option<PathBuf>,
    expected_confirmation: &str,
    experiment: &str,
    execute: impl FnOnce(
        &str,
        &std::sync::atomic::AtomicBool,
        &mut dyn FnMut(&wpi_transport::mode_test::ModeTestEvent) -> bool,
    ) -> Result<T, String>,
) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    let confirmation = confirmation
        .as_deref()
        .ok_or("Experimental confirmation is required")?;
    if confirmation != expected_confirmation {
        return Err("Experimental confirmation phrase does not match".into());
    }
    let path = report.ok_or("A new .jsonl report path is required")?;
    if path.extension().is_none_or(|e| e != "jsonl") {
        return Err("The experiment journal must be a new .jsonl file".into());
    }
    let mut journal = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    writeln!(
        journal,
        "{}",
        serde_json::json!({"kind":"experiment_header","application_version":wpi_core::VERSION,"experiment":experiment,"recovery_authorized":false,"firmware_or_partition_write_commands":false})
    )?;
    journal.flush()?;
    journal.sync_all()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    let mut journal_error = None;
    let result = execute(confirmation, &cancelled, &mut |event| {
        if let wpi_transport::mode_test::ModeTestEvent::Progress { event } = event {
            eprintln!("{:?}: {}", event.state, event.message);
        }
        let write = (|| -> Result<(), Box<dyn Error>> {
            serde_json::to_writer(&mut journal, event)?;
            writeln!(journal)?;
            journal.flush()?;
            journal.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write {
            journal_error = Some(e.to_string());
            return false;
        }
        !cancelled.load(Ordering::Acquire)
    });
    let outcome = match &result {
        Ok(summary) => serde_json::json!({"kind":"experiment_result","summary":summary}),
        Err(error) => {
            serde_json::json!({"kind":"experiment_result","error":error,"recovery_authorized":false})
        }
    };
    if journal_error.is_none() {
        writeln!(journal, "{outcome}")?;
        journal.flush()?;
        journal.sync_all()?;
    }
    if let Some(e) = journal_error {
        return Err(format!(
            "Experiment journal failed: {e}. Inspect phone state before any further command"
        )
        .into());
    }
    print(&outcome)?;
    result?;
    Ok(())
}
fn run() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Devices { serial: true } => print(wpi_transport::serial_candidates()?)?,
        Command::Devices { serial: false } => print(wpi_transport::enumerate()?)?,
        Command::Probe { id } => print(wpi_transport::probe(&id)?)?,
        Command::IdentityProbe { id } => print(wpi_transport::identity_probe::run(&id)?)?,
        Command::ModeTest {
            id,
            execute,
            confirm,
            report,
        } => {
            if !execute {
                print(wpi_transport::mode_test::preview(&id)?)?;
            } else {
                use std::{
                    io::Write,
                    sync::{
                        atomic::{AtomicBool, Ordering},
                        Arc,
                    },
                };
                let confirmation = confirm
                    .as_deref()
                    .ok_or("Experimental confirmation is required")?;
                if confirmation != wpi_transport::mode_test::CONFIRMATION {
                    return Err("Experimental confirmation phrase does not match".into());
                }
                let path = report.ok_or("A new .jsonl report path is required")?;
                if path.extension().is_none_or(|e| e != "jsonl") {
                    return Err("The experiment journal must be a new .jsonl file".into());
                }
                let mut journal = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?;
                writeln!(
                    journal,
                    "{}",
                    serde_json::json!({"kind":"experiment_header", "application_version":wpi_core::VERSION,"experiment":"rm875_normal_flash_normal","recovery_authorized":false,"firmware_or_partition_write_commands":false})
                )?;
                journal.flush()?;
                journal.sync_all()?;
                let cancelled = Arc::new(AtomicBool::new(false));
                let signal = cancelled.clone();
                ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
                let mut journal_error = None;
                let result =
                    wpi_transport::mode_test::run(&id, confirmation, &cancelled, |event| {
                        if let wpi_transport::mode_test::ModeTestEvent::Progress { event } = event {
                            eprintln!("{:?}: {}", event.state, event.message);
                        }
                        let write = (|| -> Result<(), Box<dyn Error>> {
                            serde_json::to_writer(&mut journal, event)?;
                            writeln!(journal)?;
                            journal.flush()?;
                            journal.sync_all()?;
                            Ok(())
                        })();
                        if let Err(e) = write {
                            journal_error = Some(e.to_string());
                            return false;
                        }
                        !cancelled.load(Ordering::Acquire)
                    });
                let outcome = match &result {
                    Ok(summary) => {
                        serde_json::json!({"kind":"experiment_result","summary":summary})
                    }
                    Err(error) => {
                        serde_json::json!({"kind":"experiment_result","error":error,"recovery_authorized":false})
                    }
                };
                if journal_error.is_none() {
                    writeln!(journal, "{outcome}")?;
                    journal.flush()?;
                    journal.sync_all()?;
                }
                if let Some(e) = journal_error {
                    return Err(format!("Experiment journal failed: {e}. Inspect phone state before any further command").into());
                }
                print(&outcome)?;
                result?;
            }
        }
        Command::ModePublicIdTest {
            id,
            execute,
            confirm,
            report,
        } => {
            use wpi_transport::mode_test::public_id;
            if !execute {
                print(public_id::preview(&id)?)?;
            } else {
                execute_experiment(
                    confirm,
                    report,
                    public_id::CONFIRMATION,
                    public_id::EXPERIMENT,
                    |confirmation, cancelled, events| {
                        public_id::run(&id, confirmation, cancelled, events)
                    },
                )?;
            }
        }
        Command::PrepareMode { id, target } => {
            let p = wpi_transport::probe(&id)?;
            print(wpi_core::reconnect::prepare(
                Some(p.device),
                target,
                p.info.map(|i| i.protocol_major),
                profiles::current_host(),
                TransportKind::Usb,
            ))?;
        }
        Command::CheckReconnect {
            baseline,
            id,
            target,
        } => {
            let value = read_json(&baseline)?;
            let before: DeviceIdentity =
                serde_json::from_value(value.get("device").cloned().unwrap_or(value))?;
            let after = wpi_transport::probe(&id)?.device;
            print(wpi_core::reconnect::compare(&before, &after, target))?;
        }
        Command::ReplayMode { input } => {
            let scenario: ModeScenario = serde_json::from_value(read_json(&input)?)?;
            let mut transport = wpi_protocol::replay::ReplayTransport::new(scenario.exchanges);
            let mut events = Vec::new();
            let result = wpi_core::mode_replay::run(
                &scenario.baseline,
                scenario.target,
                &mut transport,
                scenario.observations,
                |event| {
                    events.push(event.clone());
                    true
                },
            );
            match result {
                Ok(report) if transport.finished() => print(
                    serde_json::json!({"source_kind":"replay_only","events":events,"reconnection":report}),
                )?,
                Ok(_) => return Err("replay contains unused source exchanges".into()),
                Err(error) => {
                    print(
                        serde_json::json!({"source_kind":"replay_only","events":events,"error":error.to_string()}),
                    )?;
                    return Err(error.into());
                }
            }
        }
        Command::Inspect { input } => print(artifacts::inspect_file(&input)?)?,
        Command::PrepareRecovery { input, device_id } => {
            let device = device_id
                .map(|id| wpi_transport::probe(&id).map(|p| p.device))
                .transpose()?;
            print(artifacts::prepare_recovery(
                &input,
                device,
                profiles::current_host(),
                TransportKind::Usb,
                |_, _| true,
            )?)?;
        }
        Command::Verify { input } => {
            let mut file = artifacts::open_artifact(&input)?;
            let ffu = wpi_image::ffu::FfuMetadata::open(&mut file)?;
            ffu.verify_hashes(&mut file, |_, _| true)?;
            print(
                serde_json::json!({"chunk_hashes":"valid","catalog_authenticity":"not_verified"}),
            )?;
        }
        Command::Extract {
            input,
            partition,
            output,
        } => {
            artifacts::extract_partition(&input, &partition, &output, |_, _| true)?;
            print(serde_json::json!({"output":output,"partition":partition}))?;
        }
        Command::ConvertGpt { input, output } => {
            artifacts::convert_gpt(&input, &output)?;
            print(serde_json::json!({"output":output}))?;
        }
        Command::Patches => print(wpi_image::patch::PatchCatalog::bundled()?.summaries())?,
        Command::PatchFiles {
            input,
            output,
            definition,
            reverse,
        } => print(artifacts::patch_directory(
            &input,
            &output,
            &definition,
            reverse,
        )?)?,
        Command::Filesystem { input } => print(wpi_image::filesystem::inspect(
            &mut artifacts::open_artifact(&input)?,
        )?)?,
        Command::Files { input, path } => print(wpi_image::filesystem::list(
            &mut artifacts::open_artifact(&input)?,
            &path,
        )?)?,
        Command::ExtractFile {
            input,
            path,
            output,
        } => {
            artifacts::extract_file(&input, &path, &output)?;
            print(serde_json::json!({"output":output,"path":path}))?;
        }
        Command::PatchFat {
            input,
            output,
            definition,
            reverse,
        } => {
            let version = artifacts::patch_fat(&input, &output, &definition, reverse)?;
            print(serde_json::json!({"output":output,"version":version,"definition":definition}))?;
        }
        Command::Models => print(profiles::known_models())?,
        Command::Capabilities => print(profiles::capabilities(
            None,
            profiles::current_host(),
            TransportKind::Usb,
        ))?,
        Command::Plan {
            operation,
            device_id,
            input,
        } => {
            let device = if let Some(id) = device_id {
                Some(
                    wpi_transport::enumerate()?
                        .into_iter()
                        .find(|d| d.id == id)
                        .ok_or("device disconnected or unknown")?,
                )
            } else {
                None
            };
            let mut imports = Vec::new();
            if let Some(path) = input {
                let mut file = artifacts::open_artifact(&path)?;
                let inspection = wpi_core::inspection::inspect(&mut file)?;
                use std::io::{Seek, SeekFrom};
                file.seek(SeekFrom::Start(0))?;
                imports.push(ArtifactIdentity {
                    name: path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    size: file.metadata()?.len(),
                    sha256: wpi_image::stream::sha256(&mut file)?,
                    platform_id: inspection.ffu.map(|f| f.platform_id),
                });
            }
            print(wpi_core::operations::prepare(
                operation,
                device,
                profiles::current_host(),
                TransportKind::Usb,
                imports,
            ))?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
