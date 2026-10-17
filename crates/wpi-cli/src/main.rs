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
    /// Preview one identity-bound Normal/Flash read-only preflight/Normal experiment. No GPT or writes.
    SpecAPreflightTest {
        input: PathBuf,
        id: String,
        #[arg(long, requires_all = ["confirm", "report"])]
        execute: bool,
        #[arg(long, requires = "execute")]
        confirm: Option<String>,
        #[arg(long, requires = "execute")]
        report: Option<PathBuf>,
    },
    /// Preview or run read-only Spec A checks in an ALREADY exposed FlashApp. Never switches modes.
    PreflightSpecA {
        input: PathBuf,
        #[arg(long, conflicts_with = "replay")]
        device_id: Option<String>,
        /// Local synthetic/replay exchanges; never contacts USB.
        #[arg(long, conflicts_with = "device_id")]
        replay: Option<PathBuf>,
        /// Request NOKT only when both security reports permit the current context.
        #[arg(long)]
        read_primary_gpt: bool,
    },
    /// Build a NEW offline Spec A reference ZIP with originals, hashes and recovery metadata. No phone access.
    PackageSpecA {
        input: PathBuf,
        output: PathBuf,
        #[arg(long)]
        donor: PathBuf,
        #[arg(long)]
        sbl3: Option<PathBuf>,
        #[arg(long)]
        loader: Vec<PathBuf>,
    },
    /// Build a NEW offline UEFI or EFIESP intermediate image from local FFUs. No phone access.
    AssembleSpecA {
        input: PathBuf,
        #[arg(value_parser = ["uefi", "efiesp"])]
        component: String,
        output: PathBuf,
        #[arg(long)]
        donor: Option<PathBuf>,
    },
    /// Research-only read-only mass storage; never changes phone modes.
    Storage {
        #[command(subcommand)]
        action: StorageCommand,
    },
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
    /// Inspect Spec A boot images and optional local loaders; never unlocks or contacts USB.
    PrepareSpecA {
        input: PathBuf,
        /// Extracted raw SBL3 partition image; filenames do not prove engineering status.
        #[arg(long)]
        sbl3: Option<PathBuf>,
        /// Raw MBN or strict contiguous Intel HEX; may be repeated (maximum 32).
        #[arg(long)]
        loader: Vec<PathBuf>,
        /// Optional donor FFU; checks its EFIESP boot-file bytes only.
        #[arg(long)]
        donor: Option<PathBuf>,
    },
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
#[derive(Subcommand)]
enum StorageCommand {
    /// List recognized phone-storage candidates without opening raw disks.
    List,
    /// Inspect an already offline/read-only phone disk under exclusive access.
    Inspect { disk: u32 },
    /// Copy a selected partition or full disk into a NEW file; experimental.
    #[command(group(clap::ArgGroup::new("scope").required(true).args(["partition", "full"])))]
    Backup {
        disk: u32,
        #[arg(long)]
        expect_gpt: String,
        #[arg(long)]
        partition: Option<String>,
        #[arg(long)]
        full: bool,
        output: PathBuf,
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
    let started = std::time::Instant::now();
    let result = execute(confirmation, &cancelled, &mut |event| {
        if let wpi_transport::mode_test::ModeTestEvent::Progress { event } = event {
            eprintln!("{:?}: {}", event.state, event.message);
        }
        let write = (|| -> Result<(), Box<dyn Error>> {
            let mut value = serde_json::to_value(event)?;
            value
                .as_object_mut()
                .ok_or("Invalid experiment event")?
                .insert(
                    "elapsed_ms".into(),
                    serde_json::json!(
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
                    ),
                );
            serde_json::to_writer(&mut journal, &value)?;
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
    let mut outcome = match &result {
        Ok(summary) => serde_json::json!({"kind":"experiment_result","summary":summary}),
        Err(error) => {
            serde_json::json!({"kind":"experiment_result","error":error,"recovery_authorized":false})
        }
    };
    outcome
        .as_object_mut()
        .ok_or("Invalid experiment outcome")?
        .insert(
            "elapsed_ms".into(),
            serde_json::json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
        );
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
        Command::SpecAPreflightTest {
            input,
            id,
            execute,
            confirm,
            report,
        } => {
            let mut source = artifacts::open_artifact(&input)?;
            let reference = wpi_core::spec_a_preflight::Reference::read(&mut source)?;
            use wpi_transport::mode_test::public_id;
            if !execute {
                print(public_id::preflight_preview(&id, &reference)?)?;
            } else {
                execute_experiment(
                    confirm,
                    report,
                    public_id::PREFLIGHT_CONFIRMATION,
                    public_id::PREFLIGHT_EXPERIMENT,
                    |confirmation, cancelled, events| {
                        public_id::run_preflight(&id, &reference, confirmation, cancelled, events)
                    },
                )?;
            }
        }
        Command::PreflightSpecA {
            input,
            device_id,
            replay,
            read_primary_gpt,
        } => {
            let mut source = artifacts::open_artifact(&input)?;
            let reference = wpi_core::spec_a_preflight::Reference::read(&mut source)?;
            if device_id.is_none() && replay.is_none() {
                print(serde_json::json!({
                    "source_kind":"reference_preview_only", "reference":reference.summary(),
                    "phone_contacted":false, "phone_writes_enabled":false,
                    "next":"An explicitly selected, already exposed FlashApp or a local replay is required. This command never changes modes."
                }))?;
            } else {
                use std::sync::{
                    atomic::{AtomicBool, Ordering},
                    Arc,
                };
                let cancelled = Arc::new(AtomicBool::new(false));
                let signal = cancelled.clone();
                ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
                let progress = |stage: &str| {
                    eprintln!("Read-only preflight: {stage}");
                    !cancelled.load(Ordering::Acquire)
                };
                if let Some(path) = replay {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Scenario {
                        exchanges: Vec<wpi_protocol::replay::Exchange>,
                    }
                    let scenario: Scenario = serde_json::from_value(read_json(&path)?)?;
                    if scenario.exchanges.len() > 8 {
                        return Err("Preflight replay exceeds eight exchanges".into());
                    }
                    let mut transport =
                        wpi_protocol::replay::ReplayTransport::new(scenario.exchanges);
                    let capture = wpi_protocol::preflight::capture(
                        &mut transport,
                        reference.root(),
                        reference.platform(),
                        read_primary_gpt,
                        progress,
                    )?;
                    if !transport.finished() {
                        return Err("Preflight replay contains unused exchanges".into());
                    }
                    print(wpi_core::spec_a_preflight::assess(
                        &reference, capture, true,
                    )?)?;
                } else {
                    print(wpi_transport::spec_a_preflight::run(
                        &device_id.unwrap(),
                        &reference,
                        read_primary_gpt,
                        progress,
                    )?)?;
                }
            }
        }
        Command::Storage { action } => {
            let coordinator = wpi_core::operations::OperationCoordinator::default();
            let session = coordinator.reserve_storage_read()?;
            match action {
                StorageCommand::List => print(wpi_storage::discover()?)?,
                StorageCommand::Inspect { disk } => print(wpi_storage::inspect(disk)?)?,
                StorageCommand::Backup {
                    disk,
                    expect_gpt,
                    partition,
                    full: _,
                    output,
                } => {
                    let token = session.cancellation();
                    ctrlc::set_handler(move || {
                        token.store(true, std::sync::atomic::Ordering::Release)
                    })?;
                    let mut last = std::time::Instant::now();
                    let result = wpi_storage::backup(
                        disk,
                        &expect_gpt,
                        partition.as_deref(),
                        &output,
                        |done, total| {
                            if done == 0 || done == total || last.elapsed().as_millis() >= 250 {
                                eprintln!("Backing up: {done}/{total} bytes");
                                last = std::time::Instant::now();
                            }
                            session.safe_boundary()
                        },
                    )?;
                    print(result)?;
                }
            }
        }
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
        Command::PackageSpecA {
            input,
            output,
            donor,
            sbl3,
            loader,
        } => {
            let report = artifacts::build_spec_a_package(
                &input,
                &donor,
                sbl3.as_deref(),
                &loader,
                &output,
                |_, _, _| true,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::AssembleSpecA {
            input,
            component,
            output,
            donor,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&artifacts::assemble_spec_a(
                    &input,
                    donor.as_deref(),
                    &component,
                    &output
                )?)?
            );
        }
        Command::PrepareSpecA {
            input,
            sbl3,
            loader,
            donor,
        } => print(artifacts::prepare_spec_a(
            &input,
            sbl3.as_deref(),
            &loader,
            donor.as_deref(),
        )?)?,
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
