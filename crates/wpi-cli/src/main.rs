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
#[derive(clap::Args)]
struct CheckSpecASessionArgs {
    source: PathBuf,
    package: PathBuf,
    primary: PathBuf,
    loader: PathBuf,
    #[arg(long)]
    device_id: String,
    #[arg(long)]
    disk_sectors: u64,
    #[arg(long)]
    expect_source_sha256: String,
    #[arg(long)]
    expect_package_sha256: String,
    #[arg(long)]
    expect_primary_sha256: String,
    #[arg(long)]
    expect_loader_sha256: String,
    /// Run one correlated Normal/Flash/Normal read-only cycle after local checks.
    #[arg(long,requires_all=["confirm","journal"])]
    roundtrip: bool,
    #[arg(long, requires = "roundtrip")]
    confirm: Option<String>,
    #[arg(long, requires = "roundtrip")]
    journal: Option<PathBuf>,
}
#[derive(clap::Args)]
struct PlanSpecAFinishArgs {
    package: PathBuf,
    primary: PathBuf,
    output: PathBuf,
    #[arg(long)]
    disk_sectors: u64,
    #[arg(long)]
    expect_primary_sha256: String,
    #[arg(long)]
    expect_package_sha256: String,
}
#[derive(Subcommand)]
enum Command {
    /// Inspect an interrupted finish-stage replay journal. Never resumes or contacts USB.
    InspectSpecAFinishJournal { input: PathBuf },
    /// Compose the missing UEFI-variable and EFIESP stages from pinned local inputs. No USB access.
    PlanSpecAFinish(Box<PlanSpecAFinishArgs>),
    /// Bind pinned local unlock inputs to five read-only Normal-mode queries. No mode change or writes.
    CheckSpecASession(Box<CheckSpecASessionArgs>),
    /// Compose an advisory Spec A programmer-phase report from pinned local files. No USB access.
    PlanSpecAProgrammer {
        package: PathBuf,
        primary: PathBuf,
        output: PathBuf,
        #[arg(long)]
        disk_sectors: u64,
        #[arg(long)]
        expect_primary_sha256: String,
        #[arg(long)]
        expect_package_sha256: String,
    },
    /// Run a local recovery protocol replay with a NEW durable JSONL journal. No USB access.
    ReplayRecovery {
        input: PathBuf,
        scenario: PathBuf,
        journal: PathBuf,
    },
    /// Audit a pinned stock FFU's manifest and GPT templates against saved evidence. Local only.
    AuditRecovery {
        input: PathBuf,
        primary: PathBuf,
        output: PathBuf,
        #[arg(long)]
        disk_sectors: u64,
        #[arg(long)]
        expect_primary_sha256: String,
        #[arg(long)]
        expect_ffu_sha256: String,
    },
    /// Analyze a pinned reference ZIP against a saved live primary GPT. Local files only.
    PlanSpecALayout {
        package: PathBuf,
        primary: PathBuf,
        output: PathBuf,
        #[arg(long)]
        disk_sectors: u64,
        #[arg(long)]
        expect_primary_sha256: String,
        #[arg(long)]
        expect_package_sha256: String,
    },
    /// Preview one preflight/return-boot GPT capture cycle. No context/timer/firmware writes.
    BootGptTest {
        input: PathBuf,
        id: String,
        output: PathBuf,
        #[arg(long, requires_all = ["confirm", "report"])]
        execute: bool,
        #[arg(long, requires = "execute")]
        confirm: Option<String>,
        #[arg(long, requires = "execute")]
        report: Option<PathBuf>,
    },
    /// One read-only NOKV diagnostic for an already exposed reviewed FlashApp. No mode change.
    FlashSecurityDiagnostic { id: String },
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
    /// Read-only handshake on an ALREADY exposed emergency USB endpoint. No mode changes or uploads.
    ProbeEmergency {
        id: String,
        /// Required protocol choice; no automatic detection or fallback.
        #[arg(long, value_parser = ["dload", "programmer-v1"])]
        protocol: String,
    },
    /// Fixed read-only emergency queries through an explicitly selected USB serial port.
    ProbeEmergencySerial {
        port: String,
        #[arg(long)]
        usb_device_id: String,
        #[arg(long, value_parser = ["dload", "programmer-v1"])]
        protocol: String,
    },
    /// Observe disappearance and a stable arrival on the selected physical port. Sends no commands.
    ObserveArrival {
        id: String,
        #[arg(long, value_parser = ["normal", "flash", "emergency"])]
        expected: String,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=30))]
        timeout_seconds: u64,
    },
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
        Command::ReplayRecovery {
            input,
            scenario,
            journal,
        } => {
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Scenario {
                exchanges: Vec<wpi_protocol::replay::Exchange>,
            }
            let scenario: Scenario = serde_json::from_value(read_json(&scenario)?)?;
            if scenario.exchanges.is_empty() || scenario.exchanges.len() > 512 {
                return Err("Recovery replay requires 1–512 exchanges".into());
            }
            if journal.extension().is_none_or(|e| e != "jsonl") {
                return Err("Choose a new .jsonl journal file".into());
            }
            let mut source = artifacts::open_artifact(&input)?;
            let mut transport = wpi_protocol::replay::ReplayTransport::new(scenario.exchanges);
            let cancelled = Arc::new(AtomicBool::new(false));
            let signal = cancelled.clone();
            ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
            let mut journal = wpi_core::recovery_journal::FileJournal::create(&journal)?;
            let result = wpi_core::recovery_replay::run_journaled_cancellable(
                &mut source,
                &mut transport,
                |event| {
                    eprintln!(
                        "Replay {:?}: {}/{}",
                        event.state, event.completed_bytes, event.total_bytes
                    );
                    !cancelled.load(Ordering::Acquire)
                },
                |entry| journal.append(entry),
                || !cancelled.load(Ordering::Acquire),
            );
            print(
                serde_json::json!({"replay_only":true,"phone_contacted":false,"phone_writes_enabled":false,
                "transfer_completed":result.is_ok(),"transcript_fully_consumed":transport.finished(),
                "automatic_resume_allowed":false,"error":result.as_ref().err().map(ToString::to_string)}),
            )?;
            result?;
            if !transport.finished() {
                return Err("Replay contains unused exchanges; inspect the scenario".into());
            }
        }
        Command::AuditRecovery {
            input,
            primary,
            output,
            disk_sectors,
            expect_primary_sha256,
            expect_ffu_sha256,
        } => {
            use std::io::{Read, Write};
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let mut source = artifacts::open_artifact(&input)?;
            let mut bytes = Vec::new();
            artifacts::open_artifact(&primary)?
                .take(17409)
                .read_to_end(&mut bytes)?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let signal = cancelled.clone();
            ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
            let mut last = std::time::Instant::now();
            let report = wpi_image::recovery_audit::analyze(
                &mut source,
                &bytes,
                disk_sectors,
                &expect_primary_sha256,
                &expect_ffu_sha256,
                |stage, d, t| {
                    if d == 0 || d == t || last.elapsed().as_millis() >= 250 {
                        eprintln!("{stage}: {d}/{t}");
                        last = std::time::Instant::now();
                    }
                    !cancelled.load(Ordering::Acquire)
                },
            )?;
            artifacts::write_new(&output, |writer| {
                serde_json::to_writer_pretty(&mut *writer, &report)
                    .map_err(|e| wpi_image::ImageError::Invalid(e.to_string()))?;
                writer.write_all(b"\n")?;
                Ok(())
            })?;
            print(report)?;
        }
        Command::CheckSpecASession(args) => check_spec_a_session(*args)?,
        Command::InspectSpecAFinishJournal { input } => {
            print(wpi_core::spec_a_finish_recovery::inspect(
                std::io::BufReader::new(artifacts::open_artifact(&input)?),
            )?)?;
        }
        Command::PlanSpecAFinish(args) => plan_spec_a_finish(*args)?,
        Command::PlanSpecAProgrammer {
            package,
            primary,
            output,
            disk_sectors,
            expect_primary_sha256,
            expect_package_sha256,
        } => {
            use std::{
                io::{Read, Write},
                sync::{
                    atomic::{AtomicBool, Ordering},
                    Arc,
                },
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let signal = cancelled.clone();
            ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
            let mut source = artifacts::open_artifact(&package)?;
            let mut bytes = Vec::new();
            artifacts::open_artifact(&primary)?
                .take(17409)
                .read_to_end(&mut bytes)?;
            let mut last = std::time::Instant::now();
            let plan = wpi_image::spec_a::programmer_plan::build(
                &mut source,
                &bytes,
                disk_sectors,
                &expect_primary_sha256,
                &expect_package_sha256,
                |stage, d, t| {
                    if last.elapsed().as_millis() >= 250 || d == t {
                        eprintln!("{stage}: {d}/{t}");
                        last = std::time::Instant::now();
                    }
                    !cancelled.load(Ordering::Acquire)
                },
            )?;
            artifacts::write_new(&output, |writer| {
                serde_json::to_writer_pretty(&mut *writer, plan.report())
                    .map_err(|e| wpi_image::ImageError::Invalid(e.to_string()))?;
                writer.write_all(b"\n")?;
                Ok(())
            })?;
            print(plan.report())?;
        }
        Command::PlanSpecALayout {
            package,
            primary,
            output,
            disk_sectors,
            expect_primary_sha256,
            expect_package_sha256,
        } => {
            use std::io::{Read, Write};
            let mut source = artifacts::open_artifact(&package)?;
            let mut bytes = Vec::new();
            artifacts::open_artifact(&primary)?
                .take(17409)
                .read_to_end(&mut bytes)?;
            let mut last = std::time::Instant::now();
            let report = wpi_image::spec_a::live_plan::analyze(
                &mut source,
                &bytes,
                disk_sectors,
                &expect_primary_sha256,
                &expect_package_sha256,
                |d, t| {
                    if last.elapsed().as_millis() >= 250 || d == t {
                        eprintln!("Verify offline package: {d}/{t} bytes");
                        last = std::time::Instant::now();
                    }
                    true
                },
            )?;
            artifacts::write_new(&output, |writer| {
                serde_json::to_writer_pretty(&mut *writer, &report)
                    .map_err(|e| wpi_image::ImageError::Invalid(e.to_string()))?;
                writer.write_all(b"\n")?;
                Ok(())
            })?;
            print(report)?;
        }
        Command::BootGptTest {
            input,
            id,
            output,
            execute,
            confirm,
            report,
        } => {
            let reference = wpi_core::spec_a_preflight::Reference::read(
                &mut artifacts::open_artifact(&input)?,
            )?;
            use wpi_transport::mode_test::public_id;
            if !execute {
                print(public_id::gpt_preview(&id, &reference, &output)?)?;
            } else {
                execute_experiment(
                    confirm,
                    report,
                    public_id::GPT_CONFIRMATION,
                    public_id::GPT_EXPERIMENT,
                    |confirmation, cancelled, events| {
                        public_id::run_gpt(
                            &id,
                            &reference,
                            &output,
                            confirmation,
                            cancelled,
                            events,
                        )
                    },
                )?;
            }
        }
        Command::FlashSecurityDiagnostic { id } => print(
            wpi_transport::mode_test::public_id::security_diagnostic(&id)?,
        )?,
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
        Command::ProbeEmergency { id, protocol } => {
            let protocol = match protocol.as_str() {
                "dload" => wpi_transport::emergency_probe::Protocol::Dload,
                "programmer-v1" => wpi_transport::emergency_probe::Protocol::ProgrammerV1,
                _ => return Err("Select dload or programmer-v1 explicitly".into()),
            };
            print(wpi_transport::emergency_probe::run(&id, protocol)?)?;
        }
        Command::ProbeEmergencySerial {
            port,
            usb_device_id,
            protocol,
        } => {
            let protocol = match protocol.as_str() {
                "dload" => wpi_transport::emergency_probe::Protocol::Dload,
                "programmer-v1" => wpi_transport::emergency_probe::Protocol::ProgrammerV1,
                _ => return Err("Select dload or programmer-v1 explicitly".into()),
            };
            print(wpi_transport::serial_probe::run(
                &port,
                &usb_device_id,
                protocol,
            )?)?;
        }
        Command::ObserveArrival {
            id,
            expected,
            timeout_seconds,
        } => {
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };
            let expected = match expected.as_str() {
                "normal" => DeviceMode::Normal,
                "flash" => DeviceMode::Flash,
                "emergency" => DeviceMode::Emergency,
                _ => return Err("Select a Normal/Flash/Emergency USB target".into()),
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let signal = cancelled.clone();
            ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
            print(wpi_transport::arrival::run(
                &id,
                expected,
                std::time::Duration::from_secs(timeout_seconds),
                &cancelled,
                |event| {
                    eprintln!(
                        "USB observation: {:?} ({} ms)",
                        event.stage, event.elapsed_ms
                    )
                },
            )?)?;
        }
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
fn plan_spec_a_finish(args: PlanSpecAFinishArgs) -> Result<(), Box<dyn Error>> {
    let PlanSpecAFinishArgs {
        package,
        primary,
        output,
        disk_sectors,
        expect_primary_sha256,
        expect_package_sha256,
    } = args;
    use std::{
        io::{Read, Write},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    let mut zip = artifacts::open_artifact(&package)?;
    let mut primary_bytes = Vec::new();
    artifacts::open_artifact(&primary)?
        .take(17409)
        .read_to_end(&mut primary_bytes)?;
    let mut last = std::time::Instant::now();
    let mut progress = |stage: &str, d, t| {
        if d == t || last.elapsed().as_millis() >= 250 {
            eprintln!("{stage}: {d}/{t}");
            last = std::time::Instant::now();
        }
        !cancelled.load(Ordering::Acquire)
    };
    let boot = wpi_image::spec_a::programmer_plan::build(
        &mut zip,
        &primary_bytes,
        disk_sectors,
        &expect_primary_sha256,
        &expect_package_sha256,
        &mut progress,
    )?;
    let plan = wpi_image::spec_a::finish_plan::build(&mut zip, &primary_bytes, &boot, progress)?;
    artifacts::write_new(&output, |writer| {
        serde_json::to_writer_pretty(&mut *writer, plan.report())
            .map_err(|e| wpi_image::ImageError::Invalid(e.to_string()))?;
        writer.write_all(b"\n")?;
        Ok(())
    })?;
    print(plan.report())?;
    Ok(())
}
fn check_spec_a_session(args: CheckSpecASessionArgs) -> Result<(), Box<dyn Error>> {
    let CheckSpecASessionArgs {
        source,
        package,
        primary,
        loader,
        device_id,
        disk_sectors,
        expect_source_sha256,
        expect_package_sha256,
        expect_primary_sha256,
        expect_loader_sha256,
        roundtrip,
        confirm,
        journal,
    } = args;

    if roundtrip
        && confirm.as_deref() != Some(wpi_transport::mode_test::public_id::PREPARED_CONFIRMATION)
    {
        return Err(
            "Prepared mode cycle requires the exact RM875-PREPARED-READONLY-ROUNDTRIP confirmation"
                .into(),
        );
    }

    use std::{
        io::Read,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };
    use wpi_core::{
        spec_a_emergency_replay::{EntryPlan, Loader},
        spec_a_session::Prepared,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    let mut ffu = artifacts::open_artifact(&source)?;
    let mut last = std::time::Instant::now();
    let entry = EntryPlan::read(&mut ffu, &expect_source_sha256, |d, t| {
        if d == t || last.elapsed().as_millis() >= 250 {
            eprintln!("Pin source FFU: {d}/{t}");
            last = std::time::Instant::now();
        }
        !cancelled.load(Ordering::Acquire)
    })?;
    if cancelled.load(Ordering::Acquire) {
        return Err("Cancelled before pinned reference reads".into());
    }
    let reference = entry.reference(&mut ffu)?;
    let mut loader_bytes = Vec::new();
    artifacts::open_artifact(&loader)?
        .take(wpi_image::spec_a::MAX_LOADER_FILE as u64 + 1)
        .read_to_end(&mut loader_bytes)?;
    let loader = Loader::prepare(&loader_bytes, &expect_loader_sha256, reference.root())?;
    let mut primary_bytes = Vec::new();
    artifacts::open_artifact(&primary)?
        .take(17409)
        .read_to_end(&mut primary_bytes)?;
    let mut zip = artifacts::open_artifact(&package)?;
    let boot = wpi_image::spec_a::programmer_plan::build(
        &mut zip,
        &primary_bytes,
        disk_sectors,
        &expect_primary_sha256,
        &expect_package_sha256,
        |stage, d, t| {
            if d == t || last.elapsed().as_millis() >= 250 {
                eprintln!("{stage}: {d}/{t}");
                last = std::time::Instant::now();
            }
            !cancelled.load(Ordering::Acquire)
        },
    )?;
    let prepared = Prepared::new(entry, reference, loader, boot)?;
    if roundtrip {
        use std::io::Write;
        let path = journal.ok_or("A new .jsonl journal is required")?;
        if path.extension().is_none_or(|e| e != "jsonl") {
            return Err("Prepared cycle journal must be a new .jsonl file".into());
        }
        let mut journal = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        if !journal.metadata()?.is_file() {
            return Err("Journal must be a new regular file".into());
        }
        writeln!(
            journal,
            "{}",
            serde_json::json!({"kind":"experiment_header","experiment":wpi_transport::mode_test::public_id::PREPARED_EXPERIMENT,"artifacts":prepared.artifacts(),"firmware_or_partition_write_commands":false})
        )?;
        journal.flush()?;
        journal.sync_all()?;
        let mut save_error = None;
        let started = std::time::Instant::now();
        let result = wpi_transport::mode_test::public_id::run_prepared(
            &device_id,
            &prepared,
            confirm.as_deref().unwrap(),
            &cancelled,
            |event| {
                if save_error.is_some() {
                    return false;
                }
                if let wpi_transport::mode_test::ModeTestEvent::Progress { event } = event {
                    eprintln!("{:?}: {}", event.state, event.message);
                }
                let save = (|| -> Result<(), Box<dyn Error>> {
                    let record = serde_json::json!({"elapsed_ms":started.elapsed().as_millis() as u64,"event":event});
                    let line = serde_json::to_vec(&record)?;
                    if line.len() > 65536 {
                        return Err("Prepared cycle journal record exceeds limit".into());
                    }
                    journal.write_all(&line)?;
                    journal.write_all(b"\n")?;
                    journal.flush()?;
                    journal.sync_all()?;
                    Ok(())
                })();
                if let Err(error) = save {
                    save_error = Some(error.to_string());
                    false
                } else {
                    true
                }
            },
        );
        if let Some(error) = save_error {
            return Err(format!("Prepared cycle journal failed: {error}; inspect phone state before further commands").into());
        }
        print(result?)?;
        return Ok(());
    }
    print(wpi_transport::spec_a_session::check_normal(
        &device_id,
        &prepared,
        &cancelled,
        |stage| eprintln!("{stage}"),
    )?)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
