//! Standalone experimental primary-GPT recovery. Preview is the default.
use clap::Parser;
use std::{
    error::Error,
    io::Read,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use wpi_core::{
    artifacts,
    spec_a_emergency_replay::{EntryPlan, Loader},
    spec_a_session::Prepared,
};
use wpi_transport::spec_a_native::entry_restore;
#[derive(Parser)]
#[command(
    name = "wpi-gpt-recovery",
    version,
    about = "Preview or explicitly execute captured-primary GPT recovery on an already exposed RM-875 DLOAD endpoint. No unlock or entry command."
)]
struct Args {
    source: PathBuf,
    package: PathBuf,
    primary: PathBuf,
    loader: PathBuf,
    donor_boot: PathBuf,
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
    /// Execute ONE separately approved recovery. Without this flag, no USB is enumerated.
    #[arg(long, requires_all=["device_id","confirm","journal","expect_port_sha256","expect_normal_serial_sha256"])]
    execute: bool,
    #[arg(long, requires = "execute")]
    device_id: Option<String>,
    #[arg(long, requires = "execute")]
    confirm: Option<String>,
    #[arg(long, requires = "execute")]
    journal: Option<PathBuf>,
    #[arg(long, requires = "execute")]
    expect_port_sha256: Option<String>,
    #[arg(long, requires = "execute")]
    expect_normal_serial_sha256: Option<String>,
}
#[inline(never)]
fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if args.execute && args.confirm.as_deref() != Some(entry_restore::CONFIRMATION) {
        return Err("Recovery requires the exact captured-primary recovery confirmation; no file or device was opened".into());
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))?;
    let mut source = artifacts::open_artifact(&args.source)?;
    let mut last = std::time::Instant::now();
    let entry = EntryPlan::read(&mut source, &args.expect_source_sha256, |d, t| {
        if last.elapsed().as_millis() >= 500 || d == t {
            eprintln!("Pin source FFU: {d}/{t}");
            last = std::time::Instant::now();
        }
        !cancelled.load(Ordering::Acquire)
    })?;
    let reference = entry.reference(&mut source)?;
    let mut loader = Vec::new();
    artifacts::open_artifact(&args.loader)?
        .take(wpi_image::spec_a::MAX_LOADER_FILE as u64 + 1)
        .read_to_end(&mut loader)?;
    let loader = Loader::prepare(&loader, &args.expect_loader_sha256, reference.root())?;
    let mut primary = Vec::new();
    artifacts::open_artifact(&args.primary)?
        .take(17409)
        .read_to_end(&mut primary)?;
    let mut package = artifacts::open_artifact(&args.package)?;
    let boot = wpi_image::spec_a::programmer_plan::build(
        &mut package,
        &primary,
        args.disk_sectors,
        &args.expect_primary_sha256,
        &args.expect_package_sha256,
        |_, _, _| !cancelled.load(Ordering::Acquire),
    )?;
    let finish =
        wpi_image::spec_a::finish_plan::build(&mut package, &primary, &boot, |_, _, _| {
            !cancelled.load(Ordering::Acquire)
        })?;
    let prepared = Prepared::new(entry, reference, loader, boot)?;
    let mut donor = Vec::new();
    artifacts::open_artifact(&args.donor_boot)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut donor)?;
    let plan = wpi_transport::spec_a_native::Plan::new(&prepared, &finish, &donor)?;
    if args.execute {
        let report = entry_restore::run(
            args.device_id
                .as_deref()
                .ok_or("Device selection required")?,
            &plan,
            args.confirm
                .as_deref()
                .ok_or("Recovery confirmation required")?,
            args.expect_port_sha256
                .as_deref()
                .ok_or("Port digest required")?,
            args.expect_normal_serial_sha256
                .as_deref()
                .ok_or("Normal serial digest required")?,
            args.journal
                .as_deref()
                .ok_or("New recovery journal required")?,
            &cancelled,
            |stage| eprintln!("{stage}"),
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&entry_restore::preview(&plan)?)?
        );
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
