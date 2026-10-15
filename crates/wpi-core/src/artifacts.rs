//! Native local file operations. Never opens raw device nodes.
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use wpi_image::{ImageError, Result};

pub fn open_artifact(path: &Path) -> Result<File> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(ImageError::Invalid(
            "select a regular local file, not a directory or device".into(),
        ));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(ImageError::Invalid("artifact is not a regular file".into()));
    }
    Ok(file)
}
pub fn inspect_file(path: &Path) -> Result<crate::inspection::Inspection> {
    crate::inspection::inspect_at(&mut open_artifact(path)?, reference_time())
}
fn reference_time() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}
pub fn prepare_recovery<F: FnMut(u64, u64) -> bool>(
    path: &Path,
    device: Option<wpi_types::DeviceIdentity>,
    host: wpi_types::Host,
    transport: wpi_types::TransportKind,
    mut progress: F,
) -> Result<wpi_types::RecoveryPreparation> {
    use crate::recovery_prepare::{report, ChunkIntegrity};
    let mut source = open_artifact(path)?;
    let before = source.metadata()?;
    let inspection = crate::inspection::inspect_at(&mut source, reference_time())?;
    let Some(ffu) = inspection.ffu.as_ref() else {
        return Ok(report(
            device,
            Some(&inspection),
            None,
            ChunkIntegrity::NotChecked,
            host,
            transport,
        ));
    };
    let verified_bytes = ffu.total_size - ffu.security_size;
    let total = verified_bytes
        .checked_add(before.len())
        .ok_or_else(|| ImageError::Invalid("preparation progress range overflow".into()))?;
    let integrity = match ffu.verify_hashes(&mut source, |done, _| {
        progress(done * ffu.chunk_size as u64, total)
    }) {
        Ok(()) => ChunkIntegrity::Passed,
        Err(ImageError::Cancelled) => return Err(ImageError::Cancelled),
        Err(error) => ChunkIntegrity::Failed(error.to_string()),
    };
    source.seek(SeekFrom::Start(0))?;
    let hashed = wpi_image::stream::copy_hashed(
        &mut source,
        &mut std::io::sink(),
        before.len(),
        |done, _| progress(verified_bytes + done, total),
    )?;
    let after = source.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(ImageError::Invalid(
            "source image changed during preparation; reselect and inspect it again".into(),
        ));
    }
    let artifact = wpi_types::ArtifactIdentity {
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        size: after.len(),
        sha256: hashed,
        platform_id: Some(ffu.platform_id.clone()),
    };
    Ok(report(
        device,
        Some(&inspection),
        Some(artifact),
        integrity,
        host,
        transport,
    ))
}
pub fn write_new<F: FnOnce(&mut File) -> Result<()>>(output: &Path, action: F) -> Result<()> {
    if output.exists() {
        return Err(ImageError::Invalid(
            "output already exists; select a new output file".into(),
        ));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    action(temporary.as_file_mut())?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(output)
        .map_err(|e| ImageError::Io(e.error))?;
    Ok(())
}
pub fn extract_partition<F: FnMut(u64, u64) -> bool>(
    input: &Path,
    name: &str,
    output: &Path,
    progress: F,
) -> Result<()> {
    let mut source = open_artifact(input)?;
    let source_size = source.metadata()?.len();
    let report = crate::inspection::inspect(&mut source)?;
    let gpt = report
        .gpt
        .ok_or_else(|| ImageError::Invalid("artifact contains no partition table".into()))?;
    let (start, length) = gpt.partition(name)?.byte_range()?;
    if let Some(ffu) = report.ffu {
        write_new(output, |writer| {
            ffu.extract(&mut source, writer, start, length, progress)
        })
    } else {
        if start
            .checked_add(length)
            .filter(|end| *end <= source_size)
            .is_none()
        {
            return Err(ImageError::Invalid("partition exceeds source file".into()));
        }
        source.seek(SeekFrom::Start(start))?;
        write_new(output, |writer| {
            wpi_image::stream::copy_hashed(&mut source, writer, length, progress).map(|_| ())
        })
    }
}
pub fn convert_gpt(input: &Path, output: &Path) -> Result<()> {
    let report = inspect_file(input)?;
    let xml = report
        .gpt
        .ok_or_else(|| ImageError::Invalid("artifact contains no GPT".into()))?
        .to_xml();
    write_new(output, |file| {
        file.write_all(xml.as_bytes())?;
        Ok(())
    })
}
pub fn extract_file(input: &Path, path: &str, output: &Path) -> Result<()> {
    let mut source = open_artifact(input)?;
    write_new(output, |writer| {
        wpi_image::filesystem::extract_file(&mut source, path, writer, |_, _| true)
    })
}
pub fn patch_fat(input: &Path, output: &Path, definition: &str, reverse: bool) -> Result<String> {
    let mut source = open_artifact(input)?;
    let catalog = wpi_image::patch::PatchCatalog::bundled()?;
    let mut version = String::new();
    write_new(output, |writer| {
        let length = source.metadata()?.len();
        wpi_image::stream::copy_hashed(&mut source, writer, length, |_, _| true)?;
        version = wpi_image::filesystem::patch_fat_image(writer, &catalog, definition, reverse)?;
        Ok(())
    })?;
    Ok(version)
}
pub fn patch_directory(
    input: &Path,
    output: &Path,
    definition: &str,
    reverse: bool,
) -> Result<serde_json::Value> {
    let source_root = input.canonicalize()?;
    if !source_root.is_dir() {
        return Err(ImageError::Invalid(
            "patch source must be a directory of extracted files".into(),
        ));
    }
    if output.exists() {
        return Err(ImageError::Invalid(
            "patch output must be a new directory".into(),
        ));
    }
    let catalog = wpi_image::patch::PatchCatalog::bundled()?;
    let (version, files) = catalog.prepare(definition, reverse, |relative| {
        let path = source_root.join(relative).canonicalize()?;
        if !path.starts_with(&source_root) {
            return Err(ImageError::Invalid(
                "patch target resolves outside source directory".into(),
            ));
        }
        let file = open_artifact(&path)?;
        let mut bytes = Vec::new();
        file.take(wpi_image::MAX_METADATA as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = tempfile::tempdir_in(parent)?;
    let mut manifest = Vec::new();
    for file in files {
        let path = directory.path().join(&file.path);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut writer = File::create(&path)?;
        writer.write_all(&file.bytes)?;
        writer.sync_all()?;
        manifest.push(serde_json::json!({"path":file.path,"input_sha1":file.original_sha1,"output_sha1":file.resulting_sha1}));
    }
    std::fs::create_dir(output)?;
    for item in &manifest {
        let relative = item["path"].as_str().unwrap();
        let destination = output.join(relative);
        std::fs::create_dir_all(destination.parent().unwrap())?;
        let mut source = File::open(directory.path().join(relative))?;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::copy(&mut source, &mut writer)?;
        writer.sync_all()?;
    }
    Ok(
        serde_json::json!({"definition":definition,"version":version,"reverse":reverse,"files":manifest,"note":"Only patched target files are output. Source files are preserved."}),
    )
}
