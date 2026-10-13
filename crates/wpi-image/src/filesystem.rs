//! Portable FAT/NTFS boot-sector inspection. Unsupported variants fail explicitly.
use crate::{invalid, read_at, slice, u32le, u64le, ImageError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};
use std::io::{SeekFrom, Write};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemInfo {
    pub kind: String,
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub volume_serial: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub directory: bool,
    pub size: u64,
}
struct ReadOnly<'a, R>(&'a mut R);
impl<R: Read> Read for ReadOnly<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes)
    }
}
impl<R: Seek> Seek for ReadOnly<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}
impl<R> Write for ReadOnly<'_, R> {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "source image is read-only",
        ))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn relative(path: &str) -> Result<String> {
    if path.is_empty() || path == "/" {
        Ok(String::new())
    } else {
        crate::patch::safe_relative_path(path)
    }
}
fn ntfs_file<'n, R: Read + Seek>(
    ntfs: &'n ntfs::Ntfs,
    reader: &mut R,
    path: &str,
) -> Result<ntfs::NtfsFile<'n>> {
    let mut file = ntfs
        .root_directory(reader)
        .map_err(|e| invalid(e.to_string()))?;
    for part in relative(path)?.split('/').filter(|p| !p.is_empty()) {
        let next = {
            let index = file
                .directory_index(reader)
                .map_err(|e| invalid(e.to_string()))?;
            let mut finder = index.finder();
            let entry = ntfs::indexes::NtfsFileNameIndex::find(&mut finder, ntfs, reader, part)
                .ok_or_else(|| invalid(format!("file {path} not found")))?
                .map_err(|e| invalid(e.to_string()))?;
            entry
                .to_file(ntfs, reader)
                .map_err(|e| invalid(e.to_string()))?
        };
        file = next;
    }
    Ok(file)
}
pub fn list<R: Read + Seek>(reader: &mut R, path: &str) -> Result<Vec<DirectoryEntry>> {
    let info = inspect(reader)?;
    let path = relative(path)?;
    reader.seek(SeekFrom::Start(0))?;
    let mut output = Vec::new();
    if info.kind == "NTFS" {
        let mut fs = ntfs::Ntfs::new(reader).map_err(|e| invalid(e.to_string()))?;
        fs.read_upcase_table(reader)
            .map_err(|e| invalid(e.to_string()))?;
        let directory = ntfs_file(&fs, reader, &path)?;
        let index = directory
            .directory_index(reader)
            .map_err(|e| invalid(e.to_string()))?;
        let mut entries = index.entries();
        while let Some(entry) = entries.next(reader) {
            let entry = entry.map_err(|e| invalid(e.to_string()))?;
            let name = entry
                .key()
                .ok_or_else(|| invalid("NTFS entry has no filename"))?
                .map_err(|e| invalid(e.to_string()))?;
            if name.namespace() == ntfs::structured_values::NtfsFileNamespace::Dos {
                continue;
            }
            output.push(DirectoryEntry {
                name: name.name().to_string_lossy(),
                directory: name.is_directory(),
                size: name.data_size(),
            });
            if output.len() > 65536 {
                return Err(invalid("directory exceeds entry limit"));
            }
        }
    } else {
        let fs = fatfs::FileSystem::new(ReadOnly(reader), fatfs::FsOptions::new())?;
        let root = fs.root_dir();
        let directory = if path.is_empty() {
            root
        } else {
            root.open_dir(&path)?
        };
        for entry in directory.iter() {
            let entry = entry?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            output.push(DirectoryEntry {
                name,
                directory: entry.is_dir(),
                size: entry.len(),
            });
            if output.len() > 65536 {
                return Err(invalid("directory exceeds entry limit"));
            }
        }
    }
    output.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(output)
}
pub fn extract_file<R: Read + Seek, W: Write, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    path: &str,
    writer: &mut W,
    mut progress: F,
) -> Result<()> {
    let info = inspect(reader)?;
    let path = crate::patch::safe_relative_path(path)?;
    reader.seek(SeekFrom::Start(0))?;
    if info.kind == "NTFS" {
        use ntfs::NtfsReadSeek;
        let mut fs = ntfs::Ntfs::new(reader).map_err(|e| invalid(e.to_string()))?;
        fs.read_upcase_table(reader)
            .map_err(|e| invalid(e.to_string()))?;
        let file = ntfs_file(&fs, reader, &path)?;
        let item = file
            .data(reader, "")
            .ok_or_else(|| invalid("file has no unnamed data stream"))?
            .map_err(|e| invalid(e.to_string()))?;
        let attribute = item.to_attribute().map_err(|e| invalid(e.to_string()))?;
        let mut data = attribute
            .value(reader)
            .map_err(|e| invalid(e.to_string()))?;
        let total = data.len();
        let mut done = 0u64;
        let mut buffer = vec![0; crate::COPY_BUFFER];
        while done < total {
            if !progress(done, total) {
                return Err(ImageError::Cancelled);
            }
            let n = data
                .read(reader, &mut buffer)
                .map_err(|e| invalid(e.to_string()))?;
            if n == 0 {
                return Err(invalid("NTFS data stream is truncated"));
            }
            writer.write_all(&buffer[..n])?;
            done += n as u64;
        }
        writer.flush()?;
        progress(done, total);
        Ok(())
    } else {
        let fs = fatfs::FileSystem::new(ReadOnly(reader), fatfs::FsOptions::new())?;
        let mut file = fs.root_dir().open_file(&path)?;
        let length = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(0))?;
        crate::stream::copy_hashed(&mut file, writer, length, progress).map(|_| ())
    }
}
/// Patches only the caller-provided COPY of a FAT image, preserving target lengths.
/// Root patches in NTFS images need a separate metadata-aware writer and are not supported here.
pub fn patch_fat_image<R: Read + Write + Seek>(
    reader: &mut R,
    catalog: &crate::patch::PatchCatalog,
    name: &str,
    reverse: bool,
) -> Result<String> {
    if inspect(reader)?.kind == "NTFS" {
        return Err(ImageError::Unsupported(
            "NTFS image writes are not implemented; use patch-files on extracted files".into(),
        ));
    }
    reader.seek(SeekFrom::Start(0))?;
    let fs = fatfs::FileSystem::new(reader, fatfs::FsOptions::new())?;
    let root = fs.root_dir();
    let (version, files) = catalog.prepare(name, reverse, |path| {
        let file = root.open_file(path)?;
        let mut bytes = Vec::new();
        file.take(crate::MAX_METADATA as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })?;
    for patched in files {
        let mut file = root.open_file(&patched.path)?;
        if file.seek(SeekFrom::End(0))? != patched.bytes.len() as u64 {
            return Err(invalid("FAT patch would change target file length"));
        }
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&patched.bytes)?;
        file.flush()?;
    }
    drop(root);
    fs.unmount()?;
    Ok(version)
}

pub fn inspect<R: Read + Seek>(reader: &mut R) -> Result<FilesystemInfo> {
    let boot = read_at(reader, 0, 512)?;
    inspect_boot_sector(&boot)
}
pub fn inspect_boot_sector(boot: &[u8]) -> Result<FilesystemInfo> {
    if slice(boot, 510, 2)? != [0x55, 0xaa] {
        return Err(invalid("missing filesystem boot signature"));
    }
    let bytes_per_sector = u16::from_le_bytes(slice(boot, 11, 2)?.try_into().unwrap());
    let sectors_per_cluster = *slice(boot, 13, 1)?.first().unwrap();
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        || sectors_per_cluster == 0
        || !sectors_per_cluster.is_power_of_two()
    {
        return Err(invalid("invalid filesystem sector/cluster size"));
    }
    if slice(boot, 3, 8)? == b"NTFS    " {
        let sectors = u64le(boot, 40)?;
        if sectors == 0 {
            return Err(invalid("empty NTFS volume"));
        }
        return Ok(FilesystemInfo {
            kind: "NTFS".into(),
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors: sectors,
            volume_serial: format!("{:016X}", u64le(boot, 72)?),
        });
    }
    let reserved = u16::from_le_bytes(slice(boot, 14, 2)?.try_into().unwrap()) as u32;
    let fats = boot[16] as u32;
    let root_entries = u16::from_le_bytes(slice(boot, 17, 2)?.try_into().unwrap()) as u32;
    let small_sectors = u16::from_le_bytes(slice(boot, 19, 2)?.try_into().unwrap()) as u32;
    let sectors = if small_sectors == 0 {
        u32le(boot, 32)?
    } else {
        small_sectors
    };
    let small_fat = u16::from_le_bytes(slice(boot, 22, 2)?.try_into().unwrap()) as u32;
    let fat_size = if small_fat == 0 {
        u32le(boot, 36)?
    } else {
        small_fat
    };
    if reserved == 0 || !(1..=2).contains(&fats) || sectors == 0 || fat_size == 0 {
        return Err(ImageError::Unsupported(
            "not a supported FAT or NTFS volume".into(),
        ));
    }
    let root_sectors = (root_entries as u64 * 32).div_ceil(bytes_per_sector as u64);
    let overhead = reserved as u64 + fats as u64 * fat_size as u64 + root_sectors;
    let clusters = (sectors as u64)
        .checked_sub(overhead)
        .ok_or_else(|| invalid("FAT regions exceed volume size"))?
        / sectors_per_cluster as u64;
    let (kind, serial_at) = if clusters < 4085 {
        ("FAT12", 39)
    } else if clusters < 65525 {
        ("FAT16", 39)
    } else {
        ("FAT32", 67)
    };
    Ok(FilesystemInfo {
        kind: kind.into(),
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors: sectors as u64,
        volume_serial: format!("{:08X}", u32le(boot, serial_at)?),
    })
}
