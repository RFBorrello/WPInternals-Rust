use crate::{
    layout,
    policy::{self, InventoryDisk},
    Discovery, ImageError, Result,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle, process::CommandExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::{
    Ioctl::*, SystemInformation::GetWindowsDirectoryW, IO::DeviceIoControl,
};
use wpi_core::backup::{Geometry, ReadOnlySource};
fn bad(s: &str) -> ImageError {
    ImageError::Invalid(s.into())
}
pub(super) fn raw_access_prerequisite() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = std::ptr::null_mut();
    // SAFETY: a valid pseudo process handle and writable output handle are used.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0;
    // SAFETY: the buffer exactly fits TOKEN_ELEVATION; the owned token is closed
    // on both success and failure. No privilege is enabled by this query.
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    if result == 0
        || returned as usize != std::mem::size_of::<TOKEN_ELEVATION>()
        || elevation.TokenIsElevated == 0
    {
        return Err(bad("Native unlock requires an elevated process for exclusive read-only recovery capture. Restart the CLI as Administrator before any mode test; no privilege was changed."));
    }
    Ok(())
}
fn inventory() -> Result<Vec<InventoryDisk>> {
    let mut directory = [0u16; 32768];
    // SAFETY: output buffer is valid for the supplied element count.
    let n =
        unsafe { GetWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) } as usize;
    if n == 0 || n >= directory.len() {
        return Err(bad("Cannot locate the native Windows system directory"));
    }
    let executable = std::path::PathBuf::from(String::from_utf16_lossy(&directory[..n]))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut child = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("discover-windows.ps1"),
        ])
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let pipe = child
        .stdout
        .take()
        .ok_or_else(|| bad("Storage discovery output is unavailable"))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.take(65537).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < Duration::from_secs(20) => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(bad("Storage discovery timed out; no disk was opened"));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(error.into());
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| bad("Storage discovery reader failed"))??;
    if !status?.success() || bytes.len() > 65536 {
        return Err(bad(
            "Windows storage discovery failed or exceeded its output limit; no disk was opened",
        ));
    }
    let disks: Vec<InventoryDisk> = serde_json::from_slice(&bytes)
        .map_err(|_| bad("Windows storage discovery returned invalid metadata"))?;
    if disks.len() > 64 {
        return Err(bad("Too many storage candidates"));
    }
    let mut numbers = std::collections::BTreeSet::new();
    for disk in &disks {
        if !numbers.insert(disk.number) || !policy::phone_pnp(&disk.pnp_id) {
            return Err(bad("Ambiguous or unrecognized storage inventory"));
        }
    }
    Ok(disks)
}
pub(super) fn discover() -> Result<Discovery> {
    let candidates = inventory()?.iter().map(policy::candidate).collect();
    Ok(Discovery{host_supported:true,hardware_validated:false,candidates,message:"Read-only Windows inventory only. A phone must already expose mass storage. No phone mode, mount state or disk attribute was changed; normal-mode MTP is not block access.".into()})
}
fn ioctl(file: &File, code: u32, input: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; size];
    let mut returned = 0;
    // SAFETY: all buffers remain live for the synchronous call, their lengths
    // match, and this private wrapper is called only with read/query IOCTLs.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            if input.is_empty() {
                std::ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            output.as_mut_ptr().cast(),
            size as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if returned as usize > size {
        return Err(bad("Storage query returned an oversized response"));
    }
    output.truncate(returned as usize);
    Ok(output)
}
fn u32at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or_else(|| bad("Truncated storage query"))?
            .try_into()
            .unwrap(),
    ))
}
fn u64at(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or_else(|| bad("Truncated storage query"))?
            .try_into()
            .unwrap(),
    ))
}
fn descriptor_text(b: &[u8], at: usize) -> Result<String> {
    let offset = u32at(b, at)? as usize;
    if offset < 36 || offset >= b.len() {
        return Err(bad("Missing or invalid storage descriptor string"));
    }
    let tail = &b[offset..];
    let length = tail
        .iter()
        .position(|c| *c == 0)
        .filter(|n| *n <= 256)
        .ok_or_else(|| bad("Unterminated storage descriptor string"))?;
    if !tail[..length].iter().all(|c| matches!(c, 0x20..=0x7e)) {
        return Err(bad("Unsupported storage descriptor text"));
    }
    Ok(String::from_utf8_lossy(&tail[..length]).trim().to_owned())
}
#[derive(Clone, PartialEq, Eq)]
struct Snapshot {
    number: u32,
    size: u64,
    sector_size: u32,
    descriptor: Vec<u8>,
}
fn snapshot(file: &File) -> Result<Snapshot> {
    decode_snapshot(
        &ioctl(file, IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], 12)?,
        &ioctl(file, IOCTL_DISK_GET_DRIVE_GEOMETRY, &[], 24)?,
        &ioctl(file, IOCTL_DISK_GET_LENGTH_INFO, &[], 8)?,
        &ioctl(file, IOCTL_DISK_GET_DISK_ATTRIBUTES, &[], 16)?,
        &ioctl(file, IOCTL_STORAGE_QUERY_PROPERTY, &[0; 12], 4096)?,
    )
}
fn decode_snapshot(
    device: &[u8],
    geometry: &[u8],
    size_bytes: &[u8],
    attributes: &[u8],
    descriptor: &[u8],
) -> Result<Snapshot> {
    if device.len() != 12 || geometry.len() != 24 || size_bytes.len() != 8 || attributes.len() != 16
    {
        return Err(bad("Truncated storage metadata response"));
    }
    if u32at(device, 0)? != 7 {
        return Err(bad("Source handle is not a disk device"));
    }
    let size = u64at(size_bytes, 0)?;
    if u32at(attributes, 0)? != 16 || u64at(attributes, 8)? & 3 != 3 {
        return Err(bad(
            "Source must remain offline and read-only; attributes were not changed",
        ));
    }
    let length = u32at(descriptor, 4)? as usize;
    if length < 36
        || u32at(descriptor, 0)? < 36
        || u32at(descriptor, 0)? as usize > length
        || length > descriptor.len()
        || u32at(descriptor, 28)? != 7
        || descriptor[8] != 0
    {
        return Err(bad("Storage descriptor is not a bounded USB disk"));
    }
    let descriptor = descriptor[..length].to_vec();
    let vendor = descriptor_text(&descriptor, 12)?;
    let product = descriptor_text(&descriptor, 16)?;
    let serial = descriptor_text(&descriptor, 24)?;
    if !((vendor.eq_ignore_ascii_case("QUALCOMM") && product.eq_ignore_ascii_case("MMC Storage"))
        || (vendor.eq_ignore_ascii_case("MSFT") && product.eq_ignore_ascii_case("Phone MMC Stor")))
        || serial.is_empty()
    {
        return Err(bad(
            "Held handle is not a recognized phone-storage identity",
        ));
    }
    Ok(Snapshot {
        number: u32at(device, 4)?,
        size,
        sector_size: u32at(geometry, 20)?,
        descriptor,
    })
}
/// A private read-only, non-sharing handle. No Write implementation or method.
pub(super) struct Disk {
    file: File,
    expected: Snapshot,
    gpt: Option<String>,
    ancestry: Option<(InventoryDisk, String, u64)>,
}
impl Disk {
    pub(super) fn open(number: u32) -> Result<Self> {
        let before = inventory()?
            .into_iter()
            .find(|d| d.number == number)
            .ok_or_else(|| bad("Selected phone-storage candidate is absent; no disk was opened"))?;
        let blockers = policy::blockers(&before);
        if !blockers.is_empty() {
            return Err(bad(&blockers.join("; ")));
        }
        let file=OpenOptions::new().read(true).access_mode(0x80000000).share_mode(0).open(format!(r"\\.\PhysicalDrive{number}"))
            .map_err(|e|ImageError::Invalid(format!("Cannot acquire exclusive read-only phone storage: {e}. Administrator access may be required; no privilege or disk setting was changed.")))?;
        let expected = snapshot(&file)?;
        if expected.number != number
            || expected.size.to_string() != before.size
            || expected.sector_size != before.sector_size
        {
            return Err(bad("Held storage handle contradicts discovery"));
        }
        if !descriptor_text(&expected.descriptor, 24)?.eq_ignore_ascii_case(before.serial.trim()) {
            return Err(bad(
                "Held disk serial contradicts discovery; unknown serial encodings are not inferred",
            ));
        }
        let after = inventory()?
            .into_iter()
            .find(|d| d.number == number)
            .ok_or_else(|| bad("Phone storage disappeared while opening"))?;
        if before != after {
            return Err(bad("Storage identity or state changed while opening"));
        }
        Ok(Self {
            file,
            expected,
            gpt: None,
            ancestry: None,
        })
    }
    pub(super) fn open_bound(usb_instance: &str, capacity: u64) -> Result<Self> {
        let before = inventory()?;
        let selected = policy::bound_candidate(&before, usb_instance, capacity)
            .map_err(bad)?
            .clone();
        let mut disk = Self::open(selected.number)?;
        let after = inventory()?;
        if policy::bound_candidate(&after, usb_instance, capacity).map_err(bad)? != &selected {
            return Err(bad("USB disk ancestry changed while opening"));
        }
        disk.ancestry = Some((selected, usb_instance.into(), capacity));
        Ok(disk)
    }
    pub(super) fn bind_layout(&mut self, hash: String) {
        self.gpt = Some(hash);
    }
    fn check(&self) -> Result<()> {
        if snapshot(&self.file)? != self.expected {
            return Err(bad("Held phone-storage identity, geometry or state changed; no retries or reopen performed"));
        }
        Ok(())
    }
}
impl ReadOnlySource for Disk {
    fn geometry(&self) -> Geometry {
        Geometry {
            size: self.expected.size,
            sector_size: self.expected.sector_size,
        }
    }
    fn validate(&mut self) -> Result<()> {
        self.check()?;
        if let Some((selected, usb, capacity)) = &self.ancestry {
            let current = inventory()?;
            if policy::bound_candidate(&current, usb, *capacity).map_err(bad)? != selected {
                return Err(bad("USB disk ancestry changed during capture"));
            }
        }
        if let Some(expected) = self.gpt.clone() {
            if layout::inspect(self)?.gpt_sha256 != expected {
                return Err(bad("Storage GPT changed during backup"));
            }
        }
        Ok(())
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        if buffer.is_empty()
            || buffer.len() > 1024 * 1024
            || !offset.is_multiple_of(512)
            || !buffer.len().is_multiple_of(512)
            || offset
                .checked_add(buffer.len() as u64)
                .is_none_or(|end| end > self.expected.size)
        {
            return Err(bad(
                "Raw read is unaligned, oversized or outside the selected disk",
            ));
        }
        self.check()?;
        self.file.seek(SeekFrom::Start(offset))?;
        let n = self.file.read(buffer)?;
        if n != buffer.len() {
            return Err(bad(
                "Short phone-storage read; backup interrupted without retry",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor() -> Vec<u8> {
        let mut b = vec![0; 40];
        b[..4].copy_from_slice(&40u32.to_le_bytes());
        b[28..32].copy_from_slice(&7u32.to_le_bytes());
        for (at, text) in [(12, "QUALCOMM"), (16, "MMC Storage"), (24, "TEST-SERIAL")] {
            let n = b.len() as u32;
            b[at..at + 4].copy_from_slice(&n.to_le_bytes());
            b.extend_from_slice(text.as_bytes());
            b.push(0);
        }
        let n = b.len() as u32;
        b[4..8].copy_from_slice(&n.to_le_bytes());
        b
    }
    fn responses() -> [Vec<u8>; 5] {
        let mut device = vec![0; 12];
        device[..4].copy_from_slice(&7u32.to_le_bytes());
        device[4..8].copy_from_slice(&3u32.to_le_bytes());
        let mut geometry = vec![0; 24];
        geometry[20..24].copy_from_slice(&512u32.to_le_bytes());
        let size = (32u64 * 1024 * 1024 * 1024).to_le_bytes().to_vec();
        let mut attrs = vec![0; 16];
        attrs[..4].copy_from_slice(&16u32.to_le_bytes());
        attrs[8..16].copy_from_slice(&3u64.to_le_bytes());
        [device, geometry, size, attrs, descriptor()]
    }
    fn decode(r: &[Vec<u8>; 5]) -> Result<Snapshot> {
        decode_snapshot(&r[0], &r[1], &r[2], &r[3], &r[4])
    }
    #[test]
    fn native_metadata_decoding_rejects_every_truncation_and_invalid_offsets() {
        let r = responses();
        let result = decode(&r).unwrap();
        assert_eq!(result.number, 3);
        assert_eq!(result.sector_size, 512);
        for i in 0..5 {
            for n in 0..r[i].len() {
                let mut bad = r.clone();
                bad[i].truncate(n);
                assert!(decode(&bad).is_err());
            }
        }
        for at in [0, 4, 12, 16, 24, 28] {
            let mut bad = r.clone();
            bad[4][at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode(&bad).is_err());
        }
        let mut bad = r;
        let n = bad[4].len() - 1;
        bad[4][n] = b'X';
        assert!(decode(&bad).is_err());
    }
    #[test]
    fn native_metadata_rejects_online_writable_non_disk_and_wrong_vendor() {
        for value in [0u64, 1, 2] {
            let mut r = responses();
            r[3][8..16].copy_from_slice(&value.to_le_bytes());
            assert!(decode(&r).is_err());
        }
        let mut r = responses();
        r[0][0] = 0;
        assert!(decode(&r).is_err());
        let mut r = responses();
        r[4][40] = b'X';
        assert!(decode(&r).is_err());
        let mut r = responses();
        r[4][8] = 5;
        assert!(decode(&r).is_err());
    }
}
