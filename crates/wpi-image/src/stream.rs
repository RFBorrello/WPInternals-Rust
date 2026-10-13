use crate::{ImageError, Result, COPY_BUFFER};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

pub fn copy_hashed<R: Read, W: Write, F: FnMut(u64, u64) -> bool>(
    reader: &mut R,
    writer: &mut W,
    length: u64,
    mut progress: F,
) -> Result<String> {
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut done = 0u64;
    let mut hash = Sha256::new();
    while done < length {
        if !progress(done, length) {
            return Err(ImageError::Cancelled);
        }
        let n = (length - done).min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..n])?;
        writer.write_all(&buffer[..n])?;
        hash.update(&buffer[..n]);
        done += n as u64;
    }
    writer.flush()?;
    if !progress(done, length) {
        return Err(ImageError::Cancelled);
    }
    Ok(hex::encode(hash.finalize()))
}
pub fn sha256<R: Read>(reader: &mut R) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; COPY_BUFFER];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
