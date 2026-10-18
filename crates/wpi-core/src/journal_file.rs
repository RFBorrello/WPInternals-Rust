//! Shared native JSONL sink. Synchronization is not a power-loss guarantee.
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
};
pub(crate) struct FileSink {
    file: File,
    failed: bool,
}
impl FileSink {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("Journal must be a new regular file"));
        }
        file.sync_all()?;
        Ok(Self {
            file,
            failed: false,
        })
    }
    pub(crate) fn append<T: Serialize>(&mut self, entry: &T, limit: usize) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other(
                "Journal is unusable after an earlier save failure",
            ));
        }
        let result = (|| {
            let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
            if line.len() > limit {
                return Err(io::Error::other("Journal entry exceeds limit"));
            }
            line.push(b'\n');
            self.file.write_all(&line)?;
            self.file.flush()?;
            self.file.sync_all()
        })();
        self.failed = result.is_err();
        result
    }
}
