//! Read-only block transfers for backup fault simulation, never a live device.
use crate::{ProtocolError, Result};
use std::collections::VecDeque;

pub struct BlockRead {
    pub offset: u64,
    pub length: usize,
    pub response: Vec<u8>,
    pub error: Option<String>,
}
pub struct ReplayBlockSource {
    sector_size: u32,
    size: u64,
    reads: VecDeque<BlockRead>,
}
impl ReplayBlockSource {
    pub fn new(sector_size: u32, sectors: u64, reads: Vec<BlockRead>) -> Result<Self> {
        if !matches!(sector_size, 512 | 1024 | 2048 | 4096) || sectors == 0 {
            return Err(ProtocolError::Invalid(
                "invalid replay disk geometry".into(),
            ));
        }
        let size = sectors
            .checked_mul(sector_size as u64)
            .ok_or_else(|| ProtocolError::Invalid("disk size overflow".into()))?;
        let buffered = reads
            .iter()
            .try_fold(0usize, |total, r| total.checked_add(r.response.len()));
        if buffered.is_none_or(|size| size > 32 * 1024 * 1024) {
            return Err(ProtocolError::Invalid(
                "block replay fixture exceeds 32 MiB".into(),
            ));
        }
        Ok(Self {
            sector_size,
            size,
            reads: reads.into(),
        })
    }
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn remaining(&self) -> usize {
        self.reads.len()
    }
    pub fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0
            || length > 1024 * 1024
            || !offset.is_multiple_of(self.sector_size as u64)
            || !length.is_multiple_of(self.sector_size as usize)
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > self.size)
        {
            return Err(ProtocolError::Invalid(
                "block read exceeds aligned disk bounds".into(),
            ));
        }
        let read = self
            .reads
            .pop_front()
            .ok_or_else(|| ProtocolError::Transport("block replay exhausted".into()))?;
        if read.offset != offset || read.length != length {
            return Err(ProtocolError::Invalid(
                "block replay request mismatch".into(),
            ));
        }
        if let Some(error) = read.error {
            return Err(ProtocolError::Transport(error));
        }
        if read.response.len() != length {
            return Err(ProtocolError::Transport(
                "incomplete block read; backup not published".into(),
            ));
        }
        Ok(read.response)
    }
}
