use crate::{MessageTransport, ProtocolError, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exchange {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub error: Option<String>,
}
pub struct ReplayTransport {
    exchanges: VecDeque<Exchange>,
}
impl ReplayTransport {
    pub fn new(exchanges: Vec<Exchange>) -> Self {
        Self {
            exchanges: exchanges.into(),
        }
    }
    pub fn finished(&self) -> bool {
        self.exchanges.is_empty()
    }
    /// Replay a send-only reboot. This never performs a response read or retry.
    pub fn send(&mut self, request: &[u8]) -> Result<()> {
        let response = self.exchange(request, 0)?;
        if !response.is_empty() {
            return Err(ProtocolError::Invalid(
                "send-only replay has a response".into(),
            ));
        }
        Ok(())
    }
}
impl MessageTransport for ReplayTransport {
    fn exchange(&mut self, request: &[u8], maximum_response: usize) -> Result<Vec<u8>> {
        let expected = self
            .exchanges
            .pop_front()
            .ok_or_else(|| ProtocolError::Transport("replay exhausted".into()))?;
        if expected.request != request {
            return Err(ProtocolError::Invalid("replay request mismatch".into()));
        }
        if let Some(error) = expected.error {
            return Err(ProtocolError::Transport(error));
        }
        if expected.response.len() > maximum_response {
            return Err(ProtocolError::Invalid(
                "replay response exceeds limit".into(),
            ));
        }
        Ok(expected.response)
    }
}

/// Synthetic read fragments for exactly one framed reply. No physical I/O.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FramedExchange {
    pub request: Vec<u8>,
    pub fragments: Vec<Vec<u8>>,
    pub error: Option<String>,
}
pub struct FramedReplayTransport {
    exchanges: VecDeque<FramedExchange>,
}
impl FramedReplayTransport {
    pub fn new(exchanges: Vec<FramedExchange>) -> Self {
        Self {
            exchanges: exchanges.into(),
        }
    }
    pub fn finished(&self) -> bool {
        self.exchanges.is_empty()
    }
}
impl MessageTransport for FramedReplayTransport {
    fn exchange(&mut self, request: &[u8], maximum_response: usize) -> Result<Vec<u8>> {
        let expected = self
            .exchanges
            .pop_front()
            .ok_or_else(|| ProtocolError::Transport("framed replay exhausted".into()))?;
        if expected.request != request {
            return Err(ProtocolError::Invalid(
                "framed replay request mismatch".into(),
            ));
        }
        let mut decoder = crate::qualcomm::dload::ReplyDecoder::default();
        let mut complete = None;
        for fragment in expected.fragments {
            if complete.is_some() {
                return Err(ProtocolError::Invalid("surplus reply fragments".into()));
            }
            complete = decoder.push(&fragment)?;
        }
        if let Some(error) = expected.error {
            return Err(ProtocolError::Transport(error));
        }
        let frame =
            complete.ok_or_else(|| ProtocolError::Transport("incomplete framed reply".into()))?;
        if frame.len() > maximum_response {
            return Err(ProtocolError::Invalid(
                "framed reply exceeds caller bound".into(),
            ));
        }
        Ok(frame)
    }
}
