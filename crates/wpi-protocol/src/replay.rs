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
