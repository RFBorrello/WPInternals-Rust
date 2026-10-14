//! Read-only public-ID codecs derived from WPInternals 2.9.2:
//! NokiaNormalViewModel.ReadPublicId, NokiaFlashModel.GetTerminalResponse and Terminal.Parse.
//! Copyright (c) 2018 Rene Lergner. See THIRD_PARTY_NOTICES.md.
use crate::{be32, field, MessageTransport, ProtocolError, Result};
use std::fmt;

const MAX_RESPONSE: usize = 65536;
const PUBLIC_ID_LENGTH: usize = 20;

/// Local, unauthenticated device identifier. Deliberately has no Serialize or byte getter.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicId([u8; PUBLIC_ID_LENGTH]);
impl fmt::Debug for PublicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicId([redacted])")
    }
}
impl PublicId {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: [u8; PUBLIC_ID_LENGTH] = bytes.try_into().map_err(|_| {
            ProtocolError::Invalid("public ID must contain exactly 20 bytes".into())
        })?;
        if value == [0; PUBLIC_ID_LENGTH] || value == [255; PUBLIC_ID_LENGTH] {
            return Err(ProtocolError::Invalid("blank public ID".into()));
        }
        Ok(Self(value))
    }
}

/// Kept separate from the generic Normal information allowlist.
pub fn normal_request(id: u32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc":"2.0", "id":id, "method":"ReadPublicId",
        "params":{"MessageVersion":0}
    }))
    .expect("fixed JSON-RPC request")
}
pub fn parse_normal(response: &[u8], id: u32) -> Result<PublicId> {
    if response.len() > MAX_RESPONSE {
        return Err(ProtocolError::Invalid(
            "public-ID response exceeds limit".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(response)
        .map_err(|_| ProtocolError::Invalid("malformed public-ID JSON-RPC response".into()))?;
    if value["jsonrpc"] != "2.0"
        || value["id"].as_u64() != Some(u64::from(id))
        || value.get("error").is_some()
    {
        return Err(ProtocolError::Invalid(
            "public-ID response id, version or error mismatch".into(),
        ));
    }
    let bytes = value["result"]["PublicId"]
        .as_array()
        .filter(|a| a.len() == PUBLIC_ID_LENGTH)
        .ok_or_else(|| ProtocolError::Invalid("missing or invalid public-ID array".into()))?;
    let mut result = [0; PUBLIC_ID_LENGTH];
    for (target, item) in result.iter_mut().zip(bytes) {
        *target = item
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| ProtocolError::Invalid("invalid public-ID byte".into()))?;
    }
    PublicId::parse(&result)
}

/// Fixed terminal-info query; contains no signing key, firmware, or write payload.
pub fn flash_request() -> Vec<u8> {
    let mut request = vec![0; 0xac];
    request[..6].copy_from_slice(b"NOKXFT");
    request[7] = 1;
    request[8..12].copy_from_slice(&0x18u32.to_be_bytes());
    request[12..16].copy_from_slice(&0x9cu32.to_be_bytes());
    request[20..36].copy_from_slice(&[1, 0, 16, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64]);
    request
}
pub fn parse_flash(response: &[u8]) -> Result<PublicId> {
    if response.len() > MAX_RESPONSE {
        return Err(ProtocolError::Invalid(
            "terminal response exceeds limit".into(),
        ));
    }
    crate::flash::check_status(response, b"NOKXFT")?;
    // The wrapper length is big-endian; the terminal tree and node lengths are little-endian.
    field(response, 0, 32)?;
    let wrapper_length = be32(response, 20)? as usize;
    let root_number = le32(response, 24)?;
    let root_length = le32(response, 28)? as usize;
    if wrapper_length != response.len() - 24
        || root_number != 0x10000
        || root_length != response.len() - 32
    {
        return Err(ProtocolError::Invalid(
            "terminal wrapper/root length or type mismatch".into(),
        ));
    }
    let mut at = 32;
    let mut public_id = None;
    let mut nodes = std::collections::HashSet::new();
    while at < response.len() {
        let number = le32(response, at)?;
        let length = le32(response, at + 4)? as usize;
        if nodes.len() >= 256 || !nodes.insert(number) {
            return Err(ProtocolError::Invalid(
                "duplicate or excessive terminal nodes".into(),
            ));
        }
        let payload = field(response, at + 8, length)?;
        if number == 3 {
            public_id = Some(PublicId::parse(payload)?);
        }
        at += 8 + length;
    }
    public_id.ok_or_else(|| ProtocolError::Invalid("terminal public ID is missing".into()))
}
fn le32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(field(bytes, at, 4)?.try_into().unwrap()))
}
pub fn read_normal<T: MessageTransport>(transport: &mut T, id: u32) -> Result<PublicId> {
    parse_normal(&transport.exchange(&normal_request(id), MAX_RESPONSE)?, id)
}
pub fn read_flash<T: MessageTransport>(transport: &mut T) -> Result<PublicId> {
    parse_flash(&transport.exchange(&flash_request(), MAX_RESPONSE)?)
}
