//! Read-only Nokia Care Suite JSON-RPC queries from WPinternals 2.9.2.
use crate::{MessageTransport, ProtocolError, Result};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalInfo {
    pub manufacturer_model: String,
    pub product_code: String,
    pub firmware: String,
}
pub fn request(id: u32, method: &str) -> Result<Vec<u8>> {
    if !matches!(
        method,
        "ReadManufacturerModelName" | "ReadProductCode" | "ReadSwVersion"
    ) {
        return Err(ProtocolError::Unsupported);
    }
    serde_json::to_vec(
        &serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"MessageVersion":0}}),
    )
    .map_err(|e| ProtocolError::Invalid(e.to_string()))
}
pub fn parse(response: &[u8], id: u32, key: &str) -> Result<String> {
    if response.len() > 65536 {
        return Err(ProtocolError::Invalid(
            "JSON-RPC response exceeds limit".into(),
        ));
    }
    let value: serde_json::Value =
        serde_json::from_slice(response).map_err(|e| ProtocolError::Invalid(e.to_string()))?;
    if value["jsonrpc"] != "2.0"
        || value["id"].as_u64() != Some(id as u64)
        || value.get("error").is_some()
    {
        return Err(ProtocolError::Invalid(
            "JSON-RPC response id, version or error mismatch".into(),
        ));
    }
    value["result"][key]
        .as_str()
        .filter(|s| s.len() <= 4096)
        .map(str::to_owned)
        .ok_or_else(|| ProtocolError::Invalid("missing JSON-RPC information field".into()))
}
pub fn read_info<T: MessageTransport>(transport: &mut T) -> Result<NormalInfo> {
    let model = parse(
        &transport.exchange(&request(0, "ReadManufacturerModelName")?, 65536)?,
        0,
        "ManufacturerModelName",
    )?;
    let product = parse(
        &transport.exchange(&request(1, "ReadProductCode")?, 65536)?,
        1,
        "ProductCode",
    )?;
    let firmware = parse(
        &transport.exchange(&request(2, "ReadSwVersion")?, 65536)?,
        2,
        "SwVersion",
    )?;
    Ok(NormalInfo {
        manufacturer_model: model,
        product_code: product,
        firmware,
    })
}
