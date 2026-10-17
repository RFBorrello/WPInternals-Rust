//! Context-preserving Spec A research queries, translated from NokiaFlashModel
//! in WPInternals 2.9.2. Rene Lergner, MIT. No resets, context switches or writes.
use crate::{field, flash, identity, MessageTransport, ProtocolError, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use wpi_types::DeviceMode;

pub const PRIMARY_SIZE: usize = 34 * 512;
const MAX_RESPONSE: usize = 65536;

/// A root certificate fingerprint is comparison evidence, not signer trust.
/// Neither this value nor a device public ID is serialized by the capture API.
#[derive(Clone, PartialEq, Eq)]
pub struct RootKeyHash([u8; 32]);
impl std::fmt::Debug for RootKeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKeyHash([redacted])")
    }
}
impl RootKeyHash {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid("RRKH must be 32 bytes"))?;
        if bytes == [0; 32] || bytes == [255; 32] {
            return Err(invalid(
                "blank RRKH is not verification or an engineering bypass",
            ));
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityStatus {
    pub test_device: u8,
    pub platform_secure_boot: bool,
    pub secure_ffu_efuse: bool,
    pub debug: bool,
    pub rdc: bool,
    pub authenticated: bool,
    pub uefi_secure_boot: bool,
    pub crypto_hardware_key: bool,
}
pub fn parse_security(bytes: &[u8]) -> Result<SecurityStatus> {
    if bytes.len() != 8 || bytes[1..].iter().any(|v| *v > 1) {
        return Err(invalid(
            "SS requires eight bytes and recognized boolean flags",
        ));
    }
    Ok(SecurityStatus {
        test_device: bytes[0],
        platform_secure_boot: bytes[1] == 1,
        secure_ffu_efuse: bytes[2] == 1,
        debug: bytes[3] == 1,
        rdc: bytes[4] == 1,
        authenticated: bytes[5] == 1,
        uefi_secure_boot: bytes[6] == 1,
        crypto_hardware_key: bytes[7] == 1,
    })
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplicationSecurity {
    pub version: u8,
    pub platform_secure_boot: bool,
    pub secure_ffu: bool,
    pub jtag_disabled: bool,
    pub rdc: bool,
    pub authenticated: bool,
    pub uefi_secure_boot: bool,
    pub secondary_hardware_key: bool,
}
impl ApplicationSecurity {
    fn locked(&self) -> bool {
        !(self.authenticated || self.rdc || !self.secure_ffu)
    }
    fn agrees(&self, ss: &SecurityStatus) -> bool {
        // Upstream names debug/JTAG and secondary/crypto key fields differently.
        // Do not assume that those fields describe identical settings.
        self.platform_secure_boot == ss.platform_secure_boot
            && self.secure_ffu == ss.secure_ffu_efuse
            && self.rdc == ss.rdc
            && self.authenticated == ss.authenticated
            && self.uefi_secure_boot == ss.uefi_secure_boot
    }
}

/// Strict NOKV envelope for this research path. Unknown subblocks are retained
/// only as envelope validation; duplicate IDs, trailing data and unknown security
/// encodings fail rather than making a security decision from ambiguous bytes.
pub fn parse_application(
    response: &[u8],
) -> Result<(flash::FlashInfo, Option<ApplicationSecurity>)> {
    if response.len() > MAX_RESPONSE {
        return Err(invalid("NOKV exceeds response limit"));
    }
    let info = flash::parse_info(response)?;
    let mut at = 11;
    let mut ids = BTreeSet::new();
    let mut security = None;
    for _ in 0..response[10] {
        let id = field(response, at, 1)?[0];
        if !ids.insert(id) {
            return Err(invalid("duplicate NOKV subblock"));
        }
        let len = u16::from_be_bytes(field(response, at + 1, 2)?.try_into().unwrap()) as usize;
        let p = field(response, at + 3, len)?;
        if id == 0x0f {
            if p.len() != 8
                || p[0] != 3
                || p[1..]
                    .iter()
                    .enumerate()
                    .any(|(i, v)| *v > if i == 4 { 2 } else { 1 })
            {
                return Err(invalid(
                    "unsupported NOKV security version, length or flags",
                ));
            }
            security = Some(ApplicationSecurity {
                version: p[0],
                platform_secure_boot: p[1] == 1,
                secure_ffu: p[2] == 1,
                jtag_disabled: p[3] == 1,
                rdc: p[4] == 1,
                authenticated: p[5] != 0,
                uefi_secure_boot: p[6] == 1,
                secondary_hardware_key: p[7] == 1,
            });
        }
        at += 3 + len;
    }
    if at != response.len() {
        return Err(invalid("trailing NOKV bytes"));
    }
    Ok((info, security))
}

fn invalid(message: &str) -> ProtocolError {
    ProtocolError::Invalid(message.into())
}
fn parameter<T: MessageTransport>(transport: &mut T, name: &str) -> Result<Vec<u8>> {
    let response = transport.exchange(&flash::parameter_request(name)?, 17 + 255)?;
    let value = flash::parse_parameter(&response)?;
    if response.len() != 17 + value.len() {
        return Err(invalid("trailing parameter bytes"));
    }
    Ok(value)
}
pub fn parse_primary_gpt(response: &[u8]) -> Result<Vec<u8>> {
    flash::check_status(response, b"NOKT")?;
    if response.len() != 8 + PRIMARY_SIZE {
        return Err(invalid(
            "NOKT requires exactly 34 primary sectors after its eight-byte header",
        ));
    }
    Ok(response[8..].to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GptReadStatus {
    NotRequested,
    ContextSwitchRequired,
    SecurityEvidenceMissing,
    Read,
}
/// No Deserialize or Serialize: only a successful in-memory protocol run can
/// construct this evidence. A JSON export can never be imported as authority.
pub struct Capture {
    data: Observation,
    reference_root: RootKeyHash,
    reference_platform: String,
}
pub struct Observation {
    pub info: flash::FlashInfo,
    pub application_security: Option<ApplicationSecurity>,
    pub security: SecurityStatus,
    pub primary_gpt: Option<Vec<u8>>,
    pub gpt_status: GptReadStatus,
}
impl Capture {
    pub fn matches_reference(&self, root: &RootKeyHash, platform: &str) -> bool {
        self.reference_root == *root && self.reference_platform == platform
    }
    pub fn into_observation(self) -> Observation {
        self.data
    }
}
fn boundary<F: FnMut(&str) -> bool>(f: &mut F, stage: &str) -> Result<()> {
    if f(stage) {
        Ok(())
    } else {
        Err(invalid("read-only preflight cancelled before next query"))
    }
}
fn platform_matches(actual: Option<&str>, reference: &str) -> bool {
    !reference.is_empty()
        && actual.is_some_and(|actual| {
            actual == reference
                || actual
                    .strip_prefix(reference)
                    .is_some_and(|suffix| suffix.starts_with('.'))
        })
}

/// Public IDs bookend a single command handle; this is local correlation, not
/// authenticated identity or correlation to an earlier Normal-mode session.
/// Any query error stops immediately. Never retry, switch contexts, query FVER,
/// or recover/reset the device here, including on cancellation.
pub fn capture<T: MessageTransport, F: FnMut(&str) -> bool>(
    transport: &mut T,
    reference_root: &RootKeyHash,
    reference_platform: &str,
    read_primary: bool,
    progress: F,
) -> Result<Capture> {
    capture_inner(
        transport,
        reference_root,
        reference_platform,
        read_primary,
        None,
        progress,
    )
}

/// Correlate this handle with a public ID freshly read in Normal mode. A mismatch
/// stops before RRKH/SS or GPT. Physical-port binding belongs to the adapter.
pub fn capture_bound<T: MessageTransport, F: FnMut(&str) -> bool>(
    transport: &mut T,
    reference_root: &RootKeyHash,
    reference_platform: &str,
    read_primary: bool,
    expected_public_id: &identity::PublicId,
    progress: F,
) -> Result<Capture> {
    capture_inner(
        transport,
        reference_root,
        reference_platform,
        read_primary,
        Some(expected_public_id),
        progress,
    )
}

fn capture_inner<T: MessageTransport, F: FnMut(&str) -> bool>(
    transport: &mut T,
    reference_root: &RootKeyHash,
    reference_platform: &str,
    read_primary: bool,
    expected_public_id: Option<&identity::PublicId>,
    mut progress: F,
) -> Result<Capture> {
    boundary(&mut progress, "Read current application")?;
    let first_response = transport.exchange(b"NOKV", MAX_RESPONSE)?;
    let (info, app) = parse_application(&first_response)?;
    if info.mode != DeviceMode::Flash
        || !platform_matches(info.platform_id.as_deref(), reference_platform)
    {
        return Err(invalid(
            "preflight requires current FlashApp and a matching dot-delimited reference platform",
        ));
    }
    boundary(&mut progress, "Read local public ID")?;
    let public_id = identity::read_flash(transport)?;
    if expected_public_id.is_some_and(|expected| expected != &public_id) {
        return Err(invalid(
            "Flash public ID does not match the fresh Normal baseline",
        ));
    }
    boundary(&mut progress, "Compare root key hash")?;
    if RootKeyHash::parse(&parameter(transport, "RRKH")?)? != *reference_root {
        return Err(invalid(
            "device RRKH differs from the source SBL1 certificate fingerprint",
        ));
    }
    boundary(&mut progress, "Read security status")?;
    let security = parse_security(&parameter(transport, "SS")?)?;
    if app.as_ref().is_some_and(|a| !a.agrees(&security)) {
        return Err(invalid("NOKV and SS security evidence disagree"));
    }
    let gpt_status = if !read_primary {
        GptReadStatus::NotRequested
    } else {
        match app.as_ref() {
            None => GptReadStatus::SecurityEvidenceMissing,
            Some(a) if a.locked() => GptReadStatus::ContextSwitchRequired,
            Some(_) => GptReadStatus::Read,
        }
    };
    let primary_gpt = if gpt_status == GptReadStatus::Read {
        boundary(&mut progress, "Read primary GPT in current context")?;
        Some(parse_primary_gpt(
            &transport.exchange(b"NOKT", 8 + PRIMARY_SIZE)?,
        )?)
    } else {
        None
    };
    boundary(&mut progress, "Recheck current application")?;
    let response = transport.exchange(b"NOKV", MAX_RESPONSE)?;
    let (last_info, last_app) = parse_application(&response)?;
    if serde_json::to_value(&last_info).unwrap() != serde_json::to_value(&info).unwrap()
        || last_app != app
    {
        return Err(invalid("application evidence changed during preflight"));
    }
    boundary(&mut progress, "Recheck local public ID")?;
    if identity::read_flash(transport)? != public_id {
        return Err(invalid("public ID changed during preflight"));
    }
    boundary(&mut progress, "Finish read-only preflight")?;
    Ok(Capture {
        reference_root: reference_root.clone(),
        reference_platform: reference_platform.into(),
        data: Observation {
            info,
            application_security: app,
            security,
            primary_gpt,
            gpt_status,
        },
    })
}
