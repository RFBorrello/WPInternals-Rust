//! The same parsers and profiles used by the native app, with async nusb WebUSB.
use std::io::Cursor;
use wasm_bindgen::prelude::*;
use wpi_image::{ffu::FfuMetadata, gpt::Gpt};
use wpi_types::*;

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
fn json<T: serde::Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(js_error)
}
#[wasm_bindgen]
pub fn models_json() -> Result<String, JsValue> {
    json(&wpi_core::known_models())
}
#[wasm_bindgen]
pub fn mode_preparation_json(
    device: &str,
    target: &str,
    protocol_major: Option<u8>,
) -> Result<String, JsValue> {
    let device: Option<DeviceIdentity> = serde_json::from_str(device).map_err(js_error)?;
    let target: DeviceMode = serde_json::from_str(target).map_err(js_error)?;
    json(&wpi_core::reconnect::prepare(
        device,
        target,
        protocol_major,
        Host::Browser,
        TransportKind::WebUsb,
    ))
}
#[wasm_bindgen]
pub fn reconnect_json(before: &str, after: &str, target: &str) -> Result<String, JsValue> {
    let before: DeviceIdentity = serde_json::from_str(before).map_err(js_error)?;
    let after: DeviceIdentity = serde_json::from_str(after).map_err(js_error)?;
    let target: DeviceMode = serde_json::from_str(target).map_err(js_error)?;
    json(&wpi_core::reconnect::compare(&before, &after, target))
}
#[wasm_bindgen]
pub fn capabilities_json(device: &str) -> Result<String, JsValue> {
    let selected: Option<DeviceIdentity> = serde_json::from_str(device).map_err(js_error)?;
    json(&wpi_core::capabilities(
        selected.as_ref(),
        Host::Browser,
        TransportKind::WebUsb,
    ))
}
#[wasm_bindgen]
pub fn recovery_preparation_json(device: &str, inspection: &str) -> Result<String, JsValue> {
    let device: Option<DeviceIdentity> = serde_json::from_str(device).map_err(js_error)?;
    let image: wpi_core::inspection::Inspection =
        serde_json::from_str(inspection).map_err(js_error)?;
    json(&wpi_core::recovery_prepare::report(
        device,
        Some(&image),
        None,
        wpi_core::recovery_prepare::ChunkIntegrity::NotChecked,
        Host::Browser,
        TransportKind::WebUsb,
    ))
}
/// An owned streaming verification session. Successful chunk evidence is created
/// by feeding the complete file, never by accepting a caller-supplied pass flag.
#[wasm_bindgen]
pub struct BrowserFfuVerifier {
    inner: Option<wpi_image::integrity::FfuVerifier>,
}
#[wasm_bindgen]
impl BrowserFfuVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(headers: &[u8], total_size: u64) -> Result<BrowserFfuVerifier, JsValue> {
        Ok(Self {
            inner: Some(
                wpi_image::integrity::FfuVerifier::new(headers, total_size).map_err(js_error)?,
            ),
        })
    }
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        self.inner
            .as_mut()
            .ok_or_else(|| js_error("verification session is already finished"))?
            .update(bytes)
            .map_err(js_error)
    }
    pub fn finish_preparation_json(
        &mut self,
        device: &str,
        inspection: &str,
        name: &str,
    ) -> Result<String, JsValue> {
        let verifier = self
            .inner
            .take()
            .ok_or_else(|| js_error("verification session is already finished"))?;
        let device: Option<DeviceIdentity> = serde_json::from_str(device).map_err(js_error)?;
        let image: wpi_core::inspection::Inspection =
            serde_json::from_str(inspection).map_err(js_error)?;
        let ffu = verifier.metadata();
        if image.size != ffu.total_size
            || serde_json::to_string(&image.ffu).map_err(js_error)?
                != serde_json::to_string(&Some(ffu)).map_err(js_error)?
        {
            return Err(js_error(
                "inspection and verification refer to different FFU metadata",
            ));
        }
        let mut artifact = ArtifactIdentity {
            name: name.into(),
            size: ffu.total_size,
            sha256: String::new(),
            platform_id: Some(ffu.platform_id.clone()),
        };
        let verified = verifier.finish().map_err(js_error)?;
        artifact.sha256 = verified.sha256;
        let integrity = match verified.first_mismatch {
            Some(index) => wpi_core::recovery_prepare::ChunkIntegrity::Failed(format!(
                "FFU hash mismatch at chunk {index}; checked {} chunks",
                verified.chunk_count
            )),
            None => wpi_core::recovery_prepare::ChunkIntegrity::Passed,
        };
        json(&wpi_core::recovery_prepare::report(
            device,
            Some(&image),
            Some(artifact),
            integrity,
            Host::Browser,
            TransportKind::WebUsb,
        ))
    }
}
#[wasm_bindgen]
pub fn ffu_headers_json(headers: &[u8], total_size: u64) -> Result<String, JsValue> {
    json(&FfuMetadata::read_headers(&mut Cursor::new(headers), total_size).map_err(js_error)?)
}
#[wasm_bindgen]
pub fn ffu_catalog_json(
    headers: &[u8],
    total_size: u64,
    reference_time: Option<u64>,
) -> Result<String, JsValue> {
    let mut reader = Cursor::new(headers);
    let ffu = FfuMetadata::read_headers(&mut reader, total_size).map_err(js_error)?;
    json(
        &wpi_image::catalog::inspect_at(&mut reader, &ffu, reference_time)
            .unwrap_or_else(wpi_image::catalog::unavailable),
    )
}
#[wasm_bindgen]
pub fn plat_version_json(bytes: &[u8], final_chunk: bool) -> Result<String, JsValue> {
    json(&wpi_image::firmware::scan_chunk(bytes, final_chunk).map_err(js_error)?)
}
/// The dedicated worker supplies bounded FileReaderSync slices. Rust retains
/// sparse FFU mapping, partition bounds, NTFS parsing and package validation.
#[wasm_bindgen]
pub fn mainos_firmware_json(
    metadata: &str,
    gpt: &str,
    total_size: u64,
    read: &js_sys::Function,
) -> Result<String, JsValue> {
    metadata_json(metadata, gpt, total_size, read, MetadataTask::Firmware)
}
#[wasm_bindgen]
pub fn mainos_targeting_json(
    metadata: &str,
    gpt: &str,
    total_size: u64,
    read: &js_sys::Function,
) -> Result<String, JsValue> {
    metadata_json(metadata, gpt, total_size, read, MetadataTask::Targeting)
}
#[wasm_bindgen]
pub fn ffu_catalog_image_json(
    metadata: &str,
    gpt: &str,
    total_size: u64,
    read: &js_sys::Function,
    reference_time: Option<u64>,
) -> Result<String, JsValue> {
    metadata_json(
        metadata,
        gpt,
        total_size,
        read,
        MetadataTask::Catalog(reference_time),
    )
}
enum MetadataTask {
    Firmware,
    Targeting,
    Catalog(Option<u64>),
    SpecA(SpecAInputs),
    SpecADonor(Box<wpi_image::spec_a::Preparation>),
}
#[wasm_bindgen]
pub fn spec_a_donor_json(
    report: &str,
    metadata: &str,
    gpt: &str,
    total_size: u64,
    read: &js_sys::Function,
) -> Result<String, JsValue> {
    let report = serde_json::from_str(report).map_err(js_error)?;
    metadata_json(
        metadata,
        gpt,
        total_size,
        read,
        MetadataTask::SpecADonor(report),
    )
}
#[derive(Default)]
struct SpecAInputs {
    sbl3: Option<(String, Vec<u8>)>,
    loaders: Vec<(String, Vec<u8>)>,
}
/// Small boot images are owned by this worker-side preparation session. The FFU
/// stays in its File and is read through bounded callbacks, not UI messages.
#[wasm_bindgen]
pub struct BrowserSpecAPreparation {
    inputs: Option<SpecAInputs>,
}
impl Default for BrowserSpecAPreparation {
    fn default() -> Self {
        Self::new()
    }
}
#[wasm_bindgen]
impl BrowserSpecAPreparation {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inputs: Some(SpecAInputs::default()),
        }
    }
    pub fn set_sbl3(&mut self, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
        if name.len() > 256 || bytes.len() > wpi_image::spec_a::MAX_BOOT_IMAGE {
            return Err(js_error("SBL3 name or size exceeds import limit"));
        }
        self.inputs
            .as_mut()
            .ok_or_else(|| js_error("preparation already finished"))?
            .sbl3 = Some((name.into(), bytes.to_vec()));
        Ok(())
    }
    pub fn add_loader(&mut self, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
        let inputs = self
            .inputs
            .as_mut()
            .ok_or_else(|| js_error("preparation already finished"))?;
        if name.len() > 256
            || bytes.len() > wpi_image::spec_a::MAX_LOADER_FILE
            || inputs.loaders.len() >= wpi_image::spec_a::MAX_LOADERS
        {
            return Err(js_error("loader name, size or count exceeds import limit"));
        }
        inputs.loaders.push((name.into(), bytes.to_vec()));
        Ok(())
    }
    pub fn finish_json(
        &mut self,
        metadata: &str,
        gpt: &str,
        total_size: u64,
        read: &js_sys::Function,
    ) -> Result<String, JsValue> {
        let inputs = self
            .inputs
            .take()
            .ok_or_else(|| js_error("preparation already finished"))?;
        metadata_json(metadata, gpt, total_size, read, MetadataTask::SpecA(inputs))
    }
}
fn metadata_json(
    metadata: &str,
    gpt: &str,
    total_size: u64,
    read: &js_sys::Function,
    task: MetadataTask,
) -> Result<String, JsValue> {
    use std::io::{Read, Seek, SeekFrom};
    struct Reader<'a> {
        callback: &'a js_sys::Function,
        size: u64,
        position: u64,
    }
    impl Read for Reader<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let n = bytes
                .len()
                .min(self.size.saturating_sub(self.position).min(64 * 1024) as usize);
            if n == 0 {
                return Ok(0);
            }
            if self.position > 9_007_199_254_740_991 {
                return Err(std::io::Error::other("unsafe browser offset"));
            }
            let value = self
                .callback
                .call2(
                    &JsValue::NULL,
                    &JsValue::from_f64(self.position as f64),
                    &JsValue::from_f64(n as f64),
                )
                .map_err(|_| std::io::Error::other("Browser metadata slice failed"))?;
            let data = value
                .dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| std::io::Error::other("Browser reader must return Uint8Array"))?;
            if data.length() as usize != n {
                return Err(std::io::Error::other("Browser metadata slice is truncated"));
            }
            data.copy_to(&mut bytes[..n]);
            self.position += n as u64;
            Ok(n)
        }
    }
    impl Seek for Reader<'_> {
        fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
            let position = match from {
                SeekFrom::Start(p) => i128::from(p),
                SeekFrom::End(p) => i128::from(self.size) + i128::from(p),
                SeekFrom::Current(p) => i128::from(self.position) + i128::from(p),
            };
            if position < 0 || position > i128::from(self.size) {
                return Err(std::io::Error::other("Browser seek outside file"));
            }
            self.position = position as u64;
            Ok(self.position)
        }
    }
    if total_size > 9_007_199_254_740_991 {
        return Err(js_error("unsafe browser file size"));
    }
    let ffu: FfuMetadata = serde_json::from_str(metadata).map_err(js_error)?;
    let gpt: Gpt = serde_json::from_str(gpt).map_err(js_error)?;
    let mut reader = Reader {
        callback: read,
        size: total_size,
        position: 0,
    };
    match task {
        MetadataTask::SpecADonor(mut report) => {
            wpi_image::spec_a::assess_donor(&mut report, &mut reader, &ffu, &gpt);
            json(&report)
        }
        MetadataTask::SpecA(inputs) => {
            use wpi_image::spec_a::{self, Import};
            let loaders: Vec<_> = inputs
                .loaders
                .iter()
                .map(|(name, bytes)| Import { name, bytes })
                .collect();
            json(
                &spec_a::prepare(
                    &mut reader,
                    &ffu,
                    &gpt,
                    inputs
                        .sbl3
                        .as_ref()
                        .map(|(name, bytes)| Import { name, bytes }),
                    &loaders,
                )
                .map_err(js_error)?,
            )
        }
        MetadataTask::Targeting => json(
            &wpi_image::firmware::mainos::read_targeting(&mut reader, &ffu, &gpt, |_, _| true)
                .map_err(js_error)?,
        ),
        MetadataTask::Firmware => json(
            &wpi_image::firmware::mainos::read(&mut reader, &ffu, &gpt, |_, _| true)
                .map_err(js_error)?,
        ),
        MetadataTask::Catalog(at) => json(
            &wpi_image::catalog::inspect_with_image_issuer(&mut reader, &ffu, &gpt, at)
                .map_err(js_error)?,
        ),
    }
}
#[wasm_bindgen]
pub fn ffu_segments_json(metadata: &str, start: u64, length: u64) -> Result<String, JsValue> {
    let ffu: FfuMetadata = serde_json::from_str(metadata).map_err(js_error)?;
    json(&ffu.segments(start, length).map_err(js_error)?)
}
#[wasm_bindgen]
pub fn gpt_json(header: &[u8], table: &[u8]) -> Result<String, JsValue> {
    json(&Gpt::from_parts(header, table, None).map_err(js_error)?)
}
#[wasm_bindgen]
pub fn gpt_xml(gpt: &str) -> Result<String, JsValue> {
    let gpt: Gpt = serde_json::from_str(gpt).map_err(js_error)?;
    Ok(gpt.to_xml())
}
#[wasm_bindgen]
pub fn filesystem_json(boot: &[u8]) -> Result<String, JsValue> {
    json(&wpi_image::filesystem::inspect_boot_sector(boot).map_err(js_error)?)
}
#[wasm_bindgen]
pub fn patch_catalog_json() -> Result<String, JsValue> {
    json(
        &wpi_image::patch::PatchCatalog::bundled()
            .map_err(js_error)?
            .summaries(),
    )
}

#[cfg(target_arch = "wasm32")]
fn identity(info: &nusb::DeviceInfo) -> Option<DeviceIdentity> {
    Some(DeviceIdentity {
        id: format!("{:?}", info.id()),
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        manufacturer: info.manufacturer_string().map(str::to_owned),
        product: info.product_string().map(str::to_owned),
        serial: info.serial_number().map(str::to_owned),
        model: None,
        variant: None,
        firmware: None,
        platform_id: None,
        family: BootloaderFamily::Unknown,
        mode: wpi_core::classify_usb(info.vendor_id(), info.product_id())?,
        interfaces: info
            .interfaces()
            .map(|i| UsbInterface {
                number: i.interface_number(),
                class: i.class(),
                subclass: i.subclass(),
                protocol: i.protocol(),
            })
            .collect(),
    })
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn devices_json() -> Result<String, JsValue> {
    let devices: Vec<_> = nusb::list_devices()
        .await
        .map_err(js_error)?
        .filter_map(|d| identity(&d))
        .collect();
    // A timed-out WebUSB transfer cannot be cancelled. Only allow a fresh probe
    // after enumeration has actually observed the old connection disappear.
    FAILED_PROBES.with(|failed| {
        failed
            .borrow_mut()
            .retain(|id| devices.iter().any(|d| &d.id == id))
    });
    json(&devices)
}
#[cfg(target_arch = "wasm32")]
thread_local! {
    static PROBE_ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAILED_PROBES: std::cell::RefCell<std::collections::HashSet<String>> = std::cell::RefCell::new(std::collections::HashSet::new());
}
#[cfg(target_arch = "wasm32")]
struct ProbeGuard;
#[cfg(target_arch = "wasm32")]
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        PROBE_ACTIVE.with(|active| active.set(false));
    }
}
#[cfg(target_arch = "wasm32")]
async fn exchange(
    input: &mut nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::In>,
    output: &mut nusb::Endpoint<nusb::transfer::Bulk, nusb::transfer::Out>,
    request: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    use futures_util::future::{select, Either};
    use nusb::transfer::Buffer;
    let expected = request.len();
    output.submit(Buffer::from(request));
    match select(
        Box::pin(output.next_complete()),
        Box::pin(gloo_timers::future::TimeoutFuture::new(5000)),
    )
    .await
    {
        Either::Left((completion, _)) => {
            completion.status.map_err(js_error)?;
            if completion.actual_len != expected {
                return Err(js_error(
                    "Incomplete USB request; unplug the phone before retrying",
                ));
            }
        }
        Either::Right(_) => {
            return Err(js_error(
                "USB write timed out; unplug the phone before retrying",
            ))
        }
    }
    input.submit(Buffer::new(65536));
    match select(
        Box::pin(input.next_complete()),
        Box::pin(gloo_timers::future::TimeoutFuture::new(5000)),
    )
    .await
    {
        Either::Left((completion, _)) => {
            completion.status.map_err(js_error)?;
            Ok(completion.buffer.into_vec())
        }
        Either::Right(_) => Err(js_error(
            "USB read timed out; unplug the phone before retrying",
        )),
    }
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn request_device_json() -> Result<String, JsValue> {
    let selectors: Vec<_> = [
        (0x0421, 0x066e),
        (0x0421, 0x0714),
        (0x045e, 0x0a02),
        (0x0421, 0x05ee),
        (0x0421, 0x0661),
        (0x0421, 0x06fc),
        (0x045e, 0x0a00),
        (0x0421, 0x0660),
        (0x0421, 0x0713),
        (0x045e, 0x0a01),
        (0x05c6, 0x9008),
        (0x05c6, 0x9006),
    ]
    .into_iter()
    .map(|(vid, pid)| nusb::DeviceSelector::all().with_vid_pid(vid, pid))
    .collect();
    let selected = nusb::request_device(&selectors).await.map_err(js_error)?;
    json(&selected.as_ref().and_then(identity))
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn probe_json(id: &str) -> Result<String, JsValue> {
    use futures_util::future::{select, Either};
    use nusb::transfer::{Bulk, In, Out};
    if PROBE_ACTIVE.with(|active| active.replace(true)) {
        return Err(js_error("Another phone probe is active"));
    }
    let _guard = ProbeGuard;
    if FAILED_PROBES.with(|failed| failed.borrow().contains(id)) {
        return Err(js_error("Previous probe was interrupted. Unplug the phone, scan while disconnected, then reconnect and select it again"));
    }
    let info = nusb::list_devices()
        .await
        .map_err(js_error)?
        .find(|d| format!("{:?}", d.id()) == id)
        .ok_or_else(|| js_error("Device disconnected; reconnect and select it again"))?;
    let mut result = identity(&info).ok_or_else(|| js_error("Unknown USB device"))?;
    if !matches!(result.mode, DeviceMode::Normal | DeviceMode::Flash) {
        return Err(js_error(
            "Read-only probing requires a Lumia normal or flash interface; use the desktop app for other modes",
        ));
    }
    let device = info.open().await.map_err(js_error)?;
    if device.active_configuration().is_err() {
        let value = device
            .configurations()
            .next()
            .ok_or_else(|| js_error("No USB configuration"))?
            .configuration_value();
        device.set_configuration(value).await.map_err(js_error)?;
    }
    let config = device.active_configuration().map_err(js_error)?;
    let candidate = config
        .interface_alt_settings()
        .filter(|i| i.class() == 0xff && i.alternate_setting() == 0
            && (result.mode != DeviceMode::Normal || i.interface_number() == 3))
        .find_map(|i| {
            let input = i.endpoints().find(|e| {
                e.transfer_type() == nusb::descriptors::TransferType::Bulk
                    && e.address() & 0x80 != 0
            })?;
            let output = i.endpoints().find(|e| {
                e.transfer_type() == nusb::descriptors::TransferType::Bulk
                    && e.address() & 0x80 == 0
            })?;
            Some((i.interface_number(), input.address(), output.address()))
        })
        .ok_or_else(|| {
            js_error("No accessible vendor-specific bulk interface for this mode (normal mode requires interface 3); use the desktop app")
        })?;
    let interface = device
        .claim_interface(candidate.0)
        .await
        .map_err(js_error)?;
    let probed = async {
        let mut input = interface.endpoint::<Bulk, In>(candidate.1).map_err(js_error)?;
        let mut output = interface.endpoint::<Bulk, Out>(candidate.2).map_err(js_error)?;
        if result.mode == DeviceMode::Normal {
            let mut fields = Vec::new();
            for (id, method, key) in [
                (0, "ReadManufacturerModelName", "ManufacturerModelName"),
                (1, "ReadProductCode", "ProductCode"),
                (2, "ReadSwVersion", "SwVersion"),
            ] {
                let response = exchange(&mut input, &mut output, wpi_protocol::normal::request(id, method).map_err(js_error)?).await?;
                fields.push(wpi_protocol::normal::parse(&response, id, key).map_err(js_error)?);
            }
            let normal = wpi_protocol::normal::NormalInfo { manufacturer_model: fields[0].clone(), product_code: fields[1].clone(), firmware: fields[2].clone() };
            let variant = normal.manufacturer_model.split('_').next().unwrap_or("");
            wpi_core::profiles::apply_variant(&mut result, variant);
            result.firmware = Some(normal.firmware.clone());
            json(&serde_json::json!({"device":result,"info":null,"normal":normal,"firmware":normal.firmware}))
        } else {
            let response = exchange(&mut input, &mut output, b"NOKV".to_vec()).await?;
            let flash = wpi_protocol::flash::parse_info(&response).map_err(js_error)?;
            result.mode = flash.mode;
            result.platform_id = flash.platform_id.clone();
            json(&serde_json::json!({"device":result,"info":flash,"normal":null,"firmware":null}))
        }
    }.await;
    // Endpoints are dropped before release. Bound cleanup too: browsers may
    // leave transfers pending after timeout, so a failed session is never retried.
    let released = select(
        Box::pin(async move { interface.release().await }),
        Box::pin(gloo_timers::future::TimeoutFuture::new(1000)),
    )
    .await;
    let cleanup = match released {
        Either::Left((result, _)) => result.map_err(js_error),
        Either::Right(_) => Err(js_error(
            "USB cleanup timed out; unplug the phone before retrying",
        )),
    };
    if probed.is_err() || cleanup.is_err() {
        FAILED_PROBES.with(|failed| {
            failed.borrow_mut().insert(id.to_owned());
        });
    }
    let value = probed?;
    cleanup?;
    Ok(value)
}
