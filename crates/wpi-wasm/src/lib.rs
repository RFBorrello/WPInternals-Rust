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
#[wasm_bindgen]
pub fn ffu_headers_json(headers: &[u8], total_size: u64) -> Result<String, JsValue> {
    json(&FfuMetadata::read_headers(&mut Cursor::new(headers), total_size).map_err(js_error)?)
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
