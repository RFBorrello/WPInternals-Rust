//! Worker-only local image assembly. Calls are bounded; artifacts never use USB.
use crate::{js_error, json};
use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom, Write};
use wasm_bindgen::prelude::*;
struct FileIo<'a> {
    read: &'a js_sys::Function,
    write: Option<&'a js_sys::Function>,
    size: u64,
    position: u64,
    cache: VecDeque<(u64, Vec<u8>)>,
    limit: u64,
}
impl Read for FileIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let n = bytes
            .len()
            .min(65536)
            .min(self.size.saturating_sub(self.position).min(65536) as usize);
        if n == 0 {
            return Ok(0);
        }
        if self.write.is_none() {
            let page = self.position / 65536 * 65536;
            let length = (self.size - page).min(65536) as usize;
            let data = if let Some(i) = self.cache.iter().position(|(at, _)| *at == page) {
                self.cache.remove(i).unwrap().1
            } else {
                let value = self
                    .read
                    .call2(
                        &JsValue::NULL,
                        &JsValue::from_f64(page as f64),
                        &JsValue::from_f64(length as f64),
                    )
                    .map_err(|_| std::io::Error::other("local image page read failed"))?
                    .dyn_into::<js_sys::Uint8Array>()
                    .map_err(|_| std::io::Error::other("reader must return Uint8Array"))?;
                if value.length() as usize != length {
                    return Err(std::io::Error::other("local image page truncated"));
                }
                value.to_vec()
            };
            let offset = (self.position - page) as usize;
            let count = n.min(data.len() - offset);
            bytes[..count].copy_from_slice(&data[offset..offset + count]);
            if self.cache.len() == 8 {
                self.cache.pop_front();
            }
            self.cache.push_back((page, data));
            self.position += count as u64;
            return Ok(count);
        }
        let data = self
            .read
            .call2(
                &JsValue::NULL,
                &JsValue::from_f64(self.position as f64),
                &JsValue::from_f64(n as f64),
            )
            .map_err(|_| std::io::Error::other("local image read failed"))?
            .dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| std::io::Error::other("reader must return Uint8Array"))?;
        if data.length() as usize != n {
            return Err(std::io::Error::other("local image read truncated"));
        }
        data.copy_to(&mut bytes[..n]);
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for FileIo<'_> {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        let at = match p {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(p) => self.size as i128 + p as i128,
            SeekFrom::Current(p) => self.position as i128 + p as i128,
        };
        if at < 0 || at > self.size as i128 {
            return Err(std::io::Error::other("local image seek out of bounds"));
        }
        self.position = at as u64;
        Ok(self.position)
    }
}
impl Write for FileIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let callback = self
            .write
            .ok_or_else(|| std::io::Error::other("source is read only"))?;
        let n = bytes.len().min(65536);
        if self.position + n as u64 > self.limit {
            return Err(std::io::Error::other("output exceeds its bounded size"));
        }
        let data = js_sys::Uint8Array::from(&bytes[..n]);
        let written = callback
            .call2(
                &JsValue::NULL,
                &JsValue::from_f64(self.position as f64),
                &data,
            )
            .map_err(|_| std::io::Error::other("scratch file write failed"))?
            .as_f64();
        if written != Some(n as f64) {
            return Err(std::io::Error::other("scratch file write truncated"));
        }
        self.position += n as u64;
        self.size = self.size.max(self.position);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[wasm_bindgen]
pub struct RebuiltUefi {
    bytes: Vec<u8>,
    report: String,
}
#[wasm_bindgen]
impl RebuiltUefi {
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    pub fn report_json(&self) -> String {
        self.report.clone()
    }
}
#[wasm_bindgen]
pub fn rebuild_uefi(bytes: &[u8]) -> Result<RebuiltUefi, JsValue> {
    let (bytes, report) = wpi_image::spec_a::uefi::rebuild(bytes).map_err(js_error)?;
    Ok(RebuiltUefi {
        bytes,
        report: json(&report)?,
    })
}
#[wasm_bindgen]
pub fn spec_a_donor_boot(
    metadata: &str,
    gpt: &str,
    total: u64,
    read: &js_sys::Function,
) -> Result<Vec<u8>, JsValue> {
    if total > 9_007_199_254_740_991 {
        return Err(js_error("unsafe file size"));
    }
    let ffu = serde_json::from_str(metadata).map_err(js_error)?;
    let gpt = serde_json::from_str(gpt).map_err(js_error)?;
    let mut reader = FileIo {
        read,
        write: None,
        size: total,
        position: 0,
        cache: VecDeque::new(),
        limit: 128 * 1024 * 1024,
    };
    wpi_image::spec_a::efiesp::boot_from_ffu(&mut reader, &ffu, &gpt).map_err(js_error)
}
#[wasm_bindgen]
pub fn assemble_efiesp_json(
    size: u64,
    source: &js_sys::Function,
    output_read: &js_sys::Function,
    output_write: &js_sys::Function,
    donor_boot: &[u8],
) -> Result<String, JsValue> {
    if size > 128 * 1024 * 1024 {
        return Err(js_error("EFIESP exceeds 128 MiB"));
    }
    let mut source = FileIo {
        read: source,
        write: None,
        size,
        position: 0,
        cache: VecDeque::new(),
        limit: 128 * 1024 * 1024,
    };
    let mut output = FileIo {
        read: output_read,
        write: Some(output_write),
        size: 0,
        position: 0,
        cache: VecDeque::new(),
        limit: 128 * 1024 * 1024,
    };
    json(
        &wpi_image::spec_a::efiesp::assemble(&mut source, &mut output, donor_boot, |_, _| true)
            .map_err(js_error)?,
    )
}
#[wasm_bindgen]
pub struct BrowserSpecAPackage {
    third: Option<Vec<u8>>,
    loaders: Vec<Vec<u8>>,
    consumed: bool,
}
#[wasm_bindgen]
impl BrowserSpecAPackage {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            third: None,
            loaders: Vec::new(),
            consumed: false,
        }
    }
    pub fn set_sbl3(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        if self.consumed || bytes.len() > wpi_image::spec_a::MAX_BOOT_IMAGE {
            return Err(js_error("SBL3 import exceeds 4 MiB or session is finished"));
        }
        self.third = Some(bytes.to_vec());
        Ok(())
    }
    pub fn add_loader(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        if self.consumed
            || bytes.len() > wpi_image::spec_a::MAX_LOADER_FILE
            || self.loaders.len() >= 32
        {
            return Err(js_error("loader size/count/session limit exceeded"));
        }
        self.loaders.push(bytes.to_vec());
        Ok(())
    }
    pub fn finish_json(
        &mut self,
        total: u64,
        io: &js_sys::Array,
        donor_boot: &[u8],
        progress: &js_sys::Function,
    ) -> Result<String, JsValue> {
        if self.consumed || total > 16 * 1024 * 1024 * 1024 || io.length() != 5 {
            return Err(js_error(
                "invalid package source, callbacks or completed session",
            ));
        }
        self.consumed = true;
        let functions: Vec<js_sys::Function> = io
            .iter()
            .map(|v| {
                v.dyn_into()
                    .map_err(|_| js_error("package I/O requires five functions"))
            })
            .collect::<Result<_, _>>()?;
        let mut source = FileIo {
            read: &functions[0],
            write: None,
            size: total,
            position: 0,
            cache: VecDeque::new(),
            limit: 0,
        };
        let mut scratch = FileIo {
            read: &functions[1],
            write: Some(&functions[2]),
            size: 0,
            position: 0,
            cache: VecDeque::new(),
            limit: 128 * 1024 * 1024,
        };
        let mut output = FileIo {
            read: &functions[3],
            write: Some(&functions[4]),
            size: 0,
            position: 0,
            cache: VecDeque::new(),
            limit: 512 * 1024 * 1024,
        };
        let third = self.third.as_ref().map(|bytes| wpi_image::spec_a::Import {
            name: "SBL3",
            bytes,
        });
        let loaders: Vec<_> = self
            .loaders
            .iter()
            .map(|bytes| wpi_image::spec_a::Import {
                name: "loader",
                bytes,
            })
            .collect();
        json(
            &wpi_image::spec_a::package::build(
                &mut source,
                third,
                &loaders,
                donor_boot,
                &mut scratch,
                &mut output,
                |stage, done, total| {
                    progress
                        .call3(
                            &JsValue::NULL,
                            &JsValue::from_str(stage),
                            &JsValue::from_f64(done as f64),
                            &JsValue::from_f64(total as f64),
                        )
                        .ok()
                        .and_then(|v| v.as_bool())
                        == Some(true)
                },
            )
            .map_err(js_error)?,
        )
    }
}
impl Default for BrowserSpecAPackage {
    fn default() -> Self {
        Self::new()
    }
}
