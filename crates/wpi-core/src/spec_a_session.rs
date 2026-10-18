//! Artifact-bound, read-only RM-875 session checks. No execution grant or import API.
use crate::{
    spec_a_emergency_replay::{EntryPlan, Loader},
    spec_a_journal::Artifacts,
    spec_a_preflight::Reference,
};
use serde::Serialize;
use wpi_image::spec_a::programmer_plan::Plan;
use wpi_protocol::{
    identity::{self, PublicId},
    normal,
    preflight::{self, RootKeyHash},
    MessageTransport,
};

pub const FIRMWARE: &str = "3051.50009.1451.1003";
pub const PRODUCT_CODE: &str = "059T909";
pub const VARIANT: &str = "RM-875";
const PLATFORM: &str = "Nokia.MSM8960.P5217";

struct Context {
    artifacts: Artifacts,
    root: RootKeyHash,
    platform: String,
    capacity: u64,
}
/// Owns the verified bytes used for future replay. JSON cannot reconstruct this bundle.
pub struct Prepared {
    entry: EntryPlan,
    loader: Loader,
    boot: Plan,
    context: Context,
}
impl Prepared {
    pub fn new(
        entry: EntryPlan,
        reference: Reference,
        loader: Loader,
        boot: Plan,
    ) -> Result<Self, String> {
        let layout = &boot.report().layout;
        let (sha, platform) = entry.source();
        check_sources(
            sha,
            platform,
            &reference,
            &loader,
            layout,
            boot.source_sbl1_sha256(),
        )?;
        let (input, decoded) = loader.fingerprints();
        let context = Context {
            artifacts: Artifacts {
                source_ffu_sha256: sha.into(),
                package_sha256: layout.package_sha256.clone(),
                saved_primary_sha256: layout.saved_primary_sha256.clone(),
                candidate_primary_sha256: layout.candidate_primary_sha256.clone(),
                loader_input_sha256: input.into(),
                loader_decoded_sha256: decoded.into(),
            },
            root: reference.root().clone(),
            platform: platform.into(),
            capacity: layout.recorded_capacity_sectors,
        };
        Ok(Self {
            entry,
            loader,
            boot,
            context,
        })
    }
    pub fn entry(&self) -> &EntryPlan {
        &self.entry
    }
    pub fn loader(&self) -> &Loader {
        &self.loader
    }
    pub fn boot(&self) -> &Plan {
        &self.boot
    }
    pub fn artifacts(&self) -> &Artifacts {
        &self.context.artifacts
    }
}
fn check_sources(
    sha: &str,
    platform: &str,
    reference: &Reference,
    loader: &Loader,
    layout: &wpi_image::spec_a::live_plan::Report,
    sbl1: &str,
) -> Result<(), String> {
    if !sha.eq_ignore_ascii_case(&layout.source_ffu_sha256)
        || platform != layout.source_platform
        || platform != reference.platform()
        || !reference.matches_pinned_source(sha)
        || !reference.summary().sbl1_sha256.eq_ignore_ascii_case(sbl1)
        || !loader.matches_root(reference.root())
    {
        return Err(
            "Entry FFU, pinned reference, loader root or boot-package source differs".into(),
        );
    }
    if !(platform == PLATFORM
        || platform
            .strip_prefix(PLATFORM)
            .is_some_and(|s| s.starts_with('.')))
        || layout.recorded_capacity_sectors == 0
        || layout.recorded_capacity_sectors > u64::from(u32::MAX)
    {
        return Err("This read-only session profile requires the RM-875 source platform and supported disk capacity".into());
    }
    Ok(())
}
/// Ephemeral public ID bound to this prepared bundle's lifetime. No Serialize/Clone.
/// Generic transports permit tests, not an assertion of physical hardware access.
pub struct NormalSession<'a> {
    context: &'a Context,
    public_id: PublicId,
}
struct FlashGuard<'a, T> {
    inner: &'a mut T,
    capacity: u64,
}
impl<T: MessageTransport> MessageTransport for FlashGuard<'_, T> {
    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response: usize,
    ) -> wpi_protocol::Result<Vec<u8>> {
        let reply = self.inner.exchange(request, maximum_response)?;
        if request == b"NOKV" {
            let (info, security) = preflight::parse_application(&reply)?;
            if info.protocol_major != 1
                || info.protocol_mask.is_none_or(|m| m & 1 == 0)
                || security.is_none()
                || info.emmc_sectors.map(u64::from) != Some(self.capacity)
            {
                return Err(wpi_protocol::ProtocolError::Invalid("Fresh Flash protocol, security evidence or disk capacity differs from the prepared Spec A layout".into()));
            }
        }
        Ok(reply)
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub artifacts: Artifacts,
    pub variant: &'static str,
    pub firmware: &'static str,
    pub normal_identity_bookends_match: bool,
    pub normal_flash_public_id_matches: bool,
    pub flash_root_and_security_checked: bool,
    pub flash_capacity_matches_saved_layout: bool,
    pub source_ffu_integrity_checked: bool,
    pub source_sbl1_and_loader_root_bound: bool,
    pub fresh_installed_gpt_checked: bool,
    pub identity_authenticated: bool,
    pub data_preservation_validated: bool,
    pub hardware_validated: bool,
    pub phone_writes_enabled: bool,
    pub automatic_resume_allowed: bool,
    pub blockers: Vec<&'static str>,
}
fn boundary<F: FnMut(&str) -> bool>(progress: &mut F, stage: &str) -> Result<(), String> {
    if progress(stage) {
        Ok(())
    } else {
        Err("Read-only session cancelled before next query".into())
    }
}
pub fn capture_normal<'a, T: MessageTransport, F: FnMut(&str) -> bool>(
    prepared: &'a Prepared,
    transport: &mut T,
    progress: F,
) -> Result<NormalSession<'a>, String> {
    capture(&prepared.context, transport, progress)
}
fn capture<'a, T: MessageTransport, F: FnMut(&str) -> bool>(
    context: &'a Context,
    transport: &mut T,
    mut progress: F,
) -> Result<NormalSession<'a>, String> {
    boundary(&mut progress, "Read first Normal public ID")?;
    let public_id = identity::read_normal(transport, 0).map_err(|e| e.to_string())?;
    for (id, method, key) in [
        (1, "ReadManufacturerModelName", "ManufacturerModelName"),
        (2, "ReadProductCode", "ProductCode"),
        (3, "ReadSwVersion", "SwVersion"),
    ] {
        boundary(&mut progress, method)?;
        let request = normal::request(id, method).map_err(|e| e.to_string())?;
        let reply = transport
            .exchange(&request, 65536)
            .map_err(|e| e.to_string())?;
        let value = normal::parse(&reply, id, key).map_err(|e| e.to_string())?;
        let matches = match id {
            1 => {
                value == VARIANT
                    || value
                        .strip_prefix(VARIANT)
                        .is_some_and(|s| s.starts_with('_'))
            }
            2 => value == PRODUCT_CODE,
            _ => value == FIRMWARE,
        };
        if !matches {
            return Err("Fresh Normal model, product code or firmware differs from the reviewed RM-875 session profile".into());
        }
    }
    boundary(&mut progress, "Read final Normal public ID")?;
    if identity::read_normal(transport, 4).map_err(|e| e.to_string())? != public_id {
        return Err("Normal public ID changed during the session".into());
    }
    boundary(&mut progress, "Finish Normal identity checks")?;
    Ok(NormalSession { context, public_id })
}
impl NormalSession<'_> {
    pub fn report(&self) -> Report {
        self.report_with_flash(false)
    }
    /// Consumes the baseline on success OR error; it cannot retry a failed Flash
    /// session. Physical-port checks and deadlines belong to the native adapter.
    pub fn check_flash<T: MessageTransport, F: FnMut(&str) -> bool>(
        self,
        transport: &mut T,
        progress: F,
    ) -> Result<Report, String> {
        let mut guarded = FlashGuard {
            inner: transport,
            capacity: self.context.capacity,
        };
        let _capture = preflight::capture_bound(
            &mut guarded,
            &self.context.root,
            &self.context.platform,
            false,
            &self.public_id,
            progress,
        )
        .map_err(|e| e.to_string())?
        .into_observation();
        Ok(self.report_with_flash(true))
    }
    fn report_with_flash(&self, flash: bool) -> Report {
        let mut blockers=vec![
            "Fresh installed primary/backup GPT and recoverable installed partition originals are missing.",
            "Firmware, donor and loader acceptance and independent OEM trust remain unvalidated.",
            "Data preservation and a hardware-validated recovery path remain unestablished.",
            "Live unlock execution and later boot-integrity/return-to-OS stages remain disabled.",
        ];
        if !flash {
            blockers.insert(
                0,
                "Fresh correlated Flash identity, root, security and capacity checks have not run.",
            );
        }
        Report {
            artifacts: self.context.artifacts.clone(),
            variant: VARIANT,
            firmware: FIRMWARE,
            normal_identity_bookends_match: true,
            normal_flash_public_id_matches: flash,
            flash_root_and_security_checked: flash,
            flash_capacity_matches_saved_layout: flash,
            source_ffu_integrity_checked: true,
            source_sbl1_and_loader_root_bound: true,
            fresh_installed_gpt_checked: false,
            identity_authenticated: false,
            data_preservation_validated: false,
            hardware_validated: false,
            phone_writes_enabled: false,
            automatic_resume_allowed: false,
            blockers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_a_emergency_replay::{
        Binding, Endpoint, EntryPlan, Loader, Observation, Scenario, TimedObservation,
    };
    use std::{cell::Cell, io::Cursor};
    use wpi_protocol::{
        flash, identity,
        qualcomm::{encode_hdlc, v1},
        replay::{Exchange, FramedExchange, FramedReplayTransport, ReplayTransport},
    };
    #[allow(dead_code)]
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/spec_a_emergency.rs"
        ));
    }
    use support::{parameter, plain, root, root_bytes, sha, terminal};
    fn ctx() -> Context {
        Context {
            artifacts: Artifacts {
                source_ffu_sha256: sha(b"source"),
                package_sha256: sha(b"package"),
                saved_primary_sha256: sha(b"saved"),
                candidate_primary_sha256: sha(b"candidate"),
                loader_input_sha256: sha(b"loader"),
                loader_decoded_sha256: sha(b"decoded"),
            },
            root: root(),
            platform: "SYNTHETIC.LUMIA.TEST".into(),
            capacity: 1000,
        }
    }
    fn normal_steps() -> Vec<Exchange> {
        let public = |id| {
            serde_json::to_vec(
                &serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"PublicId":vec![42;20]}}),
            )
            .unwrap()
        };
        let result = |id, key: &str, value: &str| {
            serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":id,"result":{key:value}}))
                .unwrap()
        };
        vec![
            plain(identity::normal_request(0), public(0)),
            plain(
                normal::request(1, "ReadManufacturerModelName").unwrap(),
                result(1, "ManufacturerModelName", "RM-875_eu_euro1_267"),
            ),
            plain(
                normal::request(2, "ReadProductCode").unwrap(),
                result(2, "ProductCode", PRODUCT_CODE),
            ),
            plain(
                normal::request(3, "ReadSwVersion").unwrap(),
                result(3, "SwVersion", FIRMWARE),
            ),
            plain(identity::normal_request(4), public(4)),
        ]
    }
    fn flash_steps() -> Vec<Exchange> {
        let mut info = b"NOKV\0\x02\x01\x12\x02\x02\x04".to_vec();
        let platform = b"SYNTHETIC.LUMIA.TEST";
        info.extend_from_slice(&[5, 0, platform.len() as u8]);
        info.extend_from_slice(platform);
        info.extend_from_slice(&[15, 0, 8, 3, 1, 1, 1, 0, 0, 1, 1]);
        info.extend_from_slice(&[0x10, 0, 3, 1, 0, 1]);
        // NOKV eMMC subblock (0x03): sector count in big-endian.
        info.extend_from_slice(&[3, 0, 4]);
        info.extend_from_slice(&1000u32.to_be_bytes());
        vec![
            plain(b"NOKV".to_vec(), info.clone()),
            plain(identity::flash_request(), terminal(42)),
            plain(
                flash::parameter_request("RRKH").unwrap(),
                parameter(&root_bytes()),
            ),
            plain(
                flash::parameter_request("SS").unwrap(),
                parameter(&[0, 1, 1, 1, 0, 0, 1, 1]),
            ),
            plain(b"NOKV".to_vec(), info),
            plain(identity::flash_request(), terminal(42)),
        ]
    }
    #[test]
    fn normal_and_flash_queries_bind_one_context_without_enabling_writes() {
        let context = ctx();
        let mut normal = ReplayTransport::new(normal_steps());
        let baseline = capture(&context, &mut normal, |_| true).unwrap();
        assert!(normal.finished());
        let pending = baseline.report();
        assert!(!pending.normal_flash_public_id_matches);
        assert_eq!(pending.blockers.len(), 5);
        let mut flash = ReplayTransport::new(flash_steps());
        let report = baseline.check_flash(&mut flash, |_| true).unwrap();
        assert!(flash.finished());
        assert!(
            report.normal_flash_public_id_matches
                && report.flash_root_and_security_checked
                && report.flash_capacity_matches_saved_layout
        );
        assert!(
            !report.phone_writes_enabled
                && !report.data_preservation_validated
                && !report.hardware_validated
                && !report.automatic_resume_allowed
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("PublicId"));
        assert!(!json.contains("[42"));
        assert_eq!(
            report.artifacts.package_sha256,
            context.artifacts.package_sha256
        );
    }
    #[test]
    fn faults_and_cancellation_at_every_read_boundary_leave_later_queries_unsent() {
        let context = ctx();
        for flash_phase in [false, true] {
            let steps = if flash_phase {
                flash_steps()
            } else {
                normal_steps()
            };
            for at in 0..steps.len() {
                let mut broken = steps.clone();
                broken[at].error = Some("injected disconnect".into());
                let mut replay = ReplayTransport::new(broken);
                if flash_phase {
                    let baseline =
                        capture(&context, &mut ReplayTransport::new(normal_steps()), |_| {
                            true
                        })
                        .unwrap();
                    assert!(baseline.check_flash(&mut replay, |_| true).is_err());
                } else {
                    assert!(capture(&context, &mut replay, |_| true).is_err());
                }
                for remaining in &steps[at + 1..] {
                    assert_eq!(
                        replay.exchange(&remaining.request, 65536).unwrap(),
                        remaining.response
                    );
                }
                assert!(replay.finished());
            }
            for at in 0..=steps.len() {
                let calls = Cell::new(0);
                let mut replay = ReplayTransport::new(steps.clone());
                let cancel = |_: &str| {
                    let n = calls.get();
                    calls.set(n + 1);
                    n != at
                };
                if flash_phase {
                    let baseline =
                        capture(&context, &mut ReplayTransport::new(normal_steps()), |_| {
                            true
                        })
                        .unwrap();
                    assert!(baseline.check_flash(&mut replay, cancel).is_err());
                } else {
                    assert!(capture(&context, &mut replay, cancel).is_err());
                }
                for remaining in &steps[at..] {
                    assert_eq!(
                        replay.exchange(&remaining.request, 65536).unwrap(),
                        remaining.response
                    );
                }
                assert!(replay.finished());
            }
        }
    }
    #[test]
    fn changed_identity_root_profile_and_capacity_cannot_complete() {
        let context = ctx();
        for at in [0, 1, 2, 3, 4] {
            let mut steps = normal_steps();
            let mut value: serde_json::Value = serde_json::from_slice(&steps[at].response).unwrap();
            match at {
                0 | 4 => value["result"]["PublicId"] = serde_json::json!(vec![41; 20]),
                1 => value["result"]["ManufacturerModelName"] = serde_json::json!("RM-8750"),
                2 => value["result"]["ProductCode"] = serde_json::json!("different"),
                _ => value["result"]["SwVersion"] = serde_json::json!("different"),
            };
            steps[at].response = serde_json::to_vec(&value).unwrap();
            assert!(capture(&context, &mut ReplayTransport::new(steps), |_| true).is_err());
        }
        for at in [1, 2, 5] {
            let mut steps = flash_steps();
            steps[at].response = if at == 2 {
                parameter(&[0x55; 32])
            } else {
                terminal(41)
            };
            let baseline = capture(&context, &mut ReplayTransport::new(normal_steps()), |_| {
                true
            })
            .unwrap();
            assert!(baseline
                .check_flash(&mut ReplayTransport::new(steps), |_| true)
                .is_err());
        }
        let mut wrong = ctx();
        wrong.capacity += 1;
        let baseline =
            capture(&wrong, &mut ReplayTransport::new(normal_steps()), |_| true).unwrap();
        let steps = flash_steps();
        let mut replay = ReplayTransport::new(steps.clone());
        assert!(baseline.check_flash(&mut replay, |_| true).is_err());
        for e in &steps[1..] {
            assert_eq!(replay.exchange(&e.request, 65536).unwrap(), e.response);
        }
        assert!(replay.finished());
    }
    #[test]
    fn source_coherence_rejects_unpinned_swapped_and_mislabelled_inputs() {
        let mut bytes =
            include_bytes!("../../../tests/fixtures/synthetic-spec-a-package.ffu").to_vec();
        let metadata = wpi_image::ffu::FfuMetadata::open(&mut Cursor::new(&bytes)).unwrap();
        let at = (metadata.security_size + metadata.image_size + 12) as usize;
        bytes[at..at + 192].fill(0);
        bytes[at..at + PLATFORM.len()].copy_from_slice(PLATFORM.as_bytes());
        let mut reference = Reference::read(&mut Cursor::new(&bytes)).unwrap();
        let source_sha = sha(&bytes);
        let loader =
            Loader::prepare(support::LOADER, &sha(support::LOADER), reference.root()).unwrap();
        let sbl1 = reference.summary().sbl1_sha256.clone();
        let mut layout = wpi_image::spec_a::live_plan::Report {
            schema: 1,
            kind: "synthetic-coherence-test",
            package_sha256: sha(b"package"),
            manifest_sha256: sha(b"manifest"),
            source_ffu_sha256: source_sha.clone(),
            source_platform: PLATFORM.into(),
            saved_primary_sha256: sha(b"saved"),
            candidate_primary_sha256: sha(b"candidate"),
            recorded_capacity_sectors: 1000,
            reference_capacity_sectors: 1000,
            partition_count: 0,
            disk_identity_matches_reference: false,
            primary_matches_reference: false,
            normalized_backup_pairs: vec![],
            partitions: vec![],
            payloads: vec![],
            all_payloads_fit: true,
            unaffected_partition_entries_preserved: true,
            required_installed_partition_captures: vec![],
            backup_gpt_captured: false,
            installed_partitions_preserved: false,
            phone_contacted: false,
            phone_writes_enabled: false,
            execution_blockers: vec![],
        };
        assert!(check_sources(&source_sha, PLATFORM, &reference, &loader, &layout, &sbl1).is_err());
        // Private test metadata exercises the coherence predicate; only EntryPlan's
        // pinned reader can set this marker through the public API.
        reference.mark_full_integrity_checked(&source_sha);
        check_sources(&source_sha, PLATFORM, &reference, &loader, &layout, &sbl1).unwrap();
        assert!(check_sources(
            &sha(b"other"),
            PLATFORM,
            &reference,
            &loader,
            &layout,
            &sbl1
        )
        .is_err());
        assert!(check_sources(
            &source_sha,
            PLATFORM,
            &reference,
            &loader,
            &layout,
            &sha(b"other SBL1")
        )
        .is_err());
        reference.mark_full_integrity_checked(&sha(b"other reference"));
        assert!(check_sources(&source_sha, PLATFORM, &reference, &loader, &layout, &sbl1).is_err());
        reference.mark_full_integrity_checked(&source_sha);
        for capacity in [0, u64::from(u32::MAX) + 1] {
            layout.recorded_capacity_sectors = capacity;
            assert!(
                check_sources(&source_sha, PLATFORM, &reference, &loader, &layout, &sbl1).is_err()
            );
        }
    }
}
