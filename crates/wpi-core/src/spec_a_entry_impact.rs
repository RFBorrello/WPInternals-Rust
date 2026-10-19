//! Conservative preservation audit for the validated entry profile. This is a
//! whole-chunk end-relative model, not a measurement of physical device writes.
use crate::{spec_a_emergency_replay::ENTRY_CHUNK, spec_a_session::Prepared};
use serde::Serialize;
use wpi_image::spec_a::live_plan::Range;
#[derive(Debug, Serialize)]
pub struct Intersection {
    pub partition: String,
    pub first_sector: u64,
    pub sector_count: u64,
}
#[derive(Debug, Serialize)]
pub struct Boundary {
    pub origin: &'static str,
    pub first_sector: u64,
    pub sector_count: u64,
    pub partition_intersections: Vec<Intersection>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub source_ffu_sha256: String,
    pub saved_primary_sha256: String,
    pub capacity_sectors: u64,
    pub model: &'static str,
    pub source_profile_has_end_relative_zero_chunk: bool,
    pub boundaries: Vec<Boundary>,
    pub potential_user_partition_overlap: bool,
    pub physical_write_interpretation_validated: bool,
    pub affected_installed_bytes_captured: bool,
    pub data_preservation_validated: bool,
    pub phone_writes_enabled: bool,
    pub conclusion: &'static str,
}
/// EntryPlan pins the source and requires exactly one begin-zero and one end-zero
/// mapping of the same verified 128 KiB payload. Prepared binds that entry to this
/// layout. A historical layout cannot prove allocation or actual FlashApp writes.
pub fn assess(prepared: &Prepared) -> Result<Report, String> {
    let layout = &prepared.boot().report().layout;
    let parts: Vec<_> = layout
        .partitions
        .iter()
        .map(|p| (p.partition.as_str(), &p.installed))
        .collect();
    let boundaries = boundaries(layout.recorded_capacity_sectors, &parts)?;
    let overlaps = boundaries
        .iter()
        .flat_map(|b| &b.partition_intersections)
        .any(|p| {
            ["Data", "MainOS", "EFIESP"]
                .iter()
                .any(|name| p.partition.eq_ignore_ascii_case(name))
        });
    Ok(Report {source_ffu_sha256:prepared.artifacts().source_ffu_sha256.clone(),
        saved_primary_sha256:prepared.artifacts().saved_primary_sha256.clone(),capacity_sectors:layout.recorded_capacity_sectors,
        model:"conservative_whole_begin_and_end_chunks_not_observed_writes",
        source_profile_has_end_relative_zero_chunk:true,boundaries,potential_user_partition_overlap:overlaps,
        physical_write_interpretation_validated:false,affected_installed_bytes_captured:false,
        data_preservation_validated:false,phone_writes_enabled:false,
        conclusion:"Do not infer preservation from boot-transfer ranges alone. Resolve end-relative write behavior and capture affected installed bytes or establish an alternative entry/recovery path before enabling writes."})
}
fn boundaries(capacity: u64, parts: &[(&str, &Range)]) -> Result<Vec<Boundary>, String> {
    let chunk = ENTRY_CHUNK as u64 / 512;
    if capacity < 2 * chunk || !capacity.is_multiple_of(chunk) || capacity > u64::from(u32::MAX) {
        return Err("Entry impact model requires whole-chunk-aligned bounded capacity; unknown geometry cannot establish preservation".into());
    }
    if parts
        .iter()
        .any(|(_, p)| p.first_sector > p.last_sector || p.last_sector >= capacity)
    {
        return Err("Installed partition bounds exceed recorded capacity".into());
    }
    let mut result = Vec::new();
    for (origin, first) in [("begin", 0), ("end", capacity - chunk)] {
        let last = first + chunk - 1;
        let mut intersections = Vec::new();
        for (name, p) in parts {
            let from = first.max(p.first_sector);
            let to = last.min(p.last_sector);
            if from <= to {
                intersections.push(Intersection {
                    partition: (*name).into(),
                    first_sector: from,
                    sector_count: to - from + 1,
                });
            }
        }
        result.push(Boundary {
            origin,
            first_sector: first,
            sector_count: chunk,
            partition_intersections: intersections,
        });
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn end_chunk_models_partition_tail_beside_backup_gpt() {
        let data = Range {
            first_sector: 1024,
            last_sector: 4096 - 34,
        };
        let reserved = Range {
            first_sector: 34,
            last_sector: 40,
        };
        let result =
            boundaries(4096, &[("Data", &data), ("synthetic-reserved", &reserved)]).unwrap();
        assert_eq!(result[0].first_sector, 0);
        assert_eq!(result[1].first_sector, 3840);
        assert_eq!(result[1].partition_intersections.len(), 1);
        assert_eq!(result[1].partition_intersections[0].partition, "Data");
        assert_eq!(result[1].partition_intersections[0].sector_count, 223);
        assert_eq!(result[0].partition_intersections[0].sector_count, 7);
        let short = Range {
            first_sector: 1024,
            last_sector: 3000,
        };
        assert!(boundaries(4096, &[("Data", &short)]).unwrap()[1]
            .partition_intersections
            .is_empty());
    }
    #[test]
    fn unknown_alignment_and_invalid_bounds_cannot_produce_a_clear_audit() {
        for size in [0, 255, 511, 4097, u64::MAX] {
            assert!(boundaries(size, &[]).is_err());
        }
        assert!(boundaries(
            4096,
            &[(
                "Data",
                &Range {
                    first_sector: 100,
                    last_sector: 4096
                }
            )]
        )
        .is_err());
        assert!(boundaries(
            4096,
            &[(
                "Data",
                &Range {
                    first_sector: 100,
                    last_sector: 99
                }
            )]
        )
        .is_err());
    }
}
