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
    /// Conditional on running the exact analyzed reference binary. Not a claim
    /// about the installed image and never an execution grant.
    pub reference_interpretation: Option<ReferenceInterpretation>,
    pub physical_write_interpretation_validated: bool,
    pub affected_installed_bytes_captured: bool,
    pub data_preservation_validated: bool,
    pub phone_writes_enabled: bool,
    pub conclusion: &'static str,
}
#[derive(Debug, Serialize)]
pub struct ReferenceInterpretation {
    pub code: wpi_image::spec_a::entry_code::Report,
    pub boundaries: Vec<Boundary>,
    pub potential_user_partition_overlap: bool,
    pub applicable_to_installed_phone: bool,
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
    let overlaps = user_overlap(&boundaries);
    let reference_interpretation = prepared.entry().entry_code().map(|code| {
        let bounds = footprint(
            layout.recorded_capacity_sectors,
            &parts,
            &[
                ("reference_payload_begin", 0, ENTRY_CHUNK as u64 / 512),
                (
                    "reference_header_backup_gpt_clear",
                    layout.recorded_capacity_sectors - 33,
                    33,
                ),
            ],
        );
        ReferenceInterpretation {
            code: code.clone(),
            potential_user_partition_overlap: user_overlap(&bounds),
            boundaries: bounds,
            applicable_to_installed_phone: false,
        }
    });
    let conclusion = if reference_interpretation.is_some() {
        "The exact reference FlashApp skips end-relative payload mappings and clears only backup GPT sectors on header import. Its installed binary identity is unverified. Keep that conditional analysis distinct from the conservative bound; GPT recovery material alone is not an installed backup or a validated native unlock/recovery path."
    } else {
        "No exact reference FlashApp profile is available for this prepared source. The whole-boundary model remains conservative; resolve installed write behavior and recovery before enabling writes."
    };
    Ok(Report {
        source_ffu_sha256: prepared.artifacts().source_ffu_sha256.clone(),
        saved_primary_sha256: prepared.artifacts().saved_primary_sha256.clone(),
        capacity_sectors: layout.recorded_capacity_sectors,
        model: "conservative_whole_begin_and_end_chunks_not_observed_writes",
        source_profile_has_end_relative_zero_chunk: true,
        boundaries,
        potential_user_partition_overlap: overlaps,
        reference_interpretation,
        physical_write_interpretation_validated: false,
        affected_installed_bytes_captured: false,
        data_preservation_validated: false,
        phone_writes_enabled: false,
        conclusion,
    })
}
fn user_overlap(boundaries: &[Boundary]) -> bool {
    boundaries
        .iter()
        .flat_map(|b| &b.partition_intersections)
        .any(|p| {
            ["Data", "MainOS", "EFIESP"]
                .iter()
                .any(|name| p.partition.eq_ignore_ascii_case(name))
        })
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
    Ok(footprint(
        capacity,
        parts,
        &[("begin", 0, chunk), ("end", capacity - chunk, chunk)],
    ))
}
fn footprint(
    _capacity: u64,
    parts: &[(&str, &Range)],
    ranges: &[(&'static str, u64, u64)],
) -> Vec<Boundary> {
    let mut result = Vec::new();
    for &(origin, first, count) in ranges {
        let last = first + count - 1;
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
            sector_count: count,
            partition_intersections: intersections,
        });
    }
    result
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
        let reference = footprint(4096, &[("Data", &data)], &[("header", 4096 - 33, 33)]);
        assert!(!user_overlap(&reference));
        assert!(user_overlap(&result));
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
