use std::{io::Cursor, path::Path};
use wpi_core::{
    backup::{self, Geometry, ReadOnlySource},
    operations::OperationCoordinator,
};
use wpi_image::{ImageError, Result};
struct Source {
    checks: u32,
    reads: usize,
    max: usize,
    fail_at: Option<usize>,
    changed: bool,
    geometry: Geometry,
}
impl Source {
    fn new() -> Self {
        Self {
            checks: 0,
            reads: 0,
            max: 0,
            fail_at: None,
            changed: false,
            geometry: Geometry {
                size: 3 * 1024 * 1024,
                sector_size: 512,
            },
        }
    }
}
impl ReadOnlySource for Source {
    fn geometry(&self) -> Geometry {
        self.geometry
    }
    fn validate(&mut self) -> Result<()> {
        self.checks += 1;
        if self.changed && self.checks > 1 {
            Err(ImageError::Invalid("identity changed".into()))
        } else {
            Ok(())
        }
    }
    fn read_at(&mut self, offset: u64, b: &mut [u8]) -> Result<()> {
        self.reads += 1;
        self.max = self.max.max(b.len());
        if self.fail_at == Some(self.reads) {
            return Err(ImageError::Invalid("disconnect or short read".into()));
        }
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = ((offset + i as u64) % 251) as u8;
        }
        Ok(())
    }
}
fn create(s: &mut Source, path: &Path) -> Result<backup::BackupManifest> {
    backup::create(s, "test_only", 0, 6144, path, |_, _| true)
}
#[test]
fn read_only_source_is_copied_in_bounded_chunks_and_revalidated_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("copy.img");
    let mut s = Source::new();
    let m = create(&mut s, &output).unwrap();
    assert_eq!(s.checks, 2);
    assert_eq!(s.reads, 3);
    assert_eq!(s.max, 1024 * 1024);
    assert_eq!(
        m.sha256,
        wpi_image::stream::sha256(&mut Cursor::new(std::fs::read(output).unwrap())).unwrap()
    );
    assert_eq!(m.bytes, 3 * 1024 * 1024);
}
#[test]
fn final_identity_change_discards_an_otherwise_complete_backup() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Source::new();
    s.changed = true;
    assert!(create(&mut s, &dir.path().join("copy.img")).is_err());
    assert_eq!(s.reads, 3);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[test]
fn disconnect_is_not_retried_and_never_publishes_partial_output() {
    for n in [1, 2, 3] {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Source::new();
        s.fail_at = Some(n);
        assert!(create(&mut s, &dir.path().join("copy.img")).is_err());
        assert_eq!(s.reads, n);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
#[test]
fn invalid_ranges_geometry_and_existing_outputs_do_not_copy() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("copy.img");
    let mut s = Source::new();
    for (first, count) in [(u64::MAX, 1), (0, u64::MAX), (0, 0), (6143, 2)] {
        assert!(backup::create(&mut s, "test", first, count, &output, |_, _| true).is_err());
    }
    s.geometry.sector_size = 513;
    assert!(create(&mut s, &output).is_err());
    s.geometry.sector_size = 512;
    std::fs::write(&output, b"preserve").unwrap();
    assert!(create(&mut s, &output).is_err());
    assert_eq!(s.reads, 0);
    assert_eq!(std::fs::read(output).unwrap(), b"preserve");
}
#[test]
fn cancellation_at_start_middle_and_final_boundary_removes_temporary_output() {
    for stop in [0, 1024 * 1024, 3 * 1024 * 1024] {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Source::new();
        assert!(matches!(
            backup::create(
                &mut s,
                "test",
                0,
                6144,
                &dir.path().join("copy.img"),
                |done, _| done < stop
            ),
            Err(ImageError::Cancelled)
        ));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
#[test]
fn storage_reads_share_the_operation_lock_and_release_it_on_drop() {
    let c = OperationCoordinator::default();
    let lease = c.reserve_storage_read().unwrap();
    assert!(c.reserve_storage_read().is_err());
    assert!(c.reserve_local(wpi_types::Operation::InspectGpt).is_err());
    drop(lease);
    assert!(c.reserve_local(wpi_types::Operation::InspectGpt).is_ok());
    assert!(c.reserve_local(wpi_types::Operation::StockFlash).is_err());
}
