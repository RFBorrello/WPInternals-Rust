use wpi_core::backup_replay;
use wpi_protocol::block_replay::{BlockRead, ReplayBlockSource};
fn source(response: Vec<u8>, error: Option<String>) -> ReplayBlockSource {
    ReplayBlockSource::new(
        512,
        8,
        vec![BlockRead {
            offset: 512,
            length: 2048,
            response,
            error,
        }],
    )
    .unwrap()
}
#[test]
fn complete_partition_backup_is_hashed_and_existing_outputs_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.img");
    let bytes = vec![0xAB; 2048];
    let mut replay = source(bytes.clone(), None);
    let manifest = backup_replay::create(&mut replay, 1, 4, &output, |_, _| true).unwrap();
    assert_eq!(manifest.source_kind, "replay_only");
    assert_eq!(manifest.bytes, 2048);
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    assert_eq!(
        manifest.sha256,
        wpi_image::stream::sha256(&mut std::io::Cursor::new(bytes)).unwrap()
    );
    let mut replay = source(vec![0; 2048], None);
    assert!(backup_replay::create(&mut replay, 1, 4, &output, |_, _| true).is_err());
    assert_eq!(replay.remaining(), 1);
}
#[test]
fn interrupted_or_short_backup_never_retries_or_publishes_partial_data() {
    for (response, error) in [
        (vec![1; 512], None),
        (vec![], Some("disconnected".into())),
        (vec![], Some("timeout".into())),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("backup.img");
        let mut replay = source(response, error);
        assert!(backup_replay::create(&mut replay, 1, 4, &output, |_, _| true).is_err());
        assert!(!output.exists());
        assert_eq!(replay.remaining(), 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
#[test]
fn cancellation_and_out_of_bounds_reject_before_reading_or_publishing() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.img");
    let mut replay = source(vec![0; 2048], None);
    assert!(backup_replay::create(&mut replay, u64::MAX, 4, &output, |_, _| true).is_err());
    assert!(backup_replay::create(&mut replay, 7, 4, &output, |_, _| true).is_err());
    assert!(backup_replay::create(&mut replay, 1, 4, &output, |_, _| false).is_err());
    assert_eq!(replay.remaining(), 1);
    assert!(!output.exists());
}

#[test]
fn interruption_after_a_complete_chunk_discards_the_partial_backup() {
    for cancel in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("backup.img");
        let mut source = ReplayBlockSource::new(
            512,
            4096,
            vec![
                BlockRead {
                    offset: 0,
                    length: 1024 * 1024,
                    response: vec![1; 1024 * 1024],
                    error: None,
                },
                BlockRead {
                    offset: 1024 * 1024,
                    length: 1024 * 1024,
                    response: vec![],
                    error: Some("timeout after first chunk".into()),
                },
            ],
        )
        .unwrap();
        assert!(
            backup_replay::create(&mut source, 0, 4096, &output, |done, _| !(cancel
                && done > 0))
            .is_err()
        );
        assert!(!output.exists());
        assert_eq!(source.remaining(), usize::from(cancel));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn final_boundary_cancellation_does_not_publish_a_complete_temporary_image() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("backup.img");
    let mut replay = source(vec![0; 2048], None);
    assert!(matches!(
        backup_replay::create(&mut replay, 1, 4, &output, |done, total| done < total),
        Err(wpi_image::ImageError::Cancelled)
    ));
    assert_eq!(replay.remaining(), 0);
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
