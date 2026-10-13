use std::io::{Cursor, Read, Write};
use wpi_image::{
    filesystem,
    patch::{sha1, PatchCatalog},
};
fn fat_fixture() -> Vec<u8> {
    let mut disk = Cursor::new(vec![0u8; 4 * 1024 * 1024]);
    fatfs::format_volume(&mut disk, fatfs::FormatVolumeOptions::new()).unwrap();
    let fs = fatfs::FileSystem::new(&mut disk, fatfs::FsOptions::new()).unwrap();
    let root = fs.root_dir();
    let mut file = root.create_file("kernel.bin").unwrap();
    file.write_all(b"abcdefgh").unwrap();
    file.flush().unwrap();
    drop(file);
    drop(root);
    fs.unmount().unwrap();
    disk.into_inner()
}
#[test]
fn fat_listing_and_extraction_do_not_mutate_source() {
    let bytes = fat_fixture();
    let mut disk = Cursor::new(bytes.clone());
    let files = filesystem::list(&mut disk, "").unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "kernel.bin");
    let mut output = Vec::new();
    filesystem::extract_file(&mut disk, "kernel.bin", &mut output, |_, _| true).unwrap();
    assert_eq!(output, b"abcdefgh");
    assert_eq!(disk.into_inner(), bytes);
}
#[test]
fn fat_copy_patch_preserves_filesystem_and_is_reversible() {
    let original = b"abcdefgh";
    let patched = b"abXYefgh";
    let xml=format!("<PatchDefinitions><PatchDefinition Name=\"test\"><TargetVersions><TargetVersion Description=\"fixture\"><TargetFiles><TargetFile Path=\"kernel.bin\" HashOriginal=\"{}\" HashPatched=\"{}\"><Patches><Patch Address=\"0x2\" OriginalBytes=\"6364\" PatchedBytes=\"5859\"/></Patches></TargetFile></TargetFiles></TargetVersion></TargetVersions></PatchDefinition></PatchDefinitions>",sha1(original),sha1(patched));
    let catalog = PatchCatalog::parse(&xml).unwrap();
    let mut disk = Cursor::new(fat_fixture());
    filesystem::patch_fat_image(&mut disk, &catalog, "test", false).unwrap();
    let mut output = Vec::new();
    filesystem::extract_file(&mut disk, "kernel.bin", &mut output, |_, _| true).unwrap();
    assert_eq!(output, patched);
    filesystem::patch_fat_image(&mut disk, &catalog, "test", true).unwrap();
    disk.set_position(0);
    let fs = fatfs::FileSystem::new(&mut disk, fatfs::FsOptions::new()).unwrap();
    let mut file = fs.root_dir().open_file("kernel.bin").unwrap();
    let mut output = Vec::new();
    file.read_to_end(&mut output).unwrap();
    assert_eq!(output, original);
}
#[test]
fn invalid_geometry_fails_and_ntfs_boot_sector_parses() {
    let mut boot = vec![0; 512];
    assert!(filesystem::inspect_boot_sector(&boot).is_err());
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 8;
    boot[40..48].copy_from_slice(&4096u64.to_le_bytes());
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    let info = filesystem::inspect_boot_sector(&boot).unwrap();
    assert_eq!(info.kind, "NTFS");
    assert_eq!(info.sectors_per_cluster, 8);
    boot[13] = 3;
    assert!(filesystem::inspect_boot_sector(&boot).is_err());
}

#[test]
fn ntfs_small_index_records_resident_and_fragmented_data_are_read_only() {
    let bytes = include_bytes!("../../../tests/fixtures/ntfs-large-cluster.img");
    let mut disk = Cursor::new(bytes.as_slice());
    let entries = filesystem::list(&mut disk, "").unwrap();
    assert_eq!(
        entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        ["big.bin", "tiny.txt"]
    );
    let mut resident = Vec::new();
    filesystem::extract_file(&mut disk, "TINY.TXT", &mut resident, |_, _| true).unwrap();
    assert_eq!(resident, b"resident");
    let mut fragmented = Vec::new();
    filesystem::extract_file(&mut disk, "big.bin", &mut fragmented, |_, _| true).unwrap();
    assert_eq!(&fragmented[..16384], vec![b'A'; 16384]);
    assert_eq!(&fragmented[16384..], vec![b'B'; 16384]);
    let mut corrupted = bytes.to_vec();
    // Root subnode VCN is a sector offset and must stay in the allocation stream.
    let root_vcn = 16384 + 5 * 1024 + 56 + 32 + 48;
    for vcn in [-1i64, i64::MAX, 1024] {
        corrupted[root_vcn..root_vcn + 8].copy_from_slice(&vcn.to_le_bytes());
        assert!(filesystem::list(&mut Cursor::new(&corrupted), "").is_err());
    }
    let mut compressed = bytes.to_vec();
    compressed[16384 + 7 * 1024 + 56 + 12..16384 + 7 * 1024 + 56 + 14]
        .copy_from_slice(&1u16.to_le_bytes());
    assert!(filesystem::extract_file(
        &mut Cursor::new(compressed),
        "big.bin",
        &mut Vec::new(),
        |_, _| true
    )
    .is_err());
    let mut cyclic = bytes.to_vec();
    let node = 5 * 16384 + 8192;
    cyclic[node + 28..node + 32].copy_from_slice(&64u32.to_le_bytes());
    cyclic[node + 36] = 1;
    cyclic[node + 64..node + 88].fill(0);
    cyclic[node + 72..node + 74].copy_from_slice(&24u16.to_le_bytes());
    cyclic[node + 76..node + 80].copy_from_slice(&3u32.to_le_bytes());
    cyclic[node + 80..node + 88].copy_from_slice(&16i64.to_le_bytes());
    assert!(filesystem::list(&mut Cursor::new(&cyclic), "")
        .unwrap_err()
        .to_string()
        .contains("traversal"));
    assert!(filesystem::extract_file(
        &mut Cursor::new(&cyclic),
        "missing.bin",
        &mut Vec::new(),
        |_, _| true
    )
    .unwrap_err()
    .to_string()
    .contains("traversal"));
    for record_size in [0u32, u32::MAX] {
        let mut invalid = bytes.to_vec();
        let at = 16384 + 5 * 1024 + 56 + 32 + 8;
        invalid[at..at + 4].copy_from_slice(&record_size.to_le_bytes());
        assert!(filesystem::list(&mut Cursor::new(invalid), "").is_err());
    }
}
