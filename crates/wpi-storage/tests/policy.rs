use wpi_storage::policy::{self, InventoryDisk};
fn disk() -> InventoryDisk {
    InventoryDisk {
        number: 3,
        model: "Synthetic phone".into(),
        pnp_id: r"USBSTOR\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE&REV_1\PRIVATE-ID".into(),
        serial: "PRIVATE-SERIAL".into(),
        size: (32u64 * 1024 * 1024 * 1024).to_string(),
        sector_size: 512,
        bus_type: 7,
        offline: true,
        read_only: true,
        boot: false,
        system: false,
    }
}
#[test]
fn admission_requires_exact_phone_storage_hardware_tokens() {
    let d = disk();
    assert!(policy::blockers(&d).is_empty());
    for id in [
        r"USBSTOR\DISK&VEN_MSFT&PROD_PHONE_MMC_STOR&REV_1\x",
        r"SCSI\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE\x",
    ] {
        assert!(policy::phone_pnp(id));
    }
    for id in [
        r"USBSTOR\DISK&VEN_OTHER&PROD_MMC_STORAGE\x",
        r"USBSTOR\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE_OTHER\x",
        r"OTHER\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE\x",
        r"USBSTOR\DISK&VEN_QUALCOMM&PROD_MMC_STORAGE",
    ] {
        assert!(!policy::phone_pnp(id), "accepted {id}");
    }
}
#[test]
fn system_online_writable_non_usb_and_unknown_geometry_or_identity_fail_closed() {
    for kind in 0..10 {
        let mut d = disk();
        match kind {
            0 => d.boot = true,
            1 => d.system = true,
            2 => d.offline = false,
            3 => d.read_only = false,
            4 => d.bus_type = 0,
            5 => d.sector_size = 4096,
            6 => d.size = u64::MAX.to_string(),
            7 => d.size = "unknown".into(),
            8 => d.serial.clear(),
            _ => d.model = "x".repeat(257),
        };
        assert!(!policy::blockers(&d).is_empty());
    }
}
#[test]
fn exported_inventory_and_debug_do_not_disclose_storage_identifiers() {
    let d = disk();
    let json = serde_json::to_string(&policy::candidate(&d)).unwrap();
    assert!(!json.contains("PRIVATE"));
    assert!(!format!("{d:?}").contains("PRIVATE"));
}
#[test]
fn invalid_fingerprint_is_rejected_before_any_platform_inventory_or_output() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("absent.img");
    for hash in ["bad".to_owned(), "z".repeat(64)] {
        let error = wpi_storage::backup(u32::MAX, &hash, None, &output, |_, _| {
            panic!("must not start copying")
        })
        .unwrap_err();
        assert!(matches!(error, wpi_image::ImageError::Invalid(_)));
    }
    assert!(!output.exists());
}
