//! Exact-binary static evidence, not a generic disassembler or hardware proof.
use crate::{invalid, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SOURCE_FFU: &str = "ce4724a1e4225f629ee4092400715dcd85d160470e1173c71c8065527e73e8c4";
pub const FLASH_APP: &str = "503578ed1bb90406e19067664235f974a19216e25ff4c33565bdda9365b8a1e2";

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub reference_uefi_sha256: String,
    pub reference_flash_app_sha256: String,
    pub reference_firmware: &'static str,
    pub evidence: &'static str,
    pub end_relative_descriptors_skipped_in_payload_loop: bool,
    pub header_import_clears_backup_gpt_sectors: u32,
    pub backup_clear_failure_propagated_in_header_reply: bool,
    pub reference_nokxcbe_supported: bool,
    pub reference_nokxcbe_response: &'static str,
    pub installed_binary_identity_verified: bool,
    pub physical_write_interpretation_validated: bool,
    pub phone_writes_enabled: bool,
}

/// Applies only to this exact, locally extracted binary. A matching UI version
/// or a JSON report cannot select this profile for an installed phone.
pub fn inspect_uefi(bytes: &[u8]) -> Result<Report> {
    let executable = super::uefi::extract_executable(bytes, "NokiaFlashApp")?;
    if hex::encode(Sha256::digest(&executable)) != FLASH_APP {
        return Err(invalid(
            "Unknown FlashApp binary; no write interpretation is assigned",
        ));
    }
    anchors(&executable)?;
    Ok(Report {
        reference_uefi_sha256: hex::encode(Sha256::digest(bytes)),
        reference_flash_app_sha256: FLASH_APP.into(),
        reference_firmware: "3051.50009.1424.0002",
        evidence: "offline ARM disassembly; see docs/spec-a-entry-code.md",
        end_relative_descriptors_skipped_in_payload_loop: true,
        header_import_clears_backup_gpt_sectors: 33,
        backup_clear_failure_propagated_in_header_reply: false,
        reference_nokxcbe_supported: false,
        reference_nokxcbe_response: "NOKU",
        installed_binary_identity_verified: false,
        physical_write_interpretation_validated: false,
        phone_writes_enabled: false,
    })
}

// File offsets equal RVAs in this particular PE (verified by the section table).
// These anchors make the documented interpretation reproducible; they are not
// pattern matching that accepts other binaries or a substitute for the full hash.
fn anchors(bytes: &[u8]) -> Result<()> {
    for (at, words) in [
        (0xbbac, &[0xe3510002u32, 0x0a00000c][..]), // access == 2 -> skip
        (0xbb70, &[0xe3510002, 0x0a00001b][..]),    // pending extent: same skip
        (0xe5c0, &[0xebffef0f, 0xe1b06000, 0x0bffec3a][..]), // import -> erase
        (
            0x9720,
            &[
                0xe59d0004, 0xe3a01000, 0xe58d4000, 0xe3a03021, 0xe2402021, 0xe1a00001, 0xeb000d01,
            ][..],
        ), // last 33
    ] {
        for (i, word) in words.iter().enumerate() {
            if crate::u32le(bytes, at + i * 4)? != *word {
                return Err(invalid("FlashApp analysis anchor differs"));
            }
        }
    }
    emergency_dispatch_anchors(bytes)
}

// Traced in the same exact executable: NOKX selects the extended dispatcher,
// which requires byte 4 == 'F'. NOKXCBE instead reaches the NOKU reply builder.
// No installed-firmware behavior or absence of every possible entry route is
// inferred from this one command path.
const EMERGENCY_DISPATCH_ANCHORS: &[(usize, &[u32])] = &[
    (0x12684, &[0xe5d40003, 0xe2400044, 0xe3500017, 0x308ff100]),
    (0x126e8, &[0xea000030]),             // 'X' jump-table slot -> 0x127b0
    (0x127b0, &[0xe1a00004, 0xebfff579]), // extended handler 0xfda0
    (0xfda4, &[0xe1a04000, 0xe5d00004]),
    (0xfdb8, &[0xe3500046, 0x0a00000b]), // byte 4 == 'F' -> 0xfdf0
    (0xfde0, &[0xe1a03007, 0xe1a02006, 0xe1a01005, 0xea00003b]),
    (0xfee0, &[0xe1a00004, 0xe8bd41f0, 0xea0007c4]),
    (
        0x11e50,
        &[
            0xe3a0004e, 0xe5c50000, 0xe3a0004f, 0xe5c50001, 0xe3a0004b, 0xe5c50002, 0xe3a00055,
            0xe5c50003, 0xe28dd014, 0xe3a00004, 0xe8bd8030,
        ],
    ),
];
fn emergency_dispatch_anchors(bytes: &[u8]) -> Result<()> {
    for &(at, words) in EMERGENCY_DISPATCH_ANCHORS {
        for (i, word) in words.iter().enumerate() {
            if crate::u32le(bytes, at + i * 4)? != *word {
                return Err(invalid("FlashApp emergency dispatch anchor differs"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_or_damaged_images_never_select_the_reference_profile() {
        let original = include_bytes!("../../../../tests/fixtures/spec-a/uefi.synthetic.bin");
        assert!(inspect_uefi(original).is_err());
        for n in [0, 1, 39, 255] {
            assert!(inspect_uefi(&original[..n]).is_err());
        }
        assert!(anchors(&[0; 128]).is_err());
    }

    #[test]
    fn emergency_dispatch_evidence_rejects_each_changed_or_truncated_anchor() {
        let mut code = vec![0; 0x127b8];
        for &(at, words) in EMERGENCY_DISPATCH_ANCHORS {
            for (i, word) in words.iter().enumerate() {
                code[at + i * 4..at + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        emergency_dispatch_anchors(&code).unwrap();
        for &(at, words) in EMERGENCY_DISPATCH_ANCHORS {
            for i in 0..words.len() {
                let offset = at + i * 4;
                code[offset] ^= 1;
                assert!(emergency_dispatch_anchors(&code).is_err());
                code[offset] ^= 1;
                assert!(emergency_dispatch_anchors(&code[..offset + 3]).is_err());
            }
        }
        // Synthetic anchors alone cannot select a known executable profile.
        assert!(inspect_uefi(&code).is_err());
    }
}
