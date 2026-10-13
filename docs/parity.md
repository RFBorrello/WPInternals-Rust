# Feature parity against WPInternals 2.9.2

Baseline: tag 2.9.2, commit `d8fd0aa516b16dc094df0422a3adc525af005c29`.
Later upstream changes are not implicitly accepted or enabled.

| Capability | Implementation | Hardware availability |
| --- | --- | --- |
| Device discovery | Native nusb, browser selection, native serial candidates | Experimental enumeration |
| Flash application information | Bounded NOKV parser; native NOKV/FVER and browser NOKV probe | Experimental read-only; not validated |
| Normal-mode information | Native and browser read-only Nokia Care Suite JSON-RPC model/product/firmware queries; interface 3 only | One successful native RM-875 / 3051.50009.1451.1003 / Windows ARM64 session, plus matching user-reported browser identification (browser version unknown); remains experimental |
| Mode switching | Version-specific routes, fresh source preflight and bounded reconnection/cancellation workflow in replay; advisory previews and read-only correlation checks in all frontends | Live switching blocked; native executor and hardware validation pending |
| Legacy FFU inspection | Single-store v1 headers, manifest and mapping bounds | Offline only |
| Firmware integrity | SHA-256 chunk hashes | Catalog authenticity not verified |
| Partition extraction | Streaming FFU primary mappings and raw images | Local files only |
| GPT conversion | CRC checks, bounds, UTF-16 names, Partitions.xml output | Local files only |
| FAT image file operations | Directory listing, extraction, same-length patching on new copies | CLI; real RM-875 EFIESP directory read; patching not verified on phone firmware |
| NTFS image file operations | Boot inspection, directory listing, file extraction; patched index addressing | CLI reads tested on one RM-875 MainOS; kernel hash matches upstream catalog; no writes or compressed/encrypted streams |
| Root byte patches | Upstream hash-pinned catalog, reverse and obsolete-patch handling | Extracted files / copied FAT images only |
| Stock FFU flashing/recovery | v1/v2 streaming workflow restricted to replay, preflight and interrupted-ack tests | Blocked; authenticated native executor and hardware validation pending |
| Recovery preparation | Shared advisory checklist; native full-file/chunk verification, browser header preview | Offline only; exports cannot authorize execution |
| Spec A / Spec B unlocking | Separate profile families only | Not implemented; blocked |
| Bootloader restore/relock | Not implemented | Blocked |
| Root installation/removal | Offline target-file patching only | Phone workflow blocked |
| Phone partition/full backup | Bounded sector-copy engine restricted to replay data; atomic output and failure tests | Blocked; native storage adapters, exclusive access and hardware validation pending |
| Phone restore/custom flashing | Not implemented | Blocked |
| Emergency recovery | HDLC codecs, Sahara HELLO parser; no programmer transfer | Enumeration only |
| Firmware/loader downloads | Not implemented | Local import required |
| WP7 devices | Research profiles only | No device protocol or unlock implementation |
| Windows Phone SDK/test app | Not ported | Separate phone-side project |

## Remaining implementation order

1. Capture read-only 1020/730 descriptors, protocol responses and firmware-format fixtures.
2. Complete stock recovery and native storage identity/exclusive-access adapters;
   test replay failure paths before hardware writes.
3. Implement metadata-aware NTFS patch writes and image rebuild validation.
4. Port the full Spec A and Spec B resource/preflight/unlock/restore state machines
   from the pinned reference. Never substitute one family’s workflow for another.
5. Add root installation, partition/full backup/restore, and custom flashing.
6. Expand by variant/firmware/host/transport evidence; investigate WP7 separately.

Every unimplemented workflow remains blocked in Rust, not only hidden in the UI.
