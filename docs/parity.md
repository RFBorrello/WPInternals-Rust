# Feature parity against WPInternals 2.9.2

Baseline: tag 2.9.2, commit `d8fd0aa516b16dc094df0422a3adc525af005c29`.
Later upstream changes are not implicitly accepted or enabled.

| Capability | Implementation | Hardware availability |
| --- | --- | --- |
| Device discovery | Native nusb, browser selection, native serial candidates | Experimental enumeration |
| Flash application information | Bounded NOKV parser; native NOKV/FVER and browser NOKV probe | Experimental read-only; not validated |
| Normal-mode information | Native and browser read-only Nokia Care Suite JSON-RPC model/product/firmware queries; interface 3 only | One successful native RM-875 / 3051.50009.1451.1003 / Windows ARM64 session, plus matching user-reported browser identification (browser version unknown); remains experimental |
| Mode switching | Replay routes and shared read-only previews/correlation; original CLI-only RM-875 harness with serial/port binding | First live attempt entered Flash then stopped because Flash lacked a USB serial; manual return to Normal verified. Original serial-only experiment remains blocked; the separate public-ID experiment has evidence below. Production switching remains blocked |
| Public-ID inspection | Dedicated Normal ReadPublicId and bounded Flash terminal-response codecs; CLI presence report | Normal query and live Flash parsing succeeded on native Windows ARM64 RM-875; no public-ID values exported |
| Public-ID mode validation | Separate CLI-only experiment; command-handle identity and port revalidation, exact Flash profile, no FVER query | One complete native Windows ARM64 RM-875 / firmware 3051.50009.1451.1003 cycle matched Normal/Flash/returning Normal IDs with unchanged firmware. Normal USB arrived about 35 seconds after NOKR, identity confirmed about 3 seconds later. Repeatability and other profiles remain unvalidated; no production capability promoted |
| Legacy FFU inspection | Single-store v1 headers, manifest and mapping bounds | Offline only |
| Firmware integrity | SHA-256 chunk hashes; portable RSA/SHA-256 CTL signature and signed hash-table binding, bounded PLAT scan and MainOS registry/DSM version fallback | Native/browser reports agree on one real RM-875 catalog and MainOS version. Older image build is flagged; OEM trust/device acceptance unverified. Recovery remains blocked |
| Signer / applicability assessment | Local-time dates, signing KU/EKU, bounded catalog/image-local RSA/SHA-256 certificate-chain checks; MainOS OEMSettings variant matching | Limited policy profile only. Real RM-875 matches; image-local production PK completes internal signatures. No independently authenticated OEM anchor, revocation, region/product mapping or write authorization |
| Partition extraction | Streaming FFU primary mappings and raw images | Local files only |
| GPT conversion | CRC checks, bounds, UTF-16 names, Partitions.xml output | Local files only |
| FAT image file operations | Directory listing, extraction, same-length patching on new copies | CLI; real RM-875 EFIESP directory read; patching not verified on phone firmware |
| NTFS image file operations | Boot inspection, directory listing, file extraction; patched index addressing | CLI reads tested on one RM-875 MainOS; kernel hash matches upstream catalog; no writes or compressed/encrypted streams |
| Root byte patches | Upstream hash-pinned catalog, reverse and obsolete-patch handling | Extracted files / copied FAT images only |
| Stock FFU flashing/recovery | v1/v2 streaming workflow restricted to replay, preflight and interrupted-ack tests | Blocked; authenticated native executor and hardware validation pending |
| Recovery preparation | Shared advisory checklist; native and browser full-file/chunk verification; browser uses bounded incremental WASM hashing with progress/cancellation; separate signature, binding, trust and version checks | Offline only; missing version metadata and unvalidated downgrades are explicit; exports cannot authorize execution |
| Read-only reconnection correlation | Fresh information comparison with a remembered baseline; serial/variant/firmware/mode checks and redacted reports | One user-confirmed RM-875 normal-mode browser unplug/replug cycle on Windows ARM64; exact browser version unknown; no Flash transition or write authorization |
| Spec A / Spec B unlocking | Separate profile families only | Not implemented; blocked |
| Bootloader restore/relock | Not implemented | Blocked |
| Root installation/removal | Offline target-file patching only | Phone workflow blocked |
| Phone partition/full backup | Bounded sector-copy engine, atomic output and failure tests; Windows experimental read-only mass-storage CLI with identity, offline/read-only/exclusive access and primary/backup GPT guards | General backup capability remains blocked; experimental Windows CLI requires already exposed storage. No live backup or macOS/Linux raw adapter validation yet |
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
