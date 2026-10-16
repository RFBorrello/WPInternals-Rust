export type DeviceMode = 'normal' | 'flash' | 'boot_manager' | 'phone_info' | 'mass_storage' | 'emergency' | 'unknown';
export type SupportStatus = 'verified' | 'experimental' | 'unsupported' | 'unknown';
export interface DeviceIdentity {
  id: string; vendor_id: number; product_id: number; manufacturer: string | null;
  product: string | null; serial: string | null; model: string | null; variant: string | null;
  firmware: string | null; platform_id: string | null;
  family: 'spec_a' | 'spec_b' | 'wp7' | 'unknown'; mode: DeviceMode;
  interfaces: { number: number; class: number; subclass: number; protocol: number }[];
}
export interface Capability { operation: string; status: SupportStatus; executable: boolean; reason: string; requirements: string[] }
export interface CapabilityReport { device_id: string | null; host: string; transport: string; capabilities: Capability[] }
export interface ModelProfile { model: string; variants: string[]; family: string; hardware_validated: boolean }
export interface StorageDiscovery { host_supported: boolean; hardware_validated: boolean; candidates: { disk_number: number; model: string; size: number; sector_size: number; offline: boolean; read_only: boolean; blockers: string[] }[]; message: string }
export interface Mapping { disk_access: number; disk_chunk: number; chunk_count: number; payload_chunk: number }
export interface FfuMetadata {
  platform_id: string; chunk_size: number; security_size: number; image_size: number; store_size: number;
  header_size: number; payload_size: number; total_size: number; hash_algorithm: number;
  hash_table_offset: number; hash_table_size: number; catalog_size: number; manifest: string; mappings: Mapping[];
}
export interface Partition { name: string; type_guid: string; guid: string; first_sector: number; last_sector: number; attributes: string }
export interface Gpt { disk_guid: string; current_lba: number; backup_lba: number; first_usable_sector: number; last_usable_sector: number; entry_count: number; entry_size: number; partitions: Partition[] }
export interface FilesystemInfo { kind: string; bytes_per_sector: number; sectors_per_cluster: number; total_sectors: number; volume_serial: string }
export interface CatalogCheck { status: 'valid' | 'invalid' | 'unsupported' | 'missing' | 'unverified'; message: string }
export interface SignerAssessment { issuer: string; not_before: string; not_after: string; checked_at_unix_seconds: number | null; validity: CatalogCheck; key_usage: CatalogCheck; extended_key_usage: CatalogCheck; extensions: CatalogCheck; chain_signatures: CatalogCheck; chain_certificate_sha256: string[]; trust_anchor: CatalogCheck; revocation: CatalogCheck }
export interface CatalogReport { signature: CatalogCheck; hash_table_binding: CatalogCheck; signer_trust: CatalogCheck; signer_subject: string | null; signer_certificate_sha256: string | null; catalog_sha256: string; membership_hash_algorithm: string | null; signer_assessment?: SignerAssessment | null; issuer_evidence?: { source: string; file_sha256: string | null; certificate_sha256: string | null; check: CatalogCheck } | null }
export interface TargetingInfo { hardware_variant: string; manufacturer_model: string | null; manufacturer: string | null; model_name: string | null; source: string }
export interface Inspection { format: string; size: number; ffu: FfuMetadata | null; gpt: Gpt | null; filesystem: FilesystemInfo | null; notes: string[]; catalog?: CatalogReport | null; firmware_version?: string | null; firmware_version_error?: string | null; firmware_version_sources?: string[]; device_targeting?: TargetingInfo | null; device_targeting_error?: string | null }
export interface ProbeResult { device: DeviceIdentity; info: Record<string, unknown> | null; normal: { manufacturer_model: string; product_code: string; firmware: string } | null; firmware: string | null }
export interface OperationEvent { sequence: number; operation: string; state: string; completed_bytes: number; total_bytes: number; message: string }
export interface ImportedArtifact { name: string; file?: File; path?: string; inspection: Inspection }
export interface RecoveryPreparation {
  plan: { operation: 'stock_flash'; executable: boolean; blockers: string[]; steps: string[]; artifacts: { name: string; sha256: string }[]; device: DeviceIdentity | null };
  checks: { key: string; label: string; status: 'passed' | 'failed' | 'missing' | 'unverified'; message: string }[];
}
export interface WorkerRequest { id: number; action: 'inspect' | 'extract' | 'gpt_xml' | 'cancel' | 'recovery_prepare' | 'spec_a_prepare' | 'spec_a_assemble'; component?: 'uefi' | 'efiesp' | 'package'; file?: File; device?: DeviceIdentity | null; partition?: string; handle?: FileSystemFileHandle; gpt?: Gpt; sbl3?: File; loaders?: File[]; donor?: File }
export interface AssemblyReport { original_sha256: string; resulting_sha256: string; size: number; phone_writes_enabled: false; preserved_other_files: boolean; signature_removed?: boolean; bcd?: { created_elements: number; changed_values: number; preserved_other_entries: boolean } }
export interface PackageReport { size: number; resulting_sha256: string; manifest_sha256: string; integrity_verified: boolean; phone_writes_enabled: false; manifest: { kind: string; source_ffu_sha256: string; originals_are_installed_backup: false; backup_gpt_captured: false; phone_writes_enabled: false; execution_blockers: string[]; files: { path: string; size: number; sha256: string }[] } }
export interface WorkerReply { id: number; kind: 'result' | 'error' | 'progress'; result?: Inspection | RecoveryPreparation | SpecAPreparation | AssemblyReport | PackageReport | string | Blob; error?: string; completed?: number; total?: number; stage?: string }
export interface BootReport { name: string; size: number; sha256: string; image: { header_kind: string; image_offset: number; code_size: number; root_certificate_sha256: string; certificate_sha256: string[] } | null; patch: { status: string; match_count: number; offset: number | null; expected: string; replacement: string } | null; error: string | null }
export interface EfiespAssessment { path: string; size: number | null; sha256: string | null; status: string; catalog_target_descriptions: string[]; prepared_copy_sha256: string | null; bcd_present: boolean; bcd_editing_implemented: boolean }
export interface SpecAPreparation { upstream_revision: string; platform_id: string; stock: BootReport[]; external_sbl3: BootReport | null; external_sbl3_fits: boolean | null; loaders: { name: string; input_sha256: string; decoded: BootReport | null; v1_marker_present: boolean; matches_stock_sbl1_root: boolean; error: string | null }[]; sbl1_prerequisites?: { loader_table_size: number; payload_generated: false } | null; sbl1_error?: string | null; uefi?: { file_count: number; targets: { name: string; patches: { label: string; offset: number; expected: string; replacement: string }[] }[]; rebuilt_image: false } | null; uefi_error?: string | null; efiesp?: EfiespAssessment | null; efiesp_error?: string | null; donor_efiesp?: EfiespAssessment | null; donor_error?: string | null; phone_writes_enabled: false; blockers: string[] }
export interface SpecAImport { name: string; file?: File; path?: string }
declare global {
  // Frontend globals only; reconnection identifiers remain in React memory.
  interface Window { __TAURI_INTERNALS__?: unknown; showSaveFilePicker?: (options: { suggestedName: string }) => Promise<FileSystemFileHandle>; }
}

export interface ModeTransitionPreparation {
  plan: { operation: 'switch_mode'; executable: boolean; blockers: string[]; steps: string[]; device: DeviceIdentity | null };
  source: DeviceMode; target: DeviceMode; route: string | null; requires_disconnect: boolean;
}
export interface ReconnectReport {
  status: 'correlated' | 'mismatch' | 'unverified'; expected_mode: DeviceMode; observed_mode: DeviceMode;
  checks: RecoveryPreparation['checks']; recovery_authorized: boolean;
}
