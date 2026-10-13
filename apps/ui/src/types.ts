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
export interface Mapping { disk_access: number; disk_chunk: number; chunk_count: number; payload_chunk: number }
export interface FfuMetadata {
  platform_id: string; chunk_size: number; security_size: number; image_size: number; store_size: number;
  header_size: number; payload_size: number; total_size: number; hash_algorithm: number;
  hash_table_offset: number; hash_table_size: number; catalog_size: number; manifest: string; mappings: Mapping[];
}
export interface Partition { name: string; type_guid: string; guid: string; first_sector: number; last_sector: number; attributes: string }
export interface Gpt { disk_guid: string; current_lba: number; backup_lba: number; first_usable_sector: number; last_usable_sector: number; entry_count: number; entry_size: number; partitions: Partition[] }
export interface FilesystemInfo { kind: string; bytes_per_sector: number; sectors_per_cluster: number; total_sectors: number; volume_serial: string }
export interface Inspection { format: string; size: number; ffu: FfuMetadata | null; gpt: Gpt | null; filesystem: FilesystemInfo | null; notes: string[] }
export interface ProbeResult { device: DeviceIdentity; info: Record<string, unknown> | null; normal: { manufacturer_model: string; product_code: string; firmware: string } | null; firmware: string | null }
export interface OperationEvent { sequence: number; operation: string; state: string; completed_bytes: number; total_bytes: number; message: string }
export interface ImportedArtifact { name: string; file?: File; path?: string; inspection: Inspection }
export interface WorkerRequest { id: number; action: 'inspect' | 'extract' | 'gpt_xml' | 'cancel'; file?: File; partition?: string; handle?: FileSystemFileHandle; gpt?: Gpt }
export interface WorkerReply { id: number; kind: 'result' | 'error' | 'progress'; result?: Inspection | string | Blob; error?: string; completed?: number; total?: number }
declare global {
  interface Window { __TAURI_INTERNALS__?: unknown; showSaveFilePicker?: (options: { suggestedName: string }) => Promise<FileSystemFileHandle>; }
}
