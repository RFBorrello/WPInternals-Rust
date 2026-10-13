import type { CapabilityReport, DeviceIdentity, ImportedArtifact, Inspection, ModelProfile, ProbeResult, RecoveryPreparation, WorkerReply, WorkerRequest } from './types';
import { initialize, wasm } from './engine';

export const desktop = Boolean(window.__TAURI_INTERNALS__);
let sequence = 0;
let worker: Worker | undefined;
const pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void; progress?: (done: number, total: number) => void }>();
function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('./firmware.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (event: MessageEvent<WorkerReply>) => {
      const response = event.data; const task = pending.get(response.id); if (!task) return;
      if (response.kind === 'progress') { task.progress?.(response.completed ?? 0, response.total ?? 0); return; }
      pending.delete(response.id);
      if (response.kind === 'error') task.reject(new Error(response.error)); else task.resolve(response.result);
    };
    worker.onerror = () => { for (const p of pending.values()) p.reject(new Error('Firmware worker failed. Reload the app before retrying.')); pending.clear(); worker?.terminate(); worker = undefined; };
  }
  return worker;
}
function request<T>(task: Omit<WorkerRequest, 'id'>, progress?: (done: number, total: number) => void): Promise<T> {
  return new Promise((resolve, reject) => { const id = ++sequence; pending.set(id, { resolve: value => resolve(value as T), reject, progress }); getWorker().postMessage({ ...task, id }); });
}
async function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> { const api = await import('@tauri-apps/api/core'); return api.invoke<T>(command, args); }
export async function startup(): Promise<{ models: ModelProfile[]; capabilities: CapabilityReport }> {
  if (desktop) return invoke('startup');
  await initialize(); return { models: JSON.parse(wasm.models_json()), capabilities: JSON.parse(wasm.capabilities_json('null')) };
}
export async function discover(): Promise<DeviceIdentity[]> { return desktop ? invoke('devices') : JSON.parse(await wasm.devices_json()); }
export async function connect(): Promise<DeviceIdentity | null> { return desktop ? (await discover())[0] ?? null : JSON.parse(await wasm.request_device_json()); }
export async function probe(device: DeviceIdentity): Promise<ProbeResult> { return desktop ? invoke('probe', { id: device.id }) : JSON.parse(await wasm.probe_json(device.id)); }
export async function capabilities(device: DeviceIdentity | null): Promise<CapabilityReport> { return desktop ? invoke('capabilities', { device }) : JSON.parse(wasm.capabilities_json(JSON.stringify(device))); }
export async function importBrowserFile(file: File): Promise<ImportedArtifact> { return { name: file.name, file, inspection: await request<Inspection>({ action: 'inspect', file }) }; }
export async function prepareRecovery(artifact: ImportedArtifact, device: DeviceIdentity | null, progress: (done: number, total: number) => void): Promise<RecoveryPreparation> {
  if (desktop && artifact.path) {
    const { listen } = await import('@tauri-apps/api/event');
    const unlisten = await listen<{ completed_bytes: number; total_bytes: number }>('operation-progress', event => progress(event.payload.completed_bytes, event.payload.total_bytes));
    try { return await invoke('prepare_recovery', { input: artifact.path, device }); } finally { unlisten(); }
  }
  if (!artifact.file) throw new Error('No local file selected');
  return request({ action: 'recovery_prepare', file: artifact.file, device }, progress);
}
export async function importDesktopFile(): Promise<ImportedArtifact | null> {
  const { open } = await import('@tauri-apps/plugin-dialog');
  const path = await open({ multiple: false, directory: false, filters: [{ name: 'Firmware and images', extensions: ['ffu', 'bin', 'img'] }] });
  if (!path || Array.isArray(path)) return null;
  return { name: path.split(/[\\/]/).pop() ?? path, path, inspection: await invoke<Inspection>('inspect_file', { path }) };
}
export async function extract(artifact: ImportedArtifact, partition: string, progress: (done: number, total: number) => void): Promise<void> {
  if (desktop && artifact.path) {
    const { save } = await import('@tauri-apps/plugin-dialog'); const output = await save({ defaultPath: `${partition}.img` }); if (!output) return;
    const { listen } = await import('@tauri-apps/api/event');
    const unlisten = await listen<{ completed_bytes: number; total_bytes: number }>('operation-progress', event => progress(event.payload.completed_bytes, event.payload.total_bytes));
    try { await invoke('extract_partition', { input: artifact.path, partition, output }); } finally { unlisten(); }
    return;
  }
  if (!artifact.file) throw new Error('No local file selected');
  // The picker is called before awaiting anything so its user gesture is preserved.
  const handle = window.showSaveFilePicker ? await window.showSaveFilePicker({ suggestedName: `${partition}.img` }) : undefined;
  const result = await request<string | Blob>({ action: 'extract', file: artifact.file, partition, handle }, progress);
  if (result instanceof Blob) download(result, `${partition}.img`);
}
export async function exportGpt(artifact: ImportedArtifact): Promise<void> {
  if (desktop && artifact.path) {
    const { save } = await import('@tauri-apps/plugin-dialog'); const output = await save({ defaultPath: 'Partitions.xml' });
    if (output) await invoke('convert_gpt', { input: artifact.path, output }); return;
  }
  if (!artifact.inspection.gpt) throw new Error('No GPT selected');
  const xml = await request<string>({ action: 'gpt_xml', gpt: artifact.inspection.gpt }); download(new Blob([xml], { type: 'application/xml' }), 'Partitions.xml');
}
export function cancel(): void { if (desktop) void invoke('cancel_operation'); else worker?.postMessage({ id: 0, action: 'cancel' }); }
export function download(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000);
}
