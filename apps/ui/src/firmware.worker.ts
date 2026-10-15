import { initialize, wasm } from './engine';
import { partitionRange, safeNumber } from './format';
import type { FfuMetadata, Gpt, Inspection, WorkerRequest, WorkerReply } from './types';

const MAX_METADATA = 32 * 1024 * 1024;
const CHUNK = 1024 * 1024;
const MAX_BLOB = 64 * 1024 * 1024;
let cancelled = false;
let active = false;
function reply(value: WorkerReply) { self.postMessage(value); }
async function read(file: File, offset: number, length: number): Promise<Uint8Array> {
  safeNumber(offset); safeNumber(length); safeNumber(offset + length);
  if (length > MAX_METADATA || offset + length > file.size) throw new Error('Image is truncated or metadata exceeds 32 MiB');
  if (cancelled) throw new Error('Operation cancelled');
  return new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
}
function le32(data: Uint8Array, offset: number): number { return new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset, true); }
function le64(data: Uint8Array, offset: number): number { return safeNumber(new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, true)); }
function aligned(n: number, chunk: number): number { return safeNumber(Math.ceil(n / chunk) * chunk); }
async function disk(file: File, ffu: FfuMetadata | null, start: number, length: number): Promise<Uint8Array> {
  if (!ffu) return read(file, start, length);
  if (length > MAX_METADATA) throw new Error('Metadata exceeds the bounded reader limit');
  const segments: { output_offset: number; file_offset: number | null; length: number }[] = JSON.parse(wasm.ffu_segments_json(JSON.stringify(ffu), BigInt(safeNumber(start)), BigInt(safeNumber(length))));
  const output = new Uint8Array(length);
  for (const segment of segments) {
    if (segment.file_offset !== null) output.set(await read(file, safeNumber(segment.file_offset), safeNumber(segment.length)), safeNumber(segment.output_offset));
  }
  return output;
}
async function inspect(file: File): Promise<Inspection> {
  safeNumber(file.size);
  const first = await read(file, 0, Math.min(file.size, 512));
  if (first.length < 512) throw new Error('File is too short to contain a supported image');
  const text = (start: number, len: number) => new TextDecoder().decode(first.subarray(start, start + len));
  let ffu: FfuMetadata | null = null;
  let ffuHeaders: Uint8Array | null = null;
  if (text(4, 12) === 'SignedImage ') {
    const chunk = le32(first, 16) * 1024;
    if (chunk < 512 || chunk > 4 * 1024 * 1024 || (chunk & (chunk - 1)) !== 0) throw new Error('Invalid FFU chunk size');
    const security = aligned(le32(first, 0) + le32(first, 24) + le32(first, 28), chunk);
    if (security > MAX_METADATA) throw new Error('FFU security header exceeds 32 MiB');
    const image = await read(file, security, 24);
    const storeOffset = safeNumber(security + aligned(le32(image, 0) + le32(image, 16), chunk));
    if (storeOffset > MAX_METADATA) throw new Error('FFU image header exceeds 32 MiB');
    const store = await read(file, storeOffset, 248);
    const headerSize = storeOffset + aligned(248 + le32(store, 212) + le32(store, 220), chunk);
    ffuHeaders = await read(file, 0, headerSize);
    ffu = JSON.parse(wasm.ffu_headers_json(ffuHeaders, BigInt(file.size))) as FfuMetadata;
  }
  const headerAt = !ffu && text(0, 8) === 'EFI PART' ? 0 : 512;
  const header = !ffu && headerAt === 512 && file.size < 1024 ? new Uint8Array(512) : await disk(file, ffu, headerAt, 512);
  if (new TextDecoder().decode(header.subarray(0, 8)) === 'EFI PART') {
    const tableSize = safeNumber(le32(header, 80) * le32(header, 84));
    const tableAt = safeNumber(le64(header, 72) * 512 - (headerAt === 0 ? 512 : 0));
    const table = await disk(file, ffu, tableAt, tableSize);
    const gpt = JSON.parse(wasm.gpt_json(header, table)) as Gpt;
    for (const p of gpt.partitions) partitionRange(p.first_sector, p.last_sector);
    const report: Inspection = { format: ffu ? 'FFU' : 'GPT / raw disk image', size: file.size, ffu, gpt, filesystem: null, notes: ffu ? ['Structure and GPT CRCs checked. Signer trust and phone acceptance remain unverified.', 'End-relative FFU writes are metadata only; no disk capacity is assumed.'] : ['GPT header and entry CRCs checked.'] };
    if (ffu && ffuHeaders) {
      report.catalog = JSON.parse(wasm.ffu_catalog_json(ffuHeaders, BigInt(file.size)));
      try { report.firmware_version = await platVersion(file, ffu, gpt); }
      catch (error) { if (cancelled) throw error; report.firmware_version_error = String(error); }
    }
    return report;
  }
  if (ffu) throw new Error('FFU does not contain a valid primary GPT');
  return { format: 'Filesystem image', size: file.size, ffu: null, gpt: null, filesystem: JSON.parse(wasm.filesystem_json(first)), notes: [] };
}
async function platVersion(file: File, ffu: FfuMetadata, gpt: Gpt): Promise<string | null> {
  const matches = gpt.partitions.filter(p => p.name === 'PLAT');
  if (!matches.length) return null;
  if (matches.length !== 1) throw new Error('Ambiguous PLAT partition');
  const { start, length } = partitionRange(matches[0].first_sector, matches[0].last_sector);
  if (length > 64 * 1024 * 1024) throw new Error('PLAT scan exceeds 64 MiB');
  let carry = new Uint8Array(0);
  let version: string | null = null;
  for (let done = 0; done < length; done += 64 * 1024) {
    const block = await disk(file, ffu, start + done, Math.min(64 * 1024, length - done));
    const data = new Uint8Array(carry.length + block.length);
    data.set(carry); data.set(block, carry.length);
    const observed: string | null = JSON.parse(wasm.plat_version_json(data, done + block.length === length));
    if (observed !== null) {
      if (version !== null && version !== observed) throw new Error('Contradictory PLAT SWVERSION values');
      version = observed;
    }
    carry = data.slice(Math.max(0, data.length - 138));
  }
  return version;
}
self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  if (request.action === 'cancel') { cancelled = true; return; }
  if (active) { reply({ id: request.id, kind: 'error', error: 'Another operation is active' }); return; }
  active = true; cancelled = false;
  let writer: FileSystemWritableFileStream | undefined;
  try {
    await initialize();
    if (request.action === 'gpt_xml') {
      if (!request.gpt) throw new Error('No partition table selected');
      reply({ id: request.id, kind: 'result', result: wasm.gpt_xml(JSON.stringify(request.gpt)) });
    } else {
      if (!request.file) throw new Error('No local file selected');
      const report = await inspect(request.file);
      if (request.action === 'inspect') reply({ id: request.id, kind: 'result', result: report });
      else if (request.action === 'recovery_prepare') reply({ id: request.id, kind: 'result', result: JSON.parse(wasm.recovery_preparation_json(JSON.stringify(request.device ?? null), JSON.stringify(report))) });
      else {
        const matches = report.gpt?.partitions.filter(p => p.name === request.partition) ?? [];
        if (matches.length !== 1) throw new Error('Partition not found or ambiguous');
        const { start, length } = partitionRange(matches[0].first_sector, matches[0].last_sector);
        if (!request.handle && length > MAX_BLOB) throw new Error('Large exports require Chrome/Edge’s file picker or the desktop app. Browser download fallback is limited to 64 MiB.');
        if (request.handle) writer = await request.handle.createWritable();
        const parts: BlobPart[] = [];
        for (let done = 0; done < length; done += CHUNK) {
          if (cancelled) throw new Error('Operation cancelled');
          const data = await disk(request.file, report.ffu, start + done, Math.min(CHUNK, length - done));
          if (writer) await writer.write(data as Uint8Array<ArrayBuffer>);
          else parts.push(data as Uint8Array<ArrayBuffer>);
          reply({ id: request.id, kind: 'progress', completed: Math.min(done + CHUNK, length), total: length });
        }
        if (cancelled) throw new Error('Operation cancelled');
        if (writer) { await writer.close(); writer = undefined; }
        reply({ id: request.id, kind: 'result', result: request.handle ? 'Partition saved' : new Blob(parts, { type: 'application/octet-stream' }) });
      }
    }
  } catch (error) {
    if (writer) await writer.abort().catch(() => undefined);
    reply({ id: request.id, kind: 'error', error: String(error) });
  } finally { active = false; }
};
