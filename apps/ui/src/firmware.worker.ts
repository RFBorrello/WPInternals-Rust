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
  const bytes = new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
  if (cancelled) throw new Error('Operation cancelled');
  if (bytes.length !== length) throw new Error('Image read was truncated; reselect the local file');
  return bytes;
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
async function inspect(file: File, captureHeaders?: (headers: Uint8Array) => void): Promise<Inspection> {
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
    captureHeaders?.(ffuHeaders);
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
      report.catalog = JSON.parse(wasm.ffu_catalog_json(ffuHeaders, BigInt(file.size), BigInt(Math.floor(Date.now() / 1000))));
      try {
        await new Promise(resolve => setTimeout(resolve, 0));
        if (cancelled) throw new Error('Operation cancelled');
        if (typeof FileReaderSync === 'undefined') throw new Error('Image issuer lookup requires worker FileReaderSync; use the desktop app');
        const reader = new FileReaderSync();
        const slice = (offset: number, length: number) => {
          safeNumber(offset); safeNumber(length); safeNumber(offset + length);
          if (length > 64 * 1024 || offset + length > file.size) throw new Error('Issuer read exceeds bounded file slice');
          return new Uint8Array(reader.readAsArrayBuffer(file.slice(offset, offset + length)));
        };
        report.catalog = JSON.parse(wasm.ffu_catalog_image_json(JSON.stringify(ffu), JSON.stringify(gpt), BigInt(file.size), slice, BigInt(Math.floor(Date.now() / 1000))));
        await new Promise(resolve => setTimeout(resolve, 0));
        if (cancelled) throw new Error('Operation cancelled');
      } catch (error) { if (cancelled) throw error; report.notes.push(`Image issuer lookup unavailable: ${String(error)}`); }
      try {
        report.firmware_version = await platVersion(file, ffu, gpt);
        report.firmware_version_sources = report.firmware_version ? ['PLAT SWVERSION'] : [];
        if (!report.firmware_version) {
          // Yield before the bounded synchronous NTFS batch so queued cancellation
          // is observed. This worker never sends image contents through the UI.
          await new Promise(resolve => setTimeout(resolve, 0));
          if (cancelled) throw new Error('Operation cancelled');
          if (typeof FileReaderSync === 'undefined') throw new Error('MainOS inspection requires worker FileReaderSync; use the desktop app');
          const reader = new FileReaderSync();
          const slice = (offset: number, length: number) => {
            safeNumber(offset); safeNumber(length); safeNumber(offset + length);
            if (length > 64 * 1024 || offset + length > file.size) throw new Error('MainOS read exceeds bounded file slice');
            return new Uint8Array(reader.readAsArrayBuffer(file.slice(offset, offset + length)));
          };
          const evidence: { version: string; sources: string[] } | null = JSON.parse(wasm.mainos_firmware_json(JSON.stringify(ffu), JSON.stringify(gpt), BigInt(file.size), slice));
          await new Promise(resolve => setTimeout(resolve, 0));
          if (cancelled) throw new Error('Operation cancelled');
          report.firmware_version = evidence?.version ?? null;
          report.firmware_version_sources = evidence?.sources ?? [];
        }
      }
      catch (error) { if (cancelled) throw error; report.firmware_version_error = String(error); }
      try {
        await new Promise(resolve => setTimeout(resolve, 0));
        if (cancelled) throw new Error('Operation cancelled');
        if (typeof FileReaderSync === 'undefined') throw new Error('MainOS targeting inspection requires worker FileReaderSync; use the desktop app');
        const reader = new FileReaderSync();
        const slice = (offset: number, length: number) => {
          safeNumber(offset); safeNumber(length); safeNumber(offset + length);
          if (length > 64 * 1024 || offset + length > file.size) throw new Error('Targeting read exceeds bounded file slice');
          return new Uint8Array(reader.readAsArrayBuffer(file.slice(offset, offset + length)));
        };
        report.device_targeting = JSON.parse(wasm.mainos_targeting_json(JSON.stringify(ffu), JSON.stringify(gpt), BigInt(file.size), slice));
        await new Promise(resolve => setTimeout(resolve, 0));
        if (cancelled) throw new Error('Operation cancelled');
      } catch (error) { if (cancelled) throw error; report.device_targeting_error = String(error); }
    }
    return report;
  }
  if (ffu) throw new Error('FFU does not contain a valid primary GPT');
  return { format: 'Filesystem image', size: file.size, ffu: null, gpt: null, filesystem: JSON.parse(wasm.filesystem_json(first)), notes: [] };
}
async function prepare(file: File, report: Inspection, headers: Uint8Array | undefined, request: WorkerRequest) {
  if (!report.ffu || !headers) return JSON.parse(wasm.recovery_preparation_json(JSON.stringify(request.device ?? null), JSON.stringify(report)));
  const verifier = new wasm.BrowserFfuVerifier(headers, BigInt(file.size));
  try {
    reply({ id: request.id, kind: 'progress', completed: 0, total: file.size });
    let lastYield = performance.now();
    for (let done = 0; done < file.size; done += CHUNK) {
      const data = await read(file, done, Math.min(CHUNK, file.size - done));
      verifier.update(data);
      const completed = done + data.length;
      if (performance.now() - lastYield >= 50 || completed === file.size) {
        reply({ id: request.id, kind: 'progress', completed, total: file.size });
        // A task boundary delivers cancellation even when local slice promises
        // resolve immediately. Incomplete state is freed and never exported.
        await new Promise(resolve => setTimeout(resolve, 0));
        if (cancelled) throw new Error('Operation cancelled');
        lastYield = performance.now();
      }
    }
    if (cancelled) throw new Error('Operation cancelled');
    return JSON.parse(verifier.finish_preparation_json(JSON.stringify(request.device ?? null), JSON.stringify(report), file.name));
  } finally { verifier.free(); }
}
async function prepareSpecA(file: File, report: Inspection, request: WorkerRequest) {
  if (!report.ffu || !report.gpt) throw new Error('Spec A preparation requires a supported local FFU');
  if (typeof FileReaderSync === 'undefined') throw new Error('Offline boot-image checks require worker FileReaderSync; use the desktop app');
  if ((request.loaders?.length ?? 0) > 32) throw new Error('Select at most 32 loader files');
  const session = new wasm.BrowserSpecAPreparation();
  try {
    if (request.sbl3) session.set_sbl3(request.sbl3.name, await read(request.sbl3, 0, Math.min(request.sbl3.size, 4 * CHUNK + 1)));
    for (const loader of request.loaders ?? []) {
      if (loader.size > 512 * 1024) throw new Error('Loader import exceeds 512 KiB');
      session.add_loader(loader.name, await read(loader, 0, loader.size));
      await new Promise(resolve => setTimeout(resolve, 0));
      if (cancelled) throw new Error('Operation cancelled');
    }
    const reader = new FileReaderSync();
    const slice = (offset: number, length: number) => {
      safeNumber(offset); safeNumber(length); safeNumber(offset + length);
      if (length > 64 * 1024 || offset + length > file.size) throw new Error('Boot-image read exceeds bounded file slice');
      return new Uint8Array(reader.readAsArrayBuffer(file.slice(offset, offset + length)));
    };
    let result = JSON.parse(session.finish_json(JSON.stringify(report.ffu), JSON.stringify(report.gpt), BigInt(file.size), slice));
    if (request.donor) {
      const donorFile = request.donor;
      const donor = await inspect(donorFile);
      if (!donor.ffu || !donor.gpt) throw new Error('Donor must be a supported FFU image');
      const donorSlice = (offset: number, length: number) => {
        safeNumber(offset); safeNumber(length); safeNumber(offset + length);
        if (length > 64 * 1024 || offset + length > donorFile.size) throw new Error('Donor read exceeds bounded file slice');
        return new Uint8Array(reader.readAsArrayBuffer(donorFile.slice(offset, offset + length)));
      };
      result = JSON.parse(wasm.spec_a_donor_json(JSON.stringify(result), JSON.stringify(donor.ffu), JSON.stringify(donor.gpt), BigInt(donorFile.size), donorSlice));
    }
    await new Promise(resolve => setTimeout(resolve, 0));
    if (cancelled) throw new Error('Operation cancelled');
    return result;
  } finally { session.free(); }
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
// OPFS scratch files stay in this worker. Only bounded chunks enter WASM or the
// destination stream; neither multi-GB FFUs nor partition arrays reach the UI.
interface SyncFile {
  read(buffer: Uint8Array, options: { at: number }): number;
  write(buffer: Uint8Array, options: { at: number }): number;
  flush(): void; close(): void;
}
async function assembleSpecA(request: WorkerRequest) {
  const file = request.file;
  if (!file || !request.handle) throw new Error('Select local firmware and an output file');
  const ensureEmpty = async () => {
    if ((await request.handle!.getFile()).size !== 0) throw new Error('Output already contains data; choose a new empty file.');
  };
  await ensureEmpty();
  if (request.component === 'package') return buildSpecAPackage(request);
  const report = await inspect(file);
  if (!report.ffu || !report.gpt) throw new Error('Offline assembly requires a supported FFU');
  const sync = new FileReaderSync();
  const slice = (offset: number, length: number) => {
    safeNumber(offset); safeNumber(length);
    if (length > 65536 || offset + length > file.size) throw new Error('Assembly read exceeds file bounds');
    return new Uint8Array(sync.readAsArrayBuffer(file.slice(offset, offset + length)));
  };
  if (request.component === 'uefi') {
    const parts = report.gpt.partitions.filter(p => p.name === 'UEFI');
    if (parts.length !== 1) throw new Error('UEFI partition missing or ambiguous');
    const { start, length } = partitionRange(parts[0].first_sector, parts[0].last_sector);
    if (length > 4 * CHUNK) throw new Error('UEFI exceeds 4 MiB');
    const rebuilt = wasm.rebuild_uefi(await disk(file, report.ffu, start, length));
    try {
      await new Promise(resolve => setTimeout(resolve, 0));
      if (cancelled) throw new Error('Operation cancelled');
      await ensureEmpty();
      const writer = await request.handle.createWritable();
      try { await writer.write(rebuilt.bytes() as Uint8Array<ArrayBuffer>); if (cancelled) throw new Error('Operation cancelled'); await writer.close(); }
      catch (error) { await writer.abort().catch(() => undefined); throw error; }
      return JSON.parse(rebuilt.report_json());
    } finally { rebuilt.free(); }
  }
  if (request.component !== 'efiesp' || !request.donor) throw new Error('Select a donor FFU for EFIESP assembly');
  if (!navigator.storage?.getDirectory) throw new Error('Browser scratch storage is unavailable; use the desktop app.');
  const donor = await inspect(request.donor);
  if (!donor.ffu || !donor.gpt) throw new Error('Donor must be a supported FFU');
  const donorFile = request.donor;
  const boot = wasm.spec_a_donor_boot(JSON.stringify(donor.ffu), JSON.stringify(donor.gpt), BigInt(donorFile.size), (at: number, n: number) => {
    if (n > 65536 || at < 0 || at + n > donorFile.size) throw new Error('Donor read exceeds bounds');
    return new Uint8Array(sync.readAsArrayBuffer(donorFile.slice(at, at + n)));
  });
  const parts = report.gpt.partitions.filter(p => p.name === 'EFIESP');
  if (parts.length !== 1) throw new Error('EFIESP partition missing or ambiguous');
  const { start, length } = partitionRange(parts[0].first_sector, parts[0].last_sector);
  if (length > 128 * CHUNK) throw new Error('EFIESP exceeds 128 MiB');
  const segments: { output_offset: number; file_offset: number | null; length: number }[] = JSON.parse(wasm.ffu_segments_json(JSON.stringify(report.ffu), BigInt(start), BigInt(length)));
  const source = (at: number, n: number) => {
    if (n > 65536 || at < 0 || at + n > length) throw new Error('EFIESP read exceeds bounds');
    const bytes = new Uint8Array(n);
    for (const segment of segments) {
      const first = Math.max(at, segment.output_offset), end = Math.min(at + n, segment.output_offset + segment.length);
      if (end > first && segment.file_offset !== null) bytes.set(slice(segment.file_offset + first - segment.output_offset, end - first), first - at);
    }
    return bytes;
  };
  const directory = await navigator.storage.getDirectory();
  const name = `wpi-assembly-${crypto.randomUUID()}`;
  let scratch: SyncFile | undefined;
  try {
    const handle = await directory.getFileHandle(name, { create: true });
    const create = (handle as FileSystemFileHandle & { createSyncAccessHandle?: () => Promise<SyncFile> }).createSyncAccessHandle;
    if (!create) throw new Error('Browser scratch access is unavailable; use the desktop app.');
    scratch = await create.call(handle);
    const readScratch = (at: number, n: number) => {
      const bytes = new Uint8Array(n);
      if (scratch!.read(bytes, { at }) !== n) throw new Error('Scratch read truncated');
      return bytes;
    };
    const result = JSON.parse(wasm.assemble_efiesp_json(BigInt(length), source, readScratch,
      (at: number, bytes: Uint8Array) => scratch!.write(bytes, { at }), boot));
    scratch.flush(); scratch.close(); scratch = undefined;
    await new Promise(resolve => setTimeout(resolve, 0));
    if (cancelled) throw new Error('Operation cancelled');
    const output = await handle.getFile();
    await ensureEmpty();
    const writer = await request.handle.createWritable();
    try {
      for (let at = 0; at < output.size; at += CHUNK) {
        if (cancelled) throw new Error('Operation cancelled');
        await writer.write(await output.slice(at, at + CHUNK).arrayBuffer());
        reply({ id: request.id, kind: 'progress', completed: Math.min(at + CHUNK, output.size), total: output.size });
        await new Promise(resolve => setTimeout(resolve, 0));
      }
      if (cancelled) throw new Error('Operation cancelled');
      await writer.close();
    } catch (error) { await writer.abort().catch(() => undefined); throw error; }
    return result;
  } finally { scratch?.close(); await directory.removeEntry(name).catch(() => undefined); }
}
async function buildSpecAPackage(request: WorkerRequest) {
  const file = request.file, donorFile = request.donor, output = request.handle;
  if (!file || !donorFile || !output) throw new Error('Select stock and donor firmware and a new ZIP destination');
  if (!navigator.storage?.getDirectory) throw new Error('Browser scratch storage is unavailable; use the desktop app.');
  if (typeof FileReaderSync === 'undefined') throw new Error('Browser file access is unavailable; use the desktop app.');
  const donor = await inspect(donorFile);
  if (!donor.ffu || !donor.gpt) throw new Error('Donor must be a supported FFU');
  const sync = new FileReaderSync();
  const slice = (source: File, at: number, n: number) => {
    safeNumber(at); safeNumber(n); safeNumber(at + n);
    if (at < 0 || n > 65536 || at + n > source.size) throw new Error('Package source read exceeds bounded file slice');
    return new Uint8Array(sync.readAsArrayBuffer(source.slice(at, at + n)));
  };
  const boot = wasm.spec_a_donor_boot(JSON.stringify(donor.ffu), JSON.stringify(donor.gpt), BigInt(donorFile.size), (at: number, n: number) => slice(donorFile, at, n));
  const directory = await navigator.storage.getDirectory();
  const builder = new wasm.BrowserSpecAPackage();
  const names = [`wpi-package-esp-${crypto.randomUUID()}`, `wpi-package-zip-${crypto.randomUUID()}`];
  const scratch: SyncFile[] = [];
  try {
    if (request.sbl3) {
      if (request.sbl3.size > 4 * CHUNK) throw new Error('SBL3 exceeds 4 MiB');
      builder.set_sbl3(await read(request.sbl3, 0, request.sbl3.size));
    }
    for (const loader of request.loaders ?? []) {
      if (loader.size > 512 * 1024) throw new Error('Loader exceeds 512 KiB');
      builder.add_loader(await read(loader, 0, loader.size));
    }
    const handles: FileSystemFileHandle[] = [];
    for (const name of names) {
      const handle = await directory.getFileHandle(name, { create: true }); handles.push(handle);
      const create = (handle as FileSystemFileHandle & { createSyncAccessHandle?: () => Promise<SyncFile> }).createSyncAccessHandle;
      if (!create) throw new Error('Browser scratch access is unavailable; use the desktop app.');
      scratch.push(await create.call(handle));
    }
    const reader = (which: number) => (at: number, n: number) => {
      if (n > 65536) throw new Error('Scratch read exceeds 64 KiB');
      const bytes = new Uint8Array(n);
      if (scratch[which].read(bytes, { at }) !== n) throw new Error('Scratch read truncated');
      return bytes;
    };
    const writer = (which: number) => (at: number, bytes: Uint8Array) => {
      if (bytes.length > 65536) throw new Error('Scratch write exceeds 64 KiB');
      return scratch[which].write(bytes, { at });
    };
    await new Promise(resolve => setTimeout(resolve, 0));
    if (cancelled) throw new Error('Operation cancelled');
    let lastStage = '', lastProgress = 0;
    const report = JSON.parse(builder.finish_json(BigInt(file.size), [(at: number, n: number) => slice(file, at, n), reader(0), writer(0), reader(1), writer(1)], boot,
      (stage: string, done: number, total: number) => {
        if (stage !== lastStage || done === total || performance.now() - lastProgress >= 100) {
          reply({ id: request.id, kind: 'progress', stage, completed: done, total }); lastStage = stage; lastProgress = performance.now();
        }
        return !cancelled;
      }));
    for (const handle of scratch) { handle.flush(); handle.close(); }
    scratch.length = 0;
    await new Promise(resolve => setTimeout(resolve, 0));
    if (cancelled) throw new Error('Operation cancelled');
    if ((await output.getFile()).size !== 0) throw new Error('Output already contains data; choose a new empty file.');
    const zip = await handles[1].getFile(), destination = await output.createWritable();
    try {
      for (let at = 0; at < zip.size; at += CHUNK) {
        if (cancelled) throw new Error('Operation cancelled');
        await destination.write(await zip.slice(at, at + CHUNK).arrayBuffer());
        reply({ id: request.id, kind: 'progress', stage: 'Save verified package', completed: Math.min(at + CHUNK, zip.size), total: zip.size });
        await new Promise(resolve => setTimeout(resolve, 0));
      }
      if (cancelled) throw new Error('Operation cancelled');
      await destination.close();
    } catch (error) { await destination.abort().catch(() => undefined); throw error; }
    return report;
  } finally {
    builder.free();
    for (const handle of scratch) { try { handle.close(); } catch { /* Continue cleanup after failed storage I/O. */ } }
    for (const name of names) await directory.removeEntry(name).catch(() => undefined);
  }
}
self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  if (request.action === 'cancel') { cancelled = true; return; }
  if (active) { reply({ id: request.id, kind: 'error', error: 'Another operation is active' }); return; }
  active = true; cancelled = false;
  let writer: FileSystemWritableFileStream | undefined;
  try {
    await initialize();
    if (request.action === 'spec_a_assemble') {
      reply({ id: request.id, kind: 'result', result: await assembleSpecA(request) });
    } else if (request.action === 'gpt_xml') {
      if (!request.gpt) throw new Error('No partition table selected');
      reply({ id: request.id, kind: 'result', result: wasm.gpt_xml(JSON.stringify(request.gpt)) });
    } else {
      if (!request.file) throw new Error('No local file selected');
      let headers: Uint8Array | undefined;
      const report = await inspect(request.file, value => { headers = value; });
      if (request.action === 'inspect') reply({ id: request.id, kind: 'result', result: report });
      else if (request.action === 'recovery_prepare') reply({ id: request.id, kind: 'result', result: await prepare(request.file, report, headers, request) });
      else if (request.action === 'spec_a_prepare') reply({ id: request.id, kind: 'result', result: await prepareSpecA(request.file, report, request) });
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
