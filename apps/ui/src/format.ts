export function bytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 1024) return `${value} B`;
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4);
  return `${(value / 1024 ** unit).toFixed(unit === 1 ? 0 : 2)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`;
}
export function label(value: string): string { return value.replaceAll('_', ' ').replace(/\b\w/g, c => c.toUpperCase()); }
export function hexId(value: number): string { return value.toString(16).padStart(4, '0').toUpperCase(); }
export function safeNumber(value: number | bigint): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('Image range exceeds the browser’s exact integer limit. Use the desktop app.');
  return n;
}
export function partitionRange(first: number, last: number): { start: number; length: number } {
  safeNumber(first); safeNumber(last);
  if (last < first) throw new Error('Invalid partition range');
  return { start: safeNumber(first * 512), length: safeNumber((last - first + 1) * 512) };
}
