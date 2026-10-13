import { describe, expect, it } from 'vitest';
import { bytes, partitionRange, safeNumber } from './format';
describe('artifact ranges', () => {
  it('preserves sector-inclusive partition lengths', () => { expect(partitionRange(34,37)).toEqual({ start:17408,length:2048 }); });
  it('rejects reversed or inexact ranges', () => { expect(() => partitionRange(20,10)).toThrow(); expect(() => safeNumber(9007199254740993n)).toThrow(); expect(() => partitionRange(Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER)).toThrow(); });
  it('formats large firmware sizes', () => { expect(bytes(1024 ** 3)).toBe('1.00 GiB'); expect(bytes(-1)).toBe('—'); });
});
