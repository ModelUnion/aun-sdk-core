import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { hkdfSha256 } from '../../src/v2/crypto/hkdf.js';

/**
 * HKDF-SHA256 golden vector 一致性测试。
 *
 * 输入字段可以是 hex（*_hex）或 base64（*_b64）；info 可以是 ascii 字符串或 hex。
 */

const GOLDEN_DIR = join(__dirname, 'golden', 'hkdf');

function fromHexOrB64(rec: Record<string, unknown>, baseName: string): Uint8Array {
  const hexKey = baseName + '_hex';
  const b64Key = baseName + '_b64';
  if (typeof rec[hexKey] === 'string') {
    return Uint8Array.from(Buffer.from(rec[hexKey] as string, 'hex'));
  }
  if (typeof rec[b64Key] === 'string') {
    return Uint8Array.from(Buffer.from(rec[b64Key] as string, 'base64'));
  }
  throw new Error(`golden missing ${hexKey} or ${b64Key}`);
}

function readInfo(rec: Record<string, unknown>): Uint8Array {
  if (typeof rec.info_hex === 'string') {
    return Uint8Array.from(Buffer.from(rec.info_hex as string, 'hex'));
  }
  if (typeof rec.info === 'string') {
    return new TextEncoder().encode(rec.info as string);
  }
  throw new Error('golden missing info or info_hex');
}

describe('HKDF-SHA256 golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(3);

  for (const f of files) {
    it(f.replace('.json', ''), () => {
      const golden = JSON.parse(readFileSync(join(GOLDEN_DIR, f), 'utf-8')) as Record<string, unknown>;
      const ikm = fromHexOrB64(golden, 'ikm');
      const salt = fromHexOrB64(golden, 'salt');
      const info = readInfo(golden);
      const length = golden.length as number;
      const expected = Uint8Array.from(Buffer.from(golden.expected_okm_b64 as string, 'base64'));

      const okm = hkdfSha256(ikm, salt, info, length);

      expect(okm.length).toBe(length);
      expect(Buffer.from(okm).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
    });
  }
});

describe('HKDF empty salt = HashLen zeros', () => {
  it('empty salt path matches explicit 32-byte zero salt', () => {
    const ikm = new Uint8Array(16).fill(0xab);
    const info = new TextEncoder().encode('test');
    const a = hkdfSha256(ikm, new Uint8Array(0), info, 32);
    const b = hkdfSha256(ikm, new Uint8Array(32), info, 32);
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });
});
