import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { hkdfSha256 } from '../../src/v2/crypto/hkdf';

function b64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

const GOLDEN_DIR = join(__dirname, 'golden', 'hkdf');

describe('HKDF-SHA256 - golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(3);

  for (const f of files) {
    it(`golden: ${f}`, async () => {
      const golden = JSON.parse(
        readFileSync(join(GOLDEN_DIR, f), 'utf-8'),
      ) as Record<string, unknown>;

      // ikm
      let ikm: Uint8Array;
      if (typeof golden.ikm_b64 === 'string') ikm = b64(golden.ikm_b64);
      else if (typeof golden.ikm_hex === 'string') ikm = hex(golden.ikm_hex);
      else throw new Error('missing ikm');

      // salt
      let salt: Uint8Array;
      if (typeof golden.salt_b64 === 'string') salt = b64(golden.salt_b64);
      else if (typeof golden.salt_hex === 'string') salt = hex(golden.salt_hex);
      else salt = new Uint8Array(0);

      // info
      let info: Uint8Array;
      if (typeof golden.info === 'string') info = new TextEncoder().encode(golden.info);
      else if (typeof golden.info_b64 === 'string') info = b64(golden.info_b64 as string);
      else if (typeof golden.info_hex === 'string') info = hex(golden.info_hex as string);
      else throw new Error('missing info');

      const length = golden.length as number;
      const expected = b64(golden.expected_okm_b64 as string);

      const okm = await hkdfSha256(ikm, salt, info, length);

      expect(okm.length).toBe(length);
      expect(okm.length).toBe(expected.length);
      for (let i = 0; i < expected.length; i++) {
        if (okm[i] !== expected[i]) {
          expect.fail(
            `byte mismatch at ${i}: got 0x${okm[i].toString(16)} expected 0x${expected[i].toString(16)}`,
          );
        }
      }
    });
  }
});
