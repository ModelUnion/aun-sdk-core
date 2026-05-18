import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { aesGcmEncrypt, aesGcmDecrypt } from '../../src/v2/crypto/aead.js';

/**
 * AES-256-GCM golden vector 一致性测试。
 *
 * 输入支持 hex / b64 命名风格。
 */

const GOLDEN_DIR = join(__dirname, 'golden', 'aead');

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

describe('AES-256-GCM golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(f.replace('.json', ''), () => {
      const g = JSON.parse(readFileSync(join(GOLDEN_DIR, f), 'utf-8')) as Record<string, unknown>;

      // basic_encrypt 用 plaintext_b64+aad_b64
      // wrap_master_key 字段名稍异：wrap_key_b64+wrap_nonce_b64+master_key_b64+expected_wrapped_key_b64，无 aad
      let key: Uint8Array;
      let nonce: Uint8Array;
      let plaintext: Uint8Array;
      let aad: Uint8Array;
      let expectedCt: Uint8Array;
      let expectedTag: Uint8Array | null = null;
      let expectedCombined: Uint8Array | null = null;

      if (typeof g.wrap_key_b64 === 'string') {
        // wrap_master_key 场景：ct||tag 一体
        key = fromHexOrB64(g, 'wrap_key');
        nonce = fromHexOrB64(g, 'wrap_nonce');
        plaintext = fromHexOrB64(g, 'master_key');
        aad = new Uint8Array(0);
        expectedCombined = Uint8Array.from(
          Buffer.from(g.expected_wrapped_key_b64 as string, 'base64'),
        );
        expectedCt = expectedCombined.subarray(0, expectedCombined.length - 16);
        expectedTag = expectedCombined.subarray(expectedCombined.length - 16);
      } else {
        key = fromHexOrB64(g, 'key');
        nonce = fromHexOrB64(g, 'nonce');
        plaintext = fromHexOrB64(g, 'plaintext');
        aad = fromHexOrB64(g, 'aad');
        expectedCt = Uint8Array.from(Buffer.from(g.expected_ciphertext_b64 as string, 'base64'));
        expectedTag = Uint8Array.from(Buffer.from(g.expected_tag_b64 as string, 'base64'));
      }

      const { ciphertext, tag } = aesGcmEncrypt(key, nonce, plaintext, aad);
      expect(Buffer.from(ciphertext).toString('hex')).toBe(Buffer.from(expectedCt).toString('hex'));
      expect(Buffer.from(tag).toString('hex')).toBe(Buffer.from(expectedTag!).toString('hex'));

      // 解密回环
      const dec = aesGcmDecrypt(key, nonce, ciphertext, tag, aad);
      expect(Buffer.from(dec).toString('hex')).toBe(Buffer.from(plaintext).toString('hex'));
    });
  }
});

describe('AES-256-GCM tampering rejected', () => {
  it('flipping ciphertext bit causes decrypt failure', () => {
    const key = new Uint8Array(32).fill(0x01);
    const nonce = new Uint8Array(12).fill(0x02);
    const pt = new TextEncoder().encode('hello');
    const aad = new TextEncoder().encode('aad');
    const { ciphertext, tag } = aesGcmEncrypt(key, nonce, pt, aad);
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0x01;
    expect(() => aesGcmDecrypt(key, nonce, tampered, tag, aad)).toThrow();
  });
});
