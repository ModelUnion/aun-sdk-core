import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { aesGcmEncrypt, aesGcmDecrypt } from '../../src/v2/crypto/aead';

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

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const GOLDEN_DIR = join(__dirname, 'golden', 'aead');

describe('AES-256-GCM - golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(`golden: ${f}`, async () => {
      const golden = JSON.parse(
        readFileSync(join(GOLDEN_DIR, f), 'utf-8'),
      ) as Record<string, string>;

      // key
      const key =
        typeof golden.key_b64 === 'string'
          ? b64(golden.key_b64)
          : typeof golden.key_hex === 'string'
            ? hex(golden.key_hex)
            : typeof golden.wrap_key_b64 === 'string'
              ? b64(golden.wrap_key_b64)
              : (() => {
                  throw new Error('missing key field');
                })();

      // nonce
      const nonce =
        typeof golden.nonce_b64 === 'string'
          ? b64(golden.nonce_b64)
          : typeof golden.nonce_hex === 'string'
            ? hex(golden.nonce_hex)
            : typeof golden.wrap_nonce_b64 === 'string'
              ? b64(golden.wrap_nonce_b64)
              : (() => {
                  throw new Error('missing nonce field');
                })();

      // plaintext
      const plaintext =
        typeof golden.plaintext_b64 === 'string'
          ? b64(golden.plaintext_b64)
          : typeof golden.master_key_b64 === 'string'
            ? b64(golden.master_key_b64)
            : (() => {
                throw new Error('missing plaintext field');
              })();

      // aad（可选）
      const aad =
        typeof golden.aad_b64 === 'string' ? b64(golden.aad_b64) : new Uint8Array(0);

      // 加密：可能用 wrapped_key（ciphertext||tag 拼接）或拆开的 ciphertext+tag
      const enc = await aesGcmEncrypt(key, nonce, plaintext, aad);

      if (typeof golden.expected_wrapped_key_b64 === 'string') {
        const expectedWrapped = b64(golden.expected_wrapped_key_b64);
        const got = new Uint8Array(enc.ciphertext.length + enc.tag.length);
        got.set(enc.ciphertext, 0);
        got.set(enc.tag, enc.ciphertext.length);
        expect(got.length).toBe(expectedWrapped.length);
        expect(eqBytes(got, expectedWrapped)).toBe(true);
      } else {
        const expectedCt = b64(golden.expected_ciphertext_b64);
        const expectedTag = b64(golden.expected_tag_b64);
        expect(eqBytes(enc.ciphertext, expectedCt)).toBe(true);
        expect(eqBytes(enc.tag, expectedTag)).toBe(true);
      }

      // 反向：解密回明文
      const decrypted = await aesGcmDecrypt(key, nonce, enc.ciphertext, enc.tag, aad);
      expect(eqBytes(decrypted, plaintext)).toBe(true);
    });
  }
});

describe('AES-256-GCM - tamper detection', () => {
  it('tampered tag → decrypt throws', async () => {
    const key = new Uint8Array(32).fill(0x01);
    const nonce = new Uint8Array(12).fill(0x02);
    const pt = new TextEncoder().encode('hello aun');
    const aad = new TextEncoder().encode('aad');
    const { ciphertext, tag } = await aesGcmEncrypt(key, nonce, pt, aad);
    const badTag = new Uint8Array(tag);
    badTag[0] ^= 0xff;
    await expect(aesGcmDecrypt(key, nonce, ciphertext, badTag, aad)).rejects.toThrow();
  });

  it('tampered aad → decrypt throws', async () => {
    const key = new Uint8Array(32).fill(0x01);
    const nonce = new Uint8Array(12).fill(0x02);
    const pt = new TextEncoder().encode('hello aun');
    const aad = new TextEncoder().encode('aad');
    const { ciphertext, tag } = await aesGcmEncrypt(key, nonce, pt, aad);
    const wrongAad = new TextEncoder().encode('AAD');
    await expect(aesGcmDecrypt(key, nonce, ciphertext, tag, wrongAad)).rejects.toThrow();
  });
});
