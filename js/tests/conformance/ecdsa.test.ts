import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { ecdsaSignRaw, ecdsaVerifyRaw } from '../../src/v2/crypto/ecdsa';

function b64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

const GOLDEN_DIR = join(__dirname, 'golden', 'ecdsa');

describe('ECDSA P-256 SHA-256 RAW - golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(`golden: ${f}`, async () => {
      const golden = JSON.parse(
        readFileSync(join(GOLDEN_DIR, f), 'utf-8'),
      ) as Record<string, string>;

      const priv = b64(golden.private_key_b64);
      const pubDer = b64(golden.public_key_der_b64);
      const msg = b64(golden.message_b64);
      const expectedSig = b64(golden.expected_signature_b64);

      // RFC 6979 deterministic：sign 必须字节一致
      const sig = await ecdsaSignRaw(priv, msg);
      expect(sig.length).toBe(64);
      expect(sig.length).toBe(expectedSig.length);
      expect(eqBytes(sig, expectedSig)).toBe(true);

      // 验签自家签名
      const ok = await ecdsaVerifyRaw(pubDer, sig, msg);
      expect(ok).toBe(true);

      // 验签 golden 期望签名
      const ok2 = await ecdsaVerifyRaw(pubDer, expectedSig, msg);
      expect(ok2).toBe(true);
    });
  }
});

describe('ECDSA - tamper detection', () => {
  it('tampered signature → verify=false', async () => {
    const priv = new Uint8Array(32).fill(0x42);
    // 用 noble 计算公钥来构造 SPKI（避免再引入 crypto.subtle 生成）
    const { p256 } = await import('@noble/curves/nist.js');
    const pubRaw = p256.getPublicKey(priv, false) as Uint8Array; // 65B uncompressed

    // SPKI = SEQ { SEQ { OID id-ecPublicKey, OID prime256v1 }, BIT STRING <pubRaw> }
    // 用 WebCrypto 导出标准 SPKI 即可
    const x = pubRaw.subarray(1, 33);
    const y = pubRaw.subarray(33, 65);
    function bytesToB64Url(b: Uint8Array): string {
      let bin = '';
      for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    const pubKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: bytesToB64Url(x), y: bytesToB64Url(y), ext: true },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const pubDer = new Uint8Array(await crypto.subtle.exportKey('spki', pubKey));

    const msg = new TextEncoder().encode('hello aun v2');
    const sig = await ecdsaSignRaw(priv, msg);

    expect(await ecdsaVerifyRaw(pubDer, sig, msg)).toBe(true);

    const badSig = new Uint8Array(sig);
    badSig[0] ^= 0xff;
    expect(await ecdsaVerifyRaw(pubDer, badSig, msg)).toBe(false);

    const badMsg = new TextEncoder().encode('hello aun v3');
    expect(await ecdsaVerifyRaw(pubDer, sig, badMsg)).toBe(false);
  });
});
