import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ecdsaSignRaw, ecdsaVerifyRaw } from '../../src/v2/crypto/ecdsa.js';

/**
 * ECDSA-SHA256 RAW（RFC 6979）golden vector 一致性测试。
 *
 * 字段：
 *  private_key_b64       — P-256 私钥标量
 *  public_key_der_b64    — DER SPKI 公钥
 *  message_b64           — 待签名消息
 *  expected_signature_b64 — 64 字节 RAW 签名
 *
 * RFC 6979 deterministic 决定了同私钥+同消息 → 同签名，可逐字节比较。
 */

const GOLDEN_DIR = join(__dirname, 'golden', 'ecdsa');

function b64(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, 'base64'));
}

describe('ECDSA-SHA256 RAW (RFC 6979) golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(f.replace('.json', ''), () => {
      const g = JSON.parse(readFileSync(join(GOLDEN_DIR, f), 'utf-8')) as Record<string, string>;
      const priv = b64(g.private_key_b64);
      const pub = b64(g.public_key_der_b64);
      const msg = b64(g.message_b64);
      const expectedSig = b64(g.expected_signature_b64);

      const sig = ecdsaSignRaw(priv, msg);
      expect(sig.length).toBe(64);
      // 字节级一致（依赖 RFC 6979 deterministic）
      expect(Buffer.from(sig).toString('hex')).toBe(Buffer.from(expectedSig).toString('hex'));

      // 双向：用 expected 验签也通过
      expect(ecdsaVerifyRaw(pub, expectedSig, msg)).toBe(true);
      // 我们生成的也通过
      expect(ecdsaVerifyRaw(pub, sig, msg)).toBe(true);
    });
  }
});

describe('ECDSA verify rejects tampered inputs', () => {
  it('tampered message → verify false', () => {
    const golden = JSON.parse(
      readFileSync(join(GOLDEN_DIR, 'basic_sign.json'), 'utf-8'),
    ) as Record<string, string>;
    const pub = b64(golden.public_key_der_b64);
    const sig = b64(golden.expected_signature_b64);
    const tampered = new TextEncoder().encode('hello aun v2 TAMPER');
    expect(ecdsaVerifyRaw(pub, sig, tampered)).toBe(false);
  });

  it('signature length != 64 → verify false', () => {
    const golden = JSON.parse(
      readFileSync(join(GOLDEN_DIR, 'basic_sign.json'), 'utf-8'),
    ) as Record<string, string>;
    const pub = b64(golden.public_key_der_b64);
    const msg = b64(golden.message_b64);
    expect(ecdsaVerifyRaw(pub, new Uint8Array(63), msg)).toBe(false);
    expect(ecdsaVerifyRaw(pub, new Uint8Array(65), msg)).toBe(false);
  });
});
