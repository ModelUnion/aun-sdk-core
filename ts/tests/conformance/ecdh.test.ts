import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ecdhComputeShared, generateP256Keypair, privateToPublicDer } from '../../src/v2/crypto/ecdh.js';

/**
 * ECDH P-256 golden vector 一致性测试。
 *
 * Golden 向量源自 Python SDK，确保 ECDH 共享秘密（X 坐标 32B）跨语言字节级一致。
 * 字段命名约定：
 *   *_priv_b64        — 私钥标量（base64）
 *   *_pub_der_b64     — 对端公钥 DER SPKI（base64）
 *   expected_shared_b64 — 预期共享秘密 32B（base64）
 */

const GOLDEN_DIR = join(__dirname, 'golden', 'ecdh');

function b64(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, 'base64'));
}

describe('ECDH golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));

  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(f.replace('.json', ''), () => {
      const golden = JSON.parse(readFileSync(join(GOLDEN_DIR, f), 'utf-8')) as Record<string, string>;

      const privKey = Object.keys(golden).find((k) => k.endsWith('_priv_b64'));
      const pubKey = Object.keys(golden).find((k) => k.endsWith('_pub_der_b64'));
      if (!privKey || !pubKey) {
        throw new Error(`golden vector ${f} missing *_priv_b64 or *_pub_der_b64 field`);
      }

      const priv = b64(golden[privKey]);
      const pub = b64(golden[pubKey]);
      const expected = b64(golden.expected_shared_b64);

      const shared = ecdhComputeShared(priv, pub);

      expect(shared.length).toBe(32);
      expect(Buffer.from(shared).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
    });
  }
});

describe('ECDH symmetry', () => {
  it('A_priv x B_pub == B_priv x A_pub', () => {
    const [aPriv, aPub] = generateP256Keypair();
    const [bPriv, bPub] = generateP256Keypair();

    const s1 = ecdhComputeShared(aPriv, bPub);
    const s2 = ecdhComputeShared(bPriv, aPub);

    expect(s1.length).toBe(32);
    expect(Buffer.from(s1).toString('hex')).toBe(Buffer.from(s2).toString('hex'));
  });

  it('privateToPublicDer matches generateP256Keypair pubkey', () => {
    const [priv, pub] = generateP256Keypair();
    const derived = privateToPublicDer(priv);
    expect(Buffer.from(derived).toString('hex')).toBe(Buffer.from(pub).toString('hex'));
  });
});
