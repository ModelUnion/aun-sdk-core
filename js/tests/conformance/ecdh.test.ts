import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import {
  ecdhComputeShared,
  generateP256Keypair,
  privateToPublicDer,
} from '../../src/v2/crypto/ecdh';

/** base64 解码（jsdom 提供 atob） */
function b64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const GOLDEN_DIR = join(__dirname, 'golden', 'ecdh');

describe('ECDH P-256 - golden vectors', () => {
  const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.json'));
  expect(files.length).toBeGreaterThanOrEqual(2);

  for (const f of files) {
    it(`golden: ${f}`, async () => {
      const golden = JSON.parse(
        readFileSync(join(GOLDEN_DIR, f), 'utf-8'),
      ) as Record<string, string>;

      const privKeyName = Object.keys(golden).find((k) => k.endsWith('_priv_b64'));
      const pubKeyName = Object.keys(golden).find((k) => k.endsWith('_pub_der_b64'));
      if (!privKeyName || !pubKeyName) {
        throw new Error(`golden vector missing priv/pub field: ${Object.keys(golden)}`);
      }

      const priv = b64(golden[privKeyName]);
      const pub = b64(golden[pubKeyName]);
      const expected = b64(golden.expected_shared_b64);

      const shared = await ecdhComputeShared(priv, pub);

      expect(shared.length).toBe(32);
      expect(shared.length).toBe(expected.length);
      for (let i = 0; i < expected.length; i++) {
        if (shared[i] !== expected[i]) {
          expect.fail(
            `byte mismatch at ${i}: got 0x${shared[i].toString(16)} ` +
              `expected 0x${expected[i].toString(16)}`,
          );
        }
      }
    });
  }
});

describe('ECDH P-256 - symmetry & keypair', () => {
  it('A_priv x B_pub = B_priv x A_pub', async () => {
    const [aPriv, aPub] = await generateP256Keypair();
    const [bPriv, bPub] = await generateP256Keypair();

    expect(aPriv.length).toBe(32);
    expect(bPriv.length).toBe(32);
    expect(aPub.byteLength).toBeGreaterThan(0);
    expect(bPub.byteLength).toBeGreaterThan(0);

    const s1 = await ecdhComputeShared(aPriv, bPub);
    const s2 = await ecdhComputeShared(bPriv, aPub);

    expect(s1.length).toBe(32);
    expect(Array.from(s1)).toEqual(Array.from(s2));
  });

  it('privateToPublicDer matches generated pub', async () => {
    const [priv, pub] = await generateP256Keypair();
    const recomputed = await privateToPublicDer(priv);
    // SPKI 编码确定，应该字节级一致
    expect(Array.from(recomputed)).toEqual(Array.from(pub));
  });
});
