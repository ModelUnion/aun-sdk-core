import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { compute1DHWrap, compute3DHWrap } from '../../src/v2/crypto/dh-path';

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

describe('1DH wrap_key - golden', () => {
  it('basic.json', async () => {
    const golden = JSON.parse(
      readFileSync(join(__dirname, 'golden', '1dh', 'basic.json'), 'utf-8'),
    ) as Record<string, string>;

    const senderPriv = b64(golden.sender_session_priv_b64);
    const recvIKPub = b64(golden.recv_ik_pub_der_b64);
    const salt = b64(golden.salt_b64);
    const expected = b64(golden.expected_wrap_key_b64);

    const wrap = await compute1DHWrap(senderPriv, recvIKPub, salt);

    expect(wrap.length).toBe(32);
    expect(eqBytes(wrap, expected)).toBe(true);
  });
});

describe('3DH wrap_key - golden', () => {
  it('basic.json', async () => {
    const golden = JSON.parse(
      readFileSync(join(__dirname, 'golden', '3dh', 'basic.json'), 'utf-8'),
    ) as Record<string, string>;

    const senderSessionPriv = b64(golden.sender_session_priv_b64);
    const senderMasterPriv = b64(golden.sender_master_priv_b64);
    const recvIKPub = b64(golden.recv_ik_pub_der_b64);
    const recvSPKPub = b64(golden.recv_spk_pub_der_b64);
    const salt = b64(golden.salt_b64);
    const expected = b64(golden.expected_wrap_key_b64);

    const wrap = await compute3DHWrap(
      senderSessionPriv,
      senderMasterPriv,
      recvIKPub,
      recvSPKPub,
      salt,
    );

    expect(wrap.length).toBe(32);
    expect(eqBytes(wrap, expected)).toBe(true);
  });
});
