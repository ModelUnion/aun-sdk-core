import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compute1DHWrap, compute3DHWrap } from '../../src/v2/crypto/dh-path.js';

/**
 * 1DH / 3DH wrap_key 派生 golden vector 一致性测试。
 *
 * 1DH: HKDF(ECDH(senderSession, recvIK), salt, "AUN-V2-1DH", 32)
 * 3DH: HKDF(DH1||DH2||DH3, salt, "AUN-V2-3DH", 32)
 */

const GOLDEN_1DH = join(__dirname, 'golden', '1dh', 'basic.json');
const GOLDEN_3DH = join(__dirname, 'golden', '3dh', 'basic.json');

function b64(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, 'base64'));
}

describe('1DH wrap_key golden', () => {
  it('basic', () => {
    const g = JSON.parse(readFileSync(GOLDEN_1DH, 'utf-8')) as Record<string, string>;
    const senderSessionPriv = b64(g.sender_session_priv_b64);
    const recvIKPub = b64(g.recv_ik_pub_der_b64);
    const salt = b64(g.salt_b64);
    const expected = b64(g.expected_wrap_key_b64);

    const out = compute1DHWrap(senderSessionPriv, recvIKPub, salt);
    expect(out.length).toBe(32);
    expect(Buffer.from(out).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
  });
});

describe('3DH wrap_key golden', () => {
  it('basic', () => {
    const g = JSON.parse(readFileSync(GOLDEN_3DH, 'utf-8')) as Record<string, string>;
    const senderSessionPriv = b64(g.sender_session_priv_b64);
    const senderMasterPriv = b64(g.sender_master_priv_b64);
    const recvIKPub = b64(g.recv_ik_pub_der_b64);
    const recvSPKPub = b64(g.recv_spk_pub_der_b64);
    const salt = b64(g.salt_b64);
    const expected = b64(g.expected_wrap_key_b64);

    const out = compute3DHWrap(senderSessionPriv, senderMasterPriv, recvIKPub, recvSPKPub, salt);
    expect(out.length).toBe(32);
    expect(Buffer.from(out).toString('hex')).toBe(Buffer.from(expected).toString('hex'));
  });
});
