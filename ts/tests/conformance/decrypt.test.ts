import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decryptMessage } from '../../src/v2/e2ee/decrypt.js';

/**
 * Python ↔ TS 互通解密：
 *   - 加载 Python 生成的 golden envelope（位于 ts/tests/conformance/golden/envelope/
 *     或 python/tests/conformance/golden/envelope/，优先 TS 本地副本）
 *   - 用 decryption_inputs 中的接收方密钥解密
 *   - 比对 expected_payload
 *
 * 用例覆盖：
 *   - p2p_3dh.json：P2P 3DH 路径
 *   - p2p_1dh.json：P2P 1DH 路径
 *   - p2p_multi.json：多接收方（Bob 3DH + Alice2 1DH）
 *   - group_3dh_1dh.json：群（Bob 3DH + Carol 1DH）
 */

const TS_GOLDEN = join(__dirname, 'golden', 'envelope');
const PY_GOLDEN = join(
  __dirname,
  '..',
  '..',
  '..',
  'python',
  'tests',
  'conformance',
  'golden',
  'envelope',
);

interface DecryptionInputs {
  self_aid: string;
  self_device_id: string;
  self_ik_priv_b64: string;
  self_spk_priv_b64: string | null;
  sender_pub_der_b64: string;
}

function loadVector(file: string): Record<string, unknown> {
  // 优先 TS 本地副本，否则回退 Python 源副本
  for (const dir of [TS_GOLDEN, PY_GOLDEN]) {
    const p = join(dir, file);
    try {
      const raw = readFileSync(p, 'utf-8');
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      /* try next */
    }
  }
  throw new Error(`golden envelope vector not found: ${file}`);
}

function b64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

function runVector(file: string, inputsKey: string): void {
  const v = loadVector(file);
  const inputs = v[inputsKey] as DecryptionInputs;
  const decrypted = decryptMessage(
    v.envelope as Record<string, unknown>,
    inputs.self_aid,
    inputs.self_device_id,
    b64(inputs.self_ik_priv_b64),
    inputs.self_spk_priv_b64 ? b64(inputs.self_spk_priv_b64) : undefined,
    b64(inputs.sender_pub_der_b64),
  );
  expect(decrypted).toEqual(v.expected_payload);
}

describe('Python ↔ TS interop: P2P', () => {
  it('p2p_3dh.json', () => runVector('p2p_3dh.json', 'decryption_inputs'));
  it('p2p_1dh.json', () => runVector('p2p_1dh.json', 'decryption_inputs'));
  it('p2p_multi.json (Bob 3DH)', () =>
    runVector('p2p_multi.json', 'decryption_inputs_bob'));
  it('p2p_multi.json (Alice2 1DH)', () =>
    runVector('p2p_multi.json', 'decryption_inputs_alice2'));
});

describe('decryptMessage error classification', () => {
  it('3DH row 缺少本地 SPK 私钥 → spk_missing', () => {
    const v = loadVector('p2p_3dh.json');
    const inputs = v.decryption_inputs as DecryptionInputs;
    expect(() => decryptMessage(
      v.envelope as Record<string, unknown>,
      inputs.self_aid,
      inputs.self_device_id,
      b64(inputs.self_ik_priv_b64),
      undefined,
      b64(inputs.sender_pub_der_b64),
    )).toThrow(/spk_missing/);
  });

  it('3DH row 使用错误 SPK 私钥 → wrap_key_decrypt_failed', () => {
    const v = loadVector('group_3dh_1dh.json');
    const inputs = v.decryption_inputs_bob as DecryptionInputs;
    expect(() => decryptMessage(
      v.envelope as Record<string, unknown>,
      inputs.self_aid,
      inputs.self_device_id,
      b64(inputs.self_ik_priv_b64),
      b64(inputs.self_ik_priv_b64),
      b64(inputs.sender_pub_der_b64),
    )).toThrow(/wrap_key_decrypt_failed: .*key_source=group_device_prekey.*spk_id=/);
  });
});

describe('Python ↔ TS interop: Group', () => {
  it('group_3dh_1dh.json (Bob 3DH)', () =>
    runVector('group_3dh_1dh.json', 'decryption_inputs_bob'));
  it('group_3dh_1dh.json (Carol 1DH)', () =>
    runVector('group_3dh_1dh.json', 'decryption_inputs_carol'));
});
