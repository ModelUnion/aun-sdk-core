import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { decryptMessage } from '../../src/v2/e2ee/decrypt';

function b64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

interface DecryptInputs {
  self_aid: string;
  self_device_id: string;
  self_ik_priv_b64: string;
  self_spk_priv_b64: string | null;
  sender_pub_der_b64: string;
}

interface GoldenVector {
  description?: string;
  envelope: Record<string, unknown>;
  decryption_inputs?: DecryptInputs;
  decryption_inputs_bob?: DecryptInputs;
  decryption_inputs_alice2?: DecryptInputs;
  decryption_inputs_carol?: DecryptInputs;
  expected_payload: Record<string, unknown>;
}

function loadGolden(filename: string): GoldenVector {
  const path = join(__dirname, 'golden', 'envelope', filename);
  return JSON.parse(readFileSync(path, 'utf-8')) as GoldenVector;
}

async function runCase(
  envelope: Record<string, unknown>,
  inputs: DecryptInputs,
  expected: Record<string, unknown>,
): Promise<void> {
  const ikPriv = b64(inputs.self_ik_priv_b64);
  const spkPriv = inputs.self_spk_priv_b64 ? b64(inputs.self_spk_priv_b64) : undefined;
  const senderPub = b64(inputs.sender_pub_der_b64);
  const decrypted = await decryptMessage(
    envelope,
    inputs.self_aid,
    inputs.self_device_id,
    ikPriv,
    spkPriv,
    senderPub,
  );
  expect(decrypted).toEqual(expected);
}

describe('decryptMessage - golden interop (Python ↔ JS)', () => {
  it('p2p_3dh: Bob decrypts', async () => {
    const v = loadGolden('p2p_3dh.json');
    if (!v.decryption_inputs) throw new Error('missing decryption_inputs');
    await runCase(v.envelope, v.decryption_inputs, v.expected_payload);
  });

  it('p2p_1dh: Bob decrypts', async () => {
    const v = loadGolden('p2p_1dh.json');
    if (!v.decryption_inputs) throw new Error('missing decryption_inputs');
    await runCase(v.envelope, v.decryption_inputs, v.expected_payload);
  });

  it('p2p_multi: Bob decrypts (3DH)', async () => {
    const v = loadGolden('p2p_multi.json');
    if (!v.decryption_inputs_bob) throw new Error('missing decryption_inputs_bob');
    await runCase(v.envelope, v.decryption_inputs_bob, v.expected_payload);
  });

  it('p2p_multi: Alice-2 decrypts (1DH self_sync)', async () => {
    const v = loadGolden('p2p_multi.json');
    if (!v.decryption_inputs_alice2) throw new Error('missing decryption_inputs_alice2');
    await runCase(v.envelope, v.decryption_inputs_alice2, v.expected_payload);
  });

  it('group_3dh_1dh: Bob decrypts (3DH)', async () => {
    const v = loadGolden('group_3dh_1dh.json');
    if (!v.decryption_inputs_bob) throw new Error('missing decryption_inputs_bob');
    await runCase(v.envelope, v.decryption_inputs_bob, v.expected_payload);
  });

  it('group_3dh_1dh: Carol decrypts (1DH)', async () => {
    const v = loadGolden('group_3dh_1dh.json');
    if (!v.decryption_inputs_carol) throw new Error('missing decryption_inputs_carol');
    await runCase(v.envelope, v.decryption_inputs_carol, v.expected_payload);
  });
});

describe('decryptMessage - error classification', () => {
  it('3DH row 缺少本地 SPK 私钥 → spk_missing', async () => {
    const v = loadGolden('p2p_3dh.json');
    if (!v.decryption_inputs) throw new Error('missing decryption_inputs');
    const inputs = v.decryption_inputs;
    await expect(
      decryptMessage(
        v.envelope,
        inputs.self_aid,
        inputs.self_device_id,
        b64(inputs.self_ik_priv_b64),
        undefined,
        b64(inputs.sender_pub_der_b64),
      ),
    ).rejects.toThrow(/spk_missing/);
  });

  it('3DH row 使用错误 SPK 私钥 → wrap_key_decrypt_failed', async () => {
    const v = loadGolden('group_3dh_1dh.json');
    if (!v.decryption_inputs_bob) throw new Error('missing decryption_inputs_bob');
    const inputs = v.decryption_inputs_bob;
    await expect(
      decryptMessage(
        v.envelope,
        inputs.self_aid,
        inputs.self_device_id,
        b64(inputs.self_ik_priv_b64),
        b64(inputs.self_ik_priv_b64),
        b64(inputs.sender_pub_der_b64),
      ),
    ).rejects.toThrow(/wrap_key_decrypt_failed: .*key_source=group_device_prekey.*spk_id=/);
  });
});

describe('decryptMessage - tamper detection', () => {
  it('tampered ciphertext → throws / fails', async () => {
    const v = loadGolden('p2p_1dh.json');
    if (!v.decryption_inputs) throw new Error('missing decryption_inputs');
    const env: Record<string, unknown> = JSON.parse(JSON.stringify(v.envelope));
    // 改一个字节
    const ct = b64(env.ciphertext as string);
    ct[0] ^= 0xff;
    let bin = '';
    for (let i = 0; i < ct.length; i++) bin += String.fromCharCode(ct[i]);
    env.ciphertext = btoa(bin);

    const inputs = v.decryption_inputs;
    const ikPriv = b64(inputs.self_ik_priv_b64);
    const spkPriv = inputs.self_spk_priv_b64 ? b64(inputs.self_spk_priv_b64) : undefined;
    const senderPub = b64(inputs.sender_pub_der_b64);

    await expect(
      decryptMessage(
        env,
        inputs.self_aid,
        inputs.self_device_id,
        ikPriv,
        spkPriv,
        senderPub,
      ),
    ).rejects.toThrow();
  });

  it('wrong sender public key → signature verify fails', async () => {
    const v = loadGolden('p2p_1dh.json');
    if (!v.decryption_inputs) throw new Error('missing decryption_inputs');

    const inputs = v.decryption_inputs;
    const ikPriv = b64(inputs.self_ik_priv_b64);
    const spkPriv = inputs.self_spk_priv_b64 ? b64(inputs.self_spk_priv_b64) : undefined;
    // 用接收方的 IK 公钥冒充 sender 公钥（错误公钥）
    const wrongPub = b64(
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8FpLZ9frHZJ7KuY949oIAljvjjd5PhHLLgEgXseIA1Q79nk6Iw6FlKYN+NxQpHxQLKVRWdsJIKM0tDK4B80Zdg==',
    );

    await expect(
      decryptMessage(
        v.envelope,
        inputs.self_aid,
        inputs.self_device_id,
        ikPriv,
        spkPriv,
        wrongPub,
      ),
    ).rejects.toThrow(/sender_signature/);
  });
});
