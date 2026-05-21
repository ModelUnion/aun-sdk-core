import { describe, it, expect } from 'vitest';
import { encryptGroupMessage } from '../../src/v2/e2ee/encrypt-group.js';
import { decryptMessage } from '../../src/v2/e2ee/decrypt.js';
import { generateP256Keypair } from '../../src/v2/crypto/ecdh.js';
import { ProtectedHeaders } from '../../src/protected-headers.js';

/**
 * Group 加密自加密自解密回环：
 *   - 多成员（3DH + 1DH 混合）
 *   - state_commitment 占位 vs 显式
 */

describe('encryptGroupMessage roundtrip', () => {
  it('mixed 3DH + 1DH members', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const [bobSpkPriv, bobSpkPubDer] = generateP256Keypair();
    const [carolIkPriv, carolIkPubDer] = generateP256Keypair();

    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const targets = [
      {
        aid: 'bob.aid.com',
        deviceId: 'dev-bob-1',
        role: 'member',
        keySource: 'group_device_prekey',
        ikPkDer: bobIkPubDer,
        spkPkDer: bobSpkPubDer,
        spkId: 'sha256:bob_spk_1',
      },
      {
        aid: 'carol.aid.com',
        deviceId: 'dev-carol-1',
        role: 'member',
        keySource: 'aid_master',
        ikPkDer: carolIkPubDer,
      },
    ];
    const payload = { text: 'group hi' };

    const envelope = encryptGroupMessage(
      sender,
      'g-test.aid.com',
      5,
      targets,
      payload,
      {},
      { state_version: 1, state_hash: 'abc', state_chain: 'chain-1' },
    );

    expect(envelope.type).toBe('e2ee.group_encrypted');
    expect(envelope.group_id).toBe('g-test.aid.com');
    expect(envelope.epoch).toBe(5);
    const aad = envelope.aad as Record<string, unknown>;
    expect(aad.wrap_protocol).toBe('1DH+3DH');
    expect(aad.state_commitment).toEqual({
      state_version: 1,
      state_hash: 'abc',
      state_chain: 'chain-1',
    });

    // Bob 3DH
    const decBob = decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      bobSpkPriv,
      aliceIkPubDer,
    );
    expect(decBob).toEqual(payload);

    // Carol 1DH
    const decCarol = decryptMessage(
      envelope as Record<string, unknown>,
      'carol.aid.com',
      'dev-carol-1',
      carolIkPriv,
      undefined,
      aliceIkPubDer,
    );
    expect(decCarol).toEqual(payload);
  });

  it('default state_commitment uses placeholder', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const target = {
      aid: 'bob.aid.com',
      deviceId: 'dev-bob-1',
      role: 'member',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptGroupMessage(sender, 'g-x', 0, [target], { hi: 1 });
    const aad = envelope.aad as Record<string, unknown>;
    expect(aad.state_commitment).toEqual({
      state_version: 0,
      state_hash: '',
      state_chain: '',
    });
    const dec = decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    );
    expect(dec).toEqual({ hi: 1 });
  });

  it('protected_headers 支持 ProtectedHeaders 实例并绑定 group V2 envelope', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const target = {
      aid: 'bob.aid.com',
      deviceId: 'dev-bob-1',
      role: 'member',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptGroupMessage(
      sender,
      'g-test.aid.com',
      2,
      [target],
      { type: 'group-text', text: 'headers' },
      {
        protectedHeaders: new ProtectedHeaders({ Device_ID: 'dev-bob-1', slot_id: 'slot-a' }),
        context: { type: 'run', id: 'run-g' },
      },
      { state_version: 7, state_hash: 'state-hash', state_chain: 'state-chain' },
    );

    expect(envelope.protected_headers).toMatchObject({
      device_id: 'dev-bob-1',
      slot_id: 'slot-a',
      payload_type: 'group-text',
    });
    expect((envelope.protected_headers as Record<string, unknown>)._auth).toBeDefined();
    expect(envelope.context).toMatchObject({ type: 'run', id: 'run-g' });
    expect((envelope.aad as Record<string, unknown>).state_commitment).toEqual({
      state_version: 7,
      state_hash: 'state-hash',
      state_chain: 'state-chain',
    });
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual({ type: 'group-text', text: 'headers' });
  });

  it('未显式传 protected_headers 时也应自动注入 payload_type', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const target = {
      aid: 'bob.aid.com',
      deviceId: 'dev-bob-1',
      role: 'member',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptGroupMessage(
      sender,
      'g-test.aid.com',
      2,
      [target],
      { type: 'group-text', text: 'default headers' },
      {},
      { state_version: 7, state_hash: 'state-hash', state_chain: 'state-chain' },
    );

    expect(envelope.protected_headers).toMatchObject({
      payload_type: 'group-text',
    });
    expect((envelope.protected_headers as Record<string, unknown>)._auth).toBeDefined();
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual({ type: 'group-text', text: 'default headers' });
  });
});
