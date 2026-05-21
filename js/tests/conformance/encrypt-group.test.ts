import { describe, it, expect } from 'vitest';
import { encryptGroupMessage } from '../../src/v2/e2ee/encrypt-group';
import { decryptMessage } from '../../src/v2/e2ee/decrypt';
import { generateP256Keypair } from '../../src/v2/crypto/ecdh';

describe('encryptGroupMessage - self loop', () => {
  it('group 3DH+1DH: bob 3DH, carol 1DH', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [bobSpkPriv, bobSpkPub] = await generateP256Keypair();
    const [carolIkPriv, carolIkPub] = await generateP256Keypair();

    const payload = { text: 'group hello', list: ['a', 'b'] };
    const env = await encryptGroupMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      'g-test.aid.com',
      5,
      [
        {
          aid: 'bob.aid.com',
          deviceId: 'dev-bob-1',
          role: 'member',
          keySource: 'group_device_prekey',
          ikPkDer: bobIkPub,
          spkPkDer: bobSpkPub,
          spkId: 'sha256:bob_spk_1',
        },
        {
          aid: 'carol.aid.com',
          deviceId: 'dev-carol-1',
          role: 'member',
          keySource: 'aid_master',
          ikPkDer: carolIkPub,
        },
      ],
      payload,
      undefined,
      { state_version: 1, state_hash: 'abc123', state_chain: 'chain-link-1' },
    );

    expect((env as any).type).toBe('e2ee.group_encrypted');
    expect((env as any).group_id).toBe('g-test.aid.com');
    expect((env as any).epoch).toBe(5);
    expect((env as any).aad.wrap_protocol).toBe('1DH+3DH');
    expect((env as any).aad.state_commitment).toEqual({
      state_version: 1,
      state_hash: 'abc123',
      state_chain: 'chain-link-1',
    });

    // Bob 解密
    const decBob = await decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      bobSpkPriv,
      aliceIkPub,
    );
    expect(decBob).toEqual(payload);

    // Carol 解密
    const decCarol = await decryptMessage(
      env,
      'carol.aid.com',
      'dev-carol-1',
      carolIkPriv,
      undefined,
      aliceIkPub,
    );
    expect(decCarol).toEqual(payload);
  });

  it('group 1DH only: state_commitment defaults', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();

    const payload = { text: 'plain group', n: 0 };
    const env = await encryptGroupMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      'g-x',
      1,
      [
        {
          aid: 'bob.aid.com',
          deviceId: 'dev-bob-1',
          role: 'member',
          keySource: 'aid_master',
          ikPkDer: bobIkPub,
        },
      ],
      payload,
    );

    expect((env as any).aad.wrap_protocol).toBe('1DH');
    expect((env as any).aad.state_commitment).toEqual({
      state_version: 0,
      state_hash: '',
      state_chain: '',
    });

    const decBob = await decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    );
    expect(decBob).toEqual(payload);
  });
});
