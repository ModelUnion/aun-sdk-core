import { describe, it, expect } from 'vitest';
import { encryptP2PMessage } from '../../src/v2/e2ee/encrypt-p2p';
import { decryptMessage } from '../../src/v2/e2ee/decrypt';
import {
  generateP256Keypair,
  privateToPublicDer,
} from '../../src/v2/crypto/ecdh';

const SDK_VERSION = '0.5.4';

describe('encryptP2PMessage - self loop', () => {
  it('1DH path: alice -> bob (no SPK)', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();

    const payload = { text: 'hello bob 1DH', n: 7 };
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'aid_master',
            ikPkDer: bobIkPub,
          },
        ],
      },
      payload,
    );

    expect((env as any).type).toBe('e2ee.p2p_encrypted');
    expect((env as any).version).toBe('v2');
    expect((env as any).aad.wrap_protocol).toBe('1DH');
    expect((env as any).recipients.length).toBe(1);
    expect((env as any).protected_headers).toMatchObject({
      sdk_lang: 'javascript',
      sdk_version: SDK_VERSION,
    });
    expect((env as any).protected_headers.sdk_version).toBe(SDK_VERSION);

    const decrypted = await decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    );
    expect(decrypted).toEqual(payload);
  });

  it('3DH path: alice -> bob (with SPK)', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [bobSpkPriv, bobSpkPub] = await generateP256Keypair();

    const payload = { text: 'hello bob 3DH', list: [1, 2, 3] };
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'peer_device_prekey',
            ikPkDer: bobIkPub,
            spkPkDer: bobSpkPub,
            spkId: 'sha256:bob_spk_1',
          },
        ],
      },
      payload,
    );

    expect((env as any).aad.wrap_protocol).toBe('3DH');
    expect((env as any).recipients[0][5]).toBe('sha256:bob_spk_1');

    const decrypted = await decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      bobSpkPriv,
      aliceIkPub,
    );
    expect(decrypted).toEqual(payload);
  });

  it('spkPkDer 存在但 spkId 为空时按 1DH 写信封', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [, bobSpkPub] = await generateP256Keypair();

    const payload = { text: 'SPK pub without SPK ID uses 1DH' };
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'peer_device_prekey',
            ikPkDer: bobIkPub,
            spkPkDer: bobSpkPub,
            spkId: '',
          },
        ],
      },
      payload,
    );

    expect((env as any).aad.wrap_protocol).toBe('1DH');
    expect((env as any).recipients[0][3]).toBe('aid_master');
    expect((env as any).recipients[0][5]).toBe('');
    const decrypted = await decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    );
    expect(decrypted).toEqual(payload);
  });

  it('multi-recipient: bob 3DH + alice-2 1DH self_sync', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [alice2IkPriv, alice2IkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const [bobSpkPriv, bobSpkPub] = await generateP256Keypair();

    const payload = { text: 'multi', n: 2 };
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'peer_device_prekey',
            ikPkDer: bobIkPub,
            spkPkDer: bobSpkPub,
            spkId: 'sha256:bob_spk_1',
          },
          {
            aid: 'alice.aid.com',
            deviceId: 'dev-alice-2',
            role: 'self_sync',
            keySource: 'aid_master',
            ikPkDer: alice2IkPub,
          },
        ],
      },
      payload,
    );

    expect((env as any).aad.wrap_protocol).toBe('1DH+3DH');
    expect((env as any).recipients.length).toBe(2);

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

    // Alice2 解密（1DH 自同步）
    const decAlice2 = await decryptMessage(
      env,
      'alice.aid.com',
      'dev-alice-2',
      alice2IkPriv,
      undefined,
      aliceIkPub,
    );
    expect(decAlice2).toEqual(payload);
  });

  it('mismatched recipient returns null', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();

    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'aid_master',
            ikPkDer: bobIkPub,
          },
        ],
      },
      { text: 'no body here' },
    );

    const dec = await decryptMessage(
      env,
      'carol.aid.com',
      'dev-carol-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    );
    expect(dec).toBeNull();
  });

  it('protected_headers value normalization is canonical across languages', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'aid_master',
            ikPkDer: bobIkPub,
          },
        ],
      },
      { type: 'text', text: 'metadata' },
      {
        protectedHeaders: {
          ' Device_ID ': 'dev-bob-1',
          flag: true,
          ratio: 1.0,
          empty: null,
          nested: { b: 2, a: 1 },
          sdk_vesion: '0.0.0',
          sdk_version: '0.0.0',
        },
      },
    );

    expect((env as any).protected_headers).toMatchObject({
      device_id: 'dev-bob-1',
      flag: 'true',
      ratio: '1',
      empty: '',
      nested: '{"a":1,"b":2}',
      payload_type: 'text',
      sdk_lang: 'javascript',
      sdk_version: SDK_VERSION,
    });
    expect((env as any).protected_headers.sdk_version).toBe(SDK_VERSION);
    await expect(decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    )).resolves.toEqual({ type: 'text', text: 'metadata' });
  });

  it('tampered protected_headers fail metadata auth', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'aid_master',
            ikPkDer: bobIkPub,
          },
        ],
      },
      { type: 'text', text: 'metadata' },
      { protectedHeaders: { trace_id: 'trace-1' } },
    );
    (env as any).protected_headers.trace_id = 'trace-2';

    await expect(decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    )).rejects.toThrow(/protected_headers _auth verification failed/);
  });

  it('privateToPublicDer matches generateP256Keypair (regression)', async () => {
    const [priv, pub] = await generateP256Keypair();
    const recomputed = await privateToPublicDer(priv);
    expect(Array.from(recomputed)).toEqual(Array.from(pub));
  });

  it('payload.type 应复制到信封顶层 payload_type', async () => {
    const [aliceIkPriv, aliceIkPub] = await generateP256Keypair();
    const [bobIkPriv, bobIkPub] = await generateP256Keypair();
    const env = await encryptP2PMessage(
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-1',
        ikPriv: aliceIkPriv,
        ikPubDer: aliceIkPub,
      },
      {
        targets: [
          {
            aid: 'bob.aid.com',
            deviceId: 'dev-bob-1',
            role: 'peer',
            keySource: 'aid_master',
            ikPkDer: bobIkPub,
          },
        ],
      },
      { type: 'text', text: 'visible type' },
    );

    expect((env as any).payload_type).toBe('text');
    expect((env as any).protected_headers.payload_type).toBe('text');
    expect((env as any).protected_headers.sdk_lang).toBe('javascript');
    expect((env as any).protected_headers.sdk_version).toBe(SDK_VERSION);
    expect((env as any).protected_headers.sdk_version).toBe(SDK_VERSION);
    await expect(decryptMessage(
      env,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPub,
    )).resolves.toEqual({ type: 'text', text: 'visible type' });
  });
});
