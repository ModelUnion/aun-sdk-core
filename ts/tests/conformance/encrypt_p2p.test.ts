import { describe, it, expect } from 'vitest';
import { encryptP2PMessage } from '../../src/v2/e2ee/encrypt-p2p.js';
import { decryptMessage } from '../../src/v2/e2ee/decrypt.js';
import { generateP256Keypair, privateToPublicDer } from '../../src/v2/crypto/ecdh.js';
import { ProtectedHeaders } from '../../src/protected-headers.js';
import { VERSION as SDK_VERSION } from '../../src/version.js';

/**
 * P2P 加密自加密自解密回环：
 *   - 3DH 路径（target 带 SPK）
 *   - 1DH 路径（target 无 SPK）
 *   - 多接收方（peer 3DH + self_sync 1DH）
 *
 * 不依赖 golden 向量，验证 encrypt/decrypt 自洽。
 */

describe('encryptP2PMessage roundtrip', () => {
  it('3DH path: encrypt → decrypt', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const [bobSpkPriv, bobSpkPubDer] = generateP256Keypair();

    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const target = {
      aid: 'bob.aid.com',
      deviceId: 'dev-bob-1',
      role: 'peer',
      keySource: 'peer_device_prekey',
      ikPkDer: bobIkPubDer,
      spkPkDer: bobSpkPubDer,
      spkId: 'sha256:bob_spk_1',
    };
    const payload = { text: 'Hello 3DH', n: 42 };

    const envelope = encryptP2PMessage(sender, { targets: [target] }, payload);

    expect(envelope.type).toBe('e2ee.p2p_encrypted');
    expect((envelope.aad as Record<string, unknown>).wrap_protocol).toBe('3DH');

    const decrypted = decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      bobSpkPriv,
      aliceIkPubDer,
    );
    expect(decrypted).toEqual(payload);
  });

  it('1DH path: encrypt → decrypt without SPK', () => {
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };
    const payload = { text: 'Hello 1DH' };

    const envelope = encryptP2PMessage(sender, { targets: [target] }, payload);
    expect((envelope.aad as Record<string, unknown>).wrap_protocol).toBe('1DH');
    expect(envelope.protected_headers).toMatchObject({
      sdk_lang: 'typescript',
      sdk_version: SDK_VERSION,
    });
    expect((envelope.protected_headers as Record<string, unknown>).sdk_vesion).toBeUndefined();

    const decrypted = decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    );
    expect(decrypted).toEqual(payload);
  });

  it('spkPkDer 存在但 spkId 为空时按 1DH 写信封', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const [, bobSpkPubDer] = generateP256Keypair();

    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const target = {
      aid: 'bob.aid.com',
      deviceId: 'dev-bob-1',
      role: 'peer',
      keySource: 'peer_device_prekey',
      ikPkDer: bobIkPubDer,
      spkPkDer: bobSpkPubDer,
      spkId: '',
    };
    const payload = { text: 'SPK pub without SPK ID uses 1DH' };

    const envelope = encryptP2PMessage(sender, { targets: [target] }, payload);
    expect((envelope.aad as Record<string, unknown>).wrap_protocol).toBe('1DH');
    const row = (envelope.recipients as string[][])[0]!;
    expect(row[3]).toBe('aid_master');
    expect(row[5]).toBe('');
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual(payload);
  });

  it('protected_headers 支持 ProtectedHeaders 实例并自动注入 payload_type', () => {
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };
    const envelope = encryptP2PMessage(
      sender,
      { targets: [target] },
      { type: 'text', text: 'headers' },
      {
        protectedHeaders: new ProtectedHeaders({ Device_ID: 'dev-bob-1', priority: 1 }),
        context: { type: 'run', id: 'run-1', _auth: 'ignored' },
      },
    );

    expect(envelope.protected_headers).toMatchObject({
      device_id: 'dev-bob-1',
      priority: '1',
      payload_type: 'text',
    });
    expect((envelope.protected_headers as Record<string, unknown>)._auth).toBeDefined();
    expect(envelope.context).toMatchObject({ type: 'run', id: 'run-1' });
    expect((envelope.context as Record<string, unknown>)._auth).toBeDefined();
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual({ type: 'text', text: 'headers' });
  });

  it('protected_headers 普通对象也应规范化为小写键并自动注入 payload_type', () => {
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptP2PMessage(
      sender,
      { targets: [target] },
      { type: 'text', text: 'plain headers' },
      {
        protectedHeaders: {
          Device_ID: 'dev-bob-1',
          priority: 1,
          flag: true,
          ratio: 1.0,
          empty: null,
          nested: { b: 2, a: 1 },
          sdk_vesion: '0.0.0',
          sdk_version: '0.0.0',
        },
        context: { type: 'run', id: 'run-1', _auth: 'ignored' },
      },
    );

    expect(envelope.protected_headers).toMatchObject({
      device_id: 'dev-bob-1',
      priority: '1',
      flag: 'true',
      ratio: '1',
      empty: '',
      nested: '{"a":1,"b":2}',
      payload_type: 'text',
      sdk_lang: 'typescript',
      sdk_version: SDK_VERSION,
    });
    expect((envelope.protected_headers as Record<string, unknown>).sdk_vesion).toBeUndefined();
    expect((envelope.protected_headers as Record<string, unknown>)._auth).toBeDefined();
    expect(envelope.context).toMatchObject({ type: 'run', id: 'run-1' });
    expect((envelope.context as Record<string, unknown>)._auth).toBeDefined();
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual({ type: 'text', text: 'plain headers' });
  });

  it('protected_headers 被篡改时解密应拒绝', () => {
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptP2PMessage(
      sender,
      { targets: [target] },
      { type: 'text', text: 'tamper headers' },
      { protectedHeaders: { trace_id: 'trace-1' } },
    ) as Record<string, unknown>;
    (envelope.protected_headers as Record<string, unknown>).trace_id = 'trace-2';

    expect(() =>
      decryptMessage(
        envelope,
        'bob.aid.com',
        'dev-bob-1',
        bobIkPriv,
        undefined,
        aliceIkPubDer,
      ),
    ).toThrow(/protected_headers _auth verification failed/);
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptP2PMessage(sender, { targets: [target] }, { type: 'text', text: 'default headers' });

    expect(envelope.protected_headers).toMatchObject({
      payload_type: 'text',
    });
    expect((envelope.protected_headers as Record<string, unknown>)._auth).toBeDefined();
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual({ type: 'text', text: 'default headers' });
  });

  it('multi-recipient: peer 3DH + self_sync 1DH', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const [bobSpkPriv, bobSpkPubDer] = generateP256Keypair();
    const [alice2IkPriv, alice2IkPubDer] = generateP256Keypair();

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
        role: 'peer',
        keySource: 'peer_device_prekey',
        ikPkDer: bobIkPubDer,
        spkPkDer: bobSpkPubDer,
        spkId: 'sha256:bob_spk_1',
      },
      {
        aid: 'alice.aid.com',
        deviceId: 'dev-alice-2',
        role: 'self_sync',
        keySource: 'peer_device_prekey',
        ikPkDer: alice2IkPubDer,
      },
    ];
    const payload = { text: 'multi', n: 2 };

    const envelope = encryptP2PMessage(sender, { targets }, payload);
    expect((envelope.aad as Record<string, unknown>).wrap_protocol).toBe('1DH+3DH');

    // Bob 用 3DH 解
    const decBob = decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      bobSpkPriv,
      aliceIkPubDer,
    );
    expect(decBob).toEqual(payload);

    // Alice2 用 1DH 解
    const decAlice2 = decryptMessage(
      envelope as Record<string, unknown>,
      'alice.aid.com',
      'dev-alice-2',
      alice2IkPriv,
      undefined,
      aliceIkPubDer,
    );
    expect(decAlice2).toEqual(payload);
  });

  it('non-recipient returns null', () => {
    const [aliceIkPriv, aliceIkPubDer] = generateP256Keypair();
    const [bobIkPriv, bobIkPubDer] = generateP256Keypair();
    const [, eveIkPubDer] = generateP256Keypair();
    const eveIkPriv = (() => {
      // 生成 Eve 自己的密钥对（用于错误身份解密）
      const [priv] = generateP256Keypair();
      return priv;
    })();

    const sender = {
      aid: 'alice.aid.com',
      deviceId: 'dev-alice-1',
      ikPriv: aliceIkPriv,
      ikPubDer: aliceIkPubDer,
    };
    const target = {
      aid: 'bob.aid.com',
      deviceId: 'dev-bob-1',
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };
    const envelope = encryptP2PMessage(sender, { targets: [target] }, { text: 'x' });

    const result = decryptMessage(
      envelope as Record<string, unknown>,
      'eve.aid.com',
      'dev-eve-1',
      eveIkPriv,
      undefined,
      aliceIkPubDer,
    );
    expect(result).toBeNull();

    // 关注未使用变量警告
    void bobIkPriv;
    void eveIkPubDer;
  });
});

describe('encryptP2PMessage signature integrity', () => {
  it('tampered ciphertext fails verification', () => {
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };
    const envelope = encryptP2PMessage(sender, { targets: [target] }, { x: 1 }) as Record<
      string,
      unknown
    >;
    // 翻转密文一字节后重编码
    const ctBytes = Buffer.from(envelope.ciphertext as string, 'base64');
    ctBytes[0] ^= 0x01;
    envelope.ciphertext = ctBytes.toString('base64');

    expect(() =>
      decryptMessage(
        envelope,
        'bob.aid.com',
        'dev-bob-1',
        bobIkPriv,
        undefined,
        aliceIkPubDer,
      ),
    ).toThrow();
  });

  it('payload.type 应复制到信封顶层 payload_type', () => {
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
      role: 'peer',
      keySource: 'aid_master',
      ikPkDer: bobIkPubDer,
    };

    const envelope = encryptP2PMessage(sender, { targets: [target] }, { type: 'text', text: 'visible type' });

    expect(envelope.payload_type).toBe('text');
    expect((envelope.protected_headers as Record<string, unknown>).payload_type).toBe('text');
    expect((envelope.protected_headers as Record<string, unknown>).sdk_lang).toBe('typescript');
    expect((envelope.protected_headers as Record<string, unknown>).sdk_version).toBe(SDK_VERSION);
    expect((envelope.protected_headers as Record<string, unknown>).sdk_vesion).toBeUndefined();
    expect(decryptMessage(
      envelope as Record<string, unknown>,
      'bob.aid.com',
      'dev-bob-1',
      bobIkPriv,
      undefined,
      aliceIkPubDer,
    )).toEqual({ type: 'text', text: 'visible type' });
  });
});

// 触发未使用导入告警避免
void privateToPublicDer;
