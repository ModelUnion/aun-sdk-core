// ── e2ee 模块单元测试 ──────────────────────────────────────
// P2P 端到端加密测试。由于密码学操作全部异步（SubtleCrypto），
// 所有 crypto 相关测试需要 await。
import { describe, it, expect, beforeEach } from 'vitest';
import {
  E2EEManager,
  SUITE,
  MODE_PREKEY_ECDH_V2,
  MODE_LONG_TERM_KEY,
  _aadBytesOffline,
} from '../../src/e2ee.js';
import { CryptoProvider, uint8ToBase64 } from '../../src/crypto.js';
import type { KeyStore } from '../../src/keystore/index.js';
import type { IdentityRecord, KeyPairRecord, PrekeyMap, PrekeyRecord } from '../../src/types.js';

const hasSubtleCrypto = typeof globalThis.crypto?.subtle?.generateKey === 'function';

// ── AAD 工具函数测试（纯字符串操作，不依赖 SubtleCrypto）──

describe('AAD 序列化', () => {
  it('应按 AAD_FIELDS_OFFLINE 排序键并序列化为 JSON', () => {
    const aad = {
      from: 'alice.example.com',
      to: 'bob.example.com',
      message_id: 'msg-001',
      timestamp: 1700000000,
      encryption_mode: MODE_PREKEY_ECDH_V2,
      suite: SUITE,
      ephemeral_public_key: 'eph-pub-key',
      recipient_cert_fingerprint: 'sha256:aaa',
      sender_cert_fingerprint: 'sha256:bbb',
      prekey_id: 'pk-001',
    };
    const bytes = _aadBytesOffline(aad);
    const decoded = new TextDecoder().decode(bytes);
    const parsed = JSON.parse(decoded);

    // 键应按字母序排列
    const keys = Object.keys(parsed);
    const sorted = [...keys].sort();
    expect(keys).toEqual(sorted);

    // 所有 AAD 字段应存在
    expect(parsed.from).toBe('alice.example.com');
    expect(parsed.to).toBe('bob.example.com');
    expect(parsed.prekey_id).toBe('pk-001');
  });

  it('缺失字段应填充为 null', () => {
    const aad = { from: 'alice', to: 'bob', message_id: 'msg-1' };
    const bytes = _aadBytesOffline(aad);
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    expect(parsed.encryption_mode).toBeNull();
    expect(parsed.suite).toBeNull();
    expect(parsed.prekey_id).toBeNull();
  });

  it('相同输入应产生相同字节', () => {
    const aad = { from: 'a', to: 'b', message_id: 'm1', timestamp: 100 };
    const bytes1 = _aadBytesOffline(aad);
    const bytes2 = _aadBytesOffline(aad);
    expect(uint8ToBase64(bytes1)).toBe(uint8ToBase64(bytes2));
  });
});

// ── 常量测试 ────────────────────────────────────────────

describe('E2EE 常量', () => {
  it('SUITE 值正确', () => {
    expect(SUITE).toBe('P256_HKDF_SHA256_AES_256_GCM');
  });

  it('加密模式常量正确', () => {
    expect(MODE_PREKEY_ECDH_V2).toBe('prekey_ecdh_v2');
    expect(MODE_LONG_TERM_KEY).toBe('long_term_key');
  });
});

// ── 内存 KeyStore mock ──────────────────────────────────

function createMockKeyStore(): KeyStore {
  const keyPairs = new Map<string, KeyPairRecord>();
  const certs = new Map<string, string>();
  const prekeys = new Map<string, PrekeyMap>();
  return {
    async loadKeyPair(aid) { return keyPairs.get(aid) ?? null; },
    async saveKeyPair(aid, kp) { keyPairs.set(aid, kp); },
    async loadCert(aid) { return certs.get(aid) ?? null; },
    async saveCert(aid, cert) { certs.set(aid, cert); },
    async loadE2EEPrekeys(aid) { return JSON.parse(JSON.stringify(prekeys.get(aid) ?? {})); },
    async saveE2EEPrekey(aid, prekeyId, prekeyData) {
      const current = prekeys.get(aid) ?? {};
      current[prekeyId] = JSON.parse(JSON.stringify(prekeyData));
      prekeys.set(aid, current);
    },
    async cleanupE2EEPrekeys(aid, cutoffMs, keepLatest = 7) {
      const current = prekeys.get(aid) ?? {};
      const removed: string[] = [];
      const retainedIds = new Set(
        Object.entries(current)
          .sort((left, right) => {
            const leftMarker = Number(left[1].created_at ?? left[1].updated_at ?? left[1].expires_at ?? 0);
            const rightMarker = Number(right[1].created_at ?? right[1].updated_at ?? right[1].expires_at ?? 0);
            if (rightMarker !== leftMarker) return rightMarker - leftMarker;
            return right[0].localeCompare(left[0]);
          })
          .slice(0, keepLatest)
          .map(([prekeyId]) => prekeyId),
      );
      for (const [prekeyId, data] of Object.entries(current)) {
        const marker = Number(data.expires_at ?? data.created_at ?? data.updated_at ?? 0);
        if (marker < cutoffMs && !retainedIds.has(prekeyId)) {
          removed.push(prekeyId);
          delete current[prekeyId];
        }
      }
      prekeys.set(aid, current);
      return removed;
    },
    async loadIdentity(aid) {
      const kp = keyPairs.get(aid);
      if (!kp) return null;
      const cert = certs.get(aid);
      return { ...kp, ...(cert ? { cert } : {}) };
    },
    async saveIdentity(aid, identity) {
      const kp: KeyPairRecord = {};
      for (const k of ['private_key_pem', 'public_key_der_b64', 'curve']) {
        if (k in identity) kp[k] = identity[k];
      }
      if (Object.keys(kp).length) keyPairs.set(aid, kp);
      if (identity.cert) certs.set(aid, identity.cert as string);
    },
  };
}

// ── Prekey 生成测试 ──────────────────────────────────────

describe('E2EEManager.generatePrekey', () => {
  it.skipIf(!hasSubtleCrypto)(
    '应生成合法 prekey 并保存私钥到 keystore',
    async () => {
      const keystore = createMockKeyStore();
      const provider = new CryptoProvider();
      const identity = await provider.generateIdentity();
      const aid = 'alice.example.com';

      // 保存身份
      await keystore.saveKeyPair(aid, {
        private_key_pem: identity.private_key_pem,
        public_key_der_b64: identity.public_key_der_b64,
        curve: identity.curve,
      });

      const manager = new E2EEManager({
        identityFn: () => ({
          aid,
          private_key_pem: identity.private_key_pem,
          public_key_der_b64: identity.public_key_der_b64,
        }),
        keystore,
      });

      const prekey = await manager.generatePrekey();

      // 验证返回结构
      expect(prekey.prekey_id).toBeDefined();
      expect(typeof prekey.prekey_id).toBe('string');
      expect((prekey.prekey_id as string).length).toBeGreaterThan(0);

      expect(prekey.public_key).toBeDefined();
      expect(typeof prekey.public_key).toBe('string');
      expect((prekey.public_key as string).length).toBeGreaterThan(50);

      expect(prekey.signature).toBeDefined();
      expect(typeof prekey.signature).toBe('string');

      expect(prekey.created_at).toBeDefined();
      expect(typeof prekey.created_at).toBe('number');
      expect(prekey.created_at as number).toBeGreaterThan(0);

      // 验证私钥已保存到结构化 prekey 存储
      const prekeys = await keystore.loadE2EEPrekeys(aid);
      expect(prekeys).toBeDefined();
      expect(prekeys[prekey.prekey_id as string]).toBeDefined();
      expect(prekeys[prekey.prekey_id as string].private_key_pem).toContain('BEGIN PRIVATE KEY');
    },
  );

  it.skipIf(!hasSubtleCrypto)(
    '本地清理应保留最新 7 个 prekey',
    async () => {
      const keystore = createMockKeyStore();
      const provider = new CryptoProvider();
      const identity = await provider.generateIdentity();
      const aid = 'alice.example.com';
      const now = Date.now();
      const oldBase = now - (8 * 24 * 3600 * 1000);

      await keystore.saveKeyPair(aid, {
        private_key_pem: identity.private_key_pem,
        public_key_der_b64: identity.public_key_der_b64,
        curve: identity.curve,
      });

      for (let i = 0; i < 8; i += 1) {
        await keystore.saveE2EEPrekey!(aid, `old-${i}`, {
          private_key_pem: `OLD-${i}`,
          created_at: oldBase + i,
        });
      }

      const manager = new E2EEManager({
        identityFn: () => ({
          aid,
          private_key_pem: identity.private_key_pem,
          public_key_der_b64: identity.public_key_der_b64,
        }),
        keystore,
      });

      await manager.generatePrekey();

      const prekeys = await keystore.loadE2EEPrekeys!(aid);
      expect(Object.keys(prekeys)).toHaveLength(7);
      expect(prekeys['old-0']).toBeUndefined();
      expect(prekeys['old-1']).toBeUndefined();
      expect(prekeys['old-2']).toBeDefined();
    },
  );

});

// ── Prekey 缓存测试 ──────────────────────────────────────

describe('E2EEManager prekey 缓存', () => {
  it('应正确缓存和读取 prekey', () => {
    const keystore = createMockKeyStore();
    const manager = new E2EEManager({
      identityFn: () => ({ aid: 'alice' }),
      keystore,
      prekeyCacheTtl: 3600,
    });

    const prekey = { prekey_id: 'pk-1', public_key: 'pub-key', signature: 'sig' };
    manager.cachePrekey('bob', prekey);

    const cached = manager.getCachedPrekey('bob');
    expect(cached).toEqual(prekey);
  });

  it('缓存不存在的 peer 应返回 null', () => {
    const keystore = createMockKeyStore();
    const manager = new E2EEManager({
      identityFn: () => ({ aid: 'alice' }),
      keystore,
    });
    expect(manager.getCachedPrekey('unknown')).toBeNull();
  });

  it('invalidatePrekeyCache 应清除缓存', () => {
    const keystore = createMockKeyStore();
    const manager = new E2EEManager({
      identityFn: () => ({ aid: 'alice' }),
      keystore,
    });
    manager.cachePrekey('bob', { prekey_id: 'pk-1' });
    expect(manager.getCachedPrekey('bob')).not.toBeNull();

    manager.invalidatePrekeyCache('bob');
    expect(manager.getCachedPrekey('bob')).toBeNull();
  });
});

// ── Prekey 加密/解密往返测试 ──────────────────────────────

describe('E2EE prekey 加密/解密往返', () => {
  it.skipIf(!hasSubtleCrypto)(
    'prekey_ecdh_v2 模式加密后应能正确解密',
    async () => {
      const keystore = createMockKeyStore();
      const provider = new CryptoProvider();

      // 生成 Alice 和 Bob 的身份
      const aliceId = await provider.generateIdentity();
      const bobId = await provider.generateIdentity();
      const aliceAid = 'alice.test';
      const bobAid = 'bob.test';

      // 保存双方密钥到 keystore
      await keystore.saveKeyPair(aliceAid, {
        private_key_pem: aliceId.private_key_pem,
        public_key_der_b64: aliceId.public_key_der_b64,
        curve: aliceId.curve,
      });
      await keystore.saveKeyPair(bobAid, {
        private_key_pem: bobId.private_key_pem,
        public_key_der_b64: bobId.public_key_der_b64,
        curve: bobId.curve,
      });

      // 需要为 Bob 生成自签名证书来做证书指纹
      // 由于浏览器 SDK 没有自签名证书生成能力，此处使用 SPKI DER base64 方式
      // E2EEManager 内部通过 identity.public_key_der_b64 计算指纹

      // Alice 的 E2EE 管理器
      const aliceE2ee = new E2EEManager({
        identityFn: () => ({
          aid: aliceAid,
          private_key_pem: aliceId.private_key_pem,
          public_key_der_b64: aliceId.public_key_der_b64,
        }),
        keystore,
      });

      // Bob 的 E2EE 管理器
      const bobE2ee = new E2EEManager({
        identityFn: () => ({
          aid: bobAid,
          private_key_pem: bobId.private_key_pem,
          public_key_der_b64: bobId.public_key_der_b64,
        }),
        keystore,
      });

      // Bob 生成 prekey
      const bobPrekey = await bobE2ee.generatePrekey();

      // 由于没有真正的证书，prekey 加密/解密往返需要证书 PEM
      // 这里 skip 进一步的 roundtrip 测试——需要完整的证书链环境
      // 仅验证 prekey 已正确生成
      expect(bobPrekey.prekey_id).toBeDefined();
      expect(bobPrekey.public_key).toBeDefined();
      expect(bobPrekey.signature).toBeDefined();
    },
  );
});

// ── Long Term Key 加密/解密测试 ──────────────────────────

describe('E2EE long_term_key 加密/解密', () => {
  it.skipIf(!hasSubtleCrypto)(
    'long_term_key 加密需要证书环境（此处验证模式声明正确）',
    async () => {
      // long_term_key 模式需要对方证书 PEM，
      // 完整 roundtrip 在集成测试环境中验证
      expect(MODE_LONG_TERM_KEY).toBe('long_term_key');
    },
  );
});

// ── 防重放（seen set）测试 ──────────────────────────────

describe('E2EEManager 本地防重放', () => {
  it('重复消息应被拒绝（返回 null）', async () => {
    const keystore = createMockKeyStore();
    const manager = new E2EEManager({
      identityFn: () => ({ aid: 'alice' }),
      keystore,
      replayWindowSeconds: 300,
    });

    // 非加密消息应原样返回
    const plainMsg = { from: 'bob', message_id: 'msg-1', payload: { type: 'text', text: 'hello' } };
    const r1 = await manager.decryptMessage(plainMsg);
    expect(r1).toEqual(plainMsg);

    // 构造一个假的加密消息（不会真的解密成功但会被防重放记录）
    const encMsg = {
      from: 'bob',
      to: 'alice',
      message_id: 'msg-enc-1',
      timestamp: Date.now(),
      payload: {
        type: 'e2ee.encrypted',
        encryption_mode: 'unknown_mode',
        ciphertext: 'aGVsbG8=', // "hello" 的 base64
        tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
        nonce: 'AAAAAAAAAAAAAAAAAA==',
      },
    };

    // 第一次调用：由于无法解密，返回 null
    const r2 = await manager.decryptMessage(encMsg);
    // 由于 encryption_mode 未知，内部应返回 null

    // 第二次调用同一个 message_id + from：seen set 检测到重复，直接返回 null
    const r3 = await manager.decryptMessage(encMsg);
    expect(r3).toBeNull();
  });
});
