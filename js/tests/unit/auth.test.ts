// ── auth 模块单元测试（桩测试）──────────────────────────────
// AuthFlow 的完整测试需要 Gateway 环境（WebSocket + PKI），
// 此处仅测试可独立验证的工具方法和构造逻辑。
import { describe, it, expect } from 'vitest';
import { AuthFlow } from '../../src/auth.js';
import { CryptoProvider } from '../../src/crypto.js';
import type { KeyStore } from '../../src/keystore/index.js';
import { StateError } from '../../src/errors.js';
import type { IdentityRecord, JsonObject, KeyPairRecord } from '../../src/types.js';

const hasSubtleCrypto = typeof globalThis.crypto?.subtle?.generateKey === 'function';

// ── 内存 KeyStore mock ──────────────────────────────────

function createMockKeyStore(): KeyStore {
  const keyPairs = new Map<string, KeyPairRecord>();
  const certs = new Map<string, string>();
  const identities = new Map<string, IdentityRecord>();
  return {
    async loadKeyPair(aid) { return keyPairs.get(aid) ?? null; },
    async saveKeyPair(aid, kp) { keyPairs.set(aid, kp); },
    async loadCert(aid) { return certs.get(aid) ?? null; },
    async saveCert(aid, cert) { certs.set(aid, cert); },
    async loadIdentity(aid) {
      const kp = keyPairs.get(aid);
      const id = identities.get(aid);
      if (!kp && !id) return null;
      const cert = certs.get(aid);
      return { ...(kp ?? {}), ...(id ?? {}), ...(cert ? { cert } : {}) };
    },
    async saveIdentity(aid, identity) {
      const kp: KeyPairRecord = {};
      for (const k of ['private_key_pem', 'public_key_der_b64', 'curve']) {
        if (k in identity) kp[k] = identity[k];
      }
      if (Object.keys(kp).length) keyPairs.set(aid, kp);
      if (identity.cert) certs.set(aid, identity.cert as string);
      identities.set(aid, { ...(identities.get(aid) ?? {}), ...identity });
    },
  };
}

describe('AuthFlow 构造', () => {
  it('应正确创建实例', () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({
      keystore: ks,
      crypto: new CryptoProvider(),
    });
    expect(auth).toBeDefined();
  });
});

describe('AuthFlow.loadIdentity', () => {
  it('无身份时应抛出 StateError', async () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ keystore: ks, crypto: new CryptoProvider() });

    await expect(auth.loadIdentity()).rejects.toThrow(StateError);
  });

  it.skipIf(!hasSubtleCrypto)(
    '有身份时应正确加载',
    async () => {
      const ks = createMockKeyStore();
      const crypto = new CryptoProvider();
      const identity = await crypto.generateIdentity();
      const aid = 'test-user.example.com';

      await ks.saveIdentity(aid, {
        ...(identity as IdentityRecord),
        aid,
      });

      const auth = new AuthFlow({ keystore: ks, crypto, aid });
      const loaded = await auth.loadIdentity(aid);
      expect(loaded).not.toBeNull();
      expect(loaded.aid).toBe(aid);
      expect(loaded.private_key_pem).toBe(identity.private_key_pem);
    },
  );
});

describe('AuthFlow.loadIdentityOrNull', () => {
  it('无身份时应返回 null 而非抛异常', async () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ keystore: ks, crypto: new CryptoProvider() });

    const result = await auth.loadIdentityOrNull();
    expect(result).toBeNull();
  });
});

describe('AuthFlow.loadIdentityOrNone', () => {
  it('应作为 loadIdentityOrNull 的兼容别名返回 null', async () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ keystore: ks, crypto: new CryptoProvider() });

    const result = await auth.loadIdentityOrNone();
    expect(result).toBeNull();
  });
});

describe('AuthFlow.getAccessTokenExpiry', () => {
  it('有 access_token_expires_at 时应返回时间戳', () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ keystore: ks, crypto: new CryptoProvider() });

    const identity = { access_token_expires_at: 1700000000 };
    expect(auth.getAccessTokenExpiry(identity)).toBe(1700000000);
  });

  it('无 access_token_expires_at 时应返回 null', () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ keystore: ks, crypto: new CryptoProvider() });

    expect(auth.getAccessTokenExpiry({})).toBeNull();
  });
});
