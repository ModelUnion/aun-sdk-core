// ── auth 模块单元测试（桩测试）──────────────────────────────
// AuthFlow 的完整测试需要 Gateway 环境（WebSocket + PKI），
// 此处仅测试可独立验证的工具方法和构造逻辑。
import { describe, it, expect, vi } from 'vitest';
import { AuthFlow } from '../../src/auth.js';
import { CryptoProvider } from '../../src/crypto.js';
import type { KeyStore } from '../../src/keystore/index.js';
import { AuthError, StateError } from '../../src/errors.js';
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
      tokenStore: ks,
      crypto: new CryptoProvider(),
    });
    expect(auth).toBeDefined();
  });
});

describe('AuthFlow.loadIdentity', () => {
  it('无身份时应抛出 StateError', async () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider() });

    await expect(auth.loadIdentity()).rejects.toThrow(StateError);
  });

  it.skipIf(!hasSubtleCrypto)(
    '注入身份后应正确加载',
    async () => {
      const ks = createMockKeyStore();
      const crypto = new CryptoProvider();
      const identity = await crypto.generateIdentity();
      const aid = 'test-user.example.com';

      const auth = new AuthFlow({ tokenStore: ks, crypto, aid });
      auth.setIdentity({ ...(identity as IdentityRecord), aid });
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
    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider() });

    const result = await auth.loadIdentityOrNull();
    expect(result).toBeNull();
  });
});

describe('AuthFlow.loadIdentityOrNone', () => {
  it('应作为 loadIdentityOrNull 的兼容别名返回 null', async () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider() });

    const result = await auth.loadIdentityOrNone();
    expect(result).toBeNull();
  });
});

describe('AuthFlow 空 device_id 实例态', () => {
  it('空 device_id 应从 instance_state 加载实例级 token', async () => {
    const keystore = {
      loadInstanceState: vi.fn().mockResolvedValue({ access_token: 'tok-empty-device' }),
      saveIdentity: vi.fn(),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: '',
      verifySsl: false,
    });

    const state = await (auth as any)._loadInstanceState('alice.agentid.pub');

    expect(keystore.loadInstanceState).toHaveBeenCalledWith('alice.agentid.pub', '', '');
    expect(state.access_token).toBe('tok-empty-device');
  });

  it('空 device_id 应写入 instance_state 而不是留在共享身份元数据', async () => {
    const updatedStates: Record<string, unknown>[] = [];
    const keystore = {
      saveIdentity: vi.fn().mockResolvedValue(undefined),
      updateInstanceState: vi.fn(async (_aid: string, _deviceId: string, _slotId: string, updater: (state: Record<string, unknown>) => Record<string, unknown> | void) => {
        const current: Record<string, unknown> = {};
        updater(current);
        updatedStates.push({ ...current });
        return current;
      }),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: '',
      verifySsl: false,
    });

    await (auth as any)._persistIdentity({
      aid: 'alice.agentid.pub',
      private_key_pem: 'PRIVATE',
      access_token: 'tok-empty-device',
      refresh_token: 'ref-empty-device',
    });

    expect(keystore.updateInstanceState).toHaveBeenCalledWith('alice.agentid.pub', '', '', expect.any(Function));
    expect(updatedStates[0]).toMatchObject({
      access_token: 'tok-empty-device',
      refresh_token: 'ref-empty-device',
    });
  });

  it('refresh 业务失败且要求重登时应清掉本地 token 缓存', async () => {
    const updatedStates: Record<string, unknown>[] = [];
    const keystore = {
      saveIdentity: vi.fn().mockResolvedValue(undefined),
      updateInstanceState: vi.fn(async (_aid: string, _deviceId: string, _slotId: string, updater: (state: Record<string, unknown>) => Record<string, unknown> | void) => {
        const current: Record<string, unknown> = {
          access_token: 'old-access',
          refresh_token: 'old-refresh',
          kite_token: 'old-kite',
          access_token_expires_at: 123456,
        };
        const updated = updater(current) ?? current;
        updatedStates.push({ ...updated });
        return updated;
      }),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: 'dev-refresh',
      slotId: 'slot-refresh',
      verifySsl: false,
    });
    const identity: Record<string, unknown> = {
      aid: 'alice.agentid.pub',
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      kite_token: 'old-kite',
      access_token_expires_at: 123456,
    };
    (auth as any)._refreshAccessToken = vi.fn().mockRejectedValue(new AuthError('invalid_or_expired_refresh_token', {
      data: {
        success: false,
        error: 'invalid_or_expired_refresh_token',
        relogin_required: true,
      },
    }));

    await expect(auth.refreshCachedTokens('ws://gateway/aun', identity as any)).rejects.toThrow(AuthError);

    expect(identity.access_token).toBe('');
    expect(identity.refresh_token).toBe('');
    expect(identity.kite_token).toBe('');
    expect(identity.access_token_expires_at).toBe(0);
    expect(keystore.updateInstanceState).toHaveBeenCalledWith('alice.agentid.pub', 'dev-refresh', 'slot-refresh', expect.any(Function));
    expect(updatedStates[updatedStates.length - 1]).toMatchObject({
      access_token: '',
      refresh_token: '',
      kite_token: '',
      access_token_expires_at: 0,
    });
  });

  it('connectSession 在 refresh 失败后应继续走两步登录', async () => {
    const keystore = {
      saveIdentity: vi.fn().mockResolvedValue(undefined),
      updateInstanceState: vi.fn(async (_aid: string, _deviceId: string, _slotId: string, updater: (state: Record<string, unknown>) => Record<string, unknown> | void) => {
        const current: Record<string, unknown> = {};
        return updater(current) ?? current;
      }),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: 'dev-refresh',
      slotId: 'slot-refresh',
      verifySsl: false,
    });
    const identity: Record<string, unknown> = {
      aid: 'alice.agentid.pub',
      access_token: 'expired-access',
      refresh_token: 'expired-refresh',
      kite_token: 'old-kite',
      access_token_expires_at: 1,
    };
    auth.loadIdentity = vi.fn().mockResolvedValue(identity as any);
    auth.refreshCachedTokens = vi.fn().mockRejectedValue(new AuthError('invalid_or_expired_refresh_token', {
      data: {
        success: false,
        error: 'invalid_or_expired_refresh_token',
        relogin_required: true,
      },
    }));
    auth.authenticate = vi.fn().mockResolvedValue({ access_token: 'login-access' });
    (auth as any)._initializeSession = vi.fn().mockResolvedValue({ status: 'ok' });

    const result = await auth.connectSession(
      { call: vi.fn() } as any,
      { params: { nonce: 'nonce-1' } },
      'ws://gateway/aun',
    );

    expect(auth.authenticate).toHaveBeenCalledWith('ws://gateway/aun', 'alice.agentid.pub');
    expect(result.token).toBe('login-access');
    expect(identity.access_token).toBe('');
    expect(identity.refresh_token).toBe('');
  });
});
describe('AuthFlow.getAccessTokenExpiry', () => {
  it('有 access_token_expires_at 时应返回时间戳', () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider() });

    const identity = { access_token_expires_at: 1700000000 };
    expect(auth.getAccessTokenExpiry(identity)).toBe(1700000000);
  });

  it('无 access_token_expires_at 时应返回 null', () => {
    const ks = createMockKeyStore();
    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider() });

    expect(auth.getAccessTokenExpiry({})).toBeNull();
  });
});
