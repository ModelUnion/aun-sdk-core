// ── token 复用 + gateway_url 持久化 — 与 Python SDK 行为对齐的单元测试 ──
//
// 覆盖两组改进：
//   A. AuthFlow.authenticate() 优先复用 cached access_token（未过期且有 refresh_token）
//   B. AUNClient/AIDStore gateway 解析命中 keystore 缓存时跳过 well-known discovery，
//      discovery 成功后写入 keystore metadata（key='gateway_url'）

import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { AIDStore } from '../../src/aid-store.js';
import { AuthFlow } from '../../src/auth.js';
import { CryptoProvider } from '../../src/crypto.js';
import type { KeyStore } from '../../src/keystore/index.js';
import type { IdentityRecord, KeyPairRecord } from '../../src/types.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ── 内存 KeyStore mock（含 metadata KV，用于 gateway_url 测试）────────
function createMockKeyStore(): KeyStore & { _md: Map<string, Map<string, string>> } {
  const keyPairs = new Map<string, KeyPairRecord>();
  const certs = new Map<string, string>();
  const identities = new Map<string, IdentityRecord>();
  const md = new Map<string, Map<string, string>>();
  return {
    _md: md,
    async loadKeyPair(aid) {
      return keyPairs.get(aid) ?? null;
    },
    async saveKeyPair(aid, kp) {
      keyPairs.set(aid, kp);
    },
    async loadCert(aid) {
      return certs.get(aid) ?? null;
    },
    async saveCert(aid, cert) {
      certs.set(aid, cert);
    },
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
    async getMetadata(aid, key) {
      return md.get(aid)?.get(key) ?? '';
    },
    async setMetadata(aid, key, value) {
      let bucket = md.get(aid);
      if (!bucket) {
        bucket = new Map();
        md.set(aid, bucket);
      }
      if (!value) bucket.delete(key);
      else bucket.set(key, value);
    },
  };
}

// ── A. authenticate() 优先复用 cached access_token ─────────────────────

describe('AuthFlow.authenticate cached token reuse', () => {
  it('1) cached token 未过期且有 refresh_token 时直接返回，不走 _login', async () => {
    const ks = createMockKeyStore();
    const aid = 'alice.agentid.pub';
    const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
    await ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PEM',
      public_key_der_b64: 'PUB',
      curve: 'P-256',
      cert: 'CERT',
      access_token: 'cached-access',
      refresh_token: 'cached-refresh',
      access_token_expires_at: futureExpiry,
    });

    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider(), aid });
    auth.setIdentity({ aid, private_key_pem: 'PEM', public_key_der_b64: 'PUB', curve: 'P-256', cert: 'CERT', access_token: 'cached-access', refresh_token: 'cached-refresh', access_token_expires_at: futureExpiry });
    const loginSpy = vi.spyOn(auth as any, '_login').mockRejectedValue(new Error('should not be called'));

    const result = await auth.authenticate('ws://gateway/aun', aid);

    expect(loginSpy).not.toHaveBeenCalled();
    expect(result).toEqual({
      aid,
      access_token: 'cached-access',
      refresh_token: 'cached-refresh',
      expires_at: futureExpiry,
      gateway: 'ws://gateway/aun',
    });
  });

  it('2) 无 cached_token 时走 _login', async () => {
    const ks = createMockKeyStore();
    const aid = 'alice.agentid.pub';
    await ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PEM',
      public_key_der_b64: 'PUB',
      curve: 'P-256',
      cert: 'CERT',
      // 没有 access_token，也没有 refresh_token
    });

    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider(), aid });
    auth.setIdentity({ aid, private_key_pem: 'PEM', public_key_der_b64: 'PUB', curve: 'P-256', cert: 'CERT' });
    const loginSpy = vi.spyOn(auth as any, '_login').mockResolvedValue({
      access_token: 'fresh-access',
      refresh_token: 'fresh-refresh',
      expires_in: 3600,
    });
    vi.spyOn(auth as any, '_assertCertMatchesLocalKeypair').mockReturnValue(undefined);
    vi.spyOn(auth as any, '_validateNewCert').mockResolvedValue(undefined);

    const result = await auth.authenticate('ws://gateway/aun', aid);

    expect(loginSpy).toHaveBeenCalledTimes(1);
    expect(result.access_token).toBe('fresh-access');
    expect(result.refresh_token).toBe('fresh-refresh');
  });

  it('3) cached_token 已过期时走 _login', async () => {
    const ks = createMockKeyStore();
    const aid = 'alice.agentid.pub';
    const pastExpiry = Math.floor(Date.now() / 1000) - 60; // 已过期
    await ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PEM',
      public_key_der_b64: 'PUB',
      curve: 'P-256',
      cert: 'CERT',
      access_token: 'expired-access',
      refresh_token: 'cached-refresh',
      access_token_expires_at: pastExpiry,
    });

    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider(), aid });
    auth.setIdentity({ aid, private_key_pem: 'PEM', public_key_der_b64: 'PUB', curve: 'P-256', cert: 'CERT' });
    const loginSpy = vi.spyOn(auth as any, '_login').mockResolvedValue({
      access_token: 'fresh-access',
      refresh_token: 'fresh-refresh',
      expires_in: 3600,
    });
    vi.spyOn(auth as any, '_assertCertMatchesLocalKeypair').mockReturnValue(undefined);
    vi.spyOn(auth as any, '_validateNewCert').mockResolvedValue(undefined);

    const result = await auth.authenticate('ws://gateway/aun', aid);

    expect(loginSpy).toHaveBeenCalledTimes(1);
    expect(result.access_token).toBe('fresh-access');
  });

  it('3b) 有 cached_token 但缺 refresh_token 时仍走 _login（与 Python 一致）', async () => {
    const ks = createMockKeyStore();
    const aid = 'alice.agentid.pub';
    const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
    await ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PEM',
      public_key_der_b64: 'PUB',
      curve: 'P-256',
      cert: 'CERT',
      access_token: 'cached-access',
      access_token_expires_at: futureExpiry,
      // 没有 refresh_token
    });

    const auth = new AuthFlow({ tokenStore: ks, crypto: new CryptoProvider(), aid });
    auth.setIdentity({ aid, private_key_pem: 'PEM', public_key_der_b64: 'PUB', curve: 'P-256', cert: 'CERT' });
    const loginSpy = vi.spyOn(auth as any, '_login').mockResolvedValue({
      access_token: 'fresh-access',
      refresh_token: 'fresh-refresh',
      expires_in: 3600,
    });
    vi.spyOn(auth as any, '_assertCertMatchesLocalKeypair').mockReturnValue(undefined);
    vi.spyOn(auth as any, '_validateNewCert').mockResolvedValue(undefined);

    await auth.authenticate('ws://gateway/aun', aid);
    expect(loginSpy).toHaveBeenCalledTimes(1);
  });
});

// ── B. _resolveGateway IndexedDB 缓存与持久化 ────────────────────────

describe('gateway_url cache + persist', () => {
  it('4) keystore 命中 gateway_url 缓存时跳过 discovery', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.agentid.pub';
    const ks = (client as any)._tokenStore;
    await ks.setMetadata('alice.agentid.pub', 'gateway_url', 'ws://cached-gateway/aun');

    const discoverSpy = vi
      .spyOn((client as any)._discovery, 'discover')
      .mockRejectedValue(new Error('discovery should not be called'));

    const url = await (client as any)._resolveGatewayForAid('alice.agentid.pub');

    expect(url).toBe('ws://cached-gateway/aun');
    expect(discoverSpy).not.toHaveBeenCalled();
    // 命中缓存后写回到内存 _gatewayUrl
    expect(client.gatewayUrl).toBe('ws://cached-gateway/aun');
  });

  it('5) discovery 成功后将 gateway_url 写入 keystore metadata', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'bob.agentid.pub';

    const discoverSpy = vi
      .spyOn((client as any)._discovery, 'discover')
      .mockResolvedValue('ws://discovered-gateway/aun');

    const url = await (client as any)._resolveGatewayForAid('bob.agentid.pub');

    expect(url).toBe('ws://discovered-gateway/aun');
    expect(discoverSpy).toHaveBeenCalled();

    const ks = (client as any)._tokenStore;
    const persisted = await ks.getMetadata('bob.agentid.pub', 'gateway_url');
    expect(persisted).toBe('ws://discovered-gateway/aun');
  });

  it('5b) primary 失败但 fallback 成功时也持久化', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'charlie.agentid.pub';

    const discoverSpy = vi
      .spyOn((client as any)._discovery, 'discover')
      .mockRejectedValueOnce(new Error('primary not reachable'))
      .mockResolvedValueOnce('ws://fallback-gateway/aun');

    const url = await (client as any)._resolveGatewayForAid('charlie.agentid.pub');

    expect(url).toBe('ws://fallback-gateway/aun');
    expect(discoverSpy).toHaveBeenCalledTimes(2);

    const ks = (client as any)._tokenStore;
    const persisted = await ks.getMetadata('charlie.agentid.pub', 'gateway_url');
    expect(persisted).toBe('ws://fallback-gateway/aun');
  });

  it('6) 内存 _gatewayUrl 优先于 keystore 缓存和 discovery', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'dave.agentid.pub';
    (client as any)._gatewayUrl = 'ws://memory-gateway/aun';

    const ks = (client as any)._tokenStore;
    await ks.setMetadata('dave.agentid.pub', 'gateway_url', 'ws://stale-cache/aun');

    const discoverSpy = vi.spyOn((client as any)._discovery, 'discover');
    const getMetaSpy = vi.spyOn(ks, 'getMetadata');

    const url = await (client as any)._resolveGatewayForAid('dave.agentid.pub');

    expect(url).toBe('ws://memory-gateway/aun');
    expect(discoverSpy).not.toHaveBeenCalled();
    expect(getMetaSpy).not.toHaveBeenCalled();
  });

  it('7) 空字符串不写入 keystore（_persistGatewayUrl 防御性检查）', async () => {
    const store = new AIDStore({ aunPath: 'aun', encryptionSeed: '' });
    const ks = createMockKeyStore();
    (store as any)._keystore = ks;
    const setSpy = vi.spyOn(ks, 'setMetadata');

    await (store as any)._persistGatewayUrl('eve.agentid.pub', '');

    expect(setSpy).not.toHaveBeenCalled();
  });

  it('8) keystore 无 gateway_url 记录时返回空（不阻塞 discovery）', async () => {
    const store = new AIDStore({ aunPath: 'aun', encryptionSeed: '' });
    (store as any)._keystore = createMockKeyStore();
    const cached = await (store as any)._loadCachedGatewayUrl('frank.agentid.pub');
    expect(cached).toBe('');
  });
});
