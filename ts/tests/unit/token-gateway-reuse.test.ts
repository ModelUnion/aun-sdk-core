/**
 * Token 复用 + gateway 持久化单元测试。
 *
 * 验证：
 * 1. authenticate() 优先复用 keystore 里的 cached access_token，跳过两阶段重登
 * 2. authenticate() 在没有 cached_token 时走 _login
 * 3. authenticate() 在 cached_token 过期时走 _login
 * 4. _resolveGateway 在 keystore metadata 命中时跳过 well-known discovery
 * 5. _resolveGateway 在 discovery 成功后持久化 gateway_url
 * 6. 内存 _gatewayUrl 优先于 keystore 缓存
 * 7. 空字符串不写入 keystore
 * 8. keystore 无记录时返回空字符串
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { AUNClient } from '../../src/client.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function setupClient(): AUNClient {
  const aunPath = mkdtempSync(join(tmpdir(), 'aun-token-gw-reuse-'));
  return new AUNClient({ aun_path: aunPath });
}

function setupClientWithAid(aid: string): AUNClient {
  const aunPath = mkdtempSync(join(tmpdir(), 'aun-token-gw-reuse-'));
  // 建立 AID 目录，让 _persistGatewayUrl 能写入
  const safe = aid.replace(/[\/\\:]/g, '_');
  mkdirSync(join(aunPath, 'AIDs', safe), { recursive: true });
  return new AUNClient({ aun_path: aunPath });
}

function loadGatewayMetadata(client: AUNClient, aid: string): string {
  return String((client as any)._keystore.loadMetadata(aid)?.gateway_url ?? '').trim();
}

// ── 改进 A: authenticate() 复用 cached_token ─────────────────────────

describe('AuthFlow.authenticate cached_token 复用', () => {
  it('keystore 里有有效 cached_token 时直接返回，不走 _login', async () => {
    const aid = 'alice.test.com';
    const client = setupClient();
    const authFlow = (client as any)._auth;

    const futureExpiry = Math.floor(Date.now() / 1000) + 3600;
    const identity = {
      aid,
      private_key_pem: '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----',
      public_key_der_b64: 'AAAA',
      cert: '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----',
      access_token: 'cached-access-tok',
      refresh_token: 'cached-refresh-tok',
      access_token_expires_at: futureExpiry,
    };

    authFlow._loadIdentityOrRaise = vi.fn().mockReturnValue(identity);
    authFlow._validateCachedCredentials = vi.fn().mockReturnValue('');
    const loginSpy = vi.fn();
    authFlow._login = loginSpy;

    const result = await authFlow.authenticate('ws://gateway/aun', { aid });

    expect(loginSpy).not.toHaveBeenCalled();
    expect(result.access_token).toBe('cached-access-tok');
    expect(result.refresh_token).toBe('cached-refresh-tok');
    expect(result.aid).toBe(aid);
    expect(result.gateway).toBe('ws://gateway/aun');
  });

  it('没有 cached_token 时走 _login', async () => {
    const aid = 'alice.test.com';
    const client = setupClient();
    const authFlow = (client as any)._auth;

    const identity = {
      aid,
      private_key_pem: 'fake',
      public_key_der_b64: 'AAAA',
      cert: 'fake-cert',
      // 没有 access_token / refresh_token
    };

    authFlow._loadIdentityOrRaise = vi.fn().mockReturnValue(identity);
    authFlow._assertCertMatchesLocalKeypair = vi.fn();
    authFlow._validateCachedCredentials = vi.fn().mockReturnValue('no certificate');
    authFlow._login = vi.fn().mockResolvedValue({
      access_token: 'new-tok',
      refresh_token: 'new-refresh',
      expires_in: 3600,
    });
    authFlow._validateNewCert = vi.fn().mockResolvedValue(undefined);
    authFlow._persistIdentity = vi.fn();

    const result = await authFlow.authenticate('ws://gateway/aun', { aid });

    expect(authFlow._login).toHaveBeenCalledTimes(1);
    expect(result.access_token).toBe('new-tok');
  });

  it('cached_token 已过期时走 _login', async () => {
    const aid = 'alice.test.com';
    const client = setupClient();
    const authFlow = (client as any)._auth;

    const pastExpiry = Math.floor(Date.now() / 1000) - 100;
    const identity = {
      aid,
      private_key_pem: 'fake',
      public_key_der_b64: 'AAAA',
      cert: 'fake-cert',
      access_token: 'expired-tok',
      refresh_token: 'old-refresh',
      access_token_expires_at: pastExpiry,
    };

    authFlow._loadIdentityOrRaise = vi.fn().mockReturnValue(identity);
    authFlow._assertCertMatchesLocalKeypair = vi.fn();
    authFlow._validateCachedCredentials = vi.fn().mockReturnValue('access_token expired');
    authFlow._login = vi.fn().mockResolvedValue({
      access_token: 'fresh-tok',
      refresh_token: 'fresh-refresh',
      expires_in: 3600,
    });
    authFlow._validateNewCert = vi.fn().mockResolvedValue(undefined);
    authFlow._persistIdentity = vi.fn();

    const result = await authFlow.authenticate('ws://gateway/aun', { aid });

    expect(authFlow._login).toHaveBeenCalledTimes(1);
    expect(result.access_token).toBe('fresh-tok');
  });
});

// ── 改进 B: gateway_url 持久化 ───────────────────────────────────────

describe('AUNClient._resolveGatewayForAid keystore 持久化', () => {
  it('keystore metadata 命中时跳过 discovery', async () => {
    const aid = 'alice.test.com';
    const client = setupClientWithAid(aid);
    (client as any)._aid = aid;

    (client as any)._keystore.saveMetadata(aid, { gateway_url: 'wss://cached-gateway.test/aun' });

    // mock discovery —— 不应被调用
    const discoverSpy = vi.fn();
    (client as any)._discovery = { discover: discoverSpy };

    const result = await (client as any)._resolveGatewayForAid(aid);

    expect(result).toBe('wss://cached-gateway.test/aun');
    expect(discoverSpy).not.toHaveBeenCalled();
  });

  it('discovery 成功后 gateway_url 应被写入 keystore metadata', async () => {
    const aid = 'alice.test.com';
    const client = setupClientWithAid(aid);
    (client as any)._aid = aid;
    (client as any)._gatewayUrl = null;

    const discoverSpy = vi.fn().mockResolvedValue('wss://discovered.test/aun');
    (client as any)._discovery = { discover: discoverSpy };

    const result = await (client as any)._resolveGatewayForAid(aid);
    expect(result).toBe('wss://discovered.test/aun');

    expect(loadGatewayMetadata(client, aid)).toBe('wss://discovered.test/aun');
  });

  it('内存里的 _gatewayUrl 优先级最高（即使 keystore 有值）', async () => {
    const aid = 'alice.test.com';
    const client = setupClient();
    (client as any)._aid = aid;

    (client as any)._keystore.saveMetadata(aid, { gateway_url: 'wss://stale.test/aun' });
    (client as any)._gatewayUrl = 'wss://memory-fresh.test/aun';

    const discoverSpy = vi.fn();
    (client as any)._discovery = { discover: discoverSpy };

    const result = await (client as any)._resolveGatewayForAid(aid);
    expect(result).toBe('wss://memory-fresh.test/aun');
    expect(discoverSpy).not.toHaveBeenCalled();
  });

  it('keystore 没有记录时返回空字符串', () => {
    const aid = 'alice-no-record.test.com';
    const client = setupClient();

    expect(loadGatewayMetadata(client, aid)).toBe('');
  });

  it('authenticate discovery 成功后应补写 gateway_url 缓存', async () => {
    const aid = 'alice.test.com';
    const client = setupClientWithAid(aid);
    (client as any)._aid = aid;
    (client as any)._currentAid = { aid, isPrivateKeyValid: () => true };
    (client as any)._state = 'standby';
    (client as any)._gatewayUrl = null;
    (client as any)._discovery = {
      discover: vi.fn().mockResolvedValue('wss://discovered-auth.test/aun'),
    };
    (client as any)._auth.authenticate = vi.fn().mockResolvedValue({
      aid,
      access_token: 'tok',
      refresh_token: 'ref',
      gateway: 'wss://discovered-auth.test/aun',
    });
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue({ aid });

    await client.authenticate();

    expect(loadGatewayMetadata(client, aid)).toBe('wss://discovered-auth.test/aun');
  });
});

