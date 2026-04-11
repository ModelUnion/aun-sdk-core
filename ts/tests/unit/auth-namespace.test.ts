import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { AUNClient } from '../../src/client.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('AuthNamespace agent.md', () => {
  it('底层 AuthFlow 兼容 loadIdentityOrNull 命名', () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    const result = (client as any)._auth.loadIdentityOrNull();
    expect(result).toBeNull();
  });

  it('uploadAgentMd 应复用缓存 access_token', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    (client as any)._gatewayUrl = 'ws://gateway.agentid.pub/aun';
    (client as any)._aid = 'alice.agentid.pub';
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue({
      aid: 'alice.agentid.pub',
      access_token: 'cached-token',
      access_token_expires_at: Date.now() / 1000 + 3600,
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ aid: 'alice.agentid.pub', etag: '"etag-1"' }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.auth.uploadAgentMd('# Alice\n');

    expect(result).toEqual({ aid: 'alice.agentid.pub', etag: '"etag-1"' });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://alice.agentid.pub/agent.md',
      expect.objectContaining({
        method: 'PUT',
        body: '# Alice\n',
        headers: expect.objectContaining({
          Authorization: 'Bearer cached-token',
          'Content-Type': 'text/markdown; charset=utf-8',
        }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('uploadAgentMd 在 token 缺失时应回退 authenticate', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    (client as any)._gatewayUrl = 'ws://gateway.agentid.pub/aun';
    (client as any)._aid = 'alice.agentid.pub';
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue({
      aid: 'alice.agentid.pub',
    });

    const authSpy = vi.spyOn(client.auth, 'authenticate').mockResolvedValue({
      aid: 'alice.agentid.pub',
      access_token: 'fresh-token',
      gateway: 'ws://gateway.agentid.pub/aun',
    });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ aid: 'alice.agentid.pub', etag: '"etag-2"' }),
      text: async () => '',
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.auth.uploadAgentMd('# Alice\n');

    expect(result).toEqual({ aid: 'alice.agentid.pub', etag: '"etag-2"' });
    expect(authSpy).toHaveBeenCalledWith({ aid: 'alice.agentid.pub' });
    expect(fetchMock).toHaveBeenCalledWith(
      'http://alice.agentid.pub/agent.md',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer fresh-token',
        }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('downloadAgentMd 应匿名下载', async () => {
    const client = new AUNClient({
      aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')),
      discovery_port: 18443,
    });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => '# Bob\n',
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.auth.downloadAgentMd('bob.agentid.pub');

    expect(result).toBe('# Bob\n');
    expect(fetchMock).toHaveBeenCalledWith(
      'https://bob.agentid.pub:18443/agent.md',
      expect.objectContaining({
        method: 'GET',
        headers: { Accept: 'text/markdown' },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('downloadAgentMd 超时应抛明确错误', async () => {
    vi.useFakeTimers();
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn().mockImplementation(async (_url, init?: RequestInit) => (
      await new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      })
    ));
    vi.stubGlobal('fetch', fetchMock);

    const promise = client.auth.downloadAgentMd('bob.agentid.pub');
    const assertion = expect(promise).rejects.toThrow('agent.md request timed out');
    await vi.advanceTimersByTimeAsync(30_000);

    await assertion;
    vi.useRealTimers();
  });
});
