import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { AUNClient } from '../../src/client.js';
import { buildIdentity, generateECKeypair } from './helpers.js';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function waitUntil(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('timed out waiting for condition');
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

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
        redirect: 'follow',
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it('并发手动 downloadAgentMd 同一 AID 应共用同一个下载任务', async () => {
    const client = new AUNClient({
      aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')),
      discovery_port: 18443,
    });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';
    let markStarted!: () => void;
    let releaseFetch!: () => void;
    const started = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseFetch = resolve;
    });
    const fetchMock = vi.fn().mockImplementation(async () => {
      markStarted();
      await release;
      return {
        ok: true,
        status: 200,
        text: async () => '# Bob\n',
        headers: new Headers(),
      };
    });
    vi.stubGlobal('fetch', fetchMock);

    const first = client.auth.downloadAgentMd('bob.agentid.pub');
    await started;
    const second = client.auth.downloadAgentMd('bob.agentid.pub');
    await Promise.resolve();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    releaseFetch();
    await expect(Promise.all([first, second])).resolves.toEqual(['# Bob\n', '# Bob\n']);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect((client.auth as any)._agentMdDownloadInflight.size).toBe(0);
  });

  it('不同 AID 的 downloadAgentMd 应受全局 8 并发上限控制', async () => {
    const client = new AUNClient({
      aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')),
      discovery_port: 18443,
    });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';
    let active = 0;
    let maxActive = 0;
    let started = 0;
    let releaseAll!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseAll = resolve;
    });
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      started += 1;
      await gate;
      active -= 1;
      return {
        ok: true,
        status: 200,
        text: async () => `# ${url}\n`,
        headers: new Headers(),
      };
    });
    vi.stubGlobal('fetch', fetchMock);

    const downloads = Array.from({ length: 10 }, (_, index) =>
      client.auth.downloadAgentMd(`aid-${index}.agentid.pub`));
    await waitUntil(() => started === 8);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(started).toBe(8);
    expect(maxActive).toBeLessThanOrEqual(8);

    releaseAll();
    await Promise.all(downloads);
    expect(fetchMock).toHaveBeenCalledTimes(10);
    expect(maxActive).toBeLessThanOrEqual(8);
  });

  it('downloadAgentMd 遇到 304 且已有正文缓存时应返回缓存正文', async () => {
    const client = new AUNClient({
      aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')),
      discovery_port: 18443,
    });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => '# Bob v1\n',
        headers: new Headers({
          ETag: '"etag-v1"',
          'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 304,
        text: async () => '',
        headers: new Headers(),
      });
    vi.stubGlobal('fetch', fetchMock);

    await expect(client.auth.downloadAgentMd('bob.agentid.pub')).resolves.toBe('# Bob v1\n');
    await expect(client.auth.downloadAgentMd('bob.agentid.pub')).resolves.toBe('# Bob v1\n');

    expect((fetchMock.mock.calls[1][1] as RequestInit).headers).toEqual({ Accept: 'text/markdown' });
  });

  it('downloadAgentMd 只有 ETag 没有正文缓存时应无条件 GET', async () => {
    const client = new AUNClient({
      aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')),
      discovery_port: 18443,
    });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => '',
        headers: new Headers({
          ETag: '"head-only"',
          'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 304,
        text: async () => '',
        headers: new Headers(),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => '# Bob fresh\n',
        headers: new Headers({ ETag: '"head-only"' }),
      });
    vi.stubGlobal('fetch', fetchMock);

    await expect((client.auth as any).headAgentMd('bob.agentid.pub')).resolves.toMatchObject({
      found: true,
      etag: '"head-only"',
      status: 200,
    });
    await expect(client.auth.downloadAgentMd('bob.agentid.pub')).resolves.toBe('# Bob fresh\n');

    expect((fetchMock.mock.calls[1][1] as RequestInit).headers).toEqual({ Accept: 'text/markdown' });
    expect((fetchMock.mock.calls[2][1] as RequestInit).headers).toEqual({ Accept: 'text/markdown' });
  });

  it('headAgentMd 遇到 304 应返回 not modified 元数据而不是错误', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';

    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => '',
        headers: new Headers({
          ETag: '"etag-v1"',
          'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT',
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 304,
        text: async () => '',
        headers: new Headers(),
      });
    vi.stubGlobal('fetch', fetchMock);

    await (client.auth as any).headAgentMd('bob.agentid.pub');
    await expect((client.auth as any).headAgentMd('bob.agentid.pub')).resolves.toMatchObject({
      found: true,
      etag: '"etag-v1"',
      last_modified: 'Sun, 24 May 2026 00:00:00 GMT',
      status: 304,
    });
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

  it('signAgentMd 应在尾部追加签名块并保留原 payload', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue(identity);

    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signed = await client.auth.signAgentMd(payload);

    expect(signed.startsWith(payload)).toBe(true);
    expect(signed).toContain('<!-- AUN-SIGNATURE');
    expect(signed).toMatch(/signature: [A-Za-z0-9+/=]+/);
    expect(signed).toMatch(/-->\s*$/);
  });

  it('verifyAgentMd 应返回 unsigned / verified / invalid 三态', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue(identity);

    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signed = await client.auth.signAgentMd(payload);

    const unsigned = await client.auth.verifyAgentMd(payload);
    expect(unsigned.status).toBe('unsigned');
    expect(unsigned.verified).toBe(false);

    const verified = await client.auth.verifyAgentMd(signed, {
      aid: identity.aid,
      certPem: identity.cert,
    });
    expect(verified.status).toBe('verified');
    expect(verified.verified).toBe(true);
    expect(verified.payload).toBe(payload);

    const tampered = signed.replace('Alice', 'Mallory');
    const invalid = await client.auth.verifyAgentMd(tampered, {
      aid: identity.aid,
      certPem: identity.cert,
    });
    expect(invalid.status).toBe('invalid');
    expect(invalid.verified).toBe(false);
  });

  it('verifyAgentMd 应在未传 certPem 时回退 _fetchPeerCert', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue(identity);
    (client as any)._fetchPeerCert = vi.fn().mockResolvedValue(identity.cert);

    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signed = await client.auth.signAgentMd(payload);
    const verified = await client.auth.verifyAgentMd(signed, { aid: identity.aid });

    expect(verified.status).toBe('verified');
    expect((client as any)._fetchPeerCert).toHaveBeenCalledTimes(1);
  });

  it('signAgentMd 重新签名时应替换已有签名块', async () => {
    const client = new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-auth-ns-')) });
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    (client as any)._aid = identity.aid;
    (client as any)._auth.loadIdentityOrNone = vi.fn().mockReturnValue(identity);

    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signedOnce = await client.auth.signAgentMd(payload);
    const signedTwice = await client.auth.signAgentMd(signedOnce);

    expect(signedTwice.match(/<!-- AUN-SIGNATURE/g)?.length).toBe(1);
    expect(signedTwice.startsWith(payload)).toBe(true);
  });
});
