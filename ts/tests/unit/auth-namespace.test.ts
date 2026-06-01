import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AID } from '../../src/aid.js';
import { AgentMdManager } from '../../src/agent-md.js';
import { AUNClient } from '../../src/client.js';
import { buildIdentity, generateECKeypair } from './helpers.js';

function makeMockAid(aunPath: string): AID {
  return {
    aid: 'test.aid.com', aunPath, certPem: '', publicKey: '', certSubject: '',
    certNotBefore: new Date(), certNotAfter: new Date(Date.now() + 86400000),
    certIssuer: '', certFingerprint: '', deviceId: 'default', slotId: 'default',
    verifySsl: true, rootCaPath: null, debug: false,
    isCertValid: () => true, isPrivateKeyValid: () => true,
    sign: () => ({ ok: true, data: { signature: '' } }),
    verify: () => ({ ok: true, data: { valid: true } }),
    signAgentMd: (content: string) => ({ ok: true, data: { signed: content } }),
    verifyAgentMd: (content: string) => ({ ok: true, data: { status: 'verified' as const, payload: content } }),
  } as unknown as AID;
}

function aidFromIdentity(identity: any): AID {
  return AID._create({
    aid: String(identity.aid),
    aunPath: mkdtempSync(join(tmpdir(), 'aun-aid-agent-md-')),
    certPem: String(identity.cert ?? identity.cert_pem ?? ''),
    privateKeyPem: String(identity.private_key_pem ?? ''),
    certValid: true,
    privateKeyValid: true,
  });
}

function peer(aid: string): AID {
  const item = AID._create({
    aid,
    aunPath: '',
    certPem: '',
    privateKeyPem: null,
    certValid: true,
    privateKeyValid: false,
  });
  (item as any).verifyAgentMd = (content: string) => ({ ok: true, data: { status: 'unsigned' as const, payload: content } });
  return item;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf-8');
}

async function withServer<T>(
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
  fn: (port: number) => Promise<T>,
  host = '127.0.0.1',
): Promise<T> {
  const server = createServer((req, res) => void Promise.resolve(handler(req, res)).catch((err) => {
    res.statusCode = 500;
    res.end(String(err));
  }));
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  try {
    return await fn((server.address() as AddressInfo).port);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('AUNClient agent.md manager wiring', () => {
  it('底层 AuthFlow 兼容 loadIdentityOrNull 命名', () => {
    const client = new AUNClient(makeMockAid(mkdtempSync(join(tmpdir(), 'aun-auth-ns-'))));
    const result = (client as any)._auth.loadIdentityOrNull();
    expect(result).toBeNull();
  });

  it('uploadAgentMd 应复用缓存 access_token', async () => {
    await withServer(async (req, res) => {
      expect(req.method).toBe('PUT');
      expect(req.headers.authorization).toBe('Bearer cached-token');
      expect(await readBody(req)).toBe('# Alice\n');
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ aid: '127.0.0.1', etag: '"etag-1"' }));
    }, async (port) => {
      const client = new AUNClient(makeMockAid(mkdtempSync(join(tmpdir(), 'aun-auth-ns-'))));
      (client as any)._gatewayUrl = 'ws://gateway.agentid.pub/aun';
      (client as any)._aid = '127.0.0.1';
      (client as any)._identity = {
        aid: '127.0.0.1',
        access_token: 'cached-token',
        access_token_expires_at: Date.now() / 1000 + 3600,
      };
      (client as any)._currentAid = {
        aid: '127.0.0.1',
        isPrivateKeyValid: () => true,
        signAgentMd: (content: string) => ({ ok: true, data: { signed: content } }),
      };
      ((client as any)._agentMdManager as any)._discoveryPort = port;

      const result = await client.uploadAgentMd('# Alice\n');

      expect(result).toEqual({ aid: '127.0.0.1', etag: '"etag-1"' });
      (client as any)._tokenStore?.close?.();
    });
  });

  it('uploadAgentMd 在 token 缺失时应回退 authenticate', async () => {
    await withServer(async (req, res) => {
      expect(req.headers.authorization).toBe('Bearer fresh-token');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ aid: '127.0.0.1', etag: '"etag-2"' }));
    }, async (port) => {
      const client = new AUNClient(makeMockAid(mkdtempSync(join(tmpdir(), 'aun-auth-ns-'))));
      (client as any)._gatewayUrl = 'ws://gateway.agentid.pub/aun';
      (client as any)._aid = '127.0.0.1';
      (client as any)._identity = { aid: '127.0.0.1' };
      (client as any)._currentAid = {
        aid: '127.0.0.1',
        isPrivateKeyValid: () => true,
        signAgentMd: (content: string) => ({ ok: true, data: { signed: content } }),
      };
      ((client as any)._agentMdManager as any)._discoveryPort = port;
      const authSpy = vi.spyOn((client as any)._auth, 'authenticate').mockResolvedValue({
        aid: '127.0.0.1',
        access_token: 'fresh-token',
        gateway: 'ws://gateway.agentid.pub/aun',
      });
      vi.spyOn((client as any)._auth, 'loadIdentityOrNone').mockReturnValue({ aid: '127.0.0.1', access_token: 'fresh-token' });

      const result = await client.uploadAgentMd('# Alice\n');

      expect(result).toEqual({ aid: '127.0.0.1', etag: '"etag-2"' });
      expect(authSpy).toHaveBeenCalledWith('ws://gateway.agentid.pub/aun', { aid: '127.0.0.1' });
      (client as any)._tokenStore?.close?.();
    });
  });
});

describe('AgentMdManager network behavior', () => {
  it('downloadAgentMd 应匿名下载并验签', async () => {
    await withServer((_req, res) => {
      res.writeHead(200, { ETag: '"etag-bob"' });
      res.end('# Bob\n');
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-download-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => peer(aid),
      });

      const result = await mgr.download('127.0.0.1');

      expect(result.content).toBe('# Bob\n');
      expect(result.verification.status).toBe('unsigned');
    });
  });

  it('并发 downloadAgentMd 同一 AID 应共用同一个下载任务', async () => {
    let hits = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await withServer(async (_req, res) => {
      hits += 1;
      await gate;
      res.writeHead(200, { ETag: '"etag"' });
      res.end('# Bob\n');
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-flight-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => peer(aid),
      });

      const first = mgr.download('127.0.0.1');
      const second = mgr.download('127.0.0.1');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(hits).toBe(1);
      release();
      const results = await Promise.all([first, second]);
      expect(results.map((item) => item.content)).toEqual(['# Bob\n', '# Bob\n']);
      expect(hits).toBe(1);
    });
  });

  it('不同 AID 的 downloadAgentMd 应受全局 8 并发上限控制', async () => {
    let active = 0;
    let maxActive = 0;
    let started = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await withServer(async (_req, res) => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      started += 1;
      await gate;
      active -= 1;
      res.writeHead(200, { ETag: '"etag"' });
      res.end('# Peer\n');
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-concurrency-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => peer(aid),
      });
      const downloads = Array.from({ length: 10 }, (_, index) => mgr.download(`127.0.0.${index + 1}`));
      await vi.waitFor(() => expect(started).toBe(8));
      expect(maxActive).toBeLessThanOrEqual(8);
      release();
      await Promise.all(downloads);
      expect(started).toBe(10);
      expect(maxActive).toBeLessThanOrEqual(8);
    }, '0.0.0.0');
  });

  it('downloadAgentMd 每次请求都应使用无条件 GET', async () => {
    let hits = 0;
    await withServer((req, res) => {
      hits += 1;
      expect(req.headers['if-none-match']).toBeUndefined();
      expect(req.headers['if-modified-since']).toBeUndefined();
      if (hits === 1) {
        res.writeHead(200, { ETag: '"etag-v1"', 'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT' });
        res.end('# Bob v1\n');
        return;
      }
      res.writeHead(304, { ETag: '"etag-v1"', 'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT' });
      res.end();
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-304-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => peer(aid),
      });

      expect((await mgr.download('127.0.0.1')).content).toBe('# Bob v1\n');
      expect((await mgr.download('127.0.0.1')).content).toBe('# Bob v1\n');
      expect(hits).toBe(2);
    });
  });

  it('downloadAgentMd 只有 ETag 没有正文缓存时应无条件 GET 重试', async () => {
    let hits = 0;
    await withServer((req, res) => {
      hits += 1;
      expect(req.headers['if-none-match']).toBeUndefined();
      expect(req.headers['if-modified-since']).toBeUndefined();
      if (hits === 1) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, { ETag: '"head-only"' });
      res.end('# Bob fresh\n');
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-304-empty-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => peer(aid),
      });
      mgr.saveRecord('127.0.0.1', { remote_etag: '"head-only"', remote_status: 'found' });

      expect((await mgr.download('127.0.0.1')).content).toBe('# Bob fresh\n');
      expect(hits).toBe(2);
    });
  });

  it('downloadAgentMd 超时应抛明确错误', async () => {
    await withServer((_req, _res) => {
      // 保持连接悬挂，等待客户端超时。
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-timeout-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => peer(aid),
      });

      await expect(mgr.download('127.0.0.1', 20)).rejects.toThrow('agent.md request timed out');
    });
  });

  it('downloadAgentMd 验签时通过 peerResolver 获取对端 AID', async () => {
    await withServer((_req, res) => {
      res.writeHead(200);
      res.end('# Alice\n');
    }, async (port) => {
      const peerResolver = vi.fn((aid: string) => peer(aid));
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-peer-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver,
      });

      await mgr.download('127.0.0.1');

      expect(peerResolver).toHaveBeenCalledWith('127.0.0.1');
    });
  });
});

describe('AID agent.md signing', () => {
  it('signAgentMd 应在尾部追加签名块并保留原 payload', async () => {
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signed = (aidFromIdentity(identity).signAgentMd(payload) as { ok: true; data: { signed: string } }).data.signed;

    expect(signed.startsWith(payload)).toBe(true);
    expect(signed).toContain('<!-- AUN-SIGNATURE');
    expect(signed).toMatch(/signature: [A-Za-z0-9+/=]+/);
    expect(signed).toMatch(/-->\s*$/);
  });

  it('verifyAgentMd 应返回 unsigned / verified / invalid 三态', async () => {
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    const aid = aidFromIdentity(identity);
    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signed = (aid.signAgentMd(payload) as { ok: true; data: { signed: string } }).data.signed;

    expect((aid.verifyAgentMd(payload) as { ok: true; data: { status: string } }).data.status).toBe('unsigned');
    expect((aid.verifyAgentMd(signed) as { ok: true; data: { status: string; payload: string } }).data).toMatchObject({
      status: 'verified',
      payload,
    });
    expect((aid.verifyAgentMd(signed.replace('Alice', 'Mallory')) as { ok: true; data: { status: string } }).data.status).toBe('invalid');
  });

  it('signAgentMd 重新签名时应替换已有签名块', async () => {
    const { privateKey } = generateECKeypair();
    const identity = buildIdentity('alice.agentid.pub', privateKey);
    const aid = aidFromIdentity(identity);
    const payload = '---\naid: "alice.agentid.pub"\nname: "Alice"\n---\n\n# Alice\n';
    const signedOnce = (aid.signAgentMd(payload) as { ok: true; data: { signed: string } }).data.signed;
    const signedTwice = (aid.signAgentMd(signedOnce) as { ok: true; data: { signed: string } }).data.signed;

    expect(signedTwice.match(/<!-- AUN-SIGNATURE/g)?.length).toBe(1);
    expect(signedTwice.startsWith(payload)).toBe(true);
  });
});
