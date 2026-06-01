import { afterEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { AID } from '../../src/aid.js';
import { AgentMdManager } from '../../src/agent-md.js';
import { AUNClient } from '../../src/client.js';
import { ValidationError } from '../../src/errors.js';

afterEach(() => {
  vi.restoreAllMocks();
});

function etag(content: string): string {
  return `"${createHash('sha256').update(content, 'utf-8').digest('hex')}"`;
}

function makeMockAid(aunPath: string): AID {
  return {
    aid: 'test.aid.com', aunPath, certPem: '', publicKey: '', certSubject: '',
    certNotBefore: new Date(), certNotAfter: new Date(Date.now() + 86400000),
    certIssuer: '', certFingerprint: '', deviceId: 'default', slotId: 'default',
    verifySsl: true, rootCaPath: null, debug: false,
    isCertValid: () => true, isPrivateKeyValid: () => false,
    sign: () => ({ ok: true, data: { signature: '' } }),
    verify: () => ({ ok: true, data: { valid: true } }),
    signAgentMd: () => ({ ok: true, data: { signed: '' } }),
    verifyAgentMd: () => ({ ok: true, data: { status: 'verified' as const, payload: '' } }),
  } as unknown as AID;
}

function makePeer(aid: string): AID {
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

function makeClient(aunPath = mkdtempSync(join(tmpdir(), 'aun-client-agent-md-'))): AUNClient {
  return new AUNClient(makeMockAid(aunPath));
}

function manager(client: AUNClient): AgentMdManager {
  return (client as any)._agentMdManager as AgentMdManager;
}

function readRecord(root: string, aid: string): any {
  return JSON.parse(readFileSync(join(root, aid, 'agentmd.json'), 'utf-8'));
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf-8');
}

async function withServer<T>(
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>,
  fn: (port: number) => Promise<T>,
): Promise<T> {
  const server = createServer((req, res) => void Promise.resolve(handler(req, res)).catch((err) => {
    res.statusCode = 500;
    res.end(String(err));
  }));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await fn((server.address() as AddressInfo).port);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe('client AIDs agent.md 文件存储', () => {
  it('默认路径为 {aun_path}/AIDs，client 不再暴露路径切换入口', () => {
    const base = mkdtempSync(join(tmpdir(), 'aun-client-agent-md-path-'));
    const client = makeClient(join(base, 'aun'));
    expect(manager(client).root).toBe(join(base, 'aun', 'AIDs'));
    expect((client as any).setAgentMdPath).toBeUndefined();
    expect((client as any).SetAgentMDPath).toBeUndefined();
    expect((client as any)._setAgentMdRoot).toBeUndefined();
    (client as any)._tokenStore?.close?.();
  });

  it('uploadAgentMd 无本地 AID 时拒绝', async () => {
    const client = makeClient();
    await expect(client.uploadAgentMd()).rejects.toBeInstanceOf(ValidationError);
    (client as any)._tokenStore?.close?.();
  });

  it('uploadAgentMd 签名上传后写回 agent.md 与 agentmd.json', async () => {
    await withServer(async (req, res) => {
      expect(req.method).toBe('PUT');
      expect(req.url).toBe('/agent.md');
      expect(req.headers.authorization).toBe('Bearer cached-token');
      const body = await readBody(req);
      expect(body).toContain('AUN-SIGNATURE');
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ aid: '127.0.0.1', etag: etag(body), last_modified: 'Sun, 24 May 2026 00:00:00 GMT' }));
    }, async (port) => {
      const client = makeClient();
      const mgr = manager(client);
      (mgr as any)._discoveryPort = port;
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
        signAgentMd: vi.fn((content: string) => ({ ok: true, data: { signed: `${content}\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n` } })),
      };

      const result = await client.uploadAgentMd('---\naid: 127.0.0.1\n---\n# Local\n');

      const saved = readFileSync(join(mgr.root, '127.0.0.1', 'agent.md'), 'utf-8');
      const record = readRecord(mgr.root, '127.0.0.1');
      expect(result.aid).toBe('127.0.0.1');
      expect(record.content).toBeUndefined();
      expect(record.local_etag).toBe(etag(saved));
      expect(record.remote_etag).toBe(etag(saved));
      expect(record.last_modified).toBe('Sun, 24 May 2026 00:00:00 GMT');
      (client as any)._tokenStore?.close?.();
    });
  });

  it('downloadAgentMd 由 AgentMdManager 下载、验签并持久化', async () => {
    const content = '---\naid: 127.0.0.1\n---\n# Peer\n';
    await withServer((_req, res) => {
      res.writeHead(200, {
        ETag: etag(content),
        'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT',
        'Content-Type': 'text/markdown',
      });
      res.end(content);
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-manager-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => makePeer(aid),
      });

      const info = await mgr.download('127.0.0.1');

      expect(info.content).toBe(content);
      expect(info.verification.status).toBe('unsigned');
      expect(readFileSync(join(mgr.root, '127.0.0.1', 'agent.md'), 'utf-8')).toBe(content);
      expect(readRecord(mgr.root, '127.0.0.1').remote_etag).toBe(etag(content));
    });
  });

  it('同一 AID 的 downloadAgentMd 使用 singleflight', async () => {
    let hits = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await withServer(async (_req, res) => {
      hits += 1;
      await gate;
      res.writeHead(200, { ETag: '"same"' });
      res.end('# Peer\n');
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-singleflight-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => makePeer(aid),
      });
      const first = mgr.download('127.0.0.1');
      const second = mgr.download('127.0.0.1');
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(hits).toBe(1);
      release();
      await Promise.all([first, second]);
      expect(hits).toBe(1);
    });
  });

  it('checkAgentMd 使用本地文件 etag 与 HEAD etag 比较', async () => {
    const body = '# Bob\n';
    await withServer((_req, res) => {
      res.writeHead(200, {
        ETag: etag(body),
        'Last-Modified': 'Sun, 24 May 2026 00:00:00 GMT',
        'Content-Length': String(body.length),
      });
      res.end();
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-check-')),
        verifySsl: false,
        discoveryPort: port,
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
      });
      mgr.saveRecord('127.0.0.1', { content: body, local_etag: etag(body), remote_etag: '"old"' });

      const result = await mgr.check('127.0.0.1');

      expect(result.local_found).toBe(true);
      expect(result.remote_found).toBe(true);
      expect(result.in_sync).toBe(true);
      expect(result.needs_update).toBe(false);
      expect(readRecord(mgr.root, '127.0.0.1').remote_etag).toBe(etag(body));
    });
  });

  it('observeRpcMeta 保存结构化元数据并为缺正文 AID 自动补拉', async () => {
    const body = '# Observed\n';
    await withServer((_req, res) => {
      res.writeHead(200, { ETag: etag(body), 'Last-Modified': 'Sun, 24 May 2026 00:00:01 GMT' });
      res.end(body);
    }, async (port) => {
      const mgr = new AgentMdManager({
        aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-observe-')),
        verifySsl: false,
        discoveryPort: port,
        ownerAidGetter: () => 'localhost',
        gatewayResolver: () => 'ws://gateway.agentid.pub/aun',
        peerResolver: (aid) => makePeer(aid),
      });

      mgr.observeRpcMeta({
        agent_md_etags: {
          sender: { aid: '127.0.0.1', etag: etag(body), last_modified: 'Sun, 24 May 2026 00:00:01 GMT' },
        },
      });
      await vi.waitFor(() => {
        expect(readFileSync(join(mgr.root, '127.0.0.1', 'agent.md'), 'utf-8')).toBe(body);
      });
      expect(readRecord(mgr.root, '127.0.0.1').remote_etag).toBe(etag(body));
    });
  });

  it('新边界下旧公开入口和旧私有入口已移除', () => {
    const client = makeClient();
    for (const name of [
      'publishAgentMd',
      'fetchAgentMd',
      'checkAgentMd',
      '_uploadAgentMd',
      '_downloadAgentMd',
      '_headAgentMd',
      '_verifyAgentMd',
      '_saveAgentMdRecord',
      '_loadAgentMdRecord',
      '_checkAgentMdCache',
    ]) {
      expect((client as any)[name]).toBeUndefined();
    }
    expect(typeof client.uploadAgentMd).toBe('function');
    (client as any)._tokenStore?.close?.();
  });

  it('agentmd.json 损坏时仍可按正文恢复基本记录', () => {
    const mgr = new AgentMdManager({ aunPath: mkdtempSync(join(tmpdir(), 'aun-agent-md-damaged-')) });
    const body = '# Alice\n';
    mkdirSync(join(mgr.root, 'alice.agentid.pub'), { recursive: true });
    writeFileSync(join(mgr.root, 'alice.agentid.pub', 'agent.md'), body, 'utf-8');
    writeFileSync(join(mgr.root, 'alice.agentid.pub', 'agentmd.json'), '{bad json', 'utf-8');

    const record = mgr.loadRecord('alice.agentid.pub');

    expect(record?.content).toBe(body);
    expect(record?.local_etag).toBe(etag(body));
    expect(record?.remote_etag).toBeUndefined();
  });
});
