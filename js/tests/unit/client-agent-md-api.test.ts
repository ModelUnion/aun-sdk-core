// JS（浏览器）SDK agent.md API：AIDs 逻辑目录映射到 IndexedDB。

import { afterEach, describe, expect, it, vi } from 'vitest';

import { AIDStore } from '../../src/aid-store.js';
import { AgentMdManager } from '../../src/agent-md.js';
import { AUNClient } from '../../src/client.js';
import { ValidationError } from '../../src/errors.js';
import { resultOk } from '../../src/result.js';

afterEach(() => {
  vi.restoreAllMocks();
});

async function sha256Hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function etag(content: string): Promise<string> {
  return `"${await sha256Hex(content)}"`;
}

function makeClient(): AUNClient {
  const mockAid = {
    aid: 'test.aid.com', aunPath: '/tmp/aun-js-agent-md', certPem: '', publicKey: '',
    certSubject: '', certNotBefore: new Date(), certNotAfter: new Date(Date.now() + 86400000),
    certIssuer: '', certFingerprint: '', deviceId: 'default', slotId: 'default',
    verifySsl: true, rootCaPath: null, debug: false,
    isCertValid: () => true, isPrivateKeyValid: () => false,
    sign: async () => ({ ok: true, data: { signature: '' } }),
    verify: async () => ({ ok: true, data: { valid: true } }),
    signAgentMd: async () => ({ ok: true, data: { signed: '' } }),
    verifyAgentMd: async () => ({ ok: true, data: { status: 'verified' as const, payload: '' } }),
  } as any;
  return new AUNClient(mockAid);
}

function manager(holder: any): AgentMdManager {
  return holder._agentMdManager as AgentMdManager;
}

function agentRoot(holder: any): string {
  return manager(holder).root;
}

async function readStorage(holder: any, key: string): Promise<string | null> {
  const record = await holder._tokenStore.loadAgentMdCache(agentRoot(holder), key);
  return record ? String(record.content ?? '') : null;
}

async function readContent(holder: any, aid: string): Promise<string | null> {
  return await readStorage(holder, `${aid}/agent.md`);
}

async function readMeta(holder: any, aid: string): Promise<any> {
  const raw = await readStorage(holder, `${aid}/agentmd.json`);
  expect(raw).toBeTruthy();
  return JSON.parse(raw!);
}

async function writeLocalAgentMd(holder: any, aid: string, content: string): Promise<void> {
  await manager(holder).writeContent(aid, content);
}

function makeStore(): AIDStore {
  const store = new AIDStore({ aunPath: '/tmp/aun-js-agent-md', encryptionSeed: '', verifySsl: true });
  (store as any)._resolveGateway = async () => 'ws://gateway.agentid.pub/aun';
  return store;
}

function installStoreAid(store: AIDStore, aid = 'alice.agentid.pub'): void {
  (store as any).load = async () => resultOk({
    aid: {
      aid,
      certPem: 'cert',
      privateKeyPem: 'private',
      publicKey: 'public',
      isPrivateKeyValid: () => true,
      signAgentMd: vi.fn(async (c: string) => ({
        ok: true,
        data: {
          signed: `${c}\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:${'0'.repeat(64)}\ntimestamp: 1\nsignature: x\n-->\n`,
        },
      })),
    },
  });
}

describe('js client AIDs IndexedDB 存储', () => {
  it('默认路径为 {aun_path}/AIDs，manager 内部存储根可切换/恢复', () => {
    const client = makeClient();
    const mgr = manager(client);
    expect(agentRoot(client)).toBe('/tmp/aun-js-agent-md/AIDs');
    expect((client as any).setAgentMdPath).toBeUndefined();
    expect((client as any).SetAgentMDPath).toBeUndefined();
    expect((client as any).uploadAgentMd).toBeUndefined();
    expect(mgr.setRoot('/tmp/custom-agentmd')).toBe('/tmp/custom-agentmd');
    expect(mgr.setRoot()).toBe('/tmp/aun-js-agent-md/AIDs');
  });

  it('uploadAgentMd 无本地 AID 时拒绝', async () => {
    const store = makeStore();
    const result = await store.uploadAgentMd('');
    expect(result.ok).toBe(false);
    expect((result as any).error.code).toBe('INVALID_AID_FORMAT');
  });

  it('uploadAgentMd 无本地 agent.md 正文时拒绝', async () => {
    const store = makeStore();
    installStoreAid(store);
    const result = await store.uploadAgentMd('alice.agentid.pub');
    expect(result.ok).toBe(false);
    expect((result as any).error.code).toBe('INVALID_AID_FORMAT');
  });

  it('uploadAgentMd 从 IndexedDB 的 {aid}/agent.md 读取，签名上传后写回并更新 agentmd.json', async () => {
    const store = makeStore();
    installStoreAid(store);
    const unsigned = '---\naid: alice.agentid.pub\n---\n# Alice\n';
    await writeLocalAgentMd(store, 'alice.agentid.pub', unsigned);

    let uploaded = '';
    vi.spyOn(AgentMdManager.prototype as any, '_uploadHttp').mockImplementation(async (_aid: string, c: string) => {
      uploaded = c;
      return { aid: 'alice.agentid.pub', etag: '"cloud"', last_modified: 'Sun, 24 May 2026 00:00:00 GMT' };
    });

    const result = await store.uploadAgentMd('alice.agentid.pub');

    expect(result.ok).toBe(true);
    expect((result as any).data.aid).toBe('alice.agentid.pub');
    expect(await readContent(store, 'alice.agentid.pub')).toBe(uploaded);
    const record = await readMeta(store, 'alice.agentid.pub');
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(await etag(uploaded));
    expect(record.remote_etag).toBe('"cloud"');
  });

  it('兼容 uploadAgentMd(content)：先把正文保存到 IndexedDB，再发布', async () => {
    const store = makeStore();
    installStoreAid(store);
    const unsigned = '# Alice\n';
    vi.spyOn(AgentMdManager.prototype as any, '_uploadHttp').mockResolvedValue({ aid: 'alice.agentid.pub' });

    const result = await store.uploadAgentMd('alice.agentid.pub', unsigned);

    expect(result.ok).toBe(true);
    expect(await readContent(store, 'alice.agentid.pub')).toContain('AUN-SIGNATURE');
  });

  it('downloadAgentMd 保存到 IndexedDB 的 {aid}/agent.md，并只把元数据放入 agentmd.json', async () => {
    const client = makeClient();
    const mgr = manager(client);
    (client as any)._aid = 'alice.agentid.pub';
    const body = '---\naid: bob.agentid.pub\n---\n# Bob\n';
    vi.spyOn(mgr as any, '_downloadHttp').mockResolvedValue({
      content: body,
      etag: '"bob-cloud"',
      last_modified: 'Sun, 24 May 2026 00:00:00 GMT',
      status: 200,
    });
    vi.spyOn(mgr as any, '_resolvePeer').mockResolvedValue({
      certPem: 'cert',
      verifyAgentMd: vi.fn(async () => ({ ok: true, data: { status: 'unsigned', payload: body } })),
    });

    const info = await mgr.download('bob.agentid.pub');

    expect(info.aid).toBe('bob.agentid.pub');
    expect(info.in_sync).toBeNull();
    expect(await readContent(client, 'bob.agentid.pub')).toBe(body);
    const record = await readMeta(client, 'bob.agentid.pub');
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(await etag(body));
    expect(record.remote_etag).toBe('"bob-cloud"');
  });

  it('downloadAgentMd 收到 304 且无正文缓存时应重试一次无条件 GET', async () => {
    const client = makeClient();
    const mgr = manager(client);
    (client as any)._gatewayUrl = 'wss://gateway.agentid.pub/aun';
    await mgr.saveRecord('bob.agentid.pub', { remote_etag: '"head-only"' });
    vi.spyOn(mgr as any, '_resolvePeer').mockResolvedValue({
      certPem: 'cert',
      verifyAgentMd: vi.fn(async () => ({ ok: true, data: { status: 'unsigned', payload: '# Bob\n' } })),
    });
    const calls: Array<Record<string, string>> = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init?: RequestInit) => {
      calls.push(Object.fromEntries(new Headers(init?.headers).entries()));
      if (calls.length === 1) return new Response(null, { status: 304 });
      return new Response('# Bob\n', { status: 200, headers: { ETag: '"head-only"' } });
    });

    const downloaded = await mgr.download('bob.agentid.pub');

    expect(downloaded.content).toBe('# Bob\n');
    expect(calls).toHaveLength(2);
    expect(calls[0]?.['if-none-match']).toBeUndefined();
    expect(calls[0]?.['if-modified-since']).toBeUndefined();
    expect(calls[1]?.['if-none-match']).toBeUndefined();
    expect(calls[1]?.['if-modified-since']).toBeUndefined();
  });

  it('downloadAgentMd 无 aid 且无 self aid 时拒绝', async () => {
    const client = makeClient();
    (client as any)._aid = null;
    expect((client as any).fetchAgentMd).toBeUndefined();
    await expect(manager(client).download()).rejects.toBeInstanceOf(ValidationError);
  });

  it('checkAgentMd 使用 IndexedDB 正文 etag 与 HEAD etag 比较', async () => {
    const client = makeClient();
    const mgr = manager(client);
    const body = '# Bob\n';
    await mgr.saveRecord('bob.agentid.pub', { content: body, local_etag: await etag(body), remote_etag: '"old"' });
    vi.spyOn(mgr as any, '_head').mockResolvedValue({
      aid: 'bob.agentid.pub',
      found: true,
      etag: await etag(body),
      last_modified: 'Sun, 24 May 2026 00:00:00 GMT',
      status: 200,
    });

    const result = await mgr.check('bob.agentid.pub');

    expect(result.local_found).toBe(true);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(true);
    const record = await readMeta(client, 'bob.agentid.pub');
    expect(record.remote_etag).toBe(await etag(body));
  });

  it('观察 RPC meta 时保存结构化 etag/last_modified，并为缺正文的 aid 自动拉取', async () => {
    const client = makeClient();
    const mgr = manager(client);
    (client as any)._aid = 'alice.agentid.pub';
    const fetched: string[] = [];
    vi.spyOn(mgr, 'download').mockImplementation(async (aid?: string | null) => {
      const target = String(aid ?? '');
      fetched.push(target);
      const content = `# ${target}\n`;
      await mgr.saveRecord(target, {
        content,
        local_etag: await etag(content),
        remote_status: 'found',
      });
      return { aid: target, content, verification: { status: 'unsigned' }, signature: { status: 'unsigned' }, cert_pem: '', etag: '', last_modified: '', status: 200, in_sync: false, saved_to: null, save_error: null };
    });

    await (client as any)._observeRpcMeta({
      agent_md_etag: '"alice-cloud"',
      agent_md_etags: {
        requester: { aid: 'alice.agentid.pub', etag: '"alice-cloud-2"', last_modified: 'Sun, 24 May 2026 00:00:00 GMT' },
        receiver: { aid: 'bob.agentid.pub', etag: '"bob-cloud"', last_modified: 'Sun, 24 May 2026 00:00:01 GMT' },
        sender: { aid: 'dave.agentid.pub', etag: '"dave-cloud"' },
      },
    });

    const aliceRecord = await readMeta(client, 'alice.agentid.pub');
    expect(aliceRecord.remote_etag).toBe('"alice-cloud-2"');
    expect(aliceRecord.last_modified).toBe('Sun, 24 May 2026 00:00:00 GMT');
    const bobRecord = await readMeta(client, 'bob.agentid.pub');
    expect(bobRecord.remote_etag).toBe('"bob-cloud"');
    expect(bobRecord.last_modified).toBe('Sun, 24 May 2026 00:00:01 GMT');
    const daveRecord = await readMeta(client, 'dave.agentid.pub');
    expect(daveRecord.remote_etag).toBe('"dave-cloud"');
    expect(fetched).toEqual(['alice.agentid.pub', 'bob.agentid.pub', 'dave.agentid.pub']);
    expect(await readContent(client, 'bob.agentid.pub')).toBe('# bob.agentid.pub\n');
  });

  it('checkAgentMd 在本地与云端 etag 匹配且 last_modified 未过期时不 HEAD', async () => {
    const client = makeClient();
    const mgr = manager(client);
    const body = '# Bob\n';
    const bodyEtag = await etag(body);
    await mgr.saveRecord('bob.agentid.pub', {
      content: body,
      local_etag: bodyEtag,
      remote_etag: bodyEtag,
      last_modified: new Date().toUTCString(),
      checked_at: Date.now(),
      verify_status: 'valid',
      verify_error: '',
    });
    vi.spyOn(mgr as any, '_head').mockImplementation(async () => {
      throw new Error('fresh cached checkAgentMd should not HEAD');
    });

    const result = await mgr.check('bob.agentid.pub', 7);

    expect(result.local_found).toBe(true);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(true);
    expect(result.cached).toBe(true);
    expect(result.verify_status).toBe('valid');
  });

  it('agentmd.json 损坏时 loadRecord 仍可读取正文并返回基本记录', async () => {
    const client = makeClient();
    const mgr = manager(client);
    const body = '# Alice\n';
    await writeLocalAgentMd(client, 'alice.agentid.pub', body);
    await (mgr as any)._writeStorage('alice.agentid.pub/agentmd.json', '{bad json');

    const record = await mgr.loadRecord('alice.agentid.pub');

    expect(record?.content).toBe(body);
    expect(record?.local_etag).toBe(await etag(body));
    expect(record?.remote_etag).toBeUndefined();
  });
});
