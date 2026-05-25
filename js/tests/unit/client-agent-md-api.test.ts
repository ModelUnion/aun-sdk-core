// JS（浏览器）SDK agent.md API：AgentMDs 逻辑目录映射到 IndexedDB。

import { afterEach, describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { ValidationError } from '../../src/errors.js';

afterEach(() => {
  vi.restoreAllMocks();
});

async function sha256Hex(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function etag(content: string): Promise<string> {
  return `"${await sha256Hex(content)}"`;
}

function makeClient(): AUNClient {
  return new AUNClient({ aun_path: '/tmp/aun-js-agent-md' });
}

function agentRoot(client: AUNClient): string {
  return (client as any)._agentMdPath as string;
}

async function readStorage(client: AUNClient, key: string): Promise<string | null> {
  const record = await (client as any)._keystore.loadAgentMdCache(agentRoot(client), key);
  return record ? String(record.content ?? '') : null;
}

async function readContent(client: AUNClient, aid: string): Promise<string | null> {
  return await readStorage(client, `${aid}/agent.md`);
}

async function readList(client: AUNClient): Promise<any> {
  const raw = await readStorage(client, 'list.json');
  expect(raw).toBeTruthy();
  return JSON.parse(raw!);
}

async function writeLocalAgentMd(client: AUNClient, aid: string, content: string): Promise<void> {
  await (client as any)._writeAgentMdContent(aid, content);
}

describe('js client AgentMDs IndexedDB 存储', () => {
  it('默认路径为 {aun_path}/AgentMDs，且 SetAgentMDPath 可切换/恢复', () => {
    const client = makeClient();
    expect(agentRoot(client)).toBe('/tmp/aun-js-agent-md/AgentMDs');
    expect((client as any).setAgentMdPath('/tmp/custom-agentmd')).toBe('/tmp/custom-agentmd');
    expect((client as any).SetAgentMDPath()).toBe('/tmp/aun-js-agent-md/AgentMDs');
  });

  it('publishAgentMd 无本地 AID 时拒绝', async () => {
    const client = makeClient();
    await expect(client.publishAgentMd()).rejects.toBeInstanceOf(ValidationError);
  });

  it('publishAgentMd 无本地 agent.md 正文时拒绝', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    await expect(client.publishAgentMd()).rejects.toBeInstanceOf(ValidationError);
  });

  it('publishAgentMd 从 IndexedDB 的 {aid}/agent.md 读取，签名上传后写回并更新 list.json', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const unsigned = '---\naid: alice.agentid.pub\n---\n# Alice\n';
    await writeLocalAgentMd(client, 'alice.agentid.pub', unsigned);

    let signedInput = '';
    let uploaded = '';
    vi.spyOn(client.auth, 'signAgentMd').mockImplementation(async (c: string) => {
      signedInput = c;
      return `${c}\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n`;
    });
    vi.spyOn(client.auth, 'uploadAgentMd').mockImplementation(async (c: string) => {
      uploaded = c;
      return { aid: 'alice.agentid.pub', etag: '"cloud"', last_modified: 'Sun, 24 May 2026 00:00:00 GMT' };
    });

    const result = await client.publishAgentMd();

    expect(result.aid).toBe('alice.agentid.pub');
    expect(signedInput).toBe(unsigned);
    expect(await readContent(client, 'alice.agentid.pub')).toBe(uploaded);
    const record = (await readList(client)).records['alice.agentid.pub'];
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(await etag(uploaded));
    expect(record.remote_etag).toBe('"cloud"');
    expect((client as any)._localAgentMdEtag).toBe(await etag(uploaded));
  });

  it('兼容 publishAgentMd(content)：先把正文保存到 IndexedDB，再发布', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const unsigned = '# Alice\n';
    vi.spyOn(client.auth, 'signAgentMd').mockImplementation(async (c: string) => `${c}\n<!-- signed -->\n`);
    vi.spyOn(client.auth, 'uploadAgentMd').mockResolvedValue({ aid: 'alice.agentid.pub' });

    await client.publishAgentMd(unsigned);

    expect(await readContent(client, 'alice.agentid.pub')).toContain('<!-- signed -->');
  });

  it('fetchAgentMd 保存到 IndexedDB 的 {aid}/agent.md，并只把元数据放入 list.json', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '---\naid: bob.agentid.pub\n---\n# Bob\n';
    (client.auth as any)._agentMdCache = new Map([
      ['bob.agentid.pub', { text: body, etag: '"bob-cloud"', lastModified: 'Sun, 24 May 2026 00:00:00 GMT' }],
    ]);
    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue(body);
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({ status: 'unsigned', verified: false, payload: body } as any);

    const info = await client.fetchAgentMd('bob.agentid.pub');

    expect(info.aid).toBe('bob.agentid.pub');
    expect(info.in_sync).toBeNull();
    expect(await readContent(client, 'bob.agentid.pub')).toBe(body);
    const record = (await readList(client)).records['bob.agentid.pub'];
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(await etag(body));
    expect(record.remote_etag).toBe('"bob-cloud"');
  });

  it('fetchAgentMd 无 aid 且无 self aid 时拒绝', async () => {
    const client = makeClient();
    (client as any)._aid = null;
    await expect(client.fetchAgentMd()).rejects.toBeInstanceOf(ValidationError);
  });

  it('checkAgentMd 使用 IndexedDB 正文 etag 与 HEAD etag 比较', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Bob\n';
    await (client as any)._saveAgentMdRecord('bob.agentid.pub', { content: body, local_etag: await etag(body), remote_etag: '"old"' });
    vi.spyOn(client.auth as any, 'headAgentMd').mockResolvedValue({
      aid: 'bob.agentid.pub',
      found: true,
      etag: await etag(body),
      last_modified: 'Sun, 24 May 2026 00:00:00 GMT',
      status: 200,
    });

    const result = await client.checkAgentMd('bob.agentid.pub');

    expect(result.local_found).toBe(true);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(true);
    expect((await readList(client)).records['bob.agentid.pub'].remote_etag).toBe(await etag(body));
  });

  it('观察 RPC meta 时保存结构化 etag/last_modified，并为缺正文的 aid 自动拉取', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const fetched: string[] = [];
    vi.spyOn(client, 'fetchAgentMd').mockImplementation(async (aid?: string | null) => {
      const target = String(aid ?? '');
      fetched.push(target);
      const content = `# ${target}\n`;
      await (client as any)._saveAgentMdRecord(target, {
        content,
        local_etag: await etag(content),
        remote_status: 'found',
      });
      return { aid: target, content, signature: { status: 'unsigned' }, in_sync: false } as any;
    });

    await (client as any)._observeRpcMeta({
      agent_md_etag: '"alice-cloud"',
      agent_md_etags: {
        requester: { aid: 'alice.agentid.pub', etag: '"alice-cloud-2"', last_modified: 'Sun, 24 May 2026 00:00:00 GMT' },
        receiver: { aid: 'bob.agentid.pub', etag: '"bob-cloud"', last_modified: 'Sun, 24 May 2026 00:00:01 GMT' },
        sender: { aid: 'dave.agentid.pub', etag: '"dave-cloud"' },
      },
    });

    const records = (await readList(client)).records;
    expect(records['alice.agentid.pub'].remote_etag).toBe('"alice-cloud-2"');
    expect(records['alice.agentid.pub'].last_modified).toBe('Sun, 24 May 2026 00:00:00 GMT');
    expect(records['bob.agentid.pub'].remote_etag).toBe('"bob-cloud"');
    expect(records['bob.agentid.pub'].last_modified).toBe('Sun, 24 May 2026 00:00:01 GMT');
    expect(records['dave.agentid.pub'].remote_etag).toBe('"dave-cloud"');
    expect(Object.values(records).every((record: any) => record.content === undefined)).toBe(true);
    expect(fetched).toEqual(['alice.agentid.pub', 'bob.agentid.pub', 'dave.agentid.pub']);
    expect(await readContent(client, 'bob.agentid.pub')).toBe('# bob.agentid.pub\n');
  });

  it('checkAgentMd 在本地与云端 etag 匹配且 last_modified 未过期时不 HEAD', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Bob\n';
    const bodyEtag = await etag(body);
    await (client as any)._saveAgentMdRecord('bob.agentid.pub', {
      content: body,
      local_etag: bodyEtag,
      remote_etag: bodyEtag,
      last_modified: new Date().toUTCString(),
      verify_status: 'valid',
      verify_error: '',
    });
    vi.spyOn(client.auth as any, 'headAgentMd').mockImplementation(async () => {
      throw new Error('fresh cached checkAgentMd should not HEAD');
    });

    const result = await client.checkAgentMd('bob.agentid.pub', 7);

    expect(result.local_found).toBe(true);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(true);
    expect(result.cached).toBe(true);
    expect(result.verify_status).toBe('valid');
  });

  it('list.json 损坏时按 IndexedDB 中的正文重建，并清空旧内存缓存', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Alice\n';
    await writeLocalAgentMd(client, 'alice.agentid.pub', body);
    (client as any)._agentMdCache.set('alice.agentid.pub', { aid: 'alice.agentid.pub', remote_etag: '"cloud"' });
    (client as any)._agentMdCache.set('bob.agentid.pub', { aid: 'bob.agentid.pub', remote_etag: '"stale"' });
    await (client as any)._writeAgentMdStorage('list.json', '{bad json');

    const record = await (client as any)._loadAgentMdRecord('alice.agentid.pub');

    expect(record.content).toBe(body);
    expect(record.local_etag).toBe(await etag(body));
    expect(record.remote_etag).toBeUndefined();
    const rebuilt = (await readList(client)).records['alice.agentid.pub'];
    expect(rebuilt.content).toBeUndefined();
    expect(rebuilt.local_etag).toBe(await etag(body));
    expect(rebuilt.remote_etag).toBeUndefined();
    expect((client as any)._agentMdCache.has('bob.agentid.pub')).toBe(false);
  });
});
