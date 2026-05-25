import { afterEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { AUNClient } from '../../src/client.js';
import { ValidationError } from '../../src/errors.js';

afterEach(() => {
  vi.restoreAllMocks();
});

function makeClient() {
  return new AUNClient({ aun_path: mkdtempSync(join(tmpdir(), 'aun-client-agent-md-')) });
}

function etag(content: string): string {
  return `"${createHash('sha256').update(content, 'utf-8').digest('hex')}"`;
}

function agentRoot(client: AUNClient): string {
  return (client as any)._agentMdPath as string;
}

function writeLocalAgentMd(client: AUNClient, aid: string, content: string): string {
  const file = join(agentRoot(client), aid, 'agent.md');
  mkdirSync(join(agentRoot(client), aid), { recursive: true });
  writeFileSync(file, content, 'utf-8');
  return file;
}

function readList(client: AUNClient): any {
  return JSON.parse(readFileSync(join(agentRoot(client), 'list.json'), 'utf-8'));
}

describe('client AgentMDs 文件存储', () => {
  it('默认路径为 {aun_path}/AgentMDs，且 SetAgentMDPath 可切换/恢复', () => {
    const base = mkdtempSync(join(tmpdir(), 'aun-client-agent-md-path-'));
    const client = new AUNClient({ aun_path: join(base, 'aun') });
    expect(agentRoot(client)).toBe(join(base, 'aun', 'AgentMDs'));
    expect((client as any).setAgentMdPath(join(base, 'custom'))).toBe(join(base, 'custom'));
    expect((client as any).SetAgentMDPath()).toBe(join(base, 'aun', 'AgentMDs'));
    (client as any)._keystore.close?.();
  });

  it('publishAgentMd 无本地 AID 时拒绝', async () => {
    const client = makeClient();
    await expect(client.publishAgentMd()).rejects.toBeInstanceOf(ValidationError);
    (client as any)._keystore.close?.();
  });

  it('publishAgentMd 读取默认 agent.md → 签名上传 → 原子写回并更新 list.json', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const unsigned = '---\naid: alice.agentid.pub\n---\n# Alice\n';
    writeLocalAgentMd(client, 'alice.agentid.pub', unsigned);

    let signedInput = '';
    let uploaded = '';
    vi.spyOn(client.auth, 'signAgentMd').mockImplementation(async (c: string) => {
      signedInput = c;
      return `${c}\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n`;
    });
    vi.spyOn(client.auth, 'uploadAgentMd').mockImplementation(async (c: string) => {
      uploaded = c;
      return { aid: 'alice.agentid.pub', etag: '"abc"', last_modified: 'Sun, 24 May 2026 00:00:00 GMT' };
    });

    const result = await client.publishAgentMd();

    expect(result.aid).toBe('alice.agentid.pub');
    expect(signedInput).toBe(unsigned);
    expect(readFileSync(join(agentRoot(client), 'alice.agentid.pub', 'agent.md'), 'utf-8')).toBe(uploaded);
    const record = readList(client).records['alice.agentid.pub'];
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(etag(uploaded));
    expect(record.remote_etag).toBe('"abc"');
    expect((client as any)._localAgentMdEtag).toBe(etag(uploaded));
    (client as any)._keystore.close?.();
  });

  it('fetchAgentMd 保存到默认 {aid}/agent.md，并只把元数据放入 list.json', async () => {
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
    expect(info.saved_to).toBe(join(agentRoot(client), 'bob.agentid.pub', 'agent.md'));
    expect(readFileSync(info.saved_to!, 'utf-8')).toBe(body);
    const record = readList(client).records['bob.agentid.pub'];
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(etag(body));
    expect(record.remote_etag).toBe('"bob-cloud"');
    (client as any)._keystore.close?.();
  });

  it('fetchAgentMd 无 aid 且无 self aid 时拒绝', async () => {
    const client = makeClient();
    (client as any)._aid = null;
    await expect(client.fetchAgentMd()).rejects.toBeInstanceOf(ValidationError);
    (client as any)._keystore.close?.();
  });

  it('checkAgentMd 使用本地文件 etag 与 HEAD etag 比较', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Bob\n';
    (client as any)._saveAgentMdRecord('bob.agentid.pub', { content: body, local_etag: etag(body), remote_etag: '"old"' });
    vi.spyOn(client.auth as any, 'headAgentMd').mockResolvedValue({
      aid: 'bob.agentid.pub',
      found: true,
      etag: etag(body),
      last_modified: 'Sun, 24 May 2026 00:00:00 GMT',
      status: 200,
    });

    const result = await client.checkAgentMd('bob.agentid.pub');

    expect(result.local_found).toBe(true);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(true);
    expect(readList(client).records['bob.agentid.pub'].remote_etag).toBe(etag(body));
    (client as any)._keystore.close?.();
  });

  it('观察 RPC meta 时保存结构化 etag/last_modified，并为缺正文的 aid 自动拉取', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const fetched: string[] = [];
    vi.spyOn(client, 'fetchAgentMd').mockImplementation(async (aid?: string | null) => {
      const target = String(aid ?? '');
      fetched.push(target);
      const content = `# ${target}\n`;
      (client as any)._saveAgentMdRecord(target, {
        content,
        local_etag: etag(content),
        remote_status: 'found',
      });
      return { aid: target, content, signature: { status: 'unsigned' }, in_sync: false, saved_to: null, save_error: null } as any;
    });

    (client as any)._observeRpcMeta({
      agent_md_etag: '"alice-cloud"',
      agent_md_etags: {
        requester: { aid: 'alice.agentid.pub', etag: '"alice-cloud-2"', last_modified: 'Sun, 24 May 2026 00:00:00 GMT' },
        receiver: { aid: 'bob.agentid.pub', etag: '"bob-cloud"', last_modified: 'Sun, 24 May 2026 00:00:01 GMT' },
        sender: { aid: 'dave.agentid.pub', etag: '"dave-cloud"' },
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const records = readList(client).records;
    expect(records['alice.agentid.pub'].remote_etag).toBe('"alice-cloud-2"');
    expect(records['alice.agentid.pub'].last_modified).toBe('Sun, 24 May 2026 00:00:00 GMT');
    expect(records['bob.agentid.pub'].remote_etag).toBe('"bob-cloud"');
    expect(records['bob.agentid.pub'].last_modified).toBe('Sun, 24 May 2026 00:00:01 GMT');
    expect(records['dave.agentid.pub'].remote_etag).toBe('"dave-cloud"');
    expect(Object.values(records).every((record: any) => record.content === undefined)).toBe(true);
    expect(fetched).toEqual(['alice.agentid.pub', 'bob.agentid.pub', 'dave.agentid.pub']);
    expect(readFileSync(join(agentRoot(client), 'bob.agentid.pub', 'agent.md'), 'utf-8')).toBe('# bob.agentid.pub\n');
    (client as any)._keystore.close?.();
  });

  it('checkAgentMd 在本地与云端 etag 匹配且 last_modified 未过期时不 HEAD', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Bob\n';
    const freshLastModified = new Date().toUTCString();
    (client as any)._saveAgentMdRecord('bob.agentid.pub', {
      content: body,
      local_etag: etag(body),
      remote_etag: etag(body),
      last_modified: freshLastModified,
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
    (client as any)._keystore.close?.();
  });

  it('list.json 损坏时按目录重建，并清空旧内存缓存', () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Alice\n';
    writeLocalAgentMd(client, 'alice.agentid.pub', body);
    (client as any)._agentMdCache.set('alice.agentid.pub', { aid: 'alice.agentid.pub', remote_etag: '"cloud"' });
    (client as any)._agentMdCache.set('bob.agentid.pub', { aid: 'bob.agentid.pub', remote_etag: '"stale"' });
    writeFileSync(join(agentRoot(client), 'list.json'), '{bad json', 'utf-8');

    const record = (client as any)._loadAgentMdRecord('alice.agentid.pub');

    expect(record.content).toBe(body);
    expect(record.local_etag).toBe(etag(body));
    expect(record.remote_etag).toBeUndefined();
    const rebuilt = readList(client).records['alice.agentid.pub'];
    expect(rebuilt.local_etag).toBe(etag(body));
    expect(rebuilt.remote_etag).toBeUndefined();
    expect((client as any)._agentMdCache.has('bob.agentid.pub')).toBe(false);
    (client as any)._keystore.close?.();
  });
});

