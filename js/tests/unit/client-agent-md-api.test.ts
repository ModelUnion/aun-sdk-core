// JS（浏览器）SDK 主 API 单测：client.publishAgentMd / client.fetchAgentMd
// jsdom 环境下 vitest 默认提供 globalThis.crypto.subtle 和 TextEncoder。

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

describe('js client.publishAgentMd', () => {
  it('rejects empty content', async () => {
    const client = new AUNClient();
    await expect(client.publishAgentMd('')).rejects.toBeInstanceOf(ValidationError);
  });

  it('signs → uploads → updates _localAgentMdEtag', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.agentid.pub';

    let uploaded = '';
    vi.spyOn(client.auth, 'signAgentMd').mockImplementation(
      async (c: string) =>
        c + '\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n',
    );
    vi.spyOn(client.auth, 'uploadAgentMd').mockImplementation(async (c: string) => {
      uploaded = c;
      return { aid: 'alice.agentid.pub' };
    });

    const result = await client.publishAgentMd('---\naid: alice.agentid.pub\n---\n# Alice\n');
    expect(result.aid).toBe('alice.agentid.pub');
    const want = `"${await sha256Hex(uploaded)}"`;
    expect((client as any)._localAgentMdEtag).toBe(want);
  });
});

describe('js client.fetchAgentMd', () => {
  it('uses self aid and updates _localAgentMdEtag', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.agentid.pub';

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue(
      '---\naid: alice.agentid.pub\n---\n# A\n',
    );
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({
      status: 'unsigned',
      verified: false,
      payload: '',
    } as any);

    const info = await client.fetchAgentMd();

    expect(info.aid).toBe('alice.agentid.pub');
    expect(info.signature.status).toBe('unsigned');
    expect(typeof info.in_sync).toBe('boolean');

    const want = `"${await sha256Hex(info.content)}"`;
    expect((client as any)._localAgentMdEtag).toBe(want);
  });

  it('foreign aid does not change local etag', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.agentid.pub';
    (client as any)._localAgentMdEtag = '"keep"';

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue('---\naid: bob\n---\n');
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({
      status: 'unsigned',
      verified: false,
      payload: '',
    } as any);

    const info = await client.fetchAgentMd('bob.agentid.pub');
    expect(info.in_sync).toBeNull();
    expect((client as any)._localAgentMdEtag).toBe('"keep"');
  });

  it('throws when no aid', async () => {
    const client = new AUNClient();
    (client as any)._aid = null;
    await expect(client.fetchAgentMd()).rejects.toBeInstanceOf(ValidationError);
  });

  it('in_sync=true when local digest matches remote etag', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.agentid.pub';

    const body = '---\naid: alice.agentid.pub\n---\n# A\n';
    (client as any)._remoteAgentMdEtag = `"${await sha256Hex(body)}"`;

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue(body);
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({
      status: 'unsigned',
      verified: false,
      payload: '',
    } as any);

    const info = await client.fetchAgentMd();
    expect(info.in_sync).toBe(true);
  });
});
