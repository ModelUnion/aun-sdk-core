import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, writeFileSync, existsSync, readFileSync, unlinkSync } from 'node:fs';
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

describe('client.publishAgentMd', () => {
  it('rejects empty path', async () => {
    const client = makeClient();
    await expect(client.publishAgentMd('')).rejects.toBeInstanceOf(ValidationError);
  });

  it('throws when file does not exist', async () => {
    const client = makeClient();
    await expect(client.publishAgentMd('/nope/agent.md')).rejects.toThrow();
  });

  it('reads file → signs → uploads → updates _localAgentMdEtag', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';

    const file = join(tmpdir(), `agent-${Date.now()}.md`);
    writeFileSync(file, '---\naid: alice.agentid.pub\n---\n# Alice\n', 'utf-8');

    let signedInput = '';
    let uploaded = '';
    vi.spyOn(client.auth, 'signAgentMd').mockImplementation(async (c: string) => {
      signedInput = c;
      return c + '\n<!-- AUN-SIGNATURE\ncert_fingerprint: sha256:0\ntimestamp: 1\nsignature: x\n-->\n';
    });
    vi.spyOn(client.auth, 'uploadAgentMd').mockImplementation(async (c: string) => {
      uploaded = c;
      return { aid: 'alice.agentid.pub', etag: '"abc"', agent_md_url: 'https://x' };
    });

    const result = await client.publishAgentMd(file);

    expect(result.aid).toBe('alice.agentid.pub');
    expect(signedInput.startsWith('---\naid: alice.agentid.pub')).toBe(true);
    const digest = createHash('sha256').update(uploaded).digest('hex');
    expect((client as any)._localAgentMdEtag).toBe(`"${digest}"`);

    unlinkSync(file);
  });
});

describe('client.fetchAgentMd', () => {
  it('uses self aid when omitted and updates _localAgentMdEtag', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue('---\naid: alice.agentid.pub\n---\n# Alice\n');
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({ status: 'unsigned', verified: false, payload: '' } as any);

    const info = await client.fetchAgentMd();

    expect(info.aid).toBe('alice.agentid.pub');
    expect(info.content.startsWith('---\naid: alice.agentid.pub')).toBe(true);
    expect(info.signature.status).toBe('unsigned');
    expect(typeof info.in_sync).toBe('boolean');

    const digest = createHash('sha256').update(info.content).digest('hex');
    expect((client as any)._localAgentMdEtag).toBe(`"${digest}"`);
  });

  it('does not update _localAgentMdEtag for foreign aid', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';
    (client as any)._localAgentMdEtag = '"unchanged"';

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue('---\naid: bob.agentid.pub\n---\n# Bob\n');
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({ status: 'unsigned', verified: false, payload: '' } as any);

    const info = await client.fetchAgentMd('bob.agentid.pub');

    expect(info.aid).toBe('bob.agentid.pub');
    expect(info.in_sync).toBeNull();
    expect((client as any)._localAgentMdEtag).toBe('"unchanged"');
  });

  it('writes content to savePath when given', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue('---\naid: alice.agentid.pub\n---\n# A\n');
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({ status: 'unsigned', verified: false, payload: '' } as any);

    const target = join(tmpdir(), `agent-out-${Date.now()}.md`);
    const info = await client.fetchAgentMd(undefined, target);

    expect(existsSync(target)).toBe(true);
    expect(readFileSync(target, 'utf-8').startsWith('---\naid: alice.agentid.pub')).toBe(true);
    expect(info.saved_to).toBe(target);
    expect(info.save_error).toBeNull();

    unlinkSync(target);
  });

  it('throws when no aid available', async () => {
    const client = makeClient();
    (client as any)._aid = null;
    await expect(client.fetchAgentMd()).rejects.toBeInstanceOf(ValidationError);
  });

  it('in_sync=true when local digest matches remote etag', async () => {
    const client = makeClient();
    (client as any)._aid = 'alice.agentid.pub';

    const body = '---\naid: alice.agentid.pub\n---\n# Alice\n';
    const digest = createHash('sha256').update(body).digest('hex');
    (client as any)._remoteAgentMdEtag = `"${digest}"`;

    vi.spyOn(client.auth, 'downloadAgentMd').mockResolvedValue(body);
    vi.spyOn(client.auth, 'verifyAgentMd').mockResolvedValue({ status: 'unsigned', verified: false, payload: '' } as any);

    const info = await client.fetchAgentMd();
    expect(info.in_sync).toBe(true);
  });
});
