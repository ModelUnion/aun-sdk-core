import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/client.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const TEST_TIMEOUT = 90_000;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function b64(value: string): string {
  return Buffer.from(value, 'utf-8').toString('base64');
}

function decodeText(result: { content?: unknown; source?: unknown }): string {
  return Buffer.from(String(result.content ?? result.source ?? ''), 'base64').toString('utf-8');
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-collab-ts-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect({ auto_reconnect: false });
}

describe('Collab TypeScript Docker 集成', () => {
  it('create/show/commit/log 使用真实 collab.* RPC', async () => {
    const rid = runId();
    const aliceAid = `collabtsa${rid}.${ISSUER}`;
    const rootPath = `/collab-ts/${rid}/proj`;
    const collabRoot = `${aliceAid}:${rootPath}`;
    const doc = 'spec.md';
    const alice = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      const created = await alice.collab.create(collabRoot, doc, b64('a\n'));
      expect(created.version).toBe(1);
      expect(String(created.current_target ?? '')).toContain(`${aliceAid}:/`);

      const show1 = await alice.collab.show(collabRoot, doc);
      expect(show1.version).toBe(1);
      expect(decodeText(show1)).toBe('a\n');

      const committed = await alice.collab.commit(collabRoot, doc, b64('a\nb\n'), 1);
      expect(committed.version).toBe(2);
      expect(String(committed.current_target ?? '')).toContain(`${aliceAid}:/`);

      const show2 = await alice.collab.show(collabRoot, doc);
      expect(show2.version).toBe(2);
      expect(decodeText(show2)).toBe('a\nb\n');

      const log = await alice.collab.log(collabRoot, doc);
      expect(log.map((item) => item.version)).toEqual([1, 2]);
      expect(log.every((item) => String(item.target ?? '').startsWith(`${aliceAid}:/`))).toBe(true);
    } finally {
      await alice.storage.remove(rootPath, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await alice.close();
    }
  }, TEST_TIMEOUT);
});
