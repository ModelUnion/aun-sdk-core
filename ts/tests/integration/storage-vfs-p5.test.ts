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

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-p5-ts-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

describe('P5 TypeScript StorageVFS Docker 集成', () => {
  it('write/read/list/stat/ACL/token 使用真实 storage RPC', async () => {
    const rid = runId();
    const aliceAid = `p5tsa${rid}.${ISSUER}`;
    const bobAid = `p5tsb${rid}.${ISSUER}`;
    const bucket = `p5-ts-${rid}`;
    const filePath = `/docs/${rid}/a.txt`;
    const body = `hello-p5-ts-${rid}`;

    const alice = makeClient();
    const bob = makeClient();
    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const written = await alice.storage.writeBytes(filePath, body, { owner: aliceAid, bucket, contentType: 'text/plain' });
      expect(written.type).toBe('file');
      expect(written.path).toBe(filePath);

      const stat = await alice.storage.stat(filePath, { owner: aliceAid, bucket });
      expect(stat.type).toBe('file');
      expect(stat.mode).toBeTruthy();

      const listed = await alice.storage.list(`/docs/${rid}`, { owner: aliceAid, bucket, long: true });
      expect(listed.map((node) => node.name)).toContain('a.txt');

      await expect(bob.storage.readBytes(filePath, { owner: aliceAid, bucket })).rejects.toThrow();

      await alice.storage.setAcl(`/docs/${rid}`, { owner: aliceAid, bucket, granteeAid: bobAid, perms: 'r' });
      const bobRead = await bob.storage.readBytes(filePath, { owner: aliceAid, bucket });
      expect(new TextDecoder().decode(bobRead)).toBe(body);

      await alice.storage.removeAcl(`/docs/${rid}`, { owner: aliceAid, bucket, granteeAid: bobAid });
      await expect(bob.storage.readBytes(filePath, { owner: aliceAid, bucket })).rejects.toThrow();

      const issued = await alice.storage.issueToken(filePath, { owner: aliceAid, bucket, maxReads: 1 });
      const token = String(issued.token ?? '');
      expect(token).toBeTruthy();
      const tokenRead = await bob.storage.readBytes(filePath, { owner: aliceAid, bucket, token });
      expect(new TextDecoder().decode(tokenRead)).toBe(body);
      await expect(bob.storage.readBytes(filePath, { owner: aliceAid, bucket, token })).rejects.toThrow();
    } finally {
      await alice.close();
      await bob.close();
    }
  }, TEST_TIMEOUT);
});
