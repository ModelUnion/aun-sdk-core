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

      await alice.storage.setAcl(`/docs/${rid}`, { owner: aliceAid, bucket, granteeAid: bobAid, perms: 'w' });
      await expect(bob.storage.readBytes(filePath, { owner: aliceAid, bucket })).rejects.toThrow();
      await bob.storage.writeBytes(`/docs/${rid}/bob-write.txt`, `bob-write-${rid}`, {
        owner: aliceAid,
        bucket,
        contentType: 'text/plain',
      });
      await expect(bob.storage.lowlevel.createShareLink({
        owner: aliceAid,
        bucket,
        objectKey: filePath.replace(/^\/+/, ''),
        allowedAids: [bobAid],
      })).rejects.toThrow();
      const share = await alice.storage.lowlevel.createShareLink({
        owner: aliceAid,
        bucket,
        objectKey: filePath.replace(/^\/+/, ''),
        allowedAids: [bobAid],
        expireInSeconds: 300,
      });
      const shareId = String(share.share_id ?? share.shareId ?? '');
      const bobRead = await bob.storage.lowlevel.getByShare({ shareId });
      expect(Buffer.from(String(bobRead.content ?? ''), 'base64').toString('utf-8')).toBe(body);
      await alice.storage.lowlevel.revokeShareLink({ shareId });
      await expect(bob.storage.lowlevel.getByShare({ shareId })).rejects.toThrow();

      await alice.storage.removeAcl(`/docs/${rid}`, { owner: aliceAid, bucket, granteeAid: bobAid });
      await expect(bob.storage.writeBytes(`/docs/${rid}/bob-write-after-revoke.txt`, 'no', {
        owner: aliceAid,
        bucket,
        contentType: 'text/plain',
      })).rejects.toThrow();

      const issued = await alice.storage.issueToken(filePath, { owner: aliceAid, bucket, maxReads: 1 });
      const token = String(issued.token ?? '');
      expect(token).toBeTruthy();
      const tokenRead = await bob.storage.readBytes(filePath, { owner: aliceAid, bucket, token });
      expect(new TextDecoder().decode(tokenRead)).toBe(body);
      await expect(bob.storage.readBytes(filePath, { owner: aliceAid, bucket, token })).rejects.toThrow();

      const tokens = await alice.storage.listTokens(filePath, { owner: aliceAid, bucket });
      expect((tokens.tokens ?? tokens.items ?? []) as unknown[]).not.toHaveLength(0);

      const usage = await alice.storage.df({ owner: aliceAid, bucket });
      expect(usage.owner).toBeTruthy();
      expect(usage.usedBytes).toBeGreaterThan(0);

      const copiedPath = `/docs/${rid}/copied.txt`;
      const copied = await alice.storage.copy(filePath, copiedPath, { owner: aliceAid, bucket, overwrite: true });
      expect(copied.type).toBe('file');
      expect(copied.path).toBe(copiedPath);
      expect(new TextDecoder().decode(await alice.storage.readBytes(copiedPath, { owner: aliceAid, bucket }))).toBe(body);

      const renamedPath = `/docs/${rid}/renamed.txt`;
      const renamed = await alice.storage.rename(copiedPath, renamedPath, { owner: aliceAid, bucket, overwrite: true });
      expect(renamed.path).toBe(renamedPath);
      await expect(alice.storage.stat(copiedPath, { owner: aliceAid, bucket })).rejects.toThrow();

      const linkPath = `/docs/${rid}/current.txt`;
      const link = await alice.storage.symlink(renamedPath, linkPath, { owner: aliceAid, bucket, overwrite: true });
      expect(link.type).toBe('symlink');
      expect(link.target).toBe(renamedPath);
      const lstat = await alice.storage.lstat(linkPath, { owner: aliceAid, bucket });
      expect(lstat.type).toBe('symlink');
      const statLink = await alice.storage.stat(linkPath, { owner: aliceAid, bucket });
      expect(statLink.type).toBe('file');
      const readlink = await alice.storage.readlink(linkPath, { owner: aliceAid, bucket });
      expect(readlink.target).toBe(renamedPath);

      const repointed = await alice.storage.repoint(linkPath, filePath, { owner: aliceAid, bucket });
      expect(repointed.target).toBe(filePath);
      const renamedLinkPath = `/docs/${rid}/latest.txt`;
      const renamedLink = await alice.storage.renameSymlink(linkPath, renamedLinkPath, { owner: aliceAid, bucket, overwrite: true });
      expect(renamedLink.path).toBe(renamedLinkPath);
      expect(renamedLink.target).toBe(filePath);

      const found = await alice.storage.find(`/docs/${rid}`, { owner: aliceAid, bucket, name: 'latest.txt', nodeType: 'symlink' });
      expect(found.map((node) => node.name)).toContain('latest.txt');

      const removedLink = await alice.storage.remove(renamedLinkPath, { owner: aliceAid, bucket });
      expect(removedLink.removedCount).toBeGreaterThan(0);
      const removedFile = await alice.storage.remove(renamedPath, { owner: aliceAid, bucket });
      expect(removedFile.removedCount).toBeGreaterThan(0);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, TEST_TIMEOUT);
});
