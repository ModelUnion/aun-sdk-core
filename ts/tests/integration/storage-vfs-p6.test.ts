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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-p6-ts-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function text(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

async function expectUnavailable(action: Promise<unknown>): Promise<void> {
  await expect(action).rejects.toThrow();
}

describe('P6 TypeScript StorageVFS Docker 集成', () => {
  it('mount/read/write/copy/rename/remove/unmount 使用真实 storage.fs RPC', async () => {
    const rid = runId();
    const aliceAid = `p6tsa${rid}.${ISSUER}`;
    const groupAid = `p6tsg${rid}.${ISSUER}`;
    const root = `/fs-p6-ts-${rid}`;
    const sourceDir = `${root}/source`;
    const mountDir = `${root}/memberdata/alice`;
    const body = `hello-p6-ts-${rid}`;
    const writtenViaMount = `write-p6-ts-${rid}`;

    const alice = makeClient();
    const group = makeClient();
    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(group, groupAid);

      await alice.storage.writeBytes(`${sourceDir}/a.txt`, body, { owner: aliceAid, contentType: 'text/plain' });
      await alice.storage.setAcl(sourceDir, { owner: aliceAid, granteeAid: groupAid, perms: 'rwd' });

      const mounted = await group.storage.mount(`${aliceAid}:${sourceDir}`, mountDir, { owner: groupAid, readonly: false });
      expect(mounted.type).toBe('mount');
      expect(mounted.path).toBe(mountDir);
      expect(mounted.mountSource).toContain(aliceAid);
      expect(mounted.mountSource).toContain(sourceDir.replace(/^\//, ''));

      const lstat = await group.storage.lstat(mountDir, { owner: groupAid });
      const stat = await group.storage.stat(mountDir, { owner: groupAid });
      const listed = await group.storage.list(mountDir, { owner: groupAid, long: true });
      expect(lstat.type).toBe('mount');
      expect(stat.type).toBe('dir');
      expect(listed.map((node) => node.name)).toContain('a.txt');
      expect(text(await group.storage.readBytes(`${mountDir}/a.txt`, { owner: groupAid }))).toBe(body);

      await group.storage.writeBytes(`${mountDir}/b.txt`, writtenViaMount, { owner: groupAid, contentType: 'text/plain' });
      expect(text(await alice.storage.readBytes(`${sourceDir}/b.txt`, { owner: aliceAid }))).toBe(writtenViaMount);

      const copied = await group.storage.copy(`${mountDir}/b.txt`, `${mountDir}/copied.txt`, { owner: groupAid });
      const renamed = await group.storage.rename(`${mountDir}/copied.txt`, `${mountDir}/renamed.txt`, { owner: groupAid });
      const removed = await group.storage.remove(`${mountDir}/renamed.txt`, { owner: groupAid });
      expect(copied.owner).toBe(aliceAid);
      expect(renamed.path).toBe(`${sourceDir}/renamed.txt`);
      expect(removed.removedCount).toBe(1);
      await expectUnavailable(alice.storage.stat(`${sourceDir}/renamed.txt`, { owner: aliceAid }));

      const unmounted = await group.storage.unmount(mountDir, { owner: groupAid });
      expect(Boolean(unmounted.unmounted)).toBe(true);
      await expectUnavailable(group.storage.stat(mountDir, { owner: groupAid }));
      expect(text(await alice.storage.readBytes(`${sourceDir}/a.txt`, { owner: aliceAid }))).toBe(body);
    } finally {
      await alice.storage.remove(root, { owner: aliceAid, recursive: true }).catch(() => undefined);
      await group.storage.remove(root, { owner: groupAid, recursive: true }).catch(() => undefined);
      await alice.close();
      await group.close();
    }
  }, TEST_TIMEOUT);
});
