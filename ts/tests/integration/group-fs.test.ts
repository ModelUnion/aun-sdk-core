import { describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/client.js';
import { createAIDStoreForClient, createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const TEST_TIMEOUT = 120_000;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-ts-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect({ auto_reconnect: false });
}

function groupFromResult(result: unknown): { groupId: string; groupAid: string } {
  const raw = result as Record<string, any>;
  const group = raw.group ?? {};
  const groupId = String(group.group_id ?? raw.group_id ?? '').trim();
  const groupAid = String(group.group_aid ?? raw.group_aid ?? '').trim();
  if (!groupId || !groupAid) {
    throw new Error(`createGroup 未返回 group_id/group_aid: ${JSON.stringify(result)}`);
  }
  return { groupId, groupAid };
}

describe('Group FS TypeScript Docker 集成', () => {
  it('client.group.fs mkdir/cp/ls/stat/df/mv/find/download/rm 使用真实 group.fs.* RPC', async () => {
    const rid = runId();
    const ownerAid = `gfstsowner${rid}.${ISSUER}`;
    const groupName = `gfsts${rid}`;
    const owner = makeClient();
    let groupId = '';
    let store: ReturnType<typeof createAIDStoreForClient> | null = null;

    try {
      await ensureConnected(owner, ownerAid);
      const created = await owner.createGroup({
        name: `ts-group-fs-${rid}`,
        group_name: groupName,
        visibility: 'private',
      });
      const identity = groupFromResult(created);
      groupId = identity.groupId;
      const groupAid = identity.groupAid;
      await owner.call('group.fs.namespace_ready', { group_id: groupId }).catch(() => undefined);

      store = createAIDStoreForClient(owner);
      const signOptions = { signAs: groupAid, aidStore: store };
      const baseDir = `${groupAid}:/public/ts-sdk-${rid}`;
      const source = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-src-')), 'source.txt');
      const downloaded = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-dl-')), 'download.txt');
      const body = `GROUP-FS-TS-${rid}`;
      fs.writeFileSync(source, body, 'utf-8');

      await owner.group.fs.mkdir(baseDir, { parents: true, ...signOptions });
      const uploaded = await owner.group.fs.cp(source, `${baseDir}/note.txt`, { force: true, ...signOptions }) as Record<string, any>;
      expect(uploaded.type).toBe('file');

      const listed = await owner.group.fs.ls(baseDir, { long: true }) as Record<string, any>;
      expect((listed.items ?? []).some((item: any) => item.name === 'note.txt')).toBe(true);

      const stat = await owner.group.fs.stat(`${baseDir}/note.txt`) as Record<string, any>;
      expect(stat.type).toBe('file');
      expect(stat.name).toBe('note.txt');

      const usage = await owner.group.fs.df(baseDir) as Record<string, any>;
      expect(String(usage.group_aid ?? groupAid)).toBeTruthy();

      const copied = await owner.group.fs.cp(`${baseDir}/note.txt`, `${baseDir}/copy.txt`, { force: true, ...signOptions }) as Record<string, any>;
      expect(copied.type).toBe('file');

      const moved = await owner.group.fs.mv(`${baseDir}/copy.txt`, `${baseDir}/renamed.txt`, { force: true, ...signOptions }) as Record<string, any>;
      expect(moved.name).toBe('renamed.txt');

      const found = await owner.group.fs.find(baseDir, { name: 'renamed.txt' }) as Record<string, any>;
      expect((found.items ?? []).some((item: any) => item.name === 'renamed.txt')).toBe(true);

      const result = await owner.group.fs.cp(`${baseDir}/note.txt`, downloaded, { force: true }) as Record<string, any>;
      expect(Buffer.from(result.data ?? []).toString('utf-8')).toBe(body);
      expect(fs.readFileSync(downloaded, 'utf-8')).toBe(body);

      const removed = await owner.group.fs.rm(baseDir, { recursive: true, force: true, ...signOptions }) as Record<string, any>;
      expect(Number(removed.removed_count ?? 0)).toBeGreaterThan(0);
    } finally {
      store?.close();
      if (groupId) {
        await owner.call('group.dissolve', { group_id: groupId }).catch(() => undefined);
      }
      await owner.close();
    }
  }, TEST_TIMEOUT);

  it('owner 通过 group.fs.setAcl/removeAcl 授权并撤销 admin 群自有区写权限', async () => {
    const rid = runId();
    const ownerAid = `gfstsaclowner${rid}.${ISSUER}`;
    const adminAid = `gfstsacladmin${rid}.${ISSUER}`;
    const groupName = `gfstsacl${rid}`;
    const owner = makeClient();
    const admin = makeClient();
    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(admin, adminAid);
      const created = await owner.createGroup({
        name: `ts-group-fs-acl-${rid}`,
        group_name: groupName,
        visibility: 'private',
      });
      const identity = groupFromResult(created);
      groupId = identity.groupId;
      const groupAid = identity.groupAid;
      await owner.call('group.add_member', { group_id: groupId, aid: adminAid, role: 'member' });
      const roleResult = await owner.call('group.set_role', { group_id: groupId, aid: adminAid, role: 'admin' }) as Record<string, any>;
      expect(roleResult.new_role).toBe('admin');
      await owner.call('group.fs.namespace_ready', { group_id: groupId }).catch(() => undefined);

      const baseDir = `${groupAid}:/archive/ts-acl-${rid}`;
      const before = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-acl-before-')), 'before.txt');
      const granted = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-acl-grant-')), 'granted.txt');
      const after = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-acl-after-')), 'after.txt');
      fs.writeFileSync(before, `before grant ${rid}`, 'utf-8');
      const body = `admin write after grant ${rid}`;
      fs.writeFileSync(granted, body, 'utf-8');
      fs.writeFileSync(after, `after revoke ${rid}`, 'utf-8');

      await expect(admin.group.fs.cp(before, `${baseDir}/before.txt`, { force: true, parents: true })).rejects.toThrow();

      const grant = await owner.group.fs.setAcl(baseDir, { granteeAid: 'role:admin', perms: 'rwx' }) as Record<string, any>;
      expect(grant.acl_action).toBe('set_acl');
      const uploaded = await admin.group.fs.cp(granted, `${baseDir}/granted.txt`, { force: true, parents: true }) as Record<string, any>;
      expect(uploaded.type).toBe('file');

      const downloaded = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gfs-acl-dl-')), 'downloaded.txt');
      await owner.group.fs.cp(`${baseDir}/granted.txt`, downloaded, { force: true });
      expect(fs.readFileSync(downloaded, 'utf-8')).toBe(body);

      const revoke = await owner.group.fs.removeAcl(baseDir, { granteeAid: 'role:admin' }) as Record<string, any>;
      expect(revoke.acl_action).toBe('remove_acl');
      await expect(admin.group.fs.cp(after, `${baseDir}/after.txt`, { force: true, parents: true })).rejects.toThrow();
    } finally {
      if (groupId) {
        await owner.call('group.dissolve', { group_id: groupId }).catch(() => undefined);
      }
      await admin.close();
      await owner.close();
    }
  }, TEST_TIMEOUT);
});
