// ── Playwright E2E 浏览器测试：Group FS facade ───────────────
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-fs.spec.ts --reporter=line
//
// 前置条件：
//   - Docker 单域环境运行中（不要由测试脚本启动 Kite）
//   - 浏览器通过 --host-resolver-rules 解析 gateway.agentid.pub → 127.0.0.1

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

let server: http.Server;
let baseUrl: string;

test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    const safePath = (req.url ?? '/').split('?')[0];
    const filePath = path.join(JS_ROOT, safePath);

    if (!filePath.startsWith(JS_ROOT)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

    const ext = path.extname(filePath);
    const mimeTypes: Record<string, string> = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.mjs': 'application/javascript',
      '.css': 'text/css',
      '.json': 'application/json',
    };

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] ?? 'application/octet-stream' });
      res.end(data);
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function testPageUrl(): string {
  return `${baseUrl}/tests/e2e-browser/test-page.html`;
}

async function installGroupFSHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__groupFSSmoke) return;

    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 10);
    const makeAndConnect = async (instanceId: string, aid: string): Promise<any> => {
      const client = w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-gfs-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
      return client;
    };
    const createStore = (client: any) => w.AUN_TEST_HELPERS.createStore(client);
    const textFromBytes = (data: any) => new TextDecoder().decode(new Uint8Array(data ?? []));
    const isGroupFSUnavailable = (err: any) => {
      const message = String(err?.message ?? err ?? '').toLowerCase();
      return message.includes('method not found')
        || message.includes('not implement')
        || message.includes('group.fs disabled')
        || message.includes('namespace not found');
    };

    w.__groupFSSmoke = { runId, makeAndConnect, createStore, textFromBytes, isGroupFSUnavailable, ISSUER: issuer };
  }, ISSUER);
}

test.describe('Group FS 浏览器 SDK smoke', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installGroupFSHelpers(page);
  });

  test('client.group.fs 使用真实 group.fs.* RPC 完成 POSIX 往返', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { runId, makeAndConnect, createStore, textFromBytes, isGroupFSUnavailable, ISSUER } = (window as any).__groupFSSmoke;
      const rid = runId();
      const ownerAid = `jsgfsowner${rid}.${ISSUER}`;
      const groupName = `jsgfs${rid}`;
      const owner = await makeAndConnect(`owner-${rid}`, ownerAid);
      let groupId = '';
      let store: any = null;

      try {
        let created: any;
        try {
          created = await owner.createGroup({
            name: `js-group-fs-${rid}`,
            group_name: groupName,
            visibility: 'private',
          });
        } catch (err: any) {
          const message = String(err?.message ?? err ?? '').toLowerCase();
          if (message.includes('method not found') || message.includes('not implement')) {
            return { skip: true, reason: `group.create 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }

        const group = created?.group ?? {};
        groupId = String(group?.group_id ?? created?.group_id ?? '').trim();
        const groupAid = String(group?.group_aid ?? created?.group_aid ?? '').trim();
        if (!groupId || !groupAid) {
          return { skip: false, error: `createGroup 未返回 group_id/group_aid: ${JSON.stringify(created)}` };
        }

        await owner.call('group.fs.namespace_ready', { group_id: groupId }).catch(() => undefined);
        store = createStore(owner);

        const writeOptions = { signAs: groupAid, aidStore: store };
        const baseDir = `${groupAid}:/public/js-browser-${rid}`;
        const notePath = `${baseDir}/note.txt`;
        const copyPath = `${baseDir}/copy.txt`;
        const renamedPath = `${baseDir}/renamed.txt`;
        const body = `GROUP-FS-JS-${rid}`;

        try {
          await owner.group.fs.mkdir(baseDir, { parents: true, ...writeOptions });
        } catch (err: any) {
          if (isGroupFSUnavailable(err)) {
            return { skip: true, reason: `group.fs.* 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }

        const uploaded = await owner.group.fs.cp(body, notePath, {
          force: true,
          contentType: 'text/plain',
          ...writeOptions,
        });
        const listed = await owner.group.fs.ls(baseDir, { long: true });
        const stat = await owner.group.fs.stat(notePath);
        const usage = await owner.group.fs.df(baseDir);
        const copied = await owner.group.fs.cp(notePath, copyPath, { force: true, ...writeOptions });
        const moved = await owner.group.fs.mv(copyPath, renamedPath, { force: true, ...writeOptions });
        const found = await owner.group.fs.find(baseDir, { name: 'renamed.txt' });
        const downloaded = await owner.group.fs.cp(notePath, 'bytes:', { force: true });
        const removed = await owner.group.fs.rm(baseDir, { recursive: true, force: true, ...writeOptions });

        return {
          skip: false,
          uploadedType: uploaded?.type,
          listedNames: Array.isArray(listed?.items) ? listed.items.map((item: any) => item?.name) : [],
          statType: stat?.type,
          statName: stat?.name,
          dfGroupAid: usage?.group_aid ?? groupAid,
          copiedType: copied?.type,
          movedName: moved?.name,
          foundNames: Array.isArray(found?.items) ? found.items.map((item: any) => item?.name) : [],
          downloadedText: textFromBytes(downloaded?.data),
          removedCount: Number(removed?.removed_count ?? 0),
        };
      } finally {
        if (groupId) {
          await owner.call('group.dissolve', { group_id: groupId }).catch(() => undefined);
        }
        if (store?.close) store.close();
        await owner.close();
      }
    });

    if ((result as any).skip) {
      console.log((result as any).reason);
      test.skip();
      return;
    }

    const r = result as any;
    expect(r.error ?? '').toBe('');
    expect(r.uploadedType).toBe('file');
    expect(r.listedNames).toContain('note.txt');
    expect(r.statType).toBe('file');
    expect(r.statName).toBe('note.txt');
    expect(String(r.dfGroupAid)).toBeTruthy();
    expect(r.copiedType).toBe('file');
    expect(r.movedName).toBe('renamed.txt');
    expect(r.foundNames).toContain('renamed.txt');
    expect(r.downloadedText).toContain('GROUP-FS-JS-');
    expect(r.removedCount).toBeGreaterThan(0);
  });

  test('owner 通过 group.fs.setAcl/removeAcl 授权并撤销 admin 群自有区写权限', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { runId, makeAndConnect, textFromBytes, isGroupFSUnavailable, ISSUER } = (window as any).__groupFSSmoke;
      const rid = runId();
      const ownerAid = `jsgfsaclowner${rid}.${ISSUER}`;
      const adminAid = `jsgfsacladmin${rid}.${ISSUER}`;
      const groupName = `jsgfsacl${rid}`;
      const owner = await makeAndConnect(`acl-owner-${rid}`, ownerAid);
      const admin = await makeAndConnect(`acl-admin-${rid}`, adminAid);
      let groupId = '';

      try {
        let created: any;
        try {
          created = await owner.createGroup({
            name: `js-group-fs-acl-${rid}`,
            group_name: groupName,
            visibility: 'private',
          });
        } catch (err: any) {
          const message = String(err?.message ?? err ?? '').toLowerCase();
          if (message.includes('method not found') || message.includes('not implement')) {
            return { skip: true, reason: `group.create 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }

        const group = created?.group ?? {};
        groupId = String(group?.group_id ?? created?.group_id ?? '').trim();
        const groupAid = String(group?.group_aid ?? created?.group_aid ?? '').trim();
        if (!groupId || !groupAid) {
          return { skip: false, error: `createGroup 未返回 group_id/group_aid: ${JSON.stringify(created)}` };
        }

        try {
          await owner.call('group.add_member', { group_id: groupId, aid: adminAid, role: 'member' });
          const roleResult = await owner.call('group.set_role', { group_id: groupId, aid: adminAid, role: 'admin' });
          if (roleResult?.new_role !== 'admin') {
            return { skip: false, error: `group.set_role 未返回 admin: ${JSON.stringify(roleResult)}` };
          }
        } catch (err: any) {
          const message = String(err?.message ?? err ?? '').toLowerCase();
          if (message.includes('method not found') || message.includes('not implement')) {
            return { skip: true, reason: `group.add_member/set_role 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }

        await owner.call('group.fs.namespace_ready', { group_id: groupId }).catch(() => undefined);
        const baseDir = `${groupAid}:/archive/js-acl-${rid}`;

        let beforeGrantDenied = false;
        try {
          await admin.group.fs.cp(`before grant ${rid}`, `${baseDir}/before.txt`, {
            force: true,
            parents: true,
            contentType: 'text/plain',
          });
        } catch (err: any) {
          if (isGroupFSUnavailable(err)) {
            return { skip: true, reason: `group.fs.* 不可用: ${err?.message ?? String(err)}` };
          }
          beforeGrantDenied = true;
        }

        const grant = await owner.group.fs.setAcl(baseDir, { granteeAid: 'role:admin', perms: 'rwx' });
        const acl = await owner.group.fs.getAcl(baseDir);
        const listedAcl = await owner.group.fs.listAcl(baseDir);
        const body = `admin write after grant ${rid}`;
        const uploaded = await admin.group.fs.cp(body, `${baseDir}/granted.txt`, {
          force: true,
          parents: true,
          contentType: 'text/plain',
        });
        const downloaded = await owner.group.fs.cp(`${baseDir}/granted.txt`, 'bytes:', { force: true });
        const revoke = await owner.group.fs.removeAcl(baseDir, { granteeAid: 'role:admin' });

        let afterRevokeDenied = false;
        try {
          await admin.group.fs.cp(`after revoke ${rid}`, `${baseDir}/after.txt`, {
            force: true,
            parents: true,
            contentType: 'text/plain',
          });
        } catch {
          afterRevokeDenied = true;
        }

        return {
          skip: false,
          beforeGrantDenied,
          grantAction: (grant as any)?.acl_action,
          aclHasAdmin: (((acl as any)?.acls ?? []) as any[]).some((item: any) => item?.grantee_aid === 'role:admin' && item?.perms === 'rwx'),
          listedAclHasAdmin: (((listedAcl as any)?.acls ?? []) as any[]).some((item: any) => item?.grantee_aid === 'role:admin' && item?.perms === 'rwx'),
          uploadedType: (uploaded as any)?.type,
          downloadedText: textFromBytes((downloaded as any)?.data),
          revokeAction: (revoke as any)?.acl_action,
          afterRevokeDenied,
        };
      } finally {
        if (groupId) {
          await owner.call('group.dissolve', { group_id: groupId }).catch(() => undefined);
        }
        await admin.close();
        await owner.close();
      }
    });

    if ((result as any).skip) {
      console.log((result as any).reason);
      test.skip();
      return;
    }

    const r = result as any;
    expect(r.error ?? '').toBe('');
    expect(r.beforeGrantDenied).toBe(true);
    expect(r.grantAction).toBe('set_acl');
    expect(r.aclHasAdmin).toBe(true);
    expect(r.listedAclHasAdmin).toBe(true);
    expect(r.uploadedType).toBe('file');
    expect(r.downloadedText).toContain('admin write after grant');
    expect(r.revokeAction).toBe('remove_acl');
    expect(r.afterRevokeDenied).toBe(true);
  });
});
