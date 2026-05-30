// ── Playwright E2E 浏览器测试：Group Resources ────────────────
//
// 覆盖：
//   1. 群资源直接添加 + 列表 + 删除（direct_add → list → delete）
//   2. 群资源访问票据（get_access → resolve_access_ticket）
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-resources.spec.ts --reporter=line
//
// 前置条件：
//   - Docker 环境运行中（docker compose up -d）
//   - 浏览器运行环境能通过 --host-resolver-rules 解析 gateway.agentid.pub → 127.0.0.1

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

// ── 本地 HTTP 服务器 ──────────────────────────────────────────

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

// ── 辅助：在浏览器上下文中注入 P0 测试工具 ────────────────────

async function installP0Helpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__aunP0) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 8);

    const makeAndConnect = async (instanceId: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({
        instanceId,
        issuer,
        debug: true,
      });
      if (client._configModel) {
        client._configModel.requireForwardSecrecy = false;
      }
      return client;
    };

        const ensureConnected = async (client: any, aid: string): Promise<void> => {
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

// ── 1. Group Resources: direct_add + list + delete ───────────

test.describe('Group Resources: direct_add + list + delete（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('storage.put_object → direct_add → list → delete → verify gone', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `grresa${rid}.${iss}`;
      const memberAid = `grresb${rid}.${iss}`;

      const owner = await makeAndConnect(`grres-owner-${rid}`);
      const member = await makeAndConnect(`grres-member-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: `res-${rid}`,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // 添加 member
        try {
          await owner.call('group.add_member', {
            group_id: groupId,
            aid: memberAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member failed: ${e.message}` };
        }

        await sleep(500);

        try {
          // 上传存储对象
          const bucket = `test-bucket-${rid}`;
          const objectKey = `test-file-${rid}.txt`;
          const fileContent = btoa(`hello-resource-${rid}`);

          try {
            await owner.call('storage.put_object', {
              owner_aid: ownerAid,
              bucket,
              object_key: objectKey,
              content: fileContent,
              content_type: 'text/plain',
              is_private: true,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'storage.put_object 未实现' };
            }
            return { skip: false, error: `storage.put_object failed: ${e.message}` };
          }

          await sleep(500);

          // 添加群资源
          const resourcePath = `docs/test-${rid}.txt`;
          let addOk = false;
          try {
            await owner.call('group.resources.direct_add', {
              group_id: groupId,
              resource_path: resourcePath,
              resource_type: 'file',
              title: `Test Resource ${rid}`,
              storage_ref: {
                owner_aid: ownerAid,
                bucket,
                object_key: objectKey,
                filename: `test-file-${rid}.txt`,
              },
            });
            addOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resources.direct_add 未实现' };
            }
            return { skip: false, error: `direct_add failed: ${e.message}` };
          }

          await sleep(500);

          // member 列出群资源
          let listFound = false;
          let listCount = 0;
          try {
            const listResult = await member.call('group.resources.list', {
              group_id: groupId,
              prefix: `docs/`,
            });
            const resources = listResult?.items ?? listResult?.resources ?? [];
            listCount = resources.length;
            listFound = resources.some((r: any) =>
              (r.resource_path ?? r.path) === resourcePath
            );
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resources.list 未实现' };
            }
            return { skip: false, error: `list failed: ${e.message}` };
          }

          // owner 删除群资源
          let deleteOk = false;
          try {
            await owner.call('group.resources.delete', {
              group_id: groupId,
              resource_path: resourcePath,
            });
            deleteOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resources.delete 未实现' };
            }
            return { skip: false, error: `delete failed: ${e.message}` };
          }

          await sleep(500);

          // 删除后再次列出，验证资源不存在
          let listFoundAfterDelete = true;
          try {
            const listResult2 = await member.call('group.resources.list', {
              group_id: groupId,
              prefix: `docs/`,
            });
            const resources2 = listResult2?.items ?? listResult2?.resources ?? [];
            listFoundAfterDelete = resources2.some((r: any) =>
              (r.resource_path ?? r.path) === resourcePath
            );
          } catch {
            // 列表失败不阻塞主流程
          }

          return {
            skip: false,
            addOk,
            listCount,
            listFound,
            deleteOk,
            listFoundAfterDelete,
          };
        } finally {
          if (groupId) {
            try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
          }
        }
      } finally {
        await owner.close();
        await member.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    expect(r.addOk).toBe(true);
    expect(r.listCount).toBeGreaterThanOrEqual(1);
    expect(r.listFound).toBe(true);
    expect(r.deleteOk).toBe(true);
    expect(r.listFoundAfterDelete).toBe(false);
  });
});

// ── 2. Group Resources: access_ticket ────────────────────────

test.describe('Group Resources: access_ticket（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('direct_add → get_access → resolve_access_ticket → second resolve rejected', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `grtka${rid}.${iss}`;
      const memberAid = `grtkb${rid}.${iss}`;

      const owner = await makeAndConnect(`grtk-owner-${rid}`);
      const member = await makeAndConnect(`grtk-member-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: `ticket-${rid}`,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // 添加 member
        try {
          await owner.call('group.add_member', {
            group_id: groupId,
            aid: memberAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member failed: ${e.message}` };
        }

        await sleep(500);

        try {
          // 上传存储对象
          const bucket = `ticket-bucket-${rid}`;
          const objectKey = `ticket-file-${rid}.txt`;
          const fileContent = btoa(`ticket-content-${rid}`);

          try {
            await owner.call('storage.put_object', {
              owner_aid: ownerAid,
              bucket,
              object_key: objectKey,
              content: fileContent,
              content_type: 'text/plain',
              is_private: true,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'storage.put_object 未实现' };
            }
            return { skip: false, error: `storage.put_object failed: ${e.message}` };
          }

          await sleep(500);

          // 添加群资源
          const resourcePath = `files/ticket-${rid}.txt`;
          try {
            await owner.call('group.resources.direct_add', {
              group_id: groupId,
              resource_path: resourcePath,
              resource_type: 'file',
              title: `Ticket Resource ${rid}`,
              storage_ref: {
                owner_aid: ownerAid,
                bucket,
                object_key: objectKey,
                filename: `ticket-file-${rid}.txt`,
              },
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resources.direct_add 未实现' };
            }
            return { skip: false, error: `direct_add failed: ${e.message}` };
          }

          await sleep(500);

          // member 获取访问权限
          let hasDownloadUrl = false;
          let hasAccessTicket = false;
          let accessTicket: string | undefined;
          try {
            const accessResult = await member.call('group.resources.get_access', {
              group_id: groupId,
              resource_path: resourcePath,
            });
            hasDownloadUrl = !!(accessResult?.download?.download_url ?? accessResult?.download_url);
            accessTicket = accessResult?.access_ticket?.ticket ?? accessResult?.access_ticket;
            hasAccessTicket = !!accessTicket;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resources.get_access 未实现' };
            }
            return { skip: false, error: `get_access failed: ${e.message}` };
          }

          if (!accessTicket) {
            return {
              skip: false,
              hasDownloadUrl,
              hasAccessTicket,
              firstResolveOk: false,
              secondResolveRejected: false,
              error: 'get_access 未返回 access_ticket',
            };
          }

          // 第一次 resolve — 应成功
          let firstResolveOk = false;
          try {
            const resolveResult = await member.call('group.resources.resolve_access_ticket', {
              access_ticket: accessTicket,
            });
            firstResolveOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resources.resolve_access_ticket 未实现' };
            }
            return { skip: false, error: `first resolve failed: ${e.message}` };
          }

          // 第二次 resolve 同一 ticket — 应被拒绝
          let secondResolveRejected = false;
          try {
            await member.call('group.resources.resolve_access_ticket', {
              access_ticket: accessTicket,
            });
            // 如果成功了，说明票据没有一次性限制
            secondResolveRejected = false;
          } catch {
            secondResolveRejected = true;
          }

          return {
            skip: false,
            hasDownloadUrl,
            hasAccessTicket,
            firstResolveOk,
            secondResolveRejected,
          };
        } finally {
          if (groupId) {
            try { await owner.call('group.resources.delete', {
              group_id: groupId,
              resource_path: `files/ticket-${rid}.txt`,
            }); } catch {}
            try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
          }
        }
      } finally {
        await owner.close();
        await member.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    expect(r.hasDownloadUrl).toBe(true);
    expect(r.hasAccessTicket).toBe(true);
    expect(r.firstResolveOk).toBe(true);
    expect(r.secondResolveRejected).toBe(true);
  });
});
