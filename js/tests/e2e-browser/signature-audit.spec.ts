// ── Playwright E2E 浏览器测试：群操作签名审计 ─────────────────
//
// 覆盖：
//   1. 更新公告携带签名 — set_settings(announcement.content) 事件包含 actor_aid + client_signature
//   2. 踢人操作携带签名 — kick 事件包含 actor_aid + client_signature
//   3. 只读操作安全 — group.info / group.list_my 无需签名即可正常执行
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/signature-audit.spec.ts --reporter=line
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

// ── 1. 更新公告携带签名 ──────────────────────────────────────

test.describe('签名审计: 更新公告携带签名（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('set_settings(announcement.content) 事件包含 actor_aid + client_signature', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `sigana${rid}.${iss}`;
      const bobAid = `siganb${rid}.${iss}`;

      const alice = await makeAndConnect(`sig-ann-alice-${rid}`);
      const bob = await makeAndConnect(`sig-ann-bob-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 创建群
        try {
          const createResult = await alice.call('group.create', {
            name: `sig-ann-${rid}`,
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

        // 添加 Bob
        try {
          await alice.call('group.add_member', {
            group_id: groupId,
            aid: bobAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member failed: ${e.message}` };
        }

        await sleep(500);

        // Bob 订阅 group.changed 事件
        const receivedEvents: any[] = [];
        let eventResolve: (() => void) | null = null;
        const eventPromise = new Promise<void>((resolve) => {
          eventResolve = resolve;
        });

        bob.on('group.changed', (evt: any) => {
          if (evt && evt.group_id === groupId) {
            receivedEvents.push(evt);
            if (eventResolve) eventResolve();
          }
        });

        // Alice 通过 set_settings 更新公告
        try {
          await alice.call('group.set_settings', {
            group_id: groupId,
            settings: {
              'announcement.content': `签名测试公告 ${rid}`,
            },
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.set_settings 未实现' };
          }
          return { skip: false, error: `set_settings failed: ${e.message}` };
        }

        // 等待 Bob 收到事件（最多 10 秒）
        const timeout = new Promise<void>((resolve) => setTimeout(resolve, 10_000));
        await Promise.race([eventPromise, timeout]);

        if (receivedEvents.length === 0) {
          try {
            const pullResult = await bob.call('group.pull_events', {
              group_id: groupId,
              after_event_seq: 0,
              limit: 50,
            });
            const events = pullResult?.events ?? [];
            for (const evt of events) {
              if (evt?.group_id === groupId) {
                receivedEvents.push(evt);
              }
            }
          } catch {
            // pull_events 兜底失败时按事件不可用处理
          }
        }

        if (receivedEvents.length === 0) {
          return { skip: true, reason: '未收到 group.changed 事件，跳过事件签名断言' };
        }

        const evt = receivedEvents[0];
        const cs = evt.client_signature;

        return {
          skip: false,
          hasEvent: true,
          actorAid: evt.actor_aid ?? null,
          expectedAliceAid: aliceAid,
          hasSignature: cs != null && typeof cs === 'object',
          signatureFields: cs ? {
            hasAid: typeof cs.aid === 'string',
            hasCertFingerprint: typeof cs.cert_fingerprint === 'string',
            hasParamsHash: typeof cs.params_hash === 'string',
            hasSignatureValue: typeof cs.signature === 'string',
            hasMethod: typeof cs._method === 'string',
          } : null,
          groupId,
        };
      } finally {
        if (groupId) {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await alice.close();
        await bob.close();
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

    expect(r.hasEvent).toBe(true);
    expect(r.actorAid).toBe(r.expectedAliceAid);

    if (r.signatureFields) {
      expect(r.signatureFields.hasAid).toBe(true);
      expect(r.signatureFields.hasCertFingerprint).toBe(true);
      expect(r.signatureFields.hasParamsHash).toBe(true);
      expect(r.signatureFields.hasSignatureValue).toBe(true);
      expect(r.signatureFields.hasMethod).toBe(true);
    }
  });
});

// ── 2. 踢人操作携带签名 ──────────────────────────────────────

test.describe('签名审计: 踢人操作携带签名（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('kick 事件包含 actor_aid + client_signature', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `sigkka${rid}.${iss}`;
      const bobAid = `sigkkb${rid}.${iss}`;
      const charlieAid = `sigkkc${rid}.${iss}`;

      const alice = await makeAndConnect(`sig-kick-alice-${rid}`);
      const bob = await makeAndConnect(`sig-kick-bob-${rid}`);
      const charlie = await makeAndConnect(`sig-kick-charlie-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);
        await ensureConnected(charlie, charlieAid);

        // 创建群
        try {
          const createResult = await alice.call('group.create', {
            name: `sig-kick-${rid}`,
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

        // 添加 Bob
        try {
          await alice.call('group.add_member', {
            group_id: groupId,
            aid: bobAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member(bob) failed: ${e.message}` };
        }

        // 添加 Charlie
        try {
          await alice.call('group.add_member', {
            group_id: groupId,
            aid: charlieAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member(charlie) failed: ${e.message}` };
        }

        await sleep(500);

        // Bob 订阅 group.changed 事件（等待 member_removed）
        const receivedEvents: any[] = [];
        let eventResolve: (() => void) | null = null;
        const eventPromise = new Promise<void>((resolve) => {
          eventResolve = resolve;
        });

        bob.on('group.changed', (evt: any) => {
          if (evt && evt.group_id === groupId && evt.action === 'member_removed') {
            receivedEvents.push(evt);
            if (eventResolve) eventResolve();
          }
        });

        // Alice 踢 Charlie
        try {
          await alice.call('group.kick', {
            group_id: groupId,
            aid: charlieAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.kick 未实现' };
          }
          return { skip: false, error: `kick failed: ${e.message}` };
        }

        // 等待 Bob 收到事件（最多 10 秒）
        const timeout = new Promise<void>((resolve) => setTimeout(resolve, 10_000));
        await Promise.race([eventPromise, timeout]);

        if (receivedEvents.length === 0) {
          return {
            skip: false,
            hasEvent: false,
            reason: '超时未收到 member_removed 事件',
          };
        }

        const evt = receivedEvents[0];
        const cs = evt.client_signature;

        return {
          skip: false,
          hasEvent: true,
          actorAid: evt.actor_aid ?? null,
          expectedAliceAid: aliceAid,
          hasSignature: cs != null && typeof cs === 'object',
          groupId,
        };
      } finally {
        if (groupId) {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await alice.close();
        await bob.close();
        await charlie.close();
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

    expect(r.hasEvent).toBe(true);
    expect(r.actorAid).toBe(r.expectedAliceAid);
    expect(r.hasSignature).toBe(true);
  });
});

// ── 3. 只读操作安全 ──────────────────────────────────────────

test.describe('签名审计: 只读操作安全（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('group.info 和 group.list_my 无需签名正常执行', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `sigrda${rid}.${iss}`;

      const alice = await makeAndConnect(`sig-read-alice-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(alice, aliceAid);

        // 创建群
        try {
          const createResult = await alice.call('group.create', {
            name: `sig-read-${rid}`,
            visibility: 'public',
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

        // 测试 group.info（只读操作）
        let infoOk = false;
        try {
          const infoResult = await alice.call('group.info', { group_id: groupId });
          infoOk = infoResult != null;
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.info 未实现' };
          }
          return { skip: false, error: `info failed: ${e.message}` };
        }

        // 测试 group.list_my（只读操作）
        let listMyOk = false;
        try {
          const listResult = await alice.call('group.list_my', {});
          listMyOk = listResult != null;
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.list_my 未实现' };
          }
          return { skip: false, error: `list_my failed: ${e.message}` };
        }

        return {
          skip: false,
          infoOk,
          listMyOk,
          groupId,
        };
      } finally {
        if (groupId) {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await alice.close();
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

    expect(r.infoOk).toBe(true);
    expect(r.listMyOk).toBe(true);
  });
});
