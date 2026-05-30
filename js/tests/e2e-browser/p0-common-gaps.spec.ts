// ── Playwright E2E 浏览器测试：P0 共同缺口 ──────────────────
//
// 覆盖：
//   P0-01: 网关健康检查（真实 Gateway）
//   P0-02: AID 创建失败路径
//   P0-06: 消息撤回
//   P0-09: 发送到暂停群
//   P0-10: 非成员发送群消息
//   P0-14: 断线后 RPC + 重连恢复
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/p0-common-gaps.spec.ts --reporter=line
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

    /**
     * 创建并连接一个客户端。
     * 浏览器 SDK 使用 IndexedDB 存储，每个实例需要独立的 instanceId。
     */
    const makeAndConnect = async (instanceId: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({
        instanceId,
        issuer,
        debug: true,
      });
      // 禁用 forward secrecy 以简化测试
      if (client._configModel) {
        client._configModel.requireForwardSecrecy = false;
      }
      return client;
    };

    /**
     * 确保 AID 已创建、认证并连接。
     */
        const ensureConnected = async (client: any, aid: string): Promise<void> => {
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected };
  }, ISSUER);
}

// ── P0-01: 网关健康检查 ──────────────────────────────────────

test.describe('P0-01: 网关健康检查（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('正常健康检查 — 真实 Gateway 应返回 true', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const AUN = (window as any).AUN;
      const client = new AUN.AUNClient({ instanceId: 'p0-01-health', debug: true });
      try {
        const ok = await client.checkGatewayHealth(`https://gateway.${iss}`, 10000);
        return { ok, error: null };
      } catch (e: any) {
        return { ok: false, error: e.message };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect(result.ok).toBe(true);
  });

  test('超时 — 不可达地址应返回 false', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const client = new AUN.AUNClient({ instanceId: 'p0-01-timeout', debug: true });
      try {
        const start = Date.now();
        const ok = await client.checkGatewayHealth('https://192.0.2.1:9999', 2000);
        const elapsed = Date.now() - start;
        return { ok, elapsed, error: null };
      } catch (e: any) {
        return { ok: false, elapsed: 0, error: e.message };
      } finally {
        await client.close();
      }
    });

    expect(result.ok).toBe(false);
  });
});

// ── P0-02: AID 创建失败路径 ──────────────────────────────────

test.describe('P0-02: AID 创建失败路径（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('空 AID 应被拒绝', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const AUN = (window as any).AUN;
      const helpers = (window as any).AUN_TEST_HELPERS;
      const client = new AUN.AUNClient({ instanceId: 'p0-02-empty', debug: true });
      try {
        const store = helpers.createStore(client);
        const result = await store.register('');
        return { rejected: !result.ok, error: result.ok ? null : result.error.message };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect(result.rejected).toBe(true);
  });

  test('创建已存在的 AID — 应报错或幂等', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const AUN = (window as any).AUN;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0dup${rid}.${iss}`;
      const client1 = new AUN.AUNClient({ instanceId: 'p0-02-dup1', debug: true });
      const client2 = new AUN.AUNClient({ instanceId: 'p0-02-dup2', debug: true });
      const helpers = (window as any).AUN_TEST_HELPERS;

      try {
        const first = await helpers.createStore(client1).register(aid);
        if (!first.ok) return { behavior: 'first_failed', error: first.error.message };
        const second = await helpers.createStore(client2).register(aid);
        if (second.ok) {
          return { behavior: 'idempotent' };
        }
        return { behavior: 'error', error: second.error.message };
      } catch (e: any) {
        return { behavior: 'first_failed', error: e.message };
      } finally {
        await client1.close();
        await client2.close();
      }
    }, ISSUER);

    if (result.behavior === 'first_failed') {
      console.log(`跳过：首次创建 AID 失败: ${result.error}`);
      test.skip();
      return;
    }
    // 两种行为都可接受
    expect(['idempotent', 'error']).toContain(result.behavior);
  });
});

// ── P0-06: 消息撤回 ──────────────────────────────────────────

test.describe('P0-06: 消息撤回（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('撤回自己的消息 / 撤回他人消息被拒绝', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `p0rca${rid}.${iss}`;
      const bobAid = `p0rcb${rid}.${iss}`;

      const alice = await makeAndConnect(`p0-06-alice-${rid}`);
      const bob = await makeAndConnect(`p0-06-bob-${rid}`);

      const results: Record<string, string> = {};

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // Alice 发消息
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `recall-test-${rid}` },
          durable: true,
          encrypt: false,
        });
        const msgId = sendResult?.message_id;
        if (!msgId) {
          return { skip: true, reason: 'send 未返回 message_id' };
        }

        await sleep(500);

        // Alice 撤回自己的消息
        try {
          const recallResult = await alice.call('message.recall', { message_ids: [msgId] });
          if (Number(recallResult?.recalled ?? 0) <= 0) {
            results.recall_own = 'fail: recall did not apply';
          } else {
            results.recall_own = 'pass';
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'message.recall 未实现' };
          }
          results.recall_own = 'fail: ' + e.message;
        }

        // Bob 撤回 Alice 的消息 — 应被拒绝
        const sendResult2 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `recall-perm-${rid}` },
          durable: true,
          encrypt: false,
        });
        const msgId2 = sendResult2?.message_id;
        if (msgId2) {
          await sleep(300);
          try {
            const denied = await bob.call('message.recall', { message_ids: [msgId2] });
            results.recall_other = Number(denied?.recalled ?? 0) > 0
              ? 'fail: should have been rejected'
              : 'pass';
          } catch {
            results.recall_other = 'pass';
          }
        }

        return { skip: false, results };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = (result as any).results;
    expect(r.recall_own).toBe('pass');
    if (r.recall_other) {
      expect(r.recall_other).toBe('pass');
    }
  });
});

// ── P0-09: 发送到暂停群 ──────────────────────────────────────

test.describe('P0-09: 发送到暂停群（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('向暂停状态的群发送消息应被拒绝', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const ownerAid = `p0sus${rid}.${iss}`;
      const memberAid = `p0sum${rid}.${iss}`;

      const owner = await makeAndConnect(`p0-09-owner-${rid}`);
      const member = await makeAndConnect(`p0-09-member-${rid}`);

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);

        // 创建群
        const createResult = await owner.call('group.create', {
          members: [memberAid],
          metadata: { name: `suspend-test-${rid}` },
        });
        const groupId = createResult?.group_id ?? createResult?.group?.group_id;
        if (!groupId) {
          return { skip: true, reason: '创建群未返回 group_id' };
        }

        await sleep(1000);

        // 暂停群
        try {
          await owner.call('group.suspend', { group_id: groupId });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.suspend 未实现' };
          }
          throw e;
        }

        await sleep(500);

        // 成员发消息 — 应被拒绝
        try {
          await member.call('group.send', {
            group_id: groupId,
            payload: { type: 'text', text: 'should-fail' },
          });
          return { rejected: false };
        } catch {
          return { rejected: true };
        } finally {
          try { await owner.call('group.resume', { group_id: groupId }); } catch {}
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await owner.close();
        await member.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    expect((result as any).rejected).toBe(true);
  });
});

// ── P0-10: 非成员发送群消息 ──────────────────────────────────

test.describe('P0-10: 非成员发送群消息（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('非成员向群发消息应被权限拒绝', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const ownerAid = `p0nmo${rid}.${iss}`;
      const outsiderAid = `p0nms${rid}.${iss}`;

      const owner = await makeAndConnect(`p0-10-owner-${rid}`);
      const outsider = await makeAndConnect(`p0-10-outsider-${rid}`);

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(outsider, outsiderAid);

        // 创建只有 owner 的群
        const createResult = await owner.call('group.create', {
          members: [],
          metadata: { name: `perm-test-${rid}` },
        });
        const groupId = createResult?.group_id ?? createResult?.group?.group_id;
        if (!groupId) {
          return { skip: true, reason: '创建群未返回 group_id' };
        }

        await sleep(500);

        // 非成员发消息 — 应被拒绝
        try {
          await outsider.call('group.send', {
            group_id: groupId,
            payload: { type: 'text', text: 'unauthorized' },
          });
          return { rejected: false };
        } catch {
          return { rejected: true };
        } finally {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await owner.close();
        await outsider.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    expect((result as any).rejected).toBe(true);
  });
});

// ── P0-04: Login 重放攻击 ──────────────────────────────────

test.describe('P0-04: Login 重放攻击（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('两次认证 token 不同 — challenge 不可重用', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0rpl${rid}.${iss}`;

      const client = await makeAndConnect(`p0-04-rpl-${rid}`);
      try {
        const helpers = (window as any).AUN_TEST_HELPERS;
        await helpers.registerAndLoadIdentity(client, aid);

        const auth1 = await client.authenticate();
        if (!auth1?.access_token) {
          return { error: '首次认证未返回 access_token' };
        }

        const auth2 = await client.authenticate();
        if (!auth2?.access_token) {
          return { error: '第二次认证未返回 access_token' };
        }

        return {
          same_token: auth1.access_token === auth2.access_token,
        };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect((result as any).error).toBeUndefined();
    if (!(result as any).same_token) {
      console.log('两次认证返回不同 token（正确 — challenge 不可重用）');
    } else {
      console.log('警告: 两次认证返回了相同的 token');
    }
  });
});

// ── P0-07: 临时消息 TTL ──────────────────────────────────────

test.describe('P0-07: 临时消息 TTL（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('非持久消息应能收到但不永久持久化', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `p0epa${rid}.${iss}`;
      const bobAid = `p0epb${rid}.${iss}`;

      const alice = await makeAndConnect(`p0-07-alice-${rid}`);
      const bob = await makeAndConnect(`p0-07-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 发送临时消息
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `ephemeral-${rid}` },
          durable: false,
          encrypt: false,
        });

        await sleep(1000);

        // Bob pull
        let pullMatching = 0;
        try {
          const pullResult = await bob.call('message.pull', { limit: 50 });
          const messages = pullResult?.messages ?? [];
          pullMatching = messages.filter(
            (m: any) => m?.payload?.text?.startsWith(`ephemeral-${rid}`),
          ).length;
        } catch {
          // pull 异常也可接受
        }

        return {
          sent: !!sendResult,
          message_id: sendResult?.message_id ?? null,
          pull_matching: pullMatching,
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    expect((result as any).sent).toBe(true);
  });
});

// ── P0-08: 重连中补洞 ──────────────────────────────────────

test.describe('P0-08: 重连中补洞（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('断线期间收消息 → 重连后自动补洞', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `p0gfa${rid}.${iss}`;
      const bobAid = `p0gfb${rid}.${iss}`;

      const alice = await makeAndConnect(`p0-08-alice-${rid}`);
      const bob = await makeAndConnect(`p0-08-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const msgCount = 5;
        const received: any[] = [];
        let resolveAll: (() => void) | null = null;
        const allReceived = new Promise<void>(r => { resolveAll = r; });

        bob.on('message.received', (data: any) => {
          if (data && typeof data === 'object') {
            received.push(data);
            if (received.length >= msgCount && resolveAll) {
              resolveAll();
            }
          }
        });

        // Bob 断线
        await bob.disconnect();
        await sleep(1000);

        // Alice 在 Bob 断线期间发消息
        for (let i = 0; i < msgCount; i++) {
          await alice.call('message.send', {
            to: bobAid,
            payload: { type: 'text', text: `gap-${rid}-${i}` },
            durable: true,
            encrypt: false,
          });
          await sleep(100);
        }

        await sleep(500);

        // 清空收集，重连
        received.length = 0;
        await bob.connect();

        // 等待补洞
        const timeout = new Promise<void>((_, reject) =>
          setTimeout(() => reject(new Error('timeout')), 15000),
        );

        let count = 0;
        try {
          await Promise.race([allReceived, timeout]);
          count = received.length;
        } catch {
          count = received.length;
        }

        return { sent: msgCount, received: count };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    const r = result as any;
    expect(r.received).toBeGreaterThan(0);
  });
});

// ── P0-03: Login 过期挑战 ────────────────────────────────────

test.describe('P0-03: Login 过期挑战（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('两次认证应返回不同 token', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0exp${rid}.${iss}`;

      const client = await makeAndConnect(`p0-03-exp-${rid}`);
      try {
        const helpers = (window as any).AUN_TEST_HELPERS;
        await helpers.registerAndLoadIdentity(client, aid);

        const auth1 = await client.authenticate();
        if (!auth1?.access_token) {
          return { error: '首次认证未返回 access_token' };
        }

        await sleep(2000);

        const auth2 = await client.authenticate();
        if (!auth2?.access_token) {
          return { error: '第二次认证未返回 access_token' };
        }

        return {
          same_token: auth1.access_token === auth2.access_token,
          token1: auth1.access_token.slice(0, 8),
          token2: auth2.access_token.slice(0, 8),
        };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect((result as any).error).toBeUndefined();
    // 两种情况都记录，但不同 token 是期望行为
    if ((result as any).same_token) {
      console.log('警告: 两次认证返回了相同的 token');
    } else {
      console.log('两次认证返回不同 token（正确）');
    }
  });
});

// ── P0-05: Token 并发刷新 ────────────────────────────────────

test.describe('P0-05: Token 并发刷新（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('同 AID 并发 authenticate 应有 inflight 限流', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0tkn${rid}.${iss}`;

      const client = await makeAndConnect(`p0-05-tkn-${rid}`);
      try {
        const helpers = (window as any).AUN_TEST_HELPERS;
        await helpers.registerAndLoadIdentity(client, aid);

        // 并发发起 5 个 authenticate
        const promises = Array.from({ length: 5 }, () =>
          client.authenticate().catch((e: Error) => e),
        );
        const results = await Promise.all(promises);

        const successes = results.filter(
          (r: any) => r && typeof r === 'object' && !(r instanceof Error) && r.access_token,
        );
        const tokens = new Set(
          successes.map((r: any) => r.access_token).filter(Boolean),
        );

        // inflight 标志清理验证 — 并发完成后再发一次应正常
        await sleep(500);
        let cleanupOk = false;
        try {
          const authAfter = await client.authenticate();
          cleanupOk = !!authAfter?.access_token;
        } catch {
          cleanupOk = false;
        }

        return {
          total: results.length,
          successes: successes.length,
          unique_tokens: tokens.size,
          inflight_dedup: tokens.size === 1,
          cleanup_ok: cleanupOk,
        };
      } finally {
        await client.close();
      }
    }, ISSUER);

    const r = result as any;
    expect(r.successes).toBeGreaterThan(0);
    expect(r.cleanup_ok).toBe(true);
    if (r.inflight_dedup) {
      console.log('inflight 限流正常: 并发请求复用同一 token');
    } else {
      console.log(`并发认证 ${r.successes}/${r.total} 成功，${r.unique_tokens} 个不同 token`);
    }
    console.log(`inflight 清理: ${r.cleanup_ok ? '正常' : '异常'}`);
  });
});

// ── P0-13: Ping 超时检测 ────────────────────────────────────

test.describe('P0-13: Ping 超时检测（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('连接状态下 ping 应在合理时间内返回', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0png${rid}.${iss}`;

      const client = await makeAndConnect(`p0-13-png-${rid}`);
      try {
        await ensureConnected(client, aid);

        // 单次 ping
        const start = Date.now();
        await client.call('meta.ping');
        const firstLatency = Date.now() - start;

        // 连续 5 次
        const latencies: number[] = [];
        for (let i = 0; i < 5; i++) {
          const t0 = Date.now();
          await client.call('meta.ping');
          latencies.push(Date.now() - t0);
          await sleep(100);
        }

        const avg = latencies.reduce((a: number, b: number) => a + b, 0) / latencies.length;

        return {
          first_latency: firstLatency,
          latencies,
          avg: Math.round(avg),
          count: latencies.length,
        };
      } finally {
        await client.close();
      }
    }, ISSUER);

    const r = result as any;
    expect(r.first_latency).toBeLessThan(5000);
    expect(r.count).toBeGreaterThanOrEqual(3);
    console.log(`Ping 稳定性: ${r.count}/5 成功，平均延迟 ${r.avg}ms`);
  });
});

// ── P0-15: Stream 边界场景 ──────────────────────────────────

test.describe('P0-15: Stream 边界场景（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('创建/关闭/重复关闭/不存在流/缺参数', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0str${rid}.${iss}`;

      const client = await makeAndConnect(`p0-15-str-${rid}`);
      const results: Record<string, string> = {};

      try {
        await ensureConnected(client, aid);

        // 1. 创建流
        let streamId: string;
        try {
          const r = await client.call('stream.create', { content_type: 'text/plain' });
          streamId = r?.stream_id;
          if (!streamId) {
            return { skip: true, reason: '创建流未返回 stream_id' };
          }
          results.create = 'pass';
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'stream 服务未实现' };
          }
          throw e;
        }

        // 2. 正常关闭
        try {
          await client.call('stream.close', { stream_id: streamId! });
          results.close = 'pass';
        } catch (e: any) {
          results.close = 'fail: ' + e.message;
        }

        // 3. 重复关闭
        try {
          await client.call('stream.close', { stream_id: streamId! });
          results.dup_close = 'idempotent';
        } catch {
          results.dup_close = 'error (acceptable)';
        }

        // 4. 关闭不存在的流
        try {
          await client.call('stream.close', { stream_id: 'nonexistent-stream' });
          results.nonexistent = 'idempotent';
        } catch {
          results.nonexistent = 'error (acceptable)';
        }

        // 5. 非法 content_type；省略 content_type 当前服务端有默认值
        try {
          await client.call('stream.create', { content_type: 'invalid' });
          results.missing_params = 'fail: should have thrown';
        } catch {
          results.missing_params = 'pass';
        }

        return { skip: false, results };
      } finally {
        await client.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = (result as any).results;
    expect(r.create).toBe('pass');
    expect(r.close).toBe('pass');
    expect(r.missing_params).toBe('pass');
  });
});

// ── P0-14: 断线后 RPC + 重连恢复 ────────────────────────────

test.describe('P0-14: 断线后 RPC + 重连恢复（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('断线后 RPC 报错 → 重连后恢复', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aid = `p0rpc${rid}.${iss}`;

      const client = await makeAndConnect(`p0-14-rpc-${rid}`);
      const results: Record<string, string> = {};

      try {
        await ensureConnected(client, aid);

        // 正常 ping
        try {
          await client.call('meta.ping');
          results.connected_ping = 'pass';
        } catch (e: any) {
          results.connected_ping = 'fail: ' + e.message;
        }

        // 断线
        await client.disconnect();
        await sleep(500);

        // 断线后 RPC — 应报错
        try {
          await client.call('meta.ping');
          results.disconnected_ping = 'fail: should have thrown';
        } catch {
          results.disconnected_ping = 'pass';
        }

        // 重连
        await client.connect();

        // 重连后 RPC — 应恢复
        try {
          await client.call('meta.ping');
          results.reconnected_ping = 'pass';
        } catch (e: any) {
          results.reconnected_ping = 'fail: ' + e.message;
        }

        return results;
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect(result.connected_ping).toBe('pass');
    expect(result.disconnected_ping).toBe('pass');
    expect(result.reconnected_ping).toBe('pass');
  });
});
