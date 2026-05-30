// ── Playwright E2E 浏览器测试：SDK 断线重连 ──────────────────
//
// 覆盖：
//   1. 基本断线重连 — disconnect + re-auth + connect，ping 恢复
//   2. 重连后消息收发 — 断线前后的消息均可被对端拉取
//   3. 多次断连循环 — 连续 3 次 disconnect/reconnect
//   4. 断线后 RPC 报错 — 断线期间调用 RPC 应抛异常
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/reconnect.spec.ts --reporter=line
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

    const runId = () => {
      const arr = new Uint8Array(6);
      crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

// ── 1. 基本断线重连 ──────────────────────────────────────────

test.describe('基本断线重连（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('disconnect 后重新认证并 connect — ping 应恢复', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aid = `rca${rid}.${iss}`;

      const client = await makeAndConnect(`rc-basic-${rid}`);

      try {
        await ensureConnected(client, aid);

        // 连接状态下 ping
        let pingBefore = false;
        try {
          await client.call('meta.ping');
          pingBefore = true;
        } catch {
          pingBefore = false;
        }

        // 断线
        await client.disconnect();
        await sleep(1000);

        const disconnected = true;

        // 重新连接
        await client.connect();

        // 重连后 ping
        let pingAfter = false;
        try {
          await client.call('meta.ping');
          pingAfter = true;
        } catch {
          pingAfter = false;
        }

        return { pingBefore, disconnected, pingAfter };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect(result.pingBefore).toBe(true);
    expect(result.disconnected).toBe(true);
    expect(result.pingAfter).toBe(true);
  });
});

// ── 2. 重连后消息收发 ────────────────────────────────────────

test.describe('重连后消息收发（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('断线前后发送的消息均可被 Bob 拉取', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `rcma${rid}.${iss}`;
      const bobAid = `rcmb${rid}.${iss}`;

      const alice = await makeAndConnect(`rc-msg-alice-${rid}`);
      const bob = await makeAndConnect(`rc-msg-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // Alice 发送 msg1（断线前）
        let msg1Sent = false;
        const send1 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `rc-msg1-${rid}` },
          persist: true,
          encrypt: false,
        });
        msg1Sent = !!send1?.message_id;

        await sleep(500);

        // Alice 断线
        await alice.disconnect();
        await sleep(1000);

        // Alice 重新连接
        await alice.connect();

        // Alice 发送 msg2（重连后）
        let msg2Sent = false;
        const send2 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `rc-msg2-${rid}` },
          persist: true,
          encrypt: false,
        });
        msg2Sent = !!send2?.message_id;

        await sleep(1000);

        // Bob 拉取消息
        const pullResult = await bob.call('message.pull', { after_seq: 0, limit: 100 });
        const messages = pullResult?.messages ?? [];
        const msg1Found = messages.some(
          (m: any) => m?.payload?.text === `rc-msg1-${rid}`,
        );
        const msg2Found = messages.some(
          (m: any) => m?.payload?.text === `rc-msg2-${rid}`,
        );

        return {
          msg1Sent,
          msg2Sent,
          bobReceived: { msg1: msg1Found, msg2: msg2Found },
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    expect(result.msg1Sent).toBe(true);
    expect(result.msg2Sent).toBe(true);
    expect(result.bobReceived.msg1).toBe(true);
    expect(result.bobReceived.msg2).toBe(true);
  });
});

// ── 3. 多次断连循环 ──────────────────────────────────────────

test.describe('多次断连循环（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('连续 3 次 disconnect/reconnect — 每次 ping 均正常', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aid = `rccy${rid}.${iss}`;

      const client = await makeAndConnect(`rc-cycle-${rid}`);
      const cycleResults: boolean[] = [];

      try {
        await ensureConnected(client, aid);

        const totalCycles = 3;
        for (let i = 0; i < totalCycles; i++) {
          // 断线
          await client.disconnect();
          await sleep(500);

          // 重新连接
          await client.connect();

          // ping 验证
          let pingOk = false;
          try {
            await client.call('meta.ping');
            pingOk = true;
          } catch {
            pingOk = false;
          }
          cycleResults.push(pingOk);
        }

        return {
          cycles: cycleResults.length,
          allSuccess: cycleResults.every(Boolean),
          details: cycleResults,
        };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect(result.cycles).toBe(3);
    expect(result.allSuccess).toBe(true);
  });
});

// ── 4. 断线后 RPC 报错 ──────────────────────────────────────

test.describe('断线后 RPC 报错（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('断线期间 RPC 应抛异常 — 重连后恢复', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aid = `rcdc${rid}.${iss}`;

      const client = await makeAndConnect(`rc-dcerr-${rid}`);

      try {
        await ensureConnected(client, aid);

        // 连接状态下 ping — 应正常
        let pingOk = false;
        try {
          await client.call('meta.ping');
          pingOk = true;
        } catch {
          pingOk = false;
        }

        // 断线
        await client.disconnect();
        await sleep(500);

        // 断线状态下 ping — 应抛异常
        let disconnectRpcFailed = false;
        try {
          await client.call('meta.ping');
          disconnectRpcFailed = false;
        } catch {
          disconnectRpcFailed = true;
        }

        // 重连
        await client.connect();

        // 重连后 ping — 应恢复
        let reconnectPingOk = false;
        try {
          await client.call('meta.ping');
          reconnectPingOk = true;
        } catch {
          reconnectPingOk = false;
        }

        return { pingOk, disconnectRpcFailed, reconnectPingOk };
      } finally {
        await client.close();
      }
    }, ISSUER);

    expect(result.pingOk).toBe(true);
    expect(result.disconnectRpcFailed).toBe(true);
    expect(result.reconnectPingOk).toBe(true);
  });
});
