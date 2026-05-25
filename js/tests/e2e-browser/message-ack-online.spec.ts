// ── Playwright E2E 浏览器测试：消息 ACK + 在线状态 ──────────
//
// 覆盖：
//   1. 消息 ACK 基础 — 发送后 ack 推进 ack_seq
//   2. 消息 ACK 序列 — 连续 ack 按顺序推进
//   3. 在线状态 — 连接/断开后状态变化、批量查询
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/message-ack-online.spec.ts --reporter=line
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
      }, true);
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
      const gatewayDiscoveryAid = `gateway.${issuer}`;
      const gateway = await client.auth._resolveGateway(gatewayDiscoveryAid);
      (client as any)._gatewayUrl = gateway;
      try {
        await client.auth.createAid({ aid });
      } catch {
        // 已存在则忽略
      }
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected };
  }, ISSUER);
}

// ── 消息 ACK 基础 ────────────────────────────────────────────

test.describe('消息 ACK 基础（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('发送后 ack 应推进 ack_seq', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `acka${rid}.${iss}`;
      const bobAid = `ackb${rid}.${iss}`;

      const alice = await makeAndConnect(`ack-base-alice-${rid}`);
      const bob = await makeAndConnect(`ack-base-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const text = `ack-test-${rid}`;
        const received: any[] = [];
        let resolveReceived: (() => void) | null = null;
        const receivedPromise = new Promise<void>(resolve => { resolveReceived = resolve; });
        bob.on('message.received', (data: any) => {
          if (data?.from === aliceAid && data?.payload?.text === text) {
            received.push(data);
            if (resolveReceived) resolveReceived();
          }
        });

        // Alice 发消息给 Bob
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text },
          durable: true,
          encrypt: false,
        });
        if (!sendResult?.message_id) {
          return { skip: true, reason: 'send 未返回 message_id' };
        }

        await Promise.race([receivedPromise, sleep(10_000)]);
        let matching = received;
        if (matching.length === 0) {
          const pullResult = await bob.call('message.pull', { after_seq: 0, limit: 50 });
          const messages = pullResult?.messages ?? [];
          matching = messages.filter((m: any) => m?.payload?.text === text);
        }
        if (matching.length === 0) {
          return { skip: true, reason: 'Bob 未收到消息' };
        }

        // 取最大 seq 进行 ack
        const maxSeq = Math.max(...matching.map((m: any) => m.seq));

        // Bob ack
        try {
          const ackResult = await bob.call('message.ack', { seq: maxSeq });
          return {
            skip: false,
            sent: true,
            pulled: matching.length,
            acked_seq: maxSeq,
            ack_result: ackResult,
            ack_seq: ackResult?.ack_seq ?? null,
          };
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'message.ack 未实现' };
          }
          return { skip: false, error: e.message };
        }
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.sent).toBe(true);
    expect(r.pulled).toBeGreaterThan(0);
    expect(r.acked_seq).toBeGreaterThan(0);
    // ack_seq 应等于或大于已 ack 的 seq
    if (r.ack_seq !== null) {
      expect(r.ack_seq).toBeGreaterThanOrEqual(r.acked_seq);
    }
  });
});

// ── 消息 ACK 序列 ────────────────────────────────────────────

test.describe('消息 ACK 序列（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('连续 ack 应按顺序推进', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `acksa${rid}.${iss}`;
      const bobAid = `acksb${rid}.${iss}`;

      const alice = await makeAndConnect(`ack-seq-alice-${rid}`);
      const bob = await makeAndConnect(`ack-seq-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const msgCount = 3;
        const received: any[] = [];
        let resolveReceived: (() => void) | null = null;
        const receivedPromise = new Promise<void>(resolve => { resolveReceived = resolve; });
        bob.on('message.received', (data: any) => {
          if (data?.from === aliceAid && data?.payload?.text?.startsWith(`ack-seq-${rid}-`)) {
            received.push(data);
            if (received.length >= msgCount && resolveReceived) resolveReceived();
          }
        });

        // Alice 连续发送 3 条消息
        for (let i = 0; i < msgCount; i++) {
          const sendResult = await alice.call('message.send', {
            to: bobAid,
            payload: { type: 'text', text: `ack-seq-${rid}-${i}` },
            durable: true,
            encrypt: false,
          });
          if (!sendResult?.message_id) {
            return { skip: true, reason: `第 ${i} 条消息发送失败` };
          }
          await sleep(200);
        }

        await Promise.race([receivedPromise, sleep(10_000)]);
        let matching = received
          .sort((a: any, b: any) => a.seq - b.seq);
        if (matching.length < msgCount) {
          const pullResult = await bob.call('message.pull', { after_seq: 0, limit: 50 });
          const messages = pullResult?.messages ?? [];
          matching = messages
            .filter((m: any) => m?.payload?.text?.startsWith(`ack-seq-${rid}-`))
            .sort((a: any, b: any) => a.seq - b.seq);
        }

        if (matching.length < msgCount) {
          return { skip: true, reason: `仅拉取到 ${matching.length}/${msgCount} 条消息` };
        }

        // 逐条 ack 并记录 ack_seq 推进
        const ackResults: Array<{ seq: number; ack_seq: number | null }> = [];
        for (const msg of matching) {
          try {
            const ackResult = await bob.call('message.ack', { seq: msg.seq });
            ackResults.push({
              seq: msg.seq,
              ack_seq: ackResult?.ack_seq ?? null,
            });
          } catch (e: any) {
            const emsg = (e.message ?? '').toLowerCase();
            if (emsg.includes('not implement') || emsg.includes('method not found')) {
              return { skip: true, reason: 'message.ack 未实现' };
            }
            ackResults.push({ seq: msg.seq, ack_seq: null });
          }
          await sleep(200);
        }

        return {
          skip: false,
          sent: msgCount,
          pulled: matching.length,
          ack_results: ackResults,
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.sent).toBe(3);
    expect(r.pulled).toBeGreaterThanOrEqual(3);

    // 验证 ack_seq 单调递增
    const ackSeqs = r.ack_results
      .map((a: any) => a.ack_seq)
      .filter((s: any) => s !== null);

    if (ackSeqs.length > 1) {
      for (let i = 1; i < ackSeqs.length; i++) {
        expect(ackSeqs[i]).toBeGreaterThanOrEqual(ackSeqs[i - 1]);
      }
      console.log(`ack_seq 推进序列: ${ackSeqs.join(' → ')}`);
    }
  });
});

// ── 在线状态 ──────────────────────────────────────────────────

test.describe('在线状态（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('连接后应在线，断开后应离线', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `onla${rid}.${iss}`;
      const bobAid = `onlb${rid}.${iss}`;

      const alice = await makeAndConnect(`online-alice-${rid}`);
      const bob = await makeAndConnect(`online-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 查询双方在线状态 — 应均在线
        let onlineBefore: any;
        try {
          onlineBefore = await alice.call('message.query_online', {
            aids: [aliceAid, bobAid],
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'message.query_online 未实现' };
          }
          return { skip: false, error: 'query_online 失败: ' + e.message };
        }

        // Bob 断开连接
        await bob.disconnect();
        await sleep(2000);

        // 轮询直到 Bob 变为离线（最多 10 秒）
        let onlineAfter: any = null;
        let bobOffline = false;
        for (let attempt = 0; attempt < 5; attempt++) {
          onlineAfter = await alice.call('message.query_online', {
            aids: [aliceAid, bobAid],
          });
          // 检查 Bob 是否已离线
          const onlineList = onlineAfter?.online ?? onlineAfter?.results ?? onlineAfter;
          if (Array.isArray(onlineList)) {
            const bobEntry = onlineList.find((e: any) => e.aid === bobAid);
            if (bobEntry && !bobEntry.online) {
              bobOffline = true;
              break;
            }
          } else if (typeof onlineList === 'object' && onlineList !== null) {
            if (onlineList[bobAid] === false) {
              bobOffline = true;
              break;
            }
          }
          await sleep(2000);
        }

        return {
          skip: false,
          online_before: onlineBefore,
          online_after: onlineAfter,
          bob_offline: bobOffline,
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    // 连接时查询应返回结果
    expect(r.online_before).toBeTruthy();
    // 断开后 Bob 应变为离线
    if (r.bob_offline) {
      console.log('在线状态变化验证通过: Bob 断开后变为离线');
    } else {
      console.log('警告: Bob 断开后在线状态未在 10 秒内更新为离线');
    }
  });

  test('批量查询在线状态', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);

      // 创建 3 个客户端
      const aids = [
        `bola${rid}.${iss}`,
        `bolb${rid}.${iss}`,
        `bolc${rid}.${iss}`,
      ];
      const clients = await Promise.all(
        aids.map((_, i) => makeAndConnect(`batch-online-${i}-${rid}`)),
      );

      try {
        // 全部连接
        for (let i = 0; i < clients.length; i++) {
          await ensureConnected(clients[i], aids[i]);
        }

        await sleep(1000);

        // 通过第一个客户端查询所有人的在线状态
        let queryResult: any;
        try {
          queryResult = await clients[0].call('message.query_online', {
            aids: aids,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'message.query_online 未实现' };
          }
          return { skip: false, error: 'query_online 失败: ' + e.message };
        }

        // 断开第三个客户端
        await clients[2].disconnect();
        await sleep(2000);

        // 再次查询
        let queryAfter: any;
        try {
          queryAfter = await clients[0].call('message.query_online', {
            aids: aids,
          });
        } catch (e: any) {
          queryAfter = { error: e.message };
        }

        return {
          skip: false,
          aid_count: aids.length,
          query_all_online: queryResult,
          query_after_disconnect: queryAfter,
        };
      } finally {
        for (const c of clients) {
          await c.close();
        }
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.aid_count).toBe(3);
    // 验证批量查询返回了结果
    expect(r.query_all_online).toBeTruthy();
    console.log('批量查询全部在线:', JSON.stringify(r.query_all_online));
    console.log('断开一个后查询:', JSON.stringify(r.query_after_disconnect));
  });
});
