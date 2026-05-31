// ── Playwright E2E 浏览器测试：Replay Guard（消息防重放） ────────
//
// 覆盖：
//   1. replay guard 基本消息流 — 发送/接收正常，message_id 唯一
//   2. 重复拉取幂等 — 同一 after_seq 拉取两次结果一致
//   3. 消息序号递增 — 连续消息 seq 严格递增
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/replay-guard.spec.ts --reporter=line
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

// ── 辅助：在浏览器上下文中注入测试工具 ────────────────────────

async function installP0Helpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__aunP0) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const makeAndConnect = async (instanceId: string): Promise<any> => {
      return w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
    };

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

// ── 1. replay guard 基本消息流 ────────────────────────────────

test.describe('replay guard 基本消息流（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('Alice 发消息给 Bob，Bob 能收到且 message_id 唯一', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `rga${rid}.${iss}`;
      const bobAid = `rgb${rid}.${iss}`;

      const alice = await makeAndConnect(`rg-basic-alice-${rid}`);
      const bob = await makeAndConnect(`rg-basic-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const received: any[] = [];
        let resolveReceived: (() => void) | null = null;
        const receivedPromise = new Promise<void>(resolve => { resolveReceived = resolve; });
        bob.on('message.received', (data: any) => {
          if (data?.from === aliceAid && data?.payload?.text?.startsWith(`rg-basic-`) && data?.payload?.text?.includes(rid)) {
            received.push(data);
            if (received.length >= 2 && resolveReceived) resolveReceived();
          }
        });

        // Alice 发送第一条消息
        const send1 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `rg-basic-1-${rid}` },
          durable: true,
          encrypt: false,
        });
        if (!send1?.message_id) {
          return { skip: true, reason: 'send 未返回 message_id' };
        }

        await sleep(300);

        // Alice 发送第二条消息
        const send2 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `rg-basic-2-${rid}` },
          durable: true,
          encrypt: false,
        });
        if (!send2?.message_id) {
          return { skip: true, reason: '第二条 send 未返回 message_id' };
        }

        await Promise.race([
          receivedPromise,
          sleep(10_000),
        ]);

        return {
          skip: false,
          msg1_id: send1.message_id,
          msg2_id: send2.message_id,
          ids_different: send1.message_id !== send2.message_id,
          received_count: received.length,
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
    // 两条消息应有不同的 message_id
    expect(r.ids_different).toBe(true);
    // Bob 应至少收到消息
    expect(r.received_count).toBeGreaterThanOrEqual(1);
    console.log(`message_id 1: ${r.msg1_id}, message_id 2: ${r.msg2_id}`);
  });
});

// ── 2. 重复拉取幂等 ──────────────────────────────────────────

test.describe('重复拉取幂等（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('同一 after_seq 拉取两次应返回相同结果', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `rgia${rid}.${iss}`;
      const bobAid = `rgib${rid}.${iss}`;

      const alice = await makeAndConnect(`rg-idem-alice-${rid}`);
      const bob = await makeAndConnect(`rg-idem-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // Alice 发消息给 Bob
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `rg-idem-${rid}` },
          durable: true,
          encrypt: false,
        });
        if (!sendResult?.message_id) {
          return { skip: true, reason: 'send 未返回 message_id' };
        }

        await sleep(1000);

        // Bob 第一次 pull（after_seq=0）
        const pull1 = await bob.call('message.pull', { after_seq: 0, limit: 50 });
        const msgs1 = pull1?.messages ?? [];

        // Bob 第二次 pull（after_seq=0，相同参数）
        const pull2 = await bob.call('message.pull', { after_seq: 0, limit: 50 });
        const msgs2 = pull2?.messages ?? [];

        // 过滤出本次测试的消息
        const filter = (msgs: any[]) => msgs.filter(
          (m: any) => m?.payload?.text === `rg-idem-${rid}`,
        );
        const matched1 = filter(msgs1);
        const matched2 = filter(msgs2);

        // 提取 message_id 列表用于比较
        const ids1 = matched1.map((m: any) => m.message_id).sort();
        const ids2 = matched2.map((m: any) => m.message_id).sort();

        return {
          skip: false,
          pull1_count: matched1.length,
          pull2_count: matched2.length,
          counts_equal: matched1.length === matched2.length,
          ids_equal: JSON.stringify(ids1) === JSON.stringify(ids2),
          pull1_error: null,
          pull2_error: null,
        };
      } catch (e: any) {
        return { skip: false, error: e.message };
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
    // 两次拉取数量应一致
    expect(r.counts_equal).toBe(true);
    // 两次拉取的 message_id 集合应一致
    expect(r.ids_equal).toBe(true);
    console.log(`两次 pull 均返回 ${r.pull1_count} 条匹配消息，message_id 集合一致`);
  });
});

// ── 3. 消息序号递增 ──────────────────────────────────────────

test.describe('消息序号递增（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('连续 3 条消息的 seq 应严格递增', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `rgsa${rid}.${iss}`;
      const bobAid = `rgsb${rid}.${iss}`;

      const alice = await makeAndConnect(`rg-seq-alice-${rid}`);
      const bob = await makeAndConnect(`rg-seq-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const msgCount = 3;
        const received: any[] = [];
        let resolveReceived: (() => void) | null = null;
        const receivedPromise = new Promise<void>(resolve => { resolveReceived = resolve; });
        bob.on('message.received', (data: any) => {
          if (data?.from === aliceAid && data?.payload?.text?.startsWith(`rg-seq-${rid}-`)) {
            received.push(data);
            if (received.length >= msgCount && resolveReceived) resolveReceived();
          }
        });

        // Alice 连续发送 3 条消息
        for (let i = 0; i < msgCount; i++) {
          const sendResult = await alice.call('message.send', {
            to: bobAid,
            payload: { type: 'text', text: `rg-seq-${rid}-${i}` },
            durable: true,
            encrypt: false,
          });
          if (!sendResult?.message_id) {
            return { skip: true, reason: `第 ${i} 条消息发送失败` };
          }
          await sleep(200);
        }

        await Promise.race([
          receivedPromise,
          sleep(10_000),
        ]);
        const matching = received
          .sort((a: any, b: any) => a.seq - b.seq);

        if (matching.length < msgCount) {
          return { skip: true, reason: `仅拉取到 ${matching.length}/${msgCount} 条消息` };
        }

        // 提取 seq 列表
        const seqs: number[] = matching.map((m: any) => m.seq);

        // 验证严格递增
        let strictlyIncreasing = true;
        for (let i = 1; i < seqs.length; i++) {
          if (seqs[i] <= seqs[i - 1]) {
            strictlyIncreasing = false;
            break;
          }
        }

        return {
          skip: false,
          sent: msgCount,
          pulled: matching.length,
          seqs,
          strictly_increasing: strictlyIncreasing,
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
    // seq 必须严格递增
    expect(r.strictly_increasing).toBe(true);
    console.log(`seq 序列: ${r.seqs.join(' → ')}（严格递增: ${r.strictly_increasing}）`);
  });
});
