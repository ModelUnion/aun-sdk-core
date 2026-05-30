// ── Playwright E2E 浏览器测试：V2 P2P E2EE ──────────────
//
// 覆盖（对齐 Python e2e_test_v2_p2p_e2ee.py）：
//   1. V2 session 初始化
//   2. Alice sendV2 → Bob pullV2 解密
//   3. 收到消息后 SDK 内部推进 cursor，后续 pull 不重复
//   4. 双向通信
//   5. 批量消息
//
// 运行方法：
//   npm run build && npx playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/v2-p2p.spec.ts --reporter=line
//
// 前置条件：
//   - Docker 单域环境运行中（docker compose up -d kite）
//   - 浏览器通过 --host-resolver-rules 解析 gateway.agentid.pub → 127.0.0.1

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
    if (!filePath.startsWith(JS_ROOT)) { res.writeHead(403); res.end('Forbidden'); return; }
    const ext = path.extname(filePath);
    const mimeTypes: Record<string, string> = {
      '.html': 'text/html', '.js': 'application/javascript', '.mjs': 'application/javascript',
      '.css': 'text/css', '.json': 'application/json',
    };
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); res.end('Not Found'); return; }
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] ?? 'application/octet-stream' });
      res.end(data);
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) await new Promise<void>(r => server.close(() => r()));
});

function testPageUrl(): string { return `${baseUrl}/tests/e2e-browser/test-page.html`; }

// ── 辅助：注入浏览器上下文工具函数 ──────────────────────────────

async function installV2P2PHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__v2p2p) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    /** 创建 AUNClient 并连接到 gateway */
    const makeAndConnect = async (aid: string, deviceId?: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({ issuer, debug: true });
      if (deviceId) client._deviceId = deviceId;
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
      return client;
    };

    /** 等待 push 消息（带超时） */
    const waitForPush = (
      client: any,
      fromAid: string,
      count: number = 1,
      timeout: number = 15000,
      predicate?: (msg: any) => boolean,
    ): Promise<any[]> => {
      const inbox: any[] = [];
      let done = false;
      let timer: any = null;
      let sub: any = null;
      return new Promise<any[]>((resolve) => {
        const finish = () => {
          if (done) return;
          done = true;
          if (timer) clearTimeout(timer);
          if (sub && typeof sub.unsubscribe === 'function') sub.unsubscribe();
          resolve(inbox);
        };
        sub = client.on('message.received', (data: any) => {
          if (data?.from === fromAid && (!predicate || predicate(data))) {
            inbox.push(data);
            if (inbox.length >= count) finish();
          }
        });
        timer = setTimeout(finish, timeout);
      });
    };

    w.__v2p2p = { sleep, makeAndConnect, waitForPush, ISSUER: issuer };
  }, ISSUER);
}

// ── V2 P2P E2EE 测试 ────────────────────────────────────────────

test.describe('V2 P2P E2EE 端到端测试', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installV2P2PHelpers(page);
  });

  // ── 1. V2 session 初始化 ──

  test('V2 session 自动初始化', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, ISSUER } = (window as any).__v2p2p;
      const aliceAid = `v2p-a-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const hasV2Session = !!(alice as any)._v2Session;
      const hasIkPriv = hasV2Session && !!(alice as any)._v2Session._ikPriv;
      const hasSpkId = hasV2Session && !!(alice as any)._v2Session._spkId;

      await alice.close();
      return { hasV2Session, hasIkPriv, hasSpkId };
    }, rid);

    expect(result.hasV2Session).toBe(true);
    expect(result.hasIkPriv).toBe(true);
    expect(result.hasSpkId).toBe(true);
  });

  // ── 2. Alice sendV2 → Bob pullV2 解密 ──

  test('Alice sendV2 → Bob pullV2 解密', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, waitForPush, sleep, ISSUER } = (window as any).__v2p2p;
      const aliceAid = `v2p-sa-${rid}.${ISSUER}`;
      const bobAid = `v2p-sb-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      // 清空旧消息
      try {
        const old = await (bob as any)._pullV2(0, 200);
        if (old.length > 0) await (bob as any)._ackV2();
      } catch {}

      const testText = `v2-p2p-test-${Date.now()}`;
      const pushPromise = waitForPush(bob, aliceAid, 1, 15000, (msg: any) =>
        msg?.payload?.text === testText,
      );

      const sendResult = await (alice as any)._sendV2(bobAid, { text: testText });

      // 等待 push 或 fallback 到 pull
      let pushed = await pushPromise;
      let msg: any = null;
      if (pushed.length > 0) {
        msg = pushed.find((m: any) => m?.payload?.text === testText);
      }
      if (!msg) {
        await sleep(1000);
        const pulled = await (bob as any)._pullV2();
        msg = (pulled as any[]).find((m: any) => m?.payload?.text === testText);
      }

      await alice.close();
      await bob.close();

      return {
        sent: !!(sendResult as any)?.status || !!(sendResult as any)?.message_id,
        received: !!msg,
        text: msg?.payload?.text ?? null,
        encrypted: msg?.encrypted === true,
        version: msg?.e2ee?.version ?? null,
        from: msg?.from ?? null,
      };
    }, rid);

    expect(result.sent).toBe(true);
    expect(result.received).toBe(true);
    expect(result.text).toContain('v2-p2p-test-');
    expect(result.encrypted).toBe(true);
    expect(result.version).toBe('v2');
  });

  // ── 3. 收到消息后无需应用层 ack，后续 pull 不重复 ──

  test('收到消息后无需手动 ack，pull 不重复', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, waitForPush, sleep, ISSUER } = (window as any).__v2p2p;
      const aliceAid = `v2p-aa-${rid}.${ISSUER}`;
      const bobAid = `v2p-ab-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);
      const ns = `p2p:${bobAid}`;

      const testText = `v2-ack-test-${Date.now()}`;
      const pushPromise = waitForPush(bob, aliceAid, 1, 15000, (msg: any) =>
        msg?.payload?.text === testText,
      );

      await (alice as any)._sendV2(bobAid, { text: testText });

      // 等待收到
      let pushed = await pushPromise;
      if (pushed.length === 0) {
        await sleep(1000);
        pushed = await (bob as any)._pullV2();
      }

      const pushedSeq = Number(pushed[0]?.seq ?? 0);
      const contiguousSeq = bob._seqTracker.getContiguousSeq(ns);

      // 应用层不调用 ackV2；SDK 已基于本地 contiguous_seq 避免重复拉取。
      const afterReceivePull = await (bob as any)._pullV2();

      await alice.close();
      await bob.close();

      return {
        received: pushed.length > 0,
        pushedSeq,
        contiguousSeq,
        afterReceivePullCount: (afterReceivePull as any[]).length,
      };
    }, rid);

    expect(result.received).toBe(true);
    expect(result.contiguousSeq).toBeGreaterThanOrEqual(result.pushedSeq);
    expect(result.afterReceivePullCount).toBe(0);
  });

  // ── 4. 双向通信 ──

  test('双向通信 — Alice 和 Bob 互发 V2 消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, waitForPush, sleep, ISSUER } = (window as any).__v2p2p;
      const aliceAid = `v2p-ba-${rid}.${ISSUER}`;
      const bobAid = `v2p-bb-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      // Alice → Bob
      const textA2B = `alice-to-bob-${Date.now()}`;
      const pushBob = waitForPush(bob, aliceAid, 1, 15000, (msg: any) =>
        msg?.payload?.text === textA2B,
      );
      await (alice as any)._sendV2(bobAid, { text: textA2B });
      let bobMsgs = await pushBob;
      let bobMsg: any = bobMsgs.find((m: any) => m?.payload?.text === textA2B);
      if (!bobMsg) {
        await sleep(1000);
        const pulled = await (bob as any)._pullV2();
        bobMsg = (pulled as any[]).find((m: any) => m?.payload?.text === textA2B);
      }

      // Bob → Alice
      const textB2A = `bob-to-alice-${Date.now()}`;
      const pushAlice = waitForPush(alice, bobAid, 1, 15000, (msg: any) =>
        msg?.payload?.text === textB2A,
      );
      await (bob as any)._sendV2(aliceAid, { text: textB2A });
      let aliceMsgs = await pushAlice;
      let aliceMsg: any = aliceMsgs.find((m: any) => m?.payload?.text === textB2A);
      if (!aliceMsg) {
        await sleep(1000);
        const pulled = await (alice as any)._pullV2();
        aliceMsg = (pulled as any[]).find((m: any) => m?.payload?.text === textB2A);
      }

      await alice.close();
      await bob.close();

      return {
        bobReceivedText: bobMsg?.payload?.text ?? null,
        bobFrom: bobMsg?.from ?? null,
        aliceReceivedText: aliceMsg?.payload?.text ?? null,
        aliceFrom: aliceMsg?.from ?? null,
      };
    }, rid);

    expect(result.bobReceivedText).toContain('alice-to-bob-');
    expect(result.bobFrom).toContain(`v2p-ba-${rid}`);
    expect(result.aliceReceivedText).toContain('bob-to-alice-');
    expect(result.aliceFrom).toContain(`v2p-bb-${rid}`);
  });

  // ── 5. 批量消息 ──

  test('批量消息 — 连续发送 3 条 V2 消息全部收到', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, sleep, ISSUER } = (window as any).__v2p2p;
      const aliceAid = `v2p-ca-${rid}.${ISSUER}`;
      const bobAid = `v2p-cb-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      // 清空旧消息
      try { await (bob as any)._ackV2(); } catch {}

      const N = 3;
      const texts = Array.from({ length: N }, (_, i) => `batch-${i}-${Date.now()}`);

      // 监听 message.received 事件收集（与 Python _bob_push_msgs 对齐）
      const pushMsgs: any[] = [];
      bob.on('message.received', (msg: any) => {
        pushMsgs.push(msg);
      });

      for (const text of texts) {
        await (alice as any)._sendV2(bobAid, { text });
      }

      // 等待 push 投递（与 Python 对齐：30 × 200ms = 6s）
      for (let i = 0; i < 30 && pushMsgs.length < N; i++) {
        await sleep(200);
      }

      // push 已投递则从 push 收集，否则 fallback 到 pull（与 Python 完全对齐）
      let receivedTexts: string[];
      if (pushMsgs.length >= N) {
        receivedTexts = pushMsgs.map((m: any) => m?.payload?.text).filter(Boolean);
      } else {
        const pulled = await (bob as any)._pullV2();
        const allMsgs = [...pushMsgs, ...(Array.isArray(pulled) ? pulled : [])];
        receivedTexts = allMsgs.map((m: any) => m?.payload?.text).filter(Boolean);
      }

      await alice.close();
      await bob.close();

      // 验证所有 payload text 都在合并列表中（与 Python assert p["text"] in received_texts 对齐）
      const missing = texts.filter(t => !receivedTexts.includes(t));
      return {
        totalReceived: receivedTexts.length,
        missing,
        ok: missing.length === 0,
      };
    }, rid);

    expect(result.ok).toBe(true);
    expect(result.totalReceived).toBeGreaterThanOrEqual(3);
  });

});
