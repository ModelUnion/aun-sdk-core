// ── Playwright E2E 浏览器测试：跨域 Federation 消息 ────────────
//
// 覆盖：
//   1. 跨域明文消息 — Alice(A) → Bob(B)，Bob pull 验证
//   2. 跨域双向通信 — Alice(A) ↔ Bob(B) 双向发送并各自 pull 验证
//   3. 跨域 AID 不存在 — 发送到不存在的跨域 AID 应报错
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/federation.spec.ts --reporter=line
//
// 前置条件：
//   - federation Docker 环境运行中（docker-deploy/federation-test）
//   - 浏览器运行环境能解析 gateway.aid.com / gateway.aid.net

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER_A = process.env.AUN_TEST_ISSUER_A ?? 'aid.com';
const ISSUER_B = process.env.AUN_TEST_ISSUER_B ?? 'aid.net';

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

// ── 辅助：在浏览器上下文中注入 Federation 测试工具 ──────────────

async function installFederationHelpers(page: any): Promise<void> {
  await page.evaluate(({
    issuerA,
    issuerB,
  }: {
    issuerA: string;
    issuerB: string;
  }) => {
    const w = window as any;
    if (w.__aunFed) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    /**
     * 创建客户端实例。
     * 浏览器 SDK 使用 IndexedDB 存储，每个实例需要独立的 instanceId。
     */
    const makeAndConnect = async (instanceId: string, issuer: string): Promise<any> => {
      return w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
    };

    /**
     * 确保 AID 已创建、认证并连接。
     * issuer 用于网关发现。
     */
    const ensureConnected = async (client: any, aid: string, issuer: string): Promise<void> => {
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
    };

    const messageText = (message: any): string => {
      const payload = message?.payload;
      if (payload && typeof payload === 'object') return String(payload.text ?? '');
      return String(payload ?? '');
    };

    const messageFrom = (message: any): string => String(message?.from ?? message?.sender_aid ?? '');

    const waitForMessage = async (
      client: any,
      senderAid: string,
      text: string,
      timeoutMs = 20_000,
    ): Promise<any> => {
      const queue: any[] = [];
      const sub = client.on('message.received', (message: any) => {
        if (message && typeof message === 'object') queue.push(message);
      });
      const deadline = Date.now() + timeoutMs;
      try {
        while (Date.now() < deadline) {
          while (queue.length > 0) {
            const message = queue.shift();
            if (messageFrom(message) === senderAid && messageText(message) === text) {
              return message;
            }
          }

          try {
            const pullResult = await client.call('message.pull', { after_seq: 0, limit: 50 });
            const messages = pullResult?.messages ?? [];
            const found = messages.find((m: any) => messageFrom(m) === senderAid && messageText(m) === text);
            if (found) return found;
          } catch {
            // pull 是兜底路径，失败时继续等实时事件。
          }

          await sleep(500);
        }
      } finally {
        sub?.unsubscribe?.();
      }
      throw new Error(`waitForMessage timeout: from=${senderAid} text=${text}`);
    };

    const runId = () => {
      const arr = new Uint8Array(6);
      crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };

    w.__aunFed = {
      sleep,
      makeAndConnect,
      ensureConnected,
      waitForMessage,
      runId,
      ISSUER_A: issuerA,
      ISSUER_B: issuerB,
    };
  }, { issuerA: ISSUER_A, issuerB: ISSUER_B });
}

// ── 1. 跨域明文消息 ──────────────────────────────────────────

test.describe('跨域明文消息（浏览器 Federation）', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installFederationHelpers(page);
  });

  test('Alice(A) 发明文到 Bob(B)，Bob pull 可收到', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, ensureConnected, waitForMessage, runId, ISSUER_A, ISSUER_B } = (window as any).__aunFed;
      const rid = runId();
      const aliceAid = `fed-pla-${rid}.${ISSUER_A}`;
      const bobAid = `fed-plb-${rid}.${ISSUER_B}`;

      const alice = await makeAndConnect(`fed-plain-alice-${rid}`, ISSUER_A);
      const bob = await makeAndConnect(`fed-plain-bob-${rid}`, ISSUER_B);

      try {
        await ensureConnected(alice, aliceAid, ISSUER_A);
        await ensureConnected(bob, bobAid, ISSUER_B);

        const sendText = `fed-plaintext-${rid}`;
        const receivedPromise = waitForMessage(bob, aliceAid, sendText, 20_000);
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: sendText },
          encrypt: false,
        });
        const sent = !!sendResult?.message_id;
        const receivedMessage = await receivedPromise;
        const received = !!receivedMessage;
        const payloadMatch = receivedMessage?.payload?.text === sendText;

        return { sent, received, payloadMatch };
      } finally {
        await alice.close();
        await bob.close();
      }
    });

    expect(result.sent).toBe(true);
    expect(result.received).toBe(true);
    expect(result.payloadMatch).toBe(true);
  });
});

// ── 2. 跨域双向通信 ──────────────────────────────────────────

test.describe('跨域双向通信（浏览器 Federation）', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installFederationHelpers(page);
  });

  test('Alice(A) ↔ Bob(B) 双向发送，各自 pull 验证', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, ensureConnected, waitForMessage, runId, ISSUER_A, ISSUER_B } = (window as any).__aunFed;
      const rid = runId();
      const aliceAid = `fed-bia-${rid}.${ISSUER_A}`;
      const bobAid = `fed-bib-${rid}.${ISSUER_B}`;

      const alice = await makeAndConnect(`fed-bidir-alice-${rid}`, ISSUER_A);
      const bob = await makeAndConnect(`fed-bidir-bob-${rid}`, ISSUER_B);

      try {
        await ensureConnected(alice, aliceAid, ISSUER_A);
        await ensureConnected(bob, bobAid, ISSUER_B);

        const textA2B = `fed-a2b-${rid}`;
        const textB2A = `fed-b2a-${rid}`;

        const bobReceivedPromise = waitForMessage(bob, aliceAid, textA2B, 25_000);
        const aliceReceivedPromise = waitForMessage(alice, bobAid, textB2A, 25_000);

        // Alice → Bob
        await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: textA2B },
          encrypt: false,
        });

        // Bob → Alice
        await bob.call('message.send', {
          to: aliceAid,
          payload: { type: 'text', text: textB2A },
          encrypt: false,
        });

        const [bobMessage, aliceMessage] = await Promise.all([bobReceivedPromise, aliceReceivedPromise]);
        const bobReceived = bobMessage?.payload?.text === textA2B;
        const aliceReceived = aliceMessage?.payload?.text === textB2A;

        return { aliceReceived, bobReceived };
      } finally {
        await alice.close();
        await bob.close();
      }
    });

    expect(result.bobReceived).toBe(true);
    expect(result.aliceReceived).toBe(true);
  });
});

// ── 3. 跨域 AID 不存在 ──────────────────────────────────────

test.describe('跨域 AID 不存在（浏览器 Federation）', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installFederationHelpers(page);
  });

  test('发送到不存在的跨域 AID — 应返回错误', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, ensureConnected, runId, ISSUER_A, ISSUER_B } = (window as any).__aunFed;
      const rid = runId();
      const aliceAid = `fed-nxa-${rid}.${ISSUER_A}`;

      const alice = await makeAndConnect(`fed-nonexist-alice-${rid}`, ISSUER_A);

      try {
        await ensureConnected(alice, aliceAid, ISSUER_A);

        // 发送到一个不存在的跨域 AID
        const fakeAid = `nonexistent-${rid}.unknown.invalid`;
        try {
          await alice.call('message.send', {
            to: fakeAid,
            payload: { type: 'text', text: `should-fail-${rid}` },
            encrypt: false,
          });
          return { error: false };
        } catch {
          return { error: true };
        }
      } finally {
        await alice.close();
      }
    });

    expect(result.error).toBe(true);
  });
});
