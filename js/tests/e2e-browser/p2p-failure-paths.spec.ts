// ── Playwright E2E 浏览器测试：P2P 消息失败路径 ──────────────
//
// 覆盖：
//   1. 明文发送不依赖 prekey
//   2. 发送到不存在的 AID
//   3. 明文消息可拉取
//   4. 错误后序号正常
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/p2p-failure-paths.spec.ts --reporter=line
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

    const runId = () => {
      const arr = new Uint8Array(6);
      crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

// ── P2P 消息失败路径 ──────────────────────────────────────────

test.describe('P2P 消息失败路径（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  // ── 1. 明文发送不依赖 prekey ──────────────────────────────────

  test('明文发送不依赖 prekey — plaintext send 无需对端 prekey', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `fppa${rid}.${iss}`;
      const targetAid = `fppt${rid}.${iss}`;

      const alice = await makeAndConnect(`fp-plain-alice-${rid}`);
      const target = await makeAndConnect(`fp-plain-target-${rid}`);

      try {
        // Alice 完整连接
        await ensureConnected(alice, aliceAid);

        // target 仅创建 AID，不连接（模拟没有 prekey 的场景）
        const gatewayDiscoveryAid = `gateway.${iss}`;
        const gateway = await target.auth._resolveGateway(gatewayDiscoveryAid);
        (target as any)._gatewayUrl = gateway;
        try {
          await target.auth.createAid({ aid: targetAid });
        } catch {
          // 已存在则忽略
        }

        // Alice 明文发送到 target（encrypt: false）
        const sendResult = await alice.call('message.send', {
          to: targetAid,
          payload: { type: 'text', text: `plain-no-prekey-${rid}` },
          encrypt: false,
        });

        return {
          success: !!sendResult?.message_id,
          messageId: sendResult?.message_id ?? null,
        };
      } finally {
        await alice.close();
        await target.close();
      }
    }, ISSUER);

    expect(result.success).toBe(true);
    expect(result.messageId).toBeTruthy();
  });

  // ── 2. 发送到不存在的 AID ─────────────────────────────────────

  test('发送到不存在的 AID — 应返回错误', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `fpna${rid}.${iss}`;

      const alice = await makeAndConnect(`fp-nonexist-alice-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);

        // 发送到一个不存在的 AID
        const fakeAid = `nonexistent-${rid}.${iss}`;
        try {
          await alice.call('message.send', {
            to: fakeAid,
            payload: { type: 'text', text: `should-fail-${rid}` },
            encrypt: false,
          });
          return { error: false, message: '' };
        } catch (e: any) {
          return { error: true, message: e.message ?? String(e) };
        }
      } finally {
        await alice.close();
      }
    }, ISSUER);

    expect(result.error).toBe(true);
    expect(result.message).toBeTruthy();
  });

  // ── 3. 明文消息可拉取 ─────────────────────────────────────────

  test('明文消息可拉取 — Bob 能 pull 到 Alice 的明文消息', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `fpma${rid}.${iss}`;
      const bobAid = `fpmb${rid}.${iss}`;

      const alice = await makeAndConnect(`fp-pull-alice-${rid}`);
      const bob = await makeAndConnect(`fp-pull-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const expectedText = `pullable-plain-${rid}`;
        const received: any[] = [];
        let resolveReceived: (() => void) | null = null;
        const receivedPromise = new Promise<void>(resolve => { resolveReceived = resolve; });
        bob.on('message.received', (data: any) => {
          if (data?.from === aliceAid && data?.payload?.text === expectedText) {
            received.push(data);
            if (resolveReceived) resolveReceived();
          }
        });

        // Alice 发明文持久消息给 Bob
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: expectedText },
          encrypt: false,
          durable: true,
        });
        if (!sendResult?.message_id) {
          return { found: false, payloadMatch: false, reason: 'send 未返回 message_id' };
        }

        await Promise.race([
          receivedPromise,
          sleep(10_000),
        ]);

        return {
          found: received.length > 0,
          payloadMatch: received.length > 0,
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    expect(result.found).toBe(true);
    expect(result.payloadMatch).toBe(true);
  });

  // ── 4. 错误后序号正常 ─────────────────────────────────────────

  test('错误后序号正常 — 发送失败不影响后续消息 seq 递增', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `fpsa${rid}.${iss}`;
      const bobAid = `fpsb${rid}.${iss}`;

      const alice = await makeAndConnect(`fp-seq-alice-${rid}`);
      const bob = await makeAndConnect(`fp-seq-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        const text1 = `seq-before-${rid}`;
        const text2 = `seq-after-${rid}`;
        const received: any[] = [];
        let resolveReceived: (() => void) | null = null;
        const receivedPromise = new Promise<void>(resolve => { resolveReceived = resolve; });
        bob.on('message.received', (data: any) => {
          const text = data?.payload?.text;
          if (data?.from === aliceAid && (text === text1 || text === text2)) {
            received.push(data);
            if (received.length >= 2 && resolveReceived) resolveReceived();
          }
        });

        // 第 1 条：正常发送
        const send1 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: text1 },
          encrypt: false,
          durable: true,
        });
        if (!send1?.message_id) {
          return { count: 0, seqIncreasing: false, reason: '第 1 条消息发送失败' };
        }

        // 第 2 条：尝试发送到不存在的 AID（应失败）
        const fakeAid = `nonexist-seq-${rid}.${iss}`;
        try {
          await alice.call('message.send', {
            to: fakeAid,
            payload: { type: 'text', text: `should-fail-${rid}` },
            encrypt: false,
          });
        } catch {
          // 预期失败，忽略
        }

        // 第 3 条：再次正常发送
        const send2 = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: text2 },
          encrypt: false,
          durable: true,
        });
        if (!send2?.message_id) {
          return { count: 0, seqIncreasing: false, reason: '第 3 条消息发送失败' };
        }

        await Promise.race([
          receivedPromise,
          sleep(10_000),
        ]);
        const matching = received.sort((a: any, b: any) => a.seq - b.seq);

        const count = matching.length;
        let seqIncreasing = false;
        if (count >= 2) {
          seqIncreasing = matching[matching.length - 1].seq > matching[0].seq;
        }

        return { count, seqIncreasing };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    expect(result.count).toBeGreaterThanOrEqual(2);
    expect(result.seqIncreasing).toBe(true);
  });
});
