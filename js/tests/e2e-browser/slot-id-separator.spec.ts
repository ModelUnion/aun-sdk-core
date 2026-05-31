// ── Playwright E2E 浏览器测试：slot_id 分隔符语义 ──────────────
//
// 覆盖场景（对齐 Python e2e_test_slot_id_separator.py）：
//   1. P2P 明文消息 — 同前缀实例接收（c2 踢掉 c1 后收到消息）
//   2. P2P 加密消息 — 同前缀实例接收并解密
//   3. Group 明文消息 — 同前缀实例接收群消息
//   4. Group 加密消息 — 同前缀实例接收并解密群消息
//
// 运行方法：
//   npm run build && npx playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/slot-id-separator.spec.ts --reporter=line
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

async function installHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__slotSep) return;

    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

    const makeClient = (aunPath: string, deviceId: string) => {
      const H = w.AUN_TEST_HELPERS;
      return H.createClient({
        aunPath,
        deviceId,
        requireForwardSecrecy: false,
      });
    };

    const connect = async (client: any, aid: string, slotId: string, register = false) => {
      const H = w.AUN_TEST_HELPERS;
      if (register) {
        await H.registerAndLoadIdentity(client, aid, { slotId });
      } else {
        await H.loadIdentity(client, aid, { slotId });
      }
      await client.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    };

    const waitForEvent = (client: any, event: string, predicate: (d: any) => boolean, timeoutMs = 15000): Promise<any> =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`timeout waiting for ${event}`)), timeoutMs);
        client.on(event, (data: any) => {
          if (predicate(data)) { clearTimeout(t); resolve(data); }
        });
      });

    w.__slotSep = { sleep, makeClient, connect, waitForEvent, ISSUER: issuer };
  }, ISSUER);
}

// ── 测试 ──────────────────────────────────────────────────────

test.describe('slot_id 分隔符语义 E2E', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installHelpers(page);
  });

  // ── Test 1: P2P 明文消息 ──────────────────────────────────────

  test('P2P 明文 — 同前缀 c2 踢掉 c1 后收到消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (params: { rid: string; issuer: string }) => {
      const { connect, makeClient, waitForEvent, ISSUER } = (window as any).__slotSep;
      const aliceAid = `sep-js-a-${params.rid}.${ISSUER}`;
      const bobAid = `sep-js-b-${params.rid}.${ISSUER}`;

      const alicePath = `js-slot-alice-${params.rid}`;
      const aliceDevice = `sep-js-alice-${params.rid}`;
      const c1 = makeClient(alicePath, aliceDevice);
      const c2 = makeClient(alicePath, aliceDevice);
      const bob = makeClient(`js-slot-bob-${params.rid}`, `sep-js-bob-${params.rid}`);

      // c1 以 "evolclaw cli" 连接
      await connect(c1, aliceAid, `evolclaw cli-${params.rid}`, true);

      // c2 以 "evolclaw daemon" 连接（踢掉 c1）
      await connect(c2, aliceAid, `evolclaw daemon-${params.rid}`);

      // bob 连接
      await connect(bob, bobAid, 'main', true);

      // c2 监听消息
      const text = `slot-sep-plain-${params.rid}`;
      const msgPromise = waitForEvent(c2, 'message.received', (d: any) => d?.payload?.text === text, 15000);

      // bob 发明文消息给 alice
      await bob.call('message.send', { to: aliceAid, payload: { type: 'text', text }, encrypt: false });

      let received = false;
      try {
        await msgPromise;
        received = true;
      } catch {}

      await c1.close(); await c2.close(); await bob.close();
      return { received };
    }, { rid, issuer: ISSUER });

    expect(result.received).toBe(true);
  });

  // ── Test 2: P2P 加密消息 ──────────────────────────────────────

  test('P2P 加密 — 同前缀 c2 踢掉 c1 后收到并解密消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (params: { rid: string; issuer: string }) => {
      const { connect, makeClient, waitForEvent, ISSUER } = (window as any).__slotSep;
      const aliceAid = `sep-js-ea-${params.rid}.${ISSUER}`;
      const bobAid = `sep-js-eb-${params.rid}.${ISSUER}`;

      const alicePath = `js-slot-alice-${params.rid}`;
      const aliceDevice = `sep-js-alice-${params.rid}`;
      const c1 = makeClient(alicePath, aliceDevice);
      const c2 = makeClient(alicePath, aliceDevice);
      const bob = makeClient(`js-slot-bob-${params.rid}`, `sep-js-bob-${params.rid}`);

      await connect(c1, aliceAid, `evolclaw cli-${params.rid}`, true);

      await connect(c2, aliceAid, `evolclaw daemon-${params.rid}`);

      await connect(bob, bobAid, 'main', true);

      const text = `slot-sep-enc-${params.rid}`;
      const msgPromise = waitForEvent(c2, 'message.received', (d: any) => d?.payload?.text === text, 20000);

      // bob 发加密消息
      await bob.call('message.send', { to: aliceAid, payload: { type: 'text', text }, encrypt: true });

      let received = false;
      let encrypted = false;
      try {
        const msg = await msgPromise;
        received = true;
        encrypted = msg?.encrypted === true;
      } catch {}

      await c1.close(); await c2.close(); await bob.close();
      return { received, encrypted };
    }, { rid, issuer: ISSUER });

    expect(result.received).toBe(true);
    expect(result.encrypted).toBe(true);
  });

  // ── Test 3: Group 明文消息 ────────────────────────────────────

  test('Group 明文 — 同前缀 c2 踢掉 c1 后收到群消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (params: { rid: string; issuer: string }) => {
      const { connect, makeClient, waitForEvent, ISSUER } = (window as any).__slotSep;
      const aliceAid = `sep-js-ga-${params.rid}.${ISSUER}`;
      const bobAid = `sep-js-gb-${params.rid}.${ISSUER}`;

      const alicePath = `js-slot-alice-${params.rid}`;
      const aliceDevice = `sep-js-alice-${params.rid}`;
      const c1 = makeClient(alicePath, aliceDevice);
      const c2 = makeClient(alicePath, aliceDevice);
      const bob = makeClient(`js-slot-bob-${params.rid}`, `sep-js-bob-${params.rid}`);

      await connect(c1, aliceAid, `evolclaw cli-${params.rid}`, true);

      await connect(c2, aliceAid, `evolclaw daemon-${params.rid}`);

      await connect(bob, bobAid, 'main', true);

      // bob 建群，加 alice
      const grpResult = await bob.call('group.create', { name: `sep-grp-${params.rid}`, visibility: 'private' });
      const grp = (grpResult as any)?.group ?? grpResult;
      const groupId = (grp as any)?.group_id;
      if (!groupId) throw new Error('group.create failed');
      await bob.call('group.add_member', { group_id: groupId, aid: aliceAid });

      // 等待 alice 收到加群事件
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, 5000);
        c2.on('group.member_joined', (d: any) => { if (d?.group_id === groupId) { clearTimeout(t); resolve(); } });
      });

      const text = `slot-sep-grp-${params.rid}`;
      const msgPromise = waitForEvent(c2, 'group.message_created', (d: any) => d?.payload?.text === text, 15000);

      await bob.call('group.send', { group_id: groupId, payload: { type: 'text', text }, encrypt: false });

      let received = false;
      try { await msgPromise; received = true; } catch {}

      await c1.close(); await c2.close(); await bob.close();
      return { received };
    }, { rid, issuer: ISSUER });

    expect(result.received).toBe(true);
  });

  // ── Test 4: Group 加密消息 ────────────────────────────────────

  test('Group 加密 — 同前缀 c2 踢掉 c1 后收到并解密群消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (params: { rid: string; issuer: string }) => {
      const { connect, makeClient, waitForEvent, ISSUER } = (window as any).__slotSep;
      const aliceAid = `sep-js-gea-${params.rid}.${ISSUER}`;
      const bobAid = `sep-js-geb-${params.rid}.${ISSUER}`;

      const alicePath = `js-slot-alice-${params.rid}`;
      const aliceDevice = `sep-js-alice-${params.rid}`;
      const c1 = makeClient(alicePath, aliceDevice);
      const c2 = makeClient(alicePath, aliceDevice);
      const bob = makeClient(`js-slot-bob-${params.rid}`, `sep-js-bob-${params.rid}`);

      await connect(c1, aliceAid, `evolclaw cli-${params.rid}`, true);

      await connect(c2, aliceAid, `evolclaw daemon-${params.rid}`);

      await connect(bob, bobAid, 'main', true);

      const grpResult2 = await bob.call('group.create', { name: `sep-egrp-${params.rid}`, visibility: 'private' });
      const grp2 = (grpResult2 as any)?.group ?? grpResult2;
      const groupId = (grp2 as any)?.group_id;
      if (!groupId) throw new Error('group.create failed');
      await bob.call('group.add_member', { group_id: groupId, aid: aliceAid });

      // 等待 V2 群密钥就绪
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, 8000);
        c2.on('group.v2.epoch_committed', (d: any) => { if (d?.group_id === groupId) { clearTimeout(t); resolve(); } });
      });

      const text = `slot-sep-egrp-${params.rid}`;
      const msgPromise = waitForEvent(c2, 'group.message_created', (d: any) => d?.payload?.text === text, 20000);

      await bob.call('group.send', { group_id: groupId, payload: { type: 'text', text }, encrypt: true });

      let received = false;
      let encrypted = false;
      try {
        const msg = await msgPromise;
        received = true;
        encrypted = msg?.encrypted === true;
      } catch {}

      await c1.close(); await c2.close(); await bob.close();
      return { received, encrypted };
    }, { rid, issuer: ISSUER });

    expect(result.received).toBe(true);
    expect(result.encrypted).toBe(true);
  });
});
