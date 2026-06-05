// Notify 浏览器 E2E / 跨域测试。
//
// 运行：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/notify.spec.ts --reporter=line

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const ISSUER_A = process.env.AUN_TEST_ISSUER_A ?? 'aid.com';
const ISSUER_B = process.env.AUN_TEST_ISSUER_B ?? 'aid.net';

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
      if (addr && typeof addr === 'object') baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
});

function testPageUrl(): string {
  return `${baseUrl}/tests/e2e-browser/test-page.html`;
}

async function installNotifyHelpers(page: any): Promise<void> {
  await page.evaluate(({ issuer, issuerA, issuerB }) => {
    const w = window as any;
    if (w.__aunNotify) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    const runId = () => {
      const arr = new Uint8Array(5);
      crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };
    const makeClient = async (tag: string, aid: string, slotId = '') => {
      const client = w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-notify-${tag}`,
        deviceId: `dev-${tag}`,
        slotId: slotId || `slot-${tag}`,
        requireForwardSecrecy: false,
      });
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid, { auto_reconnect: false });
      await sleep(300);
      return client;
    };
    const makePreparedClient = async (tag: string, aid: string, slotId = '') => {
      const client = w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-notify-${tag}`,
        deviceId: `dev-${tag}`,
        slotId: slotId || `slot-${tag}`,
        requireForwardSecrecy: false,
      });
      await w.AUN_TEST_HELPERS.registerAndLoadIdentity(client, aid);
      return client;
    };
    const waitForAppEvent = (client: any, event: string, token: string, timeoutMs: number) => {
      return new Promise<any | null>((resolve) => {
        let done = false;
        const sub = client.on(event, (payload: any) => {
          if (!payload || payload.token !== token || done) return;
          done = true;
          clearTimeout(timer);
          sub?.unsubscribe?.();
          resolve(payload);
        });
        const timer = setTimeout(() => {
          if (done) return;
          done = true;
          sub?.unsubscribe?.();
          resolve(null);
        }, timeoutMs);
      });
    };

    w.__aunNotify = {
      issuer,
      issuerA,
      issuerB,
      runId,
      makeClient,
      makePreparedClient,
      waitForAppEvent,
    };
  }, { issuer: ISSUER, issuerA: ISSUER_A, issuerB: ISSUER_B });
}

test.describe('Notify 浏览器 E2E', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installNotifyHelpers(page);
  });

  test('AID 在线 notify 应实时投递 app.* 事件', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { issuer, runId, makeClient, waitForAppEvent } = (window as any).__aunNotify;
      const rid = runId();
      const aliceAid = `js-notify-a-${rid}.${issuer}`;
      const bobAid = `js-notify-b-${rid}.${issuer}`;
      const token = `aid-${rid}`;
      const alice = await makeClient(`alice-${rid}`, aliceAid);
      const bob = await makeClient(`bob-${rid}`, bobAid);
      try {
        const received = waitForAppEvent(bob, 'app.typing', token, 8_000);
        await alice.notify('event/app.typing', { token, thread_id: `thread-${rid}` }, { to: bobAid, ttl_ms: 5000 });
        const payload = await received;
        return {
          delivered: !!payload,
          threadId: payload?.thread_id ?? '',
          fromAid: payload?._notify?.from_aid ?? '',
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    });

    expect(result.delivered).toBe(true);
    expect(result.threadId).toMatch(/^thread-/);
    expect(result.fromAid).toMatch(/^js-notify-a-/);
  });

  test('离线 notify 不应存储，目标重连后不补发', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { issuer, runId, makeClient, makePreparedClient, waitForAppEvent } = (window as any).__aunNotify;
      const rid = runId();
      const aliceAid = `js-notify-off-a-${rid}.${issuer}`;
      const bobAid = `js-notify-off-b-${rid}.${issuer}`;
      const token = `offline-${rid}`;
      const alice = await makeClient(`off-alice-${rid}`, aliceAid);
      const bob = await makePreparedClient(`off-bob-${rid}`, bobAid, `late-${rid}`);
      try {
        await alice.notify('event/app.offline_probe', { token, phase: 'while-offline' }, { to: bobAid, ttl_ms: 3000 });
        await (window as any).AUN_TEST_HELPERS.connectIdentity(bob, bobAid, { auto_reconnect: false });
        const payload = await waitForAppEvent(bob, 'app.offline_probe', token, 3_000);
        return { delivered: !!payload };
      } finally {
        await alice.close();
        await bob.close();
      }
    });

    expect(result.delivered).toBe(false);
  });
});

test.describe('Notify 浏览器跨域', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installNotifyHelpers(page);
  });

  test('AID notify 应能从 aid.com 在线投递到 aid.net', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { issuerA, issuerB, runId, makeClient, waitForAppEvent } = (window as any).__aunNotify;
      const rid = runId();
      const aliceAid = `js-notify-xa-${rid}.${issuerA}`;
      const bobAid = `js-notify-xb-${rid}.${issuerB}`;
      const token = `cross-${rid}`;
      const alice = await makeClient(`xa-${rid}`, aliceAid);
      const bob = await makeClient(`xb-${rid}`, bobAid);
      try {
        const received = waitForAppEvent(bob, 'app.cross_domain_ping', token, 12_000);
        await alice.notify('event/app.cross_domain_ping', { token, from: aliceAid }, { to: bobAid, ttl_ms: 10000 });
        const payload = await received;
        return {
          delivered: !!payload,
          token: payload?.token ?? '',
          fromAid: payload?._notify?.from_aid ?? '',
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    });

    expect(result.delivered).toBe(true);
    expect(result.token).toMatch(/^cross-/);
    expect(result.fromAid).toMatch(/^js-notify-xa-/);
  });
});
