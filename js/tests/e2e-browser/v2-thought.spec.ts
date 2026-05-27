// ── Playwright E2E 浏览器测试：V2 thought.put / thought.get ────
//
// 覆盖（对齐 Python tests/e2e_test_v2_thought.py）：
//   1. P2P thought.put 写出 V2 envelope（type=e2ee.p2p_encrypted, recipients[]）
//   2. P2P thought.get 解密回明文
//   3. P2P thought 重复读取（无 replay guard）
//   4. Group thought.put 写出 V2 envelope（type=e2ee.group_encrypted, recipients[]）
//   5. Group thought.get 解密回明文
//
// 运行：
//   npm run build && npx playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/v2-thought.spec.ts --reporter=line
//
// 前置：Docker 单域环境运行中；--host-resolver-rules 已映射 *.agentid.pub → 127.0.0.1。

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

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

async function installHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__v2thought) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const makeAndConnect = async (aid: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({ issuer }, true);
      try { await client.auth.registerAid({ aid }); } catch {}
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);
      return client;
    };

    w.__v2thought = { sleep, makeAndConnect, ISSUER: issuer };
  }, ISSUER);
}

// ── 五个场景测试 ──

test.describe('V2 thought 端到端测试', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installHelpers(page);
  });

  // ── 1. P2P thought.put 写出 V2 envelope ──

  test('P2P thought.put 服务端原始 payload 为 V2 envelope', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, ISSUER } = (window as any).__v2thought;
      const aliceAid = `v2t-pa-${rid}.${ISSUER}`;
      const bobAid = `v2t-pb-${rid}.${ISSUER}`;
      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      const text = `v2-thought-p2p-${rid}-${Date.now()}`;
      const ctx = { type: 'v2-run', id: `v2-thought-run-${rid}` };
      const putRes: any = await alice.call('message.thought.put', {
        to: bobAid,
        context: ctx,
        thought_id: `mt-v2-${rid}`,
        payload: { type: 'thought', text },
      });

      // 直接读 transport 原始返回，绕过 SDK 解密
      const raw: any = await (bob as any)._transport.call('message.thought.get', {
        sender_aid: aliceAid,
        context: ctx,
      });
      const items = Array.isArray(raw?.thoughts) ? raw.thoughts : [];
      const firstPayload = items[0]?.payload ?? null;

      const stored = Number(putRes?.stored_count ?? 0);
      await alice.close();
      await bob.close();

      return {
        stored,
        firstPayloadType: firstPayload?.type ?? null,
        firstVersion: firstPayload?.version ?? null,
        firstRecipientsLen: Array.isArray(firstPayload?.recipients) ? firstPayload.recipients.length : 0,
      };
    }, rid);

    expect(result.stored).toBeGreaterThanOrEqual(1);
    expect(result.firstPayloadType).toBe('e2ee.p2p_encrypted');
    expect(result.firstVersion).toBe('v2');
    expect(result.firstRecipientsLen).toBeGreaterThanOrEqual(1);
  });

  // ── 2. P2P thought.get 解密回明文 ──

  test('P2P thought.get 解密回明文', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, ISSUER } = (window as any).__v2thought;
      const aliceAid = `v2t-ga-${rid}.${ISSUER}`;
      const bobAid = `v2t-gb-${rid}.${ISSUER}`;
      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      const text = `v2-thought-get-${rid}-${Date.now()}`;
      const ctx = { type: 'v2-run', id: `v2-thought-get-run-${rid}` };
      await alice.call('message.thought.put', {
        to: bobAid,
        context: ctx,
        thought_id: `mt-v2g-${rid}`,
        payload: { type: 'thought', text },
      });

      const got: any = await bob.call('message.thought.get', {
        sender_aid: aliceAid,
        context: ctx,
      });
      const texts: string[] = [];
      const items = Array.isArray(got?.thoughts) ? got.thoughts : [];
      for (const it of items) {
        const t = it?.payload?.text;
        if (typeof t === 'string') texts.push(t);
      }
      await alice.close();
      await bob.close();
      return { containsText: texts.includes(text), text, texts };
    }, rid);

    expect(result.containsText).toBe(true);
  });

  // ── 3. P2P thought 重复读取 ──

  test('P2P thought 重复读取（无 replay guard）', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, ISSUER } = (window as any).__v2thought;
      const aliceAid = `v2t-ra-${rid}.${ISSUER}`;
      const bobAid = `v2t-rb-${rid}.${ISSUER}`;
      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      const text = `v2-thought-repeat-${rid}-${Date.now()}`;
      const ctx = { type: 'v2-run', id: `v2-thought-repeat-${rid}` };
      await alice.call('message.thought.put', {
        to: bobAid,
        context: ctx,
        thought_id: `mt-v2r-${rid}`,
        payload: { type: 'thought', text },
      });

      // 读两次都应能拿到明文
      const got1: any = await bob.call('message.thought.get', { sender_aid: aliceAid, context: ctx });
      const got2: any = await bob.call('message.thought.get', { sender_aid: aliceAid, context: ctx });

      const extract = (got: any): string[] => {
        const items = Array.isArray(got?.thoughts) ? got.thoughts : [];
        return items.map((it: any) => it?.payload?.text).filter((t: any) => typeof t === 'string');
      };

      await alice.close();
      await bob.close();
      return { first: extract(got1).includes(text), second: extract(got2).includes(text) };
    }, rid);

    expect(result.first).toBe(true);
    expect(result.second).toBe(true);
  });

  // ── 4. Group thought.put 写出 V2 envelope ──

  test('Group thought.put 服务端原始 payload 为 V2 envelope', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, sleep, ISSUER } = (window as any).__v2thought;
      const aliceAid = `v2t-gpa-${rid}.${ISSUER}`;
      const bobAid = `v2t-gpb-${rid}.${ISSUER}`;
      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      const groupResult: any = await alice.call('group.create', {
        name: `v2-thought-${rid}`,
        visibility: 'private',
      });
      const groupId = groupResult?.group?.group_id ?? groupResult?.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await sleep(1000);

      const text = `v2-group-thought-${rid}-${Date.now()}`;
      const ctx = { type: 'v2-group-run', id: `v2-group-thought-${rid}` };
      const putRes: any = await alice.call('group.thought.put', {
        group_id: groupId,
        context: ctx,
        payload: { type: 'thought', text },
      });

      // 读服务端原始 payload（绕过 SDK 解密）
      const raw: any = await (bob as any)._transport.call('group.thought.get', {
        group_id: groupId,
        sender_aid: aliceAid,
        context: ctx,
      });
      const items = Array.isArray(raw?.thoughts) ? raw.thoughts : [];
      const firstPayload = items[0]?.payload ?? null;

      await alice.close();
      await bob.close();
      return {
        putOk: !!putRes,
        firstPayloadType: firstPayload?.type ?? null,
        firstVersion: firstPayload?.version ?? null,
        firstRecipientsLen: Array.isArray(firstPayload?.recipients) ? firstPayload.recipients.length : 0,
      };
    }, rid);

    expect(result.putOk).toBe(true);
    expect(result.firstPayloadType).toBe('e2ee.group_encrypted');
    expect(result.firstVersion).toBe('v2');
    expect(result.firstRecipientsLen).toBeGreaterThanOrEqual(1);
  });

  // ── 5. Group thought.get 解密回明文 ──

  test('Group thought.get 解密回明文', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, sleep, ISSUER } = (window as any).__v2thought;
      const aliceAid = `v2t-gga-${rid}.${ISSUER}`;
      const bobAid = `v2t-ggb-${rid}.${ISSUER}`;
      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);

      const groupResult: any = await alice.call('group.create', {
        name: `v2-thought-get-${rid}`,
        visibility: 'private',
      });
      const groupId = groupResult?.group?.group_id ?? groupResult?.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await sleep(1000);

      const text = `v2-group-thought-get-${rid}-${Date.now()}`;
      const ctx = { type: 'v2-group-run', id: `v2-group-thought-get-${rid}` };
      await alice.call('group.thought.put', {
        group_id: groupId,
        context: ctx,
        payload: { type: 'thought', text },
      });

      const got: any = await bob.call('group.thought.get', {
        group_id: groupId,
        sender_aid: aliceAid,
        context: ctx,
      });
      const texts: string[] = [];
      const items = Array.isArray(got?.thoughts) ? got.thoughts : [];
      for (const it of items) {
        const t = it?.payload?.text;
        if (typeof t === 'string') texts.push(t);
      }
      await alice.close();
      await bob.close();
      return { containsText: texts.includes(text) };
    }, rid);

    expect(result.containsText).toBe(true);
  });
});
