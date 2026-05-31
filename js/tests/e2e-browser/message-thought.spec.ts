// ── Playwright E2E 浏览器测试：message.thought.get ──────────
//
// 覆盖用户反馈的场景：服务端存在 9 条 mt-* thought，SDK 解密成功后
// 返回给应用层的 thoughts[] 不能变成空数组。

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

async function installThoughtHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__aunThought) return;

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

    const payloadTexts = (result: any): string[] => {
      const thoughts = Array.isArray(result?.thoughts) ? result.thoughts : [];
      return thoughts
        .map((item: any) => item?.payload?.text)
        .filter((text: any) => typeof text === 'string');
    };

    w.__aunThought = { makeAndConnect, ensureConnected, payloadTexts };
  }, ISSUER);
}

test.describe('message.thought.get（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installThoughtHelpers(page);
  });

  test('服务端 9 条 mt-* thought 经 SDK 解密后仍返回 9 条明文 thoughts', async ({ page }) => {
    const result = await page.evaluate(async (issuer: string) => {
      const { makeAndConnect, ensureConnected, payloadTexts } = (window as any).__aunThought;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
      const aliceAid = `thought-a-${rid}.${issuer}`;
      const bobAid = `thought-b-${rid}.${issuer}`;
      const context = { type: 'run', id: `thought-run-${rid}` };
      const expectedTexts = Array.from({ length: 9 }, (_: unknown, idx: number) => `thought-${idx}-${rid}`);

      const alice = await makeAndConnect(`thought-alice-${rid}`);
      const bob = await makeAndConnect(`thought-bob-${rid}`);
      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        for (let idx = 0; idx < expectedTexts.length; idx += 1) {
          const put = await alice.call('message.thought.put', {
            to: bobAid,
            context,
            thought_id: `mt-${rid}-${idx}`,
            payload: { type: 'thought', text: expectedTexts[idx], index: idx },
            encrypt: true,
          });
          if (Number(put?.stored_count ?? 0) < idx + 1) {
            return { error: `put stored_count 异常 idx=${idx}`, put };
          }
        }

        const raw = await bob._transport.call('message.thought.get', {
          sender_aid: aliceAid,
          context,
        });
        const rawCount = Array.isArray(raw?.thoughts) ? raw.thoughts.length : -1;
        if (raw?.found !== true || rawCount !== expectedTexts.length) {
          return { error: '服务端原始 thoughts 条数异常', raw, rawCount };
        }

        const sdkResult = await bob.call('message.thought.get', {
          sender_aid: aliceAid,
          context,
        });
        const texts = payloadTexts(sdkResult);

        const repeat = await bob.call('message.thought.get', {
          sender_aid: aliceAid,
          context,
        });
        const repeatTexts = payloadTexts(repeat);

        return { expectedTexts, rawCount, texts, repeatTexts, sdkResult, repeat };
      } catch (e: any) {
        return { error: e?.message ?? String(e), stack: e?.stack };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    const r = result as any;
    expect(r.error, JSON.stringify(r)).toBeUndefined();
    expect(r.rawCount).toBe(9);
    expect(r.texts, JSON.stringify(r.sdkResult)).toEqual(r.expectedTexts);
    expect(r.repeatTexts, JSON.stringify(r.repeat)).toEqual(r.expectedTexts);
  });
});
