// ── Playwright E2E 浏览器测试：Collab 协作层 smoke ──────────────
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/collab.spec.ts --grep collab --reporter=line
//
// 前置条件：
//   - Docker 单域环境运行中（不要由测试脚本启动 Kite）
//   - 浏览器通过 --host-resolver-rules 解析 gateway.agentid.pub → 127.0.0.1

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

async function installCollabHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__collabSmoke) return;

    const makeAndConnect = async (instanceId: string, aid: string): Promise<any> => {
      const client = w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-collab-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
      return client;
    };
    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 10);
    const b64 = (text: string) => btoa(unescape(encodeURIComponent(text)));
    const text = (content: string) => decodeURIComponent(escape(atob(content)));
    const isCollabUnavailable = (err: any) => {
      const message = String(err?.message ?? err ?? '').toLowerCase();
      return message.includes('method not found')
        || message.includes('not implement')
        || message.includes('collab disabled')
        || message.includes('collab not initialized');
    };

    w.__collabSmoke = { makeAndConnect, runId, b64, text, isCollabUnavailable, ISSUER: issuer };
  }, ISSUER);
}

test.describe('collab 浏览器 SDK smoke', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installCollabHelpers(page);
  });

  test('collab create/show/commit/log 使用裸 collab.* RPC', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, runId, b64, text, isCollabUnavailable, ISSUER } = (window as any).__collabSmoke;
      const rid = runId();
      const aliceAid = `jscol${rid}.${ISSUER}`;
      const collabRoot = `${aliceAid}:/collab-smoke/${rid}/proj`;
      const doc = 'spec.md';
      const alice = await makeAndConnect(`alice-${rid}`, aliceAid);

      try {
        let created: any;
        try {
          created = await alice.collab.create(collabRoot, doc, b64(`v1-${rid}\n`));
        } catch (err: any) {
          if (isCollabUnavailable(err)) {
            return { skip: true, reason: `collab.* 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }

        const shown = await alice.collab.show(collabRoot, doc);
        const committed = await alice.collab.commit(collabRoot, doc, b64(`v1-${rid}\nv2-${rid}\n`), 1);
        const log = await alice.collab.log(collabRoot, doc);

        try {
          await alice.storage.remove(`/collab-smoke/${rid}`, { owner: aliceAid, recursive: true });
        } catch {
          // 清理失败不影响 smoke 结论。
        }

        return {
          skip: false,
          createdVersion: Number(created?.version ?? 0),
          showVersion: Number(shown?.version ?? 0),
          showText: text(String(shown?.content ?? '')),
          commitVersion: Number(committed?.version ?? 0),
          logVersions: Array.isArray(log) ? log.map((item: any) => Number(item?.version ?? 0)) : [],
          targetIsAidPath: String(committed?.current_target ?? '').startsWith(`${aliceAid}:/`),
        };
      } finally {
        await alice.close();
      }
    });

    if ((result as any).skip) {
      console.log((result as any).reason);
      test.skip();
      return;
    }

    expect((result as any).createdVersion).toBe(1);
    expect((result as any).showVersion).toBe(1);
    expect((result as any).showText).toContain('v1-');
    expect((result as any).commitVersion).toBe(2);
    expect((result as any).logVersions).toEqual([1, 2]);
    expect((result as any).targetIsAidPath).toBe(true);
  });
});
