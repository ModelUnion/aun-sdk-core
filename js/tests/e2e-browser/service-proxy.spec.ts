// Service Proxy 浏览器 E2E 边界测试。
//
// 运行：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/service-proxy.spec.ts --reporter=line

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');

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
  await new Promise<void>(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) await new Promise<void>(resolve => server.close(() => resolve()));
});

function testPageUrl(): string {
  return `${baseUrl}/tests/e2e-browser/test-page.html`;
}

test.describe('Service Proxy 浏览器 E2E 边界', () => {
  test.setTimeout(30_000);

  test('原生浏览器 WebSocket 不能携带 Authorization header，provider tunnel 必须注入 webSocketFactory', async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });

    const result = await page.evaluate(async () => {
      const w = window as any;
      const client = new w.AUN.ServiceProxyClient({
        providerAid: 'alice.agentid.pub',
        aunClient: {
          authenticate: async () => ({ access_token: 'fresh-token', expires_at: Date.now() / 1000 + 3600 }),
        },
      });
      client.discoverProxyWsUrl = async () => 'wss://proxy.agentid.pub:19890/ws/client';
      try {
        await client.connectOnce();
        return { ok: true, message: '' };
      } catch (err: any) {
        return { ok: false, name: err?.name ?? '', message: String(err?.message ?? err) };
      }
    });

    expect(result.ok).toBe(false);
    expect(`${result.name} ${result.message}`).toMatch(/AuthError|webSocketFactory|Authorization/i);
  });
});
