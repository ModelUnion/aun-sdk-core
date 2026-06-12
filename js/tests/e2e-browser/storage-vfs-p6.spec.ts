// ── Playwright E2E 浏览器测试：Storage VFS P6 mount ─────────
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/storage-vfs-p6.spec.ts --reporter=line
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

let server: http.Server;
let baseUrl: string;

test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    const safePath = (req.url ?? '/').split('?')[0];
    const filePath = path.join(JS_ROOT, safePath);
    if (!filePath.startsWith(JS_ROOT)) { res.writeHead(403); res.end('Forbidden'); return; }
    const ext = path.extname(filePath);
    const mimeTypes: Record<string, string> = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.mjs': 'application/javascript',
      '.css': 'text/css',
      '.json': 'application/json',
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
  if (server) await new Promise<void>(resolve => server.close(() => resolve()));
});

function testPageUrl(): string {
  return `${baseUrl}/tests/e2e-browser/test-page.html`;
}

async function installStorageP6Helpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__storageP6) return;

    const makeAndConnect = async (instanceId: string, aid: string): Promise<any> => {
      const client = w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-storage-p6-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
      return client;
    };
    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 10);
    const decode = (data: Uint8Array) => new TextDecoder().decode(data);
    const expectUnavailable = async (action: Promise<any>): Promise<boolean> => {
      try {
        await action;
        return false;
      } catch {
        return true;
      }
    };

    w.__storageP6 = { makeAndConnect, runId, decode, expectUnavailable, ISSUER: issuer };
  }, ISSUER);
}

test.describe('Storage VFS P6 mount（浏览器）', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installStorageP6Helpers(page);
  });

  test('mount/read/write/copy/rename/remove/unmount 使用浏览器 JS SDK VFS', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { makeAndConnect, runId, decode, expectUnavailable, ISSUER } = (window as any).__storageP6;
      const rid = runId();
      const aliceAid = `p6jsa${rid}.${ISSUER}`;
      const groupAid = `p6jsg${rid}.${ISSUER}`;
      const root = `/fs-p6-js-${rid}`;
      const sourceDir = `${root}/source`;
      const mountDir = `${root}/memberdata/alice`;
      const body = `hello-p6-js-${rid}`;
      const writtenViaMount = `write-p6-js-${rid}`;

      const alice = await makeAndConnect(`alice-${rid}`, aliceAid);
      const group = await makeAndConnect(`group-${rid}`, groupAid);
      try {
        await alice.storage.writeBytes(`${sourceDir}/a.txt`, body, { owner: aliceAid, contentType: 'text/plain' });
        await alice.storage.setAcl(sourceDir, { owner: aliceAid, granteeAid: groupAid, perms: 'rwd' });

        const mounted = await group.storage.mount(`${aliceAid}:${sourceDir}`, mountDir, { owner: groupAid, readonly: false });
        const lstat = await group.storage.lstat(mountDir, { owner: groupAid });
        const stat = await group.storage.stat(mountDir, { owner: groupAid });
        const listed = await group.storage.list(mountDir, { owner: groupAid, long: true });
        const readFromMount = decode(await group.storage.readBytes(`${mountDir}/a.txt`, { owner: groupAid }));

        await group.storage.writeBytes(`${mountDir}/b.txt`, writtenViaMount, { owner: groupAid, contentType: 'text/plain' });
        const sourceReadAfterWrite = decode(await alice.storage.readBytes(`${sourceDir}/b.txt`, { owner: aliceAid }));

        const copied = await group.storage.copy(`${mountDir}/b.txt`, `${mountDir}/copied.txt`, { owner: groupAid });
        const renamed = await group.storage.rename(`${mountDir}/copied.txt`, `${mountDir}/renamed.txt`, { owner: groupAid });
        const removed = await group.storage.remove(`${mountDir}/renamed.txt`, { owner: groupAid });
        const renamedGone = await expectUnavailable(alice.storage.stat(`${sourceDir}/renamed.txt`, { owner: aliceAid }));

        const unmounted = await group.storage.unmount(mountDir, { owner: groupAid });
        const mountGone = await expectUnavailable(group.storage.stat(mountDir, { owner: groupAid }));
        const sourceAfterUnmount = decode(await alice.storage.readBytes(`${sourceDir}/a.txt`, { owner: aliceAid }));

        return {
          mountedType: mounted.type,
          mountedPath: mounted.path,
          mountSource: mounted.mountSource,
          lstatType: lstat.type,
          statType: stat.type,
          listedNames: listed.map((node: any) => node.name),
          readFromMount,
          sourceReadAfterWrite,
          copiedOwner: copied.owner,
          renamedPath: renamed.path,
          removedCount: removed.removedCount,
          renamedGone,
          unmounted: !!unmounted.unmounted,
          mountGone,
          sourceAfterUnmount,
          aliceAid,
          sourceDir,
        };
      } finally {
        await alice.storage.remove(root, { owner: aliceAid, recursive: true }).catch(() => undefined);
        await group.storage.remove(root, { owner: groupAid, recursive: true }).catch(() => undefined);
        await alice.close();
        await group.close();
      }
    });

    expect(result.mountedType).toBe('mount');
    expect(result.mountedPath).toContain('/memberdata/alice');
    expect(result.mountSource).toContain(result.aliceAid);
    expect(result.mountSource).toContain(String(result.sourceDir).replace(/^\//, ''));
    expect(result.lstatType).toBe('mount');
    expect(result.statType).toBe('dir');
    expect(result.listedNames).toContain('a.txt');
    expect(result.readFromMount).toContain('hello-p6-js-');
    expect(result.sourceReadAfterWrite).toContain('write-p6-js-');
    expect(result.copiedOwner).toBe(result.aliceAid);
    expect(result.renamedPath).toContain('/source/renamed.txt');
    expect(result.removedCount).toBe(1);
    expect(result.renamedGone).toBe(true);
    expect(result.unmounted).toBe(true);
    expect(result.mountGone).toBe(true);
    expect(result.sourceAfterUnmount).toContain('hello-p6-js-');
  });
});
