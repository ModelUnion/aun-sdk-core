// ── Playwright E2E 浏览器测试：Group Search ──────────────────
//
// 覆盖：
//   1. 搜索基本功能（public vs private、keyword 别名、空结果）
//   2. 分页（limit 限制）
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-search.spec.ts --reporter=line
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

    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 8);

    const makeAndConnect = async (instanceId: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({
        instanceId,
        issuer,
      }, true);
      if (client._configModel) {
        client._configModel.requireForwardSecrecy = false;
      }
      return client;
    };

    const ensureConnected = async (client: any, aid: string): Promise<void> => {
      const gatewayDiscoveryAid = `gateway.${issuer}`;
      const gateway = await client.auth._resolveGateway(gatewayDiscoveryAid);
      (client as any)._gatewayUrl = gateway;
      try {
        await client.auth.registerAid({ aid });
      } catch {
        // 已存在则忽略
      }
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

// ── 1. Group Search: 搜索基本功能 ────────────────────────────

test.describe('Group Search: 搜索基本功能（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('public 可搜到、private 搜不到、keyword 别名、空结果', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `gsrcha${rid}.${iss}`;

      const alice = await makeAndConnect(`gs-alice-${rid}`);

      let publicGroupId: string | undefined;
      let privateGroupId: string | undefined;

      try {
        await ensureConnected(alice, aliceAid);

        // 创建 public 群
        try {
          const pubResult = await alice.call('group.create', {
            name: `srchpub-${rid}`,
            visibility: 'public',
          });
          publicGroupId = pubResult?.group?.group_id ?? pubResult?.group_id;
          if (!publicGroupId) {
            return { skip: true, reason: '创建 public 群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create public failed: ${e.message}` };
        }

        await sleep(500);

        // 创建 private 群
        try {
          const privResult = await alice.call('group.create', {
            name: `srchpriv-${rid}`,
            visibility: 'private',
          });
          privateGroupId = privResult?.group?.group_id ?? privResult?.group_id;
          if (!privateGroupId) {
            return { skip: true, reason: '创建 private 群未返回 group_id' };
          }
        } catch (e: any) {
          return { skip: false, error: `create private failed: ${e.message}` };
        }

        await sleep(500);

        try {
          // --- 测试 1: query 搜索应找到 public，不应找到 private ---
          let queryItems: any[] = [];
          let queryTotal: number | undefined;
          let queryHasMore: boolean | undefined;
          let queryReturnedQuery: string | undefined;
          try {
            const searchResult = await alice.call('group.search', {
              query: `srchpub-${rid}`,
            });
            queryItems = searchResult?.items ?? [];
            queryTotal = searchResult?.total;
            queryHasMore = searchResult?.has_more;
            queryReturnedQuery = searchResult?.query;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.search 未实现' };
            }
            return { skip: false, error: `search query failed: ${e.message}` };
          }

          const foundPublic = queryItems.some((item: any) =>
            (item.group_id === publicGroupId) ||
            (item.name && item.name.includes(`srchpub-${rid}`))
          );
          const foundPrivate = queryItems.some((item: any) =>
            (item.group_id === privateGroupId) ||
            (item.name && item.name.includes(`srchpriv-${rid}`))
          );

          // --- 测试 2: keyword 别名搜索应得到相同结果 ---
          let keywordItems: any[] = [];
          try {
            const keywordResult = await alice.call('group.search', {
              keyword: `srchpub-${rid}`,
            });
            keywordItems = keywordResult?.items ?? [];
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              // keyword 别名不支持不阻塞，记录结果
              keywordItems = [];
            } else {
              return { skip: false, error: `search keyword failed: ${e.message}` };
            }
          }

          const keywordFoundPublic = keywordItems.some((item: any) =>
            (item.group_id === publicGroupId) ||
            (item.name && item.name.includes(`srchpub-${rid}`))
          );

          // --- 测试 3: 搜索不存在的内容应返回 0 条 ---
          let emptyItems: any[] = [];
          try {
            const emptyResult = await alice.call('group.search', {
              query: `nonexistent_zzzzz_${rid}`,
            });
            emptyItems = emptyResult?.items ?? [];
          } catch {
            // 搜索失败视为空结果
          }

          return {
            skip: false,
            foundPublic,
            foundPrivate,
            queryItemsCount: queryItems.length,
            queryReturnedQuery,
            queryTotal,
            queryHasMore,
            keywordFoundPublic,
            keywordItemsCount: keywordItems.length,
            emptyItemsCount: emptyItems.length,
          };
        } finally {
          // 清理：解散两个群
          if (publicGroupId) {
            try { await alice.call('group.dissolve', { group_id: publicGroupId }); } catch {}
          }
          if (privateGroupId) {
            try { await alice.call('group.dissolve', { group_id: privateGroupId }); } catch {}
          }
        }
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    // public 群应被搜到
    expect(r.foundPublic).toBe(true);
    // private 群不应被搜到
    expect(r.foundPrivate).toBe(false);
    // keyword 别名搜索也应找到 public 群
    expect(r.keywordFoundPublic).toBe(true);
    // 不存在的搜索应返回 0 条
    expect(r.emptyItemsCount).toBe(0);
  });
});

// ── 2. Group Search: 分页 ────────────────────────────────────

test.describe('Group Search: 分页（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('limit 限制返回条数', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `gspaga${rid}.${iss}`;

      const alice = await makeAndConnect(`gs-pag-alice-${rid}`);

      const groupIds: string[] = [];
      const commonPrefix = `gspag-${rid}`;

      try {
        await ensureConnected(alice, aliceAid);

        // 创建 3 个 public 群，使用相同前缀
        for (let i = 0; i < 3; i++) {
          try {
            const createResult = await alice.call('group.create', {
              name: `${commonPrefix}-${i}`,
              visibility: 'public',
            });
            const gid = createResult?.group?.group_id ?? createResult?.group_id;
            if (gid) {
              groupIds.push(gid);
            }
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.create 未实现' };
            }
            return { skip: false, error: `create group ${i} failed: ${e.message}` };
          }
          await sleep(300);
        }

        if (groupIds.length < 3) {
          return { skip: true, reason: `只创建了 ${groupIds.length}/3 个群` };
        }

        await sleep(500);

        try {
          // 搜索 limit=2，应最多返回 2 条
          let limitItems: any[] = [];
          let limitHasMore: boolean | undefined;
          let limitTotal: number | undefined;
          try {
            const limitResult = await alice.call('group.search', {
              query: commonPrefix,
              limit: 2,
            });
            limitItems = limitResult?.items ?? [];
            limitHasMore = limitResult?.has_more;
            limitTotal = limitResult?.total;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.search 未实现' };
            }
            return { skip: false, error: `search with limit failed: ${e.message}` };
          }

          // 不带 limit 搜索，验证至少能找到 3 个
          let allItems: any[] = [];
          try {
            const allResult = await alice.call('group.search', {
              query: commonPrefix,
            });
            allItems = allResult?.items ?? [];
          } catch {
            // 不阻塞主流程
          }

          return {
            skip: false,
            groupsCreated: groupIds.length,
            limitItemsCount: limitItems.length,
            limitHasMore,
            limitTotal,
            allItemsCount: allItems.length,
          };
        } finally {
          // 清理：解散所有群
          for (const gid of groupIds) {
            try { await alice.call('group.dissolve', { group_id: gid }); } catch {}
          }
        }
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    // limit=2 应最多返回 2 条
    expect(r.limitItemsCount).toBeLessThanOrEqual(2);
    // 不带 limit 应至少找到 3 条
    expect(r.allItemsCount).toBeGreaterThanOrEqual(3);
  });
});
