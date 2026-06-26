// ── Playwright E2E 浏览器测试：Storage 服务 ──────────────────
//
// 覆盖：
//   1. inline put/head/get/delete 全生命周期
//   2. 跨 AID 权限：私有对象拒绝、公开对象允许
//   3. list_objects 前缀分页
//   4. overwrite + expected_version 冲突
//   5. 配额查询
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/storage.spec.ts --reporter=line
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
      return w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
    };

    /**
     * 确保 AID 已创建、认证并连接。
     */
    const ensureConnected = async (client: any, aid: string): Promise<void> => {
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
    };

    /** 生成短唯一 ID */
    const runId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 8);

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

// ── Storage: inline 存取（浏览器） ────────────────────────────

test.describe('Storage: inline 存取（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('put → head → get → delete 全生命周期', async ({ page }) => {
    test.setTimeout(60_000);

    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `stoa${rid}.${iss}`;
      const bucket = `test-bucket-${rid}`;
      const objectKey = `docs/${rid}/lifecycle.txt`;
      const bodyText = `lifecycle-data-${rid}`;

      const alice = await makeAndConnect(`sto-lc-alice-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);

        // put 私有对象
        let putResult: any;
        try {
          putResult = await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
            content: btoa(bodyText),
            content_type: 'text/plain',
            is_private: true,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'storage.put_object 未实现' };
          }
          return { skip: false, error: 'put 失败: ' + e.message };
        }
        const putOk = putResult?.object_key === objectKey;

        // head 检查元数据
        const headResult = await alice.call('storage.head_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
        });
        const headSizeOk = Number(headResult?.size_bytes || 0) === new TextEncoder().encode(bodyText).length;
        const headPrivateOk = headResult?.is_private === true;

        // get 获取内容
        const getResult = await alice.call('storage.get_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
        });
        const decoded = atob(getResult?.content || '');
        const getContentOk = decoded === bodyText;

        // delete 删除对象
        const delResult = await alice.call('storage.delete_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
        });
        const deleteOk = delResult?.deleted === true;

        // 删除后 head 应该 404 或报错
        let headAfterDeleteGone = false;
        try {
          await alice.call('storage.head_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
          });
        } catch {
          headAfterDeleteGone = true;
        }

        return { skip: false, putOk, headSizeOk, headPrivateOk, getContentOk, deleteOk, headAfterDeleteGone };
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.putOk).toBe(true);
    expect(r.headSizeOk).toBe(true);
    expect(r.headPrivateOk).toBe(true);
    expect(r.getContentOk).toBe(true);
    expect(r.deleteOk).toBe(true);
    expect(r.headAfterDeleteGone).toBe(true);
  });

  test('跨 AID 权限: 私有拒绝、公开允许', async ({ page }) => {
    test.setTimeout(60_000);

    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `stopa${rid}.${iss}`;
      const bobAid = `stopb${rid}.${iss}`;
      const bucket = `test-bucket-${rid}`;
      const publicKey = `public/${rid}/readme.txt`;
      const privateKey = `private/${rid}/secret.txt`;
      const publicBody = `public-content-${rid}`;
      const privateBody = `private-content-${rid}`;

      const alice = await makeAndConnect(`sto-perm-alice-${rid}`);
      const bob = await makeAndConnect(`sto-perm-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // Alice 放一个公开对象
        try {
          await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: publicKey,
            content: btoa(publicBody),
            content_type: 'text/plain',
            is_private: false,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'storage.put_object 未实现' };
          }
          return { skip: false, error: 'put public 失败: ' + e.message };
        }

        // Bob 读取公开对象 — 应成功
        const bobGetPublic = await bob.call('storage.get_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: publicKey,
        });
        const publicReadOk = atob(bobGetPublic?.content || '') === publicBody;

        // Alice 放一个私有对象
        await alice.call('storage.put_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: privateKey,
          content: btoa(privateBody),
          content_type: 'text/plain',
          is_private: true,
        });

        // Bob 读取私有对象 — 应失败
        let privateReadDenied = false;
        try {
          await bob.call('storage.get_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: privateKey,
          });
        } catch {
          privateReadDenied = true;
        }

        return { skip: false, publicReadOk, privateReadDenied };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.publicReadOk).toBe(true);
    expect(r.privateReadDenied).toBe(true);
  });
});

// ── Storage: 分页与版本控制（浏览器） ─────────────────────────

test.describe('Storage: 分页与版本控制（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('写 3 个同前缀对象 → list_objects 验证数量', async ({ page }) => {
    test.setTimeout(60_000);

    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `stolist${rid}.${iss}`;
      const bucket = `test-bucket-${rid}`;
      const prefix = `docs-${rid}/`;

      const alice = await makeAndConnect(`sto-list-alice-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);

        // 写 3 个同前缀对象
        const names = ['a.txt', 'b.txt', 'c.txt'];
        for (const name of names) {
          try {
            await alice.call('storage.put_object', {
              owner_aid: aliceAid,
              bucket,
              object_key: `${prefix}${name}`,
              content: btoa(`content-${name}-${rid}`),
              content_type: 'text/plain',
              is_private: true,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'storage.put_object 未实现' };
            }
            return { skip: false, error: `put ${name} 失败: ` + e.message };
          }
        }

        // list_objects 按前缀查询
        let listResult: any;
        try {
          listResult = await alice.call('storage.list_objects', {
            owner_aid: aliceAid,
            bucket,
            prefix,
            page: 1,
            size: 20,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'storage.list_objects 未实现' };
          }
          return { skip: false, error: 'list_objects 失败: ' + e.message };
        }

        const items = listResult?.items || [];
        const keys = items.map((item: any) => String(item?.object_key || ''));

        return {
          skip: false,
          count: items.length,
          keys,
          hasAll: names.every(n => keys.some((k: string) => k.includes(n))),
        };
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.count).toBeGreaterThanOrEqual(3);
    expect(r.hasAll).toBe(true);
  });

  test('覆写 + expected_version 冲突', async ({ page }) => {
    test.setTimeout(60_000);

    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `stover${rid}.${iss}`;
      const bucket = `test-bucket-${rid}`;
      const objectKey = `docs/${rid}/version-test.txt`;

      const alice = await makeAndConnect(`sto-ver-alice-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);

        // 首次 put
        let putResult: any;
        try {
          putResult = await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
            content: btoa(`v1-${rid}`),
            content_type: 'text/plain',
            is_private: true,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'storage.put_object 未实现' };
          }
          return { skip: false, error: 'put v1 失败: ' + e.message };
        }
        const version = Number(putResult?.version || 0);

        // overwrite=false — 应失败（对象已存在）
        let overwriteDenied = false;
        try {
          await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
            content: btoa(`v2-${rid}`),
            content_type: 'text/plain',
            overwrite: false,
          });
        } catch {
          overwriteDenied = true;
        }

        // expected_version 错误 — 应失败
        let wrongVersionDenied = false;
        try {
          await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
            content: btoa(`v3-${rid}`),
            content_type: 'text/plain',
            expected_version: 999,
          });
        } catch {
          wrongVersionDenied = true;
        }

        // expected_version 正确 — 应成功
        let correctVersionOk = false;
        try {
          const updated = await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
            content: btoa(`v2-updated-${rid}`),
            content_type: 'text/plain',
            expected_version: version,
          });
          correctVersionOk = Number(updated?.version || 0) === version + 1;
        } catch {
          correctVersionOk = false;
        }

        return { skip: false, overwriteDenied, wrongVersionDenied, correctVersionOk };
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.overwriteDenied).toBe(true);
    expect(r.wrongVersionDenied).toBe(true);
    expect(r.correctVersionOk).toBe(true);
  });
});

// ── Storage: 配额（浏览器） ───────────────────────────────────

test.describe('Storage: 配额（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('get_quota 返回用量信息', async ({ page }) => {
    test.setTimeout(60_000);

    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `stoq${rid}.${iss}`;
      const bucket = `test-bucket-${rid}`;
      const objectKey = `quota/${rid}/test.txt`;
      const bodyText = `quota-test-data-${rid}`;

      const alice = await makeAndConnect(`sto-quota-alice-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);

        // 先 put 一个对象确保 storage 服务可用
        try {
          await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
            content: btoa(bodyText),
            content_type: 'text/plain',
            is_private: true,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'storage.put_object 未实现' };
          }
          return { skip: false, error: 'put 失败: ' + e.message };
        }

        // 查询配额
        let quotaResult: any;
        try {
          quotaResult = await alice.call('storage.get_quota', {
            owner_aid: aliceAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'storage.get_quota 未实现' };
          }
          return { skip: false, error: 'get_quota 失败: ' + e.message };
        }

        const usedBytes = Number(quotaResult?.used_bytes ?? -1);
        const totalBytes = Number(quotaResult?.total_bytes ?? quotaResult?.quota_bytes ?? -1);

        // 清理：删除测试对象
        try {
          await alice.call('storage.delete_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: objectKey,
          });
        } catch {
          // 清理失败不影响测试结果
        }

        return {
          skip: false,
          hasUsedBytes: usedBytes >= 0,
          hasTotalBytes: totalBytes >= 0,
          usedBytes,
          totalBytes,
          usedPositive: usedBytes > 0,
        };
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      test.skip();
      return;
    }
    const r = result as any;
    expect(r.error).toBeUndefined();
    expect(r.hasUsedBytes).toBe(true);
    // put 后 used_bytes 应大于 0
    expect(r.usedPositive).toBe(true);
    if (r.hasTotalBytes) {
      console.log(`配额信息: 已用 ${r.usedBytes} / 总计 ${r.totalBytes} 字节`);
    } else {
      console.log(`配额信息: 已用 ${r.usedBytes} 字节（未返回总配额）`);
    }
  });
});

// ── Storage: VFS/软链（浏览器） ─────────────────────────────

test.describe('Storage: VFS/软链（浏览器）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('write/read/list/stat/df/token/copy/rename/symlink/find/remove', async ({ page }) => {
    test.setTimeout(90_000);

    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const aliceAid = `stovfs${rid}.${iss}`;
      const bobAid = `stovfsb${rid}.${iss}`;
      const bucket = `vfs-${rid}`;
      const dirPath = `/docs/${rid}`;
      const filePath = `${dirPath}/a.txt`;
      const body = `browser-vfs-${rid}`;
      const alice = await makeAndConnect(`sto-vfs-alice-${rid}`);
      const bob = await makeAndConnect(`sto-vfs-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        let written: any;
        try {
          written = await alice.storage.writeBytes(filePath, body, { owner: aliceAid, bucket, contentType: 'text/plain' });
        } catch (err: any) {
          const message = String(err?.message ?? '').toLowerCase();
          if (message.includes('not implement') || message.includes('method not found')) {
            return { skip: true, reason: `storage VFS 不可用: ${err?.message ?? String(err)}` };
          }
          throw err;
        }
        const read = new TextDecoder().decode(await alice.storage.readBytes(filePath, { owner: aliceAid, bucket }));
        const stat = await alice.storage.stat(filePath, { owner: aliceAid, bucket });
        const listed = await alice.storage.list(dirPath, { owner: aliceAid, bucket, long: true });
        const usage = await alice.storage.df({ owner: aliceAid, bucket });
        const touched = await alice.storage.touch(`${dirPath}/empty.txt`, { owner: aliceAid, bucket, parents: true, mtime: 1700000000 });
        const du = await alice.storage.du(dirPath, { owner: aliceAid, bucket, maxDepth: 2 });

        const token = String((await alice.storage.issueToken(filePath, { owner: aliceAid, bucket, maxReads: 1 })).token ?? '');
        const tokenRead = new TextDecoder().decode(await bob.storage.readBytes(filePath, { owner: aliceAid, bucket, token }));
        let tokenSecondDenied = false;
        try {
          await bob.storage.readBytes(filePath, { owner: aliceAid, bucket, token });
        } catch {
          tokenSecondDenied = true;
        }
        const tokens = await alice.storage.listTokens(filePath, { owner: aliceAid, bucket });

        const copiedPath = `${dirPath}/copied.txt`;
        const copied = await alice.storage.copy(filePath, copiedPath, { owner: aliceAid, bucket, overwrite: true });
        const renamedPath = `${dirPath}/renamed.txt`;
        const renamed = await alice.storage.rename(copiedPath, renamedPath, { owner: aliceAid, bucket, overwrite: true });
        const linkPath = `${dirPath}/current.txt`;
        const link = await alice.storage.symlink(renamedPath, linkPath, { owner: aliceAid, bucket, overwrite: true });
        const lstat = await alice.storage.lstat(linkPath, { owner: aliceAid, bucket });
        const statLink = await alice.storage.stat(linkPath, { owner: aliceAid, bucket });
        const readlink = await alice.storage.readlink(linkPath, { owner: aliceAid, bucket });
        const repointed = await alice.storage.repoint(linkPath, filePath, { owner: aliceAid, bucket });
        const renamedLinkPath = `${dirPath}/latest.txt`;
        const renamedLink = await alice.storage.renameSymlink(linkPath, renamedLinkPath, { owner: aliceAid, bucket, overwrite: true });
        const found = await alice.storage.find(dirPath, { owner: aliceAid, bucket, name: 'latest.txt', nodeType: 'symlink' });
        const removedLink = await alice.storage.remove(renamedLinkPath, { owner: aliceAid, bucket });
        const removedFile = await alice.storage.remove(renamedPath, { owner: aliceAid, bucket });

        return {
          skip: false,
          writtenType: written?.type,
          read,
          statType: stat?.type,
          listHasFile: listed.some((node: any) => node.name === 'a.txt'),
          usagePositive: Number(usage?.usedBytes ?? 0) > 0,
          touchedPath: touched?.path,
          duFileCount: Number(du?.fileCount ?? du?.file_count ?? 0),
          duSizeBytes: Number(du?.sizeBytes ?? du?.size_bytes ?? 0),
          tokenRead,
          tokenSecondDenied,
          tokensCount: (tokens?.tokens ?? tokens?.items ?? []).length,
          copiedPath: copied?.path,
          renamedPath: renamed?.path,
          linkType: link?.type,
          linkTarget: link?.target,
          lstatType: lstat?.type,
          statLinkType: statLink?.type,
          readlinkTarget: readlink?.target,
          repointedTarget: repointed?.target,
          renamedLinkPath: renamedLink?.path,
          foundNames: found.map((node: any) => node.name),
          removedLinkCount: removedLink?.removedCount,
          removedFileCount: removedFile?.removedCount,
        };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skip) {
      console.log((result as any).reason);
      test.skip();
      return;
    }

    const r = result as any;
    expect(r.writtenType).toBe('file');
    expect(r.read).toContain('browser-vfs-');
    expect(r.statType).toBe('file');
    expect(r.listHasFile).toBe(true);
    expect(r.usagePositive).toBe(true);
    expect(r.touchedPath).toContain('/empty.txt');
    expect(r.duFileCount).toBeGreaterThanOrEqual(2);
    expect(r.duSizeBytes).toBeGreaterThanOrEqual(r.read.length);
    expect(r.tokenRead).toBe(r.read);
    expect(r.tokenSecondDenied).toBe(true);
    expect(r.tokensCount).toBeGreaterThan(0);
    expect(r.copiedPath).toContain('/copied.txt');
    expect(r.renamedPath).toContain('/renamed.txt');
    expect(r.linkType).toBe('symlink');
    expect(r.linkTarget).toContain('/renamed.txt');
    expect(r.lstatType).toBe('symlink');
    expect(r.statLinkType).toBe('file');
    expect(r.readlinkTarget).toContain('/renamed.txt');
    expect(r.repointedTarget).toContain('/a.txt');
    expect(r.renamedLinkPath).toContain('/latest.txt');
    expect(r.foundNames).toContain('latest.txt');
    expect(r.removedLinkCount).toBeGreaterThan(0);
    expect(r.removedFileCount).toBeGreaterThan(0);
  });
});
