// ── Playwright E2E 浏览器测试：Group Settings ──────────────────
//
// 覆盖：
//   1. set_settings 写入 + get_settings 读取 + keys 过滤
//   2. 非管理员 set_settings 被拒
//   3. info 视角（owner / 非成员公开群）
//   4. 设置同步（owner 修改 → member 读取验证）
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-settings.spec.ts --reporter=line
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
      return w.AUN_TEST_HELPERS.createClient({
        aunPath: `js-${instanceId}`,
        deviceId: instanceId,
        requireForwardSecrecy: false,
      });
    };

    const ensureConnected = async (client: any, aid: string): Promise<void> => {
      await w.AUN_TEST_HELPERS.connectIdentity(client, aid);
    };

    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

// ── 1. Group Settings: set/get ──────────────────────────────────

test.describe('Group Settings: set/get（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('set_settings 写入 name+description → get_settings 验证', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `gssoa${rid}.${iss}`;

      const owner = await makeAndConnect(`gs-set-owner-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: `settings-set-${rid}`,
            visibility: 'public',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // set_settings 写入 name + description
        const newName = `Renamed-${rid}`;
        const newDesc = `Desc-${rid}`;
        let setResult: any;
        try {
          setResult = await owner.call('group.set_settings', {
            group_id: groupId,
            settings: {
              name: newName,
              description: newDesc,
            },
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.set_settings 未实现' };
          }
          return { skip: false, error: `set_settings failed: ${e.message}` };
        }

        const setGroupId = setResult?.group_id;
        const updatedKeys: string[] = setResult?.updated_keys ?? [];

        await sleep(500);

        // get_settings 全量读取
        let getResult: any;
        try {
          getResult = await owner.call('group.get_settings', {
            group_id: groupId,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.get_settings 未实现' };
          }
          return { skip: false, error: `get_settings failed: ${e.message}` };
        }

        const settingsList: Array<{ key: string; value: any }> = getResult?.settings ?? [];
        const settingsMap: Record<string, any> = {};
        for (const s of settingsList) {
          settingsMap[s.key] = s.value;
        }

        return {
          skip: false,
          setGroupId,
          updatedKeys,
          nameInUpdated: updatedKeys.includes('name'),
          descInUpdated: updatedKeys.includes('description'),
          getName: settingsMap['name'],
          getDesc: settingsMap['description'],
          expectedName: newName,
          expectedDesc: newDesc,
          groupId,
        };
      } finally {
        if (groupId) {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await owner.close();
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

    expect(r.setGroupId).toBe(r.groupId);
    expect(r.nameInUpdated).toBe(true);
    expect(r.descInUpdated).toBe(true);
    expect(r.getName).toBe(r.expectedName);
    expect(r.getDesc).toBe(r.expectedDesc);
  });

  test('get_settings keys 过滤 — 仅返回请求的 keys', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `gsfla${rid}.${iss}`;

      const owner = await makeAndConnect(`gs-filter-owner-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: `settings-filter-${rid}`,
            visibility: 'public',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // 先写入多个字段
        try {
          await owner.call('group.set_settings', {
            group_id: groupId,
            settings: {
              name: `Filtered-${rid}`,
              description: `FilterDesc-${rid}`,
              'rules.content': '测试群规',
            },
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.set_settings 未实现' };
          }
          return { skip: false, error: `set_settings failed: ${e.message}` };
        }

        await sleep(500);

        // 用 keys 过滤只读 name 和 rules.content
        let getResult: any;
        try {
          getResult = await owner.call('group.get_settings', {
            group_id: groupId,
            keys: ['name', 'rules.content'],
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.get_settings 未实现' };
          }
          return { skip: false, error: `get_settings failed: ${e.message}` };
        }

        const settingsList: Array<{ key: string; value: any }> = getResult?.settings ?? [];
        const keysReturned = settingsList.map((s: any) => s.key).sort();

        return {
          skip: false,
          keysReturned,
          expectedKeys: ['name', 'rules.content'].sort(),
          groupId,
        };
      } finally {
        if (groupId) {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await owner.close();
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

    expect(r.keysReturned).toEqual(r.expectedKeys);
  });

  test('非管理员 set_settings 被拒绝', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `gsrja${rid}.${iss}`;
      const memberAid = `gsrjb${rid}.${iss}`;

      const owner = await makeAndConnect(`gs-reject-owner-${rid}`);
      const member = await makeAndConnect(`gs-reject-member-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: `settings-reject-${rid}`,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // 添加 member
        try {
          await owner.call('group.add_member', {
            group_id: groupId,
            aid: memberAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member failed: ${e.message}` };
        }

        await sleep(500);

        // 非管理员尝试 set_settings
        let rejected = false;
        try {
          await member.call('group.set_settings', {
            group_id: groupId,
            settings: { name: 'Hacked' },
          });
          rejected = false;
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.set_settings 未实现' };
          }
          rejected = true;
        }

        return {
          skip: false,
          rejected,
          groupId,
        };
      } finally {
        if (groupId) {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await owner.close();
        await member.close();
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

    expect(r.rejected).toBe(true);
  });
});

// ── 2. Group Settings: info 视角 ──────────────────────────────────

test.describe('Group Settings: info 视角（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('owner info 返回 name + owner_aid', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `gsioa${rid}.${iss}`;

      const owner = await makeAndConnect(`gs-info-owner-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);

        const groupName = `info-owner-${rid}`;

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: groupName,
            visibility: 'public',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // owner 调用 info
        let infoResult: any;
        try {
          infoResult = await owner.call('group.info', { group_id: groupId });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.info 未实现' };
          }
          return { skip: false, error: `info failed: ${e.message}` };
        }

        return {
          skip: false,
          infoGroupId: infoResult?.group_id,
          infoName: infoResult?.name,
          infoOwnerAid: infoResult?.owner_aid,
          hasMemberCount: typeof infoResult?.member_count === 'number',
          hasUpdatedAt: 'updated_at' in (infoResult ?? {}),
          expectedGroupId: groupId,
          expectedName: groupName,
          expectedOwnerAid: ownerAid,
        };
      } finally {
        if (groupId) {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await owner.close();
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

    expect(r.infoGroupId).toBe(r.expectedGroupId);
    expect(r.infoName).toBe(r.expectedName);
    expect(r.infoOwnerAid).toBe(r.expectedOwnerAid);
    expect(r.hasMemberCount).toBe(true);
    expect(r.hasUpdatedAt).toBe(true);
  });

  test('非成员查看公开群 — 基础信息可见', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `gsipa${rid}.${iss}`;
      const outsiderAid = `gsipb${rid}.${iss}`;

      const owner = await makeAndConnect(`gs-info-pub-owner-${rid}`);
      const outsider = await makeAndConnect(`gs-info-pub-outsider-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(outsider, outsiderAid);

        const groupName = `pub-info-${rid}`;

        // 创建公开群
        try {
          const createResult = await owner.call('group.create', {
            name: groupName,
            visibility: 'public',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // 非成员调用 info
        let infoResult: any;
        try {
          infoResult = await outsider.call('group.info', { group_id: groupId });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.info 未实现' };
          }
          return { skip: false, error: `info failed: ${e.message}` };
        }

        return {
          skip: false,
          infoGroupId: infoResult?.group_id,
          infoName: infoResult?.name,
          hasOwnerAid: 'owner_aid' in (infoResult ?? {}),
          expectedGroupId: groupId,
          expectedName: groupName,
        };
      } finally {
        if (groupId) {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await owner.close();
        await outsider.close();
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

    expect(r.infoGroupId).toBe(r.expectedGroupId);
    expect(r.infoName).toBe(r.expectedName);
    // 非成员看不到 owner_aid（服务端策略）
    expect(r.hasOwnerAid).toBe(false);
  });
});

// ── 3. Group Settings: 同步 ──────────────────────────────────────

test.describe('Group Settings: 同步（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('owner 修改 settings → member 读取验证已更新', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `gssya${rid}.${iss}`;
      const memberAid = `gssyb${rid}.${iss}`;

      const owner = await makeAndConnect(`gs-sync-owner-${rid}`);
      const member = await makeAndConnect(`gs-sync-member-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);

        // 创建群
        try {
          const createResult = await owner.call('group.create', {
            name: `sync-before-${rid}`,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        // 添加 member
        try {
          await owner.call('group.add_member', {
            group_id: groupId,
            aid: memberAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
          return { skip: false, error: `add_member failed: ${e.message}` };
        }

        await sleep(500);

        // owner 修改 settings
        const updatedName = `sync-after-${rid}`;
        const updatedDesc = `SyncDesc-${rid}`;
        const updatedRules = `群规-${rid}`;
        try {
          await owner.call('group.set_settings', {
            group_id: groupId,
            settings: {
              name: updatedName,
              description: updatedDesc,
              'rules.content': updatedRules,
            },
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.set_settings 未实现' };
          }
          return { skip: false, error: `set_settings failed: ${e.message}` };
        }

        await sleep(500);

        // member 读取 settings 验证
        let memberGetResult: any;
        try {
          memberGetResult = await member.call('group.get_settings', {
            group_id: groupId,
            keys: ['name', 'description', 'rules.content'],
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.get_settings 未实现' };
          }
          return { skip: false, error: `get_settings by member failed: ${e.message}` };
        }

        const settingsList: Array<{ key: string; value: any }> = memberGetResult?.settings ?? [];
        const settingsMap: Record<string, any> = {};
        for (const s of settingsList) {
          settingsMap[s.key] = s.value;
        }

        return {
          skip: false,
          memberName: settingsMap['name'],
          memberDesc: settingsMap['description'],
          memberRules: settingsMap['rules.content'],
          expectedName: updatedName,
          expectedDesc: updatedDesc,
          expectedRules: updatedRules,
          groupId,
        };
      } finally {
        if (groupId) {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
        await owner.close();
        await member.close();
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

    expect(r.memberName).toBe(r.expectedName);
    expect(r.memberDesc).toBe(r.expectedDesc);
    expect(r.memberRules).toBe(r.expectedRules);
  });
});
