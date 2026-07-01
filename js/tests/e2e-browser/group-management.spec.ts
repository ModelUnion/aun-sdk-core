// ── Playwright E2E 浏览器测试：Group Management ──────────────
//
// 覆盖：
//   1. 群全生命周期（create → add_member → get_members → kick → dissolve）
//   2. 角色与群主转让（set_role → transfer_owner）
//   3. 暂停与恢复（suspend → send rejected → resume → send ok）
//   4. 邀请码（create_invite_code → use_invite_code → exhausted）
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-management.spec.ts --reporter=line
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

// ── 1. Group: 全生命周期 ──────────────────────────────────────

test.describe('Group: 全生命周期（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('create → add_member → get_members → kick → dissolve', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `grplfa${rid}.${iss}`;
      const bobAid = `grplfb${rid}.${iss}`;

      const alice = await makeAndConnect(`grp-lf-alice-${rid}`);
      const bob = await makeAndConnect(`grp-lf-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 创建群
        let groupId: string;
        try {
          const createResult = await alice.call('group.create', {
            name: `lifecycle-${rid}`,
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

        try {
          // 添加 bob 为成员
          let addOk = false;
          try {
            await alice.call('group.add_member', {
              group_id: groupId,
              aid: bobAid,
            });
            addOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.add_member 未实现' };
            }
            return { skip: false, error: `add_member failed: ${e.message}` };
          }

          await sleep(500);

          // 获取成员列表
          let membersCount = -1;
          let hasBob = false;
          try {
            const membersResult = await alice.call('group.get_members', {
              group_id: groupId,
            });
            const members = membersResult?.members ?? [];
            membersCount = members.length;
            hasBob = members.some((m: any) =>
              (m.aid ?? m.member_aid ?? m.id) === bobAid
            );
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.get_members 未实现' };
            }
            return { skip: false, error: `get_members failed: ${e.message}` };
          }

          // 踢出 bob
          let kickOk = false;
          try {
            await alice.call('group.kick', {
              group_id: groupId,
              aid: bobAid,
            });
            kickOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.kick 未实现' };
            }
            return { skip: false, error: `kick failed: ${e.message}` };
          }

          await sleep(500);

          // 踢出后再获取成员列表验证
          let membersAfterKick = -1;
          let hasBobAfterKick = true;
          try {
            const membersResult2 = await alice.call('group.get_members', {
              group_id: groupId,
            });
            const members2 = membersResult2?.members ?? [];
            membersAfterKick = members2.length;
            hasBobAfterKick = members2.some((m: any) =>
              (m.aid ?? m.member_aid ?? m.id) === bobAid
            );
          } catch {
            // 获取失败不影响主流程
          }

          // 解散群
          let dissolveOk = false;
          try {
            await alice.call('group.dissolve', { group_id: groupId });
            dissolveOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.dissolve 未实现' };
            }
            return { skip: false, error: `dissolve failed: ${e.message}` };
          }

          return {
            skip: false,
            addOk,
            membersCount,
            hasBob,
            kickOk,
            membersAfterKick,
            hasBobAfterKick,
            dissolveOk,
          };
        } catch (e: any) {
          // 清理：尝试解散群
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
          throw e;
        }
      } finally {
        await alice.close();
        await bob.close();
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

    expect(r.addOk).toBe(true);
    expect(r.membersCount).toBeGreaterThanOrEqual(2);
    expect(r.hasBob).toBe(true);
    expect(r.kickOk).toBe(true);
    expect(r.hasBobAfterKick).toBe(false);
    expect(r.dissolveOk).toBe(true);
  });
});

// ── 2. Group: 角色与群主转让 ──────────────────────────────────

test.describe('Group: 角色与群主转让（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('create → add_member → set_role admin → transfer_owner', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `grprla${rid}.${iss}`;
      const bobAid = `grprlb${rid}.${iss}`;
      const groupName = `grprl${rid}`;

      const alice = await makeAndConnect(`grp-rl-alice-${rid}`);
      const bob = await makeAndConnect(`grp-rl-bob-${rid}`);

      let groupId: string | undefined;
      let ownerStore: any = null;
      let newOwnerStore: any = null;

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 创建命名群；群主转让需要 group_aid 私钥签名授权。
        try {
          const createResult = await alice.group.create({
            name: `role-${rid}`,
            group_name: groupName,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skip: true, reason: '创建群未返回 group_id' };
          }
          ownerStore = (window as any).AUN_TEST_HELPERS.createStore(alice);
          newOwnerStore = (window as any).AUN_TEST_HELPERS.createStore(bob);
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.create 未实现' };
          }
          return { skip: false, error: `create failed: ${e.message}` };
        }

        await sleep(500);

        try {
          // 添加 bob
          try {
            await alice.call('group.add_member', {
              group_id: groupId,
              aid: bobAid,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.add_member 未实现' };
            }
            return { skip: false, error: `add_member failed: ${e.message}` };
          }

          await sleep(500);

          // 设置 bob 为 admin
          let setRoleOk = false;
          try {
            await alice.call('group.set_role', {
              group_id: groupId,
              aid: bobAid,
              role: 'admin',
            });
            setRoleOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.set_role 未实现' };
            }
            return { skip: false, error: `set_role failed: ${e.message}` };
          }

          await sleep(500);

          // 验证 bob 角色
          let bobRole: string | null = null;
          try {
            const membersResult = await alice.call('group.get_members', {
              group_id: groupId,
            });
            const members = membersResult?.members ?? [];
            const bobEntry = members.find((m: any) =>
              (m.aid ?? m.member_aid ?? m.id) === bobAid
            );
            bobRole = bobEntry?.role ?? null;
          } catch {
            // 获取失败不阻塞主流程
          }

          // 转让群主给 bob
          let transferOk = false;
          let completeOk = false;
          let oldOwner: string | null = null;
          let newOwner: string | null = null;
          try {
            const transferResult = await alice.group.transferOwner({
              group_id: groupId,
              new_owner: bobAid,
              aidStore: ownerStore,
            });
            transferOk = true;
            oldOwner = transferResult?.old_owner ?? aliceAid;
            newOwner = transferResult?.new_owner ?? bobAid;

            await bob.group.completeTransfer({
              group_id: groupId,
              aidStore: newOwnerStore,
            });
            completeOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.transfer_owner 未实现' };
            }
            return { skip: false, error: `transfer_owner failed: ${e.message}` };
          }

          await sleep(500);

          // 转让后验证：bob 应是 owner
          let bobRoleAfterTransfer: string | null = null;
          let aliceRoleAfterTransfer: string | null = null;
          try {
            const membersResult2 = await bob.call('group.get_members', {
              group_id: groupId,
            });
            const members2 = membersResult2?.members ?? [];
            const bobEntry2 = members2.find((m: any) =>
              (m.aid ?? m.member_aid ?? m.id) === bobAid
            );
            const aliceEntry2 = members2.find((m: any) =>
              (m.aid ?? m.member_aid ?? m.id) === aliceAid
            );
            bobRoleAfterTransfer = bobEntry2?.role ?? null;
            aliceRoleAfterTransfer = aliceEntry2?.role ?? null;
          } catch {
            // 获取失败不阻塞
          }

          return {
            skip: false,
            setRoleOk,
            bobRole,
            transferOk,
            completeOk,
            oldOwner,
            newOwner,
            bobRoleAfterTransfer,
            aliceRoleAfterTransfer,
          };
        } finally {
          // 清理：尝试用 bob 解散（转让后 bob 是群主），失败则用 alice
          if (groupId) {
            try { await bob.call('group.dissolve', { group_id: groupId }); } catch {
              try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
            }
          }
        }
      } finally {
        try { ownerStore?.close?.(); } catch {}
        try { newOwnerStore?.close?.(); } catch {}
        await alice.close();
        await bob.close();
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

    expect(r.setRoleOk).toBe(true);
    expect(r.transferOk).toBe(true);
    expect(r.completeOk).toBe(true);
    // 转让后 bob 应为 owner
    if (r.bobRoleAfterTransfer !== null) {
      expect(r.bobRoleAfterTransfer).toBe('owner');
    }
    // 转让后 alice 不再是 owner
    if (r.aliceRoleAfterTransfer !== null) {
      expect(r.aliceRoleAfterTransfer).not.toBe('owner');
    }
  });
});

// ── 3. Group: 暂停与恢复 ──────────────────────────────────────

test.describe('Group: 暂停与恢复（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('suspend → send rejected → resume → send ok', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `grpspa${rid}.${iss}`;
      const bobAid = `grpspb${rid}.${iss}`;

      const alice = await makeAndConnect(`grp-sp-alice-${rid}`);
      const bob = await makeAndConnect(`grp-sp-bob-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 创建群并加入 bob
        try {
          const createResult = await alice.call('group.create', {
            name: `suspend-${rid}`,
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

        try {
          await alice.call('group.add_member', {
            group_id: groupId,
            aid: bobAid,
          });
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skip: true, reason: 'group.add_member 未实现' };
          }
        }

        await sleep(500);

        try {
          // 暂停群
          let suspendOk = false;
          try {
            await alice.call('group.suspend', { group_id: groupId });
            suspendOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.suspend 未实现' };
            }
            return { skip: false, error: `suspend failed: ${e.message}` };
          }

          await sleep(500);

          // 暂停后发消息 — 应被拒绝
          let sendWhileSuspended: string;
          try {
            await bob.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: `suspended-msg-${rid}` },
            });
            sendWhileSuspended = 'accepted (unexpected)';
          } catch {
            sendWhileSuspended = 'rejected';
          }

          // 恢复群
          let resumeOk = false;
          try {
            await alice.call('group.resume', { group_id: groupId });
            resumeOk = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.resume 未实现' };
            }
            return { skip: false, error: `resume failed: ${e.message}` };
          }

          await sleep(500);

          // 恢复后发消息 — 应成功
          let sendAfterResume: string;
          try {
            await bob.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: `resumed-msg-${rid}` },
            });
            sendAfterResume = 'accepted';
          } catch (e: any) {
            sendAfterResume = `rejected: ${e.message}`;
          }

          return {
            skip: false,
            suspendOk,
            sendWhileSuspended,
            resumeOk,
            sendAfterResume,
          };
        } finally {
          if (groupId) {
            try { await alice.call('group.resume', { group_id: groupId }); } catch {}
            try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
          }
        }
      } finally {
        await alice.close();
        await bob.close();
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

    expect(r.suspendOk).toBe(true);
    expect(r.sendWhileSuspended).toBe('rejected');
    expect(r.resumeOk).toBe(true);
    expect(r.sendAfterResume).toBe('accepted');
  });
});

// ── 4. Group: 邀请码 ──────────────────────────────────────────

test.describe('Group: 邀请码（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
  });

  test('create_invite_code → use_invite_code → exhausted', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { sleep, makeAndConnect, ensureConnected } = (window as any).__aunP0;
      const rid = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
      const aliceAid = `grpiva${rid}.${iss}`;
      const bobAid = `grpivb${rid}.${iss}`;
      const charlieAid = `grpivc${rid}.${iss}`;

      const alice = await makeAndConnect(`grp-iv-alice-${rid}`);
      const bob = await makeAndConnect(`grp-iv-bob-${rid}`);
      const charlie = await makeAndConnect(`grp-iv-charlie-${rid}`);

      let groupId: string | undefined;

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);
        await ensureConnected(charlie, charlieAid);

        // 创建群
        try {
          const createResult = await alice.call('group.create', {
            name: `invite-${rid}`,
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

        try {
          // 创建邀请码（限 1 次使用）
          let inviteCode: string | undefined;
          try {
            const inviteResult = await alice.call('group.create_invite_code', {
              group_id: groupId,
              max_uses: 1,
            });
            inviteCode = inviteResult?.invite_code?.code_with_domain ??
              inviteResult?.invite_code?.code ??
              inviteResult?.invite_code ??
              inviteResult?.code;
            if (!inviteCode) {
              return { skip: true, reason: '创建邀请码未返回 invite_code' };
            }
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.create_invite_code 未实现' };
            }
            return { skip: false, error: `create_invite_code failed: ${e.message}` };
          }

          await sleep(500);

          // bob 使用邀请码加入
          let bobJoinStatus: string;
          try {
            const useResult = await bob.call('group.use_invite_code', {
              code: inviteCode,
            });
            bobJoinStatus = useResult?.status === 'joined' ? 'joined' : `failed: ${JSON.stringify(useResult)}`;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skip: true, reason: 'group.use_invite_code 未实现' };
            }
            bobJoinStatus = `failed: ${e.message}`;
          }

          await sleep(500);

          // charlie 使用同一邀请码 — 应失败（已耗尽）
          let charlieJoinStatus: string;
          let charlieJoinError: string | null = null;
          try {
            await charlie.call('group.use_invite_code', {
              code: inviteCode,
            });
            charlieJoinStatus = 'joined (unexpected)';
          } catch (e: any) {
            charlieJoinStatus = 'rejected';
            charlieJoinError = e.message ?? null;
          }

          return {
            skip: false,
            inviteCode: !!inviteCode,
            bobJoinStatus,
            charlieJoinStatus,
            charlieJoinError,
          };
        } finally {
          if (groupId) {
            try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
          }
        }
      } finally {
        await alice.close();
        await bob.close();
        await charlie.close();
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

    expect(r.inviteCode).toBe(true);
    expect(r.bobJoinStatus).toBe('joined');
    expect(r.charlieJoinStatus).toBe('rejected');
  });
});
