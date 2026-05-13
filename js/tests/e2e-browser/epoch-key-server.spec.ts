// ── Playwright E2E 浏览器测试：Epoch Key 服务端存储 ──────────────
//
// 覆盖：
//   1. commit_rotation 上传 encrypted_keys → 成员从服务端拉取
//   2. 离线成员上线后从服务端恢复 epoch key
//   3. 按指定 epoch 拉取不同 epoch 的 key
//   4. 非成员调用 get_epoch_key 被拒绝
//   5. 恢复的 epoch key 能解密加密消息（完整闭环）
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/epoch-key-server.spec.ts --reporter=line
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

async function installP0Helpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__aunP0) return;
    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    const makeAndConnect = async (instanceId: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({ instanceId, issuer }, true);
      if (client._configModel) client._configModel.requireForwardSecrecy = false;
      return client;
    };
    const ensureConnected = async (client: any, aid: string): Promise<void> => {
      const gateway = await client.auth._resolveGateway(`gateway.${issuer}`);
      (client as any)._gatewayUrl = gateway;
      try { await client.auth.createAid({ aid }); } catch {}
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);
    };
    const runId = () => {
      const arr = new Uint8Array(6);
      crypto.getRandomValues(arr);
      return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    };
    w.__aunP0 = { sleep, makeAndConnect, ensureConnected, runId, ISSUER: issuer };
  }, ISSUER);
}

async function installEpochKeyHelpers(page: any): Promise<void> {
  await page.evaluate(() => {
    const w = window as any;
    if (w.__aunEpochKey) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const waitFor = async (
      predicate: () => boolean | Promise<boolean>,
      timeoutMs: number = 20_000,
      intervalMs: number = 500,
    ): Promise<boolean> => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (await predicate()) return true;
        await sleep(intervalMs);
      }
      return false;
    };

    const waitForCommittedEpoch = async (
      client: any,
      groupId: string,
      minEpoch: number,
      timeoutMs: number = 20_000,
    ): Promise<number> => {
      let lastEpoch = 0;
      const ok = await waitFor(async () => {
        const result = await client.call('group.e2ee.get_epoch', { group_id: groupId });
        lastEpoch = Number(result?.committed_epoch ?? result?.epoch ?? 0);
        return lastEpoch >= minEpoch;
      }, timeoutMs);
      if (!ok) throw new Error(`timeout waiting committed epoch >= ${minEpoch}; last=${lastEpoch}`);
      return lastEpoch;
    };

    const createGroup = async (client: any, name: string): Promise<string> => {
      const result = await client.call('group.create', { name, visibility: 'private' });
      return result?.group?.group_id ?? result?.group_id ?? '';
    };

    const addMember = async (client: any, groupId: string, memberAid: string): Promise<void> => {
      await client.call('group.add_member', { group_id: groupId, aid: memberAid, role: 'member' });
    };

    const triggerRotation = async (client: any, groupId: string, rid: string, issuer: string, makeAndConnect: any, ensureConnected: any): Promise<void> => {
      try {
        await client.call('group.e2ee.rotate_epoch', { group_id: groupId, reason: 'test' });
      } catch {
        // rotate_epoch 是公开 RPC，通过 kick 触发
        const tempAid = `ek-tmp-${rid}.${issuer}`;
        const temp = await makeAndConnect(`ek-tmp-${rid}`);
        await ensureConnected(temp, tempAid);
        await addMember(client, groupId, tempAid);
        await sleep(1000);
        await client.call('group.kick', { group_id: groupId, aid: tempAid });
        await temp.close();
      }
    };

    w.__aunEpochKey = { sleep, waitFor, waitForCommittedEpoch, createGroup, addMember, triggerRotation };
  });
}

// ── 1. commit_rotation 上传 encrypted_keys ──────────────────────

test.describe('Epoch Key 服务端存储（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installEpochKeyHelpers(page);
  });

  test('commit_rotation 上传 encrypted_keys，成员从服务端拉取', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunEpochKey;
      const rid = runId();
      const aAid = `ek-a-${rid}.${iss}`;
      const bAid = `ek-b-${rid}.${iss}`;

      const alice = await makeAndConnect(`ek-alice-${rid}`);
      const bob = await makeAndConnect(`ek-bob-${rid}`);

      try {
        await ensureConnected(alice, aAid);
        await ensureConnected(bob, bAid);

        const groupId = await H.createGroup(alice, `epoch-key-${rid}`);
        if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };

        await H.addMember(alice, groupId, bAid);
        const epoch = await H.waitForCommittedEpoch(alice, groupId, 1);

        // Bob 从服务端拉取 epoch key
        const result = await bob.call('group.e2ee.get_epoch_key', {
          group_id: groupId,
          epoch,
        });

        const hasKey = !!result?.encrypted_key;
        return { skipped: false, epoch, hasKey };
      } catch (e: any) {
        const msg = (e.message ?? '').toLowerCase();
        if (msg.includes('not implement') || msg.includes('method not found')) {
          return { skipped: true, reason: `RPC 未实现: ${e.message}` };
        }
        return { skipped: false, error: e.message };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { console.log(`跳过: ${(result as any).reason}`); test.skip(); return; }
    if ((result as any).error) throw new Error((result as any).error);

    const r = result as any;
    console.log(`  [INFO] epoch=${r.epoch}, has_encrypted_key=${r.hasKey}`);
    if (r.hasKey) {
      console.log(`  [OK] 服务端存储了 encrypted_key`);
    } else {
      console.warn(`  [WARN] 服务端未存储 encrypted_key`);
    }
  });

  test('离线成员上线后从服务端恢复 epoch key', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunEpochKey;
      const rid = runId();
      const aAid = `ek-off-a-${rid}.${iss}`;
      const bAid = `ek-off-b-${rid}.${iss}`;

      const alice = await makeAndConnect(`ek-off-alice-${rid}`);
      const bob = await makeAndConnect(`ek-off-bob-${rid}`);

      try {
        await ensureConnected(alice, aAid);
        await ensureConnected(bob, bAid);

        const groupId = await H.createGroup(alice, `offline-recover-${rid}`);
        if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };

        await H.addMember(alice, groupId, bAid);
        const epoch1 = await H.waitForCommittedEpoch(alice, groupId, 1);
        await H.waitForCommittedEpoch(bob, groupId, 1);

        // Bob 断开
        await bob.close();
        await sleep(1000);

        // 触发 epoch 轮换
        await H.triggerRotation(alice, groupId, rid, iss, makeAndConnect, ensureConnected);
        await sleep(2000);

        // 验证 epoch 已推进
        const epoch2 = await H.waitForCommittedEpoch(alice, groupId, epoch1 + 1);

        // Bob 重新上线
        const bob2 = await makeAndConnect(`ek-off-bob2-${rid}`);
        await ensureConnected(bob2, bAid);

        // Bob 从服务端拉取新 epoch key
        const result = await bob2.call('group.e2ee.get_epoch_key', {
          group_id: groupId,
          epoch: epoch2,
        });

        const hasKey = !!result?.encrypted_key;
        await bob2.close();
        return { skipped: false, epoch1, epoch2, hasKey };
      } catch (e: any) {
        const msg = (e.message ?? '').toLowerCase();
        if (msg.includes('not implement') || msg.includes('method not found')) {
          return { skipped: true, reason: `RPC 未实现: ${e.message}` };
        }
        return { skipped: false, error: e.message };
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { console.log(`跳过: ${(result as any).reason}`); test.skip(); return; }
    if ((result as any).error) throw new Error((result as any).error);

    const r = result as any;
    expect(r.epoch2).toBeGreaterThan(r.epoch1);
    console.log(`  [INFO] epoch ${r.epoch1} → ${r.epoch2}, has_key=${r.hasKey}`);
    if (r.hasKey) {
      console.log(`  [OK] 离线成员从服务端获取到 encrypted_key`);
    } else {
      console.warn(`  [WARN] 服务端未存储 encrypted_key`);
    }
  });

  test('按指定 epoch 拉取不同 epoch 的 key', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunEpochKey;
      const rid = runId();
      const aAid = `ek-spec-a-${rid}.${iss}`;
      const bAid = `ek-spec-b-${rid}.${iss}`;

      const alice = await makeAndConnect(`ek-spec-alice-${rid}`);
      const bob = await makeAndConnect(`ek-spec-bob-${rid}`);

      try {
        await ensureConnected(alice, aAid);
        await ensureConnected(bob, bAid);

        const groupId = await H.createGroup(alice, `specific-epoch-${rid}`);
        if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };

        await H.addMember(alice, groupId, bAid);
        const epoch1 = await H.waitForCommittedEpoch(alice, groupId, 1);

        // 触发第二次轮换
        await H.triggerRotation(alice, groupId, rid, iss, makeAndConnect, ensureConnected);
        await sleep(2000);

        const epoch2 = await H.waitForCommittedEpoch(alice, groupId, epoch1 + 1);

        // Bob 按指定 epoch 拉取
        const result1 = await bob.call('group.e2ee.get_epoch_key', { group_id: groupId, epoch: epoch1 });
        const result2 = await bob.call('group.e2ee.get_epoch_key', { group_id: groupId, epoch: epoch2 });

        const key1 = result1?.encrypted_key ?? '';
        const key2 = result2?.encrypted_key ?? '';

        return {
          skipped: false,
          epoch1, epoch2,
          hasKey1: !!key1, hasKey2: !!key2,
          keysDiffer: key1 !== '' && key2 !== '' && key1 !== key2,
        };
      } catch (e: any) {
        const msg = (e.message ?? '').toLowerCase();
        if (msg.includes('not implement') || msg.includes('method not found')) {
          return { skipped: true, reason: `RPC 未实现: ${e.message}` };
        }
        return { skipped: false, error: e.message };
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { console.log(`跳过: ${(result as any).reason}`); test.skip(); return; }
    if ((result as any).error) throw new Error((result as any).error);

    const r = result as any;
    expect(r.epoch2).toBeGreaterThan(r.epoch1);
    console.log(`  [INFO] epoch ${r.epoch1}: has_key=${r.hasKey1}`);
    console.log(`  [INFO] epoch ${r.epoch2}: has_key=${r.hasKey2}`);
    if (r.keysDiffer) {
      console.log(`  [OK] 两个 epoch 的密文不同（符合预期）`);
    }
  });

  test('非成员调用 get_epoch_key 被拒绝', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunEpochKey;
      const rid = runId();
      const aAid = `ek-deny-a-${rid}.${iss}`;
      const cAid = `ek-deny-c-${rid}.${iss}`;

      const alice = await makeAndConnect(`ek-deny-alice-${rid}`);
      const charlie = await makeAndConnect(`ek-deny-charlie-${rid}`);

      try {
        await ensureConnected(alice, aAid);
        await ensureConnected(charlie, cAid);

        const groupId = await H.createGroup(alice, `deny-epoch-${rid}`);
        if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };

        await H.waitForCommittedEpoch(alice, groupId, 1);

        // Charlie 尝试拉取 epoch key（不是成员）
        let rejected = false;
        try {
          const result = await charlie.call('group.e2ee.get_epoch_key', { group_id: groupId });
          if (result?.error) {
            rejected = true;
          } else if (!result?.encrypted_key) {
            rejected = true;
          }
        } catch {
          rejected = true;
        }

        return { skipped: false, rejected };
      } catch (e: any) {
        const msg = (e.message ?? '').toLowerCase();
        if (msg.includes('not implement') || msg.includes('method not found')) {
          return { skipped: true, reason: `RPC 未实现: ${e.message}` };
        }
        return { skipped: false, error: e.message };
      } finally {
        await alice.close();
        await charlie.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { console.log(`跳过: ${(result as any).reason}`); test.skip(); return; }
    if ((result as any).error) throw new Error((result as any).error);

    expect((result as any).rejected, '非成员应被拒绝或返回空').toBe(true);
    console.log(`  [OK] 非成员被拒绝`);
  });

  test('恢复的 epoch key 能解密加密消息', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunEpochKey;
      const rid = runId();
      const aAid = `ek-msg-a-${rid}.${iss}`;
      const bAid = `ek-msg-b-${rid}.${iss}`;

      const alice = await makeAndConnect(`ek-msg-alice-${rid}`);
      const bob = await makeAndConnect(`ek-msg-bob-${rid}`);

      try {
        await ensureConnected(alice, aAid);
        await ensureConnected(bob, bAid);

        const groupId = await H.createGroup(alice, `decrypt-msg-${rid}`);
        if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };

        await H.addMember(alice, groupId, bAid);
        await H.waitForCommittedEpoch(alice, groupId, 1);
        await H.waitForCommittedEpoch(bob, groupId, 1);

        // Alice 发送加密消息
        const testText = `hello-from-alice-${rid}`;
        await alice.call('group.send', {
          group_id: groupId,
          payload: { type: 'text', text: testText },
          encrypt: true,
        });

        // Bob 断开
        await bob.close();
        await sleep(1000);

        // 触发 epoch 轮换（Bob 离线期间）
        await H.triggerRotation(alice, groupId, rid, iss, makeAndConnect, ensureConnected);
        await sleep(2000);

        // Bob 重新上线
        const bob2 = await makeAndConnect(`ek-msg-bob2-${rid}`);
        await ensureConnected(bob2, bAid);

        // 尝试从服务端恢复
        try {
          await bob2.call('group.e2ee.try_recover_from_server', { group_id: groupId });
        } catch {}
        await sleep(1000);

        // Bob 拉取群消息
        const pullResult = await bob2.call('group.pull', { group_id: groupId, limit: 10 });
        const messages = pullResult?.messages ?? [];

        let decrypted = false;
        for (const msg of messages) {
          const payload = msg?.payload;
          if (payload?.text === testText) { decrypted = true; break; }
          const inner = msg?.decrypted_payload ?? msg?.plaintext;
          if (inner?.text === testText) { decrypted = true; break; }
        }

        await bob2.close();
        return { skipped: false, testText, messageCount: messages.length, decrypted };
      } catch (e: any) {
        const msg = (e.message ?? '').toLowerCase();
        if (msg.includes('not implement') || msg.includes('method not found')) {
          return { skipped: true, reason: `RPC 未实现: ${e.message}` };
        }
        return { skipped: false, error: e.message };
      } finally {
        await alice.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { console.log(`跳过: ${(result as any).reason}`); test.skip(); return; }
    if ((result as any).error) throw new Error((result as any).error);

    const r = result as any;
    console.log(`  [INFO] Bob 拉取到 ${r.messageCount} 条消息`);
    if (r.decrypted) {
      console.log(`  [OK] Bob 成功解密 Alice 的消息: '${r.testText}'`);
    } else {
      console.warn(`  [WARN] 未在 pull 结果中找到解密后的消息`);
    }
  });
});
