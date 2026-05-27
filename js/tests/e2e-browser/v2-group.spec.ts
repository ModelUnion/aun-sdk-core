// ── Playwright E2E 浏览器测试：V2 Group E2EE ──────────────
//
// 覆盖（对齐 Python e2e_test_v2_group_e2ee.py）：
//   1. Alice sendGroupV2 → Bob pullGroupV2 解密
//   2. ack 后 pull 为空
//   3. 双向通信
//
// 运行方法：
//   npm run build && npx playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/v2-group.spec.ts --reporter=line
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

// ── 本地 HTTP 服务器 ──────────────────────────────────────────

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

// ── 辅助：注入浏览器上下文工具函数 ──────────────────────────────

async function installV2GroupHelpers(page: any): Promise<void> {
  await page.evaluate((issuer: string) => {
    const w = window as any;
    if (w.__v2grp) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
    const waitFor = async (predicate: () => boolean | Promise<boolean>, timeoutMs = 15000, intervalMs = 300): Promise<boolean> => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (await predicate()) return true;
        await sleep(intervalMs);
      }
      return await predicate();
    };

    const collectGroupMessages = (client: any): any[] => {
      const messages: any[] = [];
      client.on('group.message_created', (data: any) => {
        if (data && typeof data === 'object') messages.push(data);
      });
      return messages;
    };

    const findText = (messages: any[], text: string): any => {
      return messages.find((m: any) => m?.payload?.text === text);
    };

    const waitForGroupText = async (
      client: any,
      groupId: string,
      pushed: any[],
      text: string,
      timeoutMs = 6000,
    ): Promise<{ found: any; pulled: any[]; all: any[] }> => {
      await waitFor(() => !!findText(pushed, text), timeoutMs, 300);
      const pulled = await client.pullGroupV2(groupId);
      const all = pushed.concat(pulled as any[]);
      return { found: findText(all, text), pulled: pulled as any[], all };
    };

    /** 创建 AUNClient 并连接到 gateway */
    const makeAndConnect = async (aid: string, deviceId?: string): Promise<any> => {
      const AUN = w.AUN;
      const client = new AUN.AUNClient({ issuer }, true);
      if (deviceId) client._deviceId = deviceId;
      try { await client.auth.registerAid({ aid }); } catch {}
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);
      return client;
    };

    /** 创建群并添加成员 */
    const createGroupWithMembers = async (
      owner: any,
      memberClients: any[],
      memberAids: string[],
      groupName: string,
    ): Promise<string> => {
      const result = await owner.call('group.create', {
        name: groupName,
        visibility: 'private',
      });
      const groupId = result?.group?.group_id ?? result?.group_id;
      if (!groupId) throw new Error('group.create 未返回 group_id');

      for (const aid of memberAids) {
        await owner.call('group.add_member', { group_id: groupId, aid });
      }
      // 等待 owner auto-propose + confirm 完成；private 群成员进入 committed 后才能稳定收发 V2。
      const committed = await waitFor(async () => {
        const bs = await owner.call('group.v2.bootstrap', { group_id: groupId });
        const aids = Array.isArray(bs?.committed_member_aids) ? bs.committed_member_aids : [];
        return memberAids.every((aid) => aids.includes(aid));
      }, 15000, 500);
      if (!committed) throw new Error('group member V2 state not committed before timeout');
      return groupId;
    };

    w.__v2grp = {
      sleep,
      makeAndConnect,
      createGroupWithMembers,
      collectGroupMessages,
      waitForGroupText,
      ISSUER: issuer,
    };
  }, ISSUER);
}

// ── V2 Group E2EE 测试 ────────────────────────────────────────────

test.describe('V2 Group E2EE 端到端测试', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installV2GroupHelpers(page);
  });

  // ── 1. Alice sendGroupV2 → Bob pullGroupV2 解密 ──

  test('Alice sendGroupV2 → Bob pullGroupV2 解密', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, createGroupWithMembers, collectGroupMessages, waitForGroupText, ISSUER } = (window as any).__v2grp;
      const aliceAid = `v2g-sa-${rid}.${ISSUER}`;
      const bobAid = `v2g-sb-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);
      const bobPush = collectGroupMessages(bob);

      // 创建群并添加 Bob
      const groupId = await createGroupWithMembers(
        alice, [bob], [bobAid], `v2g-test-${rid}`,
      );

      // Alice 发送 V2 群消息
      const testText = `v2-group-test-${Date.now()}`;
      const sendResult = await alice.sendGroupV2(groupId, { text: testText });

      // Bob 可能已经通过 push 自动 pull 并 ack，手动 pull 只作兜底。
      const { found, all } = await waitForGroupText(bob, groupId, bobPush, testText);

      await alice.close();
      await bob.close();

      return {
        sent: !!(sendResult as any)?.status || !!(sendResult as any)?.message_id,
        messagesCount: (all as any[]).length,
        found: !!found,
        text: found?.payload?.text ?? null,
        from: found?.from ?? found?.from_aid ?? null,
        groupId: found?.group_id ?? null,
      };
    }, rid);

    expect(result.sent).toBe(true);
    expect(result.found).toBe(true);
    expect(result.text).toContain('v2-group-test-');
  });

  // ── 2. ack 后 pull 为空 ──

  test('ackGroupV2 后 pullGroupV2 为空', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, createGroupWithMembers, collectGroupMessages, waitForGroupText, ISSUER } = (window as any).__v2grp;
      const aliceAid = `v2g-aa-${rid}.${ISSUER}`;
      const bobAid = `v2g-ab-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);
      const bobPush = collectGroupMessages(bob);

      const groupId = await createGroupWithMembers(
        alice, [bob], [bobAid], `v2g-ack-${rid}`,
      );

      // Alice 发送
      const testText = `v2-group-ack-${Date.now()}`;
      await alice.sendGroupV2(groupId, { text: testText });

      // Bob 可能已经通过 push 自动 pull 并 ack，手动 pull 只作兜底。
      const { found } = await waitForGroupText(bob, groupId, bobPush, testText);
      const hasMsg = !!found;

      // Bob ack
      const ackResult = await bob.ackGroupV2(groupId);

      // ack 后再 pull 应为空
      const afterAck = await bob.pullGroupV2(groupId);

      await alice.close();
      await bob.close();

      return {
        hasMsg,
        acked: !!(ackResult as any)?.acked || (ackResult as any)?.status === 'ok',
        afterAckCount: (afterAck as any[]).length,
      };
    }, rid);

    expect(result.hasMsg).toBe(true);
    expect(result.afterAckCount).toBe(0);
  });

  // ── 3. 双向通信 ──

  test('双向通信 — Alice 和 Bob 互发 V2 群消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const { makeAndConnect, createGroupWithMembers, collectGroupMessages, waitForGroupText, ISSUER } = (window as any).__v2grp;
      const aliceAid = `v2g-ba-${rid}.${ISSUER}`;
      const bobAid = `v2g-bb-${rid}.${ISSUER}`;

      const alice = await makeAndConnect(aliceAid);
      const bob = await makeAndConnect(bobAid);
      const alicePush = collectGroupMessages(alice);
      const bobPush = collectGroupMessages(bob);

      const groupId = await createGroupWithMembers(
        alice, [bob], [bobAid], `v2g-bidir-${rid}`,
      );

      // Alice → 群
      const textAlice = `alice-group-${Date.now()}`;
      await alice.sendGroupV2(groupId, { text: textAlice });

      // Bob 可能已经通过 push 自动 pull 并 ack，手动 pull 只作兜底。
      const { found: aliceMsg } = await waitForGroupText(bob, groupId, bobPush, textAlice);

      // Bob ack 后回复
      await bob.ackGroupV2(groupId);

      const textBob = `bob-group-${Date.now()}`;
      await bob.sendGroupV2(groupId, { text: textBob });

      // Alice 可能已经通过 push 自动 pull 并 ack，手动 pull 只作兜底。
      const { found: bobMsg } = await waitForGroupText(alice, groupId, alicePush, textBob);

      await alice.close();
      await bob.close();

      return {
        aliceMsgReceived: !!aliceMsg,
        aliceMsgText: aliceMsg?.payload?.text ?? null,
        bobMsgReceived: !!bobMsg,
        bobMsgText: bobMsg?.payload?.text ?? null,
      };
    }, rid);

    expect(result.aliceMsgReceived).toBe(true);
    expect(result.aliceMsgText).toContain('alice-group-');
    expect(result.bobMsgReceived).toBe(true);
    expect(result.bobMsgText).toContain('bob-group-');
  });

});
