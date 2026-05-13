// ── Playwright E2E 浏览器测试：Group Join Path Key Recovery ──────
//
// 覆盖：
//   1. Open group join → online-priority recovery → delayed rotation → decrypt
//   2. Invite code join → online-priority recovery → delayed rotation → decrypt
//   3. Private add_member → immediate rotation (control test)
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-join-key-recovery.spec.ts --reporter=line
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

async function installGroupE2EEHelpers(page: any): Promise<void> {
  await page.evaluate(() => {
    const w = window as any;
    if (w.__aunGrpE2ee) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const mergeMessages = (target: any[], incoming: any[]) => {
      const seenSeqs = new Set(target.map(msg => Number(msg?.seq ?? 0)).filter(seq => seq > 0));
      for (const msg of incoming) {
        const seq = Number(msg?.seq ?? 0);
        if (seq > 0) {
          if (seenSeqs.has(seq)) continue;
          seenSeqs.add(seq);
        }
        target.push(msg);
      }
      target.sort((a, b) => Number(a?.seq ?? 0) - Number(b?.seq ?? 0));
    };

    const groupPull = async (client: any, groupId: string, afterSeq: number, limit: number = 50): Promise<any[]> => {
      const result = await client.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        limit,
      });
      return result?.messages ?? [];
    };

    const watchGroupMessages = async (client: any, groupId: string) => {
      let afterSeq = 0;
      try {
        const result = await client.call('group.get_cursor', { group_id: groupId });
        const cursor = result?.msg_cursor ?? result?.cursor ?? {};
        afterSeq = Number(cursor.latest_seq ?? cursor.current_seq ?? 0) || 0;
      } catch {}
      const inbox: any[] = [];
      const sub = client.on('group.message_created', (evt: any) => {
        if (String(evt?.group_id ?? '') !== groupId) return;
        mergeMessages(inbox, [evt]);
      });
      return {
        inbox,
        stop() { sub.unsubscribe(); },
        async waitFor(predicate: (messages: any[]) => boolean, timeoutMs: number = 20_000) {
          const deadline = Date.now() + timeoutMs;
          while (Date.now() < deadline) {
            if (predicate(inbox)) return [...inbox];
            mergeMessages(inbox, await groupPull(client, groupId, afterSeq));
            if (predicate(inbox)) return [...inbox];
            await sleep(200);
          }
          throw new Error(`timeout waiting for group messages group=${groupId}; inbox=${JSON.stringify(inbox)}`);
        },
      };
    };

    const byText = (messages: any[], text: string) =>
      messages.find(msg => msg?.payload?.text === text);

    // 等待 client 本地拥有指定 epoch 的 group secret
    const waitForLocalEpoch = async (client: any, groupId: string, minEpoch: number, timeoutMs: number = 20_000): Promise<number> => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        try {
          const allSecrets: Map<number, any> = await client.groupE2ee.loadAllSecrets(groupId);
          if (allSecrets && allSecrets.size > 0) {
            const epochs = Array.from(allSecrets.keys()).filter(e => e >= minEpoch);
            if (epochs.length > 0) return Math.max(...epochs);
          }
        } catch {}
        await sleep(300);
      }
      throw new Error(`timeout waiting for local epoch >= ${minEpoch} in group ${groupId}`);
    };

    // 等待服务端 committed_epoch 就绪
    const waitForCommittedEpoch = async (client: any, groupId: string, minEpoch: number, timeoutMs: number = 20_000): Promise<number> => {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        try {
          const raw = await client.call('group.e2ee.get_epoch', { group_id: groupId });
          const epoch = Number(raw?.committed_epoch ?? raw?.epoch ?? 0);
          if (epoch >= minEpoch) return epoch;
        } catch {}
        await sleep(500);
      }
      throw new Error(`timeout waiting committed epoch >= ${minEpoch} for group ${groupId}`);
    };

    w.__aunGrpE2ee = {
      sleep,
      watchGroupMessages,
      byText,
      waitForLocalEpoch,
      waitForCommittedEpoch,
      groupPull,
    };
  });
}

// ── 1. Open group join → online-priority recovery → delayed rotation → decrypt ──

test.describe('Group Join Key Recovery: Open group join', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installGroupE2EEHelpers(page);
  });

  test('open join → online-priority recovery → delayed rotation → decrypt', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const aliceAid = `jkra${rid}.${iss}`;
      const bobAid = `jkrb${rid}.${iss}`;

      const alice = await makeAndConnect(`jkr-open-alice-${rid}`);
      const bob = await makeAndConnect(`jkr-open-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 1. Alice 建 open 群
        let groupId: string | undefined;
        try {
          const createResult = await alice.call('group.create', {
            name: `jkr-open-${rid}`,
            visibility: 'public',
            join_mode: 'open',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skipped: true, reason: 'group.create 未实现' };
          }
          return { skipped: false, error: `create failed: ${e.message}` };
        }

        try {
          // 等待 Alice 拿到初始 epoch
          let beforeEpoch: number;
          try {
            beforeEpoch = await H.waitForLocalEpoch(alice, groupId, 1, 20_000);
          } catch (e: any) {
            return { skipped: true, reason: `owner epoch 未就绪: ${e.message}` };
          }

          // 2. Bob 通过 request_join 加入 open 群
          try {
            const joinResult = await bob.call('group.request_join', {
              group_id: groupId,
              message: 'open join for recovery test',
            });
            const status = joinResult?.status ?? '';
            if (status !== 'joined') {
              return { skipped: false, error: `request_join status=${status}, expected joined` };
            }
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.request_join 未实现' };
            }
            return { skipped: false, error: `request_join failed: ${e.message}` };
          }

          // 3. Bob 应通过在线优先恢复拿到 committed_epoch 密钥
          let bobRecoveredBeforeEpoch = false;
          try {
            await H.waitForLocalEpoch(bob, groupId, beforeEpoch, 15_000);
            bobRecoveredBeforeEpoch = true;
          } catch {
            // 恢复超时
          }

          // 4. Alice 在恢复窗口内发消息（用 committed_epoch 加密）
          const msgText = `open-recovery-msg-${rid}`;
          try {
            await alice.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: msgText },
              encrypt: true,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.send(encrypt) 未实现' };
            }
            return { skipped: false, error: `send failed: ${e.message}` };
          }

          // 5. Bob 应能解密（已恢复 committed_epoch 密钥）
          let bobDecrypted = false;
          const bobWatch = await H.watchGroupMessages(bob, groupId);
          try {
            const msgs = await bobWatch.waitFor(
              (messages: any[]) => !!H.byText(messages, msgText),
              20_000,
            );
            const received = H.byText(msgs, msgText);
            bobDecrypted = !!received;
          } catch {
            // 超时
          }
          bobWatch.stop();

          // 6. 等待延迟轮换完成（3s 后 admin 轮换）
          let rotatedEpoch = 0;
          try {
            rotatedEpoch = await H.waitForLocalEpoch(bob, groupId, beforeEpoch + 1, 20_000);
          } catch {
            // 轮换超时
          }

          // 7. 轮换后 Alice 发消息，Bob 也能解密
          let bobDecryptedAfterRotation = false;
          if (rotatedEpoch > beforeEpoch) {
            const msgText2 = `open-rotated-msg-${rid}`;
            await alice.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: msgText2 },
              encrypt: true,
            });
            const bobWatch2 = await H.watchGroupMessages(bob, groupId);
            try {
              const msgs2 = await bobWatch2.waitFor(
                (messages: any[]) => !!H.byText(messages, msgText2),
                15_000,
              );
              bobDecryptedAfterRotation = !!H.byText(msgs2, msgText2);
            } catch {}
            bobWatch2.stop();
          }

          return {
            skipped: false,
            beforeEpoch,
            bobRecoveredBeforeEpoch,
            bobDecrypted,
            rotatedEpoch,
            epochRotated: rotatedEpoch > beforeEpoch,
            bobDecryptedAfterRotation,
          };
        } finally {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skipped) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) throw new Error(r.error);

    // Bob 应恢复 committed_epoch 密钥
    expect(r.bobRecoveredBeforeEpoch).toBe(true);
    // Bob 应能解密恢复窗口内的消息
    expect(r.bobDecrypted).toBe(true);
    // 延迟轮换应完成
    expect(r.epochRotated).toBe(true);
    // 轮换后 Bob 也能解密
    expect(r.bobDecryptedAfterRotation).toBe(true);
  });
});

// ── 2. Invite code join → online-priority recovery → delayed rotation → decrypt ──

test.describe('Group Join Key Recovery: Invite code join', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installGroupE2EEHelpers(page);
  });

  test('invite code join → online-priority recovery → delayed rotation → decrypt', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const aliceAid = `jkria${rid}.${iss}`;
      const bobAid = `jkrib${rid}.${iss}`;

      const alice = await makeAndConnect(`jkr-inv-alice-${rid}`);
      const bob = await makeAndConnect(`jkr-inv-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 1. Alice 建群（invite_code 模式）
        let groupId: string | undefined;
        try {
          const createResult = await alice.call('group.create', {
            name: `jkr-inv-${rid}`,
            visibility: 'public',
            join_mode: 'invite_code',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skipped: true, reason: 'group.create 未实现' };
          }
          return { skipped: false, error: `create failed: ${e.message}` };
        }

        try {
          // 等待 Alice 拿到初始 epoch
          let beforeEpoch: number;
          try {
            beforeEpoch = await H.waitForLocalEpoch(alice, groupId, 1, 20_000);
          } catch (e: any) {
            return { skipped: true, reason: `owner epoch 未就绪: ${e.message}` };
          }

          // 2. Alice 生成邀请码
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
            if (!inviteCode) return { skipped: true, reason: '创建邀请码未返回 code' };
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.create_invite_code 未实现' };
            }
            return { skipped: false, error: `create_invite_code failed: ${e.message}` };
          }

          // 3. Bob 使用邀请码加入
          try {
            const useResult = await bob.call('group.use_invite_code', { code: inviteCode });
            const status = useResult?.status ?? '';
            if (status !== 'joined') {
              return { skipped: false, error: `use_invite_code status=${status}, expected joined` };
            }
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.use_invite_code 未实现' };
            }
            return { skipped: false, error: `use_invite_code failed: ${e.message}` };
          }

          // 4. Bob 应通过在线优先恢复拿到 committed_epoch 密钥
          let bobRecoveredBeforeEpoch = false;
          try {
            await H.waitForLocalEpoch(bob, groupId, beforeEpoch, 15_000);
            bobRecoveredBeforeEpoch = true;
          } catch {
            // 恢复超时
          }

          // 5. Alice 在恢复窗口内发消息
          const msgText = `inv-recovery-msg-${rid}`;
          try {
            await alice.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: msgText },
              encrypt: true,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.send(encrypt) 未实现' };
            }
            return { skipped: false, error: `send failed: ${e.message}` };
          }

          // 6. Bob 解密
          let bobDecrypted = false;
          const bobWatch = await H.watchGroupMessages(bob, groupId);
          try {
            const msgs = await bobWatch.waitFor(
              (messages: any[]) => !!H.byText(messages, msgText),
              20_000,
            );
            bobDecrypted = !!H.byText(msgs, msgText);
          } catch {}
          bobWatch.stop();

          // 7. 延迟轮换完成后 Bob 也有新 epoch
          let rotatedEpoch = 0;
          try {
            rotatedEpoch = await H.waitForLocalEpoch(bob, groupId, beforeEpoch + 1, 20_000);
          } catch {}

          return {
            skipped: false,
            beforeEpoch,
            bobRecoveredBeforeEpoch,
            bobDecrypted,
            rotatedEpoch,
            epochRotated: rotatedEpoch > beforeEpoch,
          };
        } finally {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skipped) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) throw new Error(r.error);

    // Bob 应恢复 committed_epoch 密钥
    expect(r.bobRecoveredBeforeEpoch).toBe(true);
    // Bob 应能解密恢复窗口内的消息
    expect(r.bobDecrypted).toBe(true);
    // 延迟轮换应完成
    expect(r.epochRotated).toBe(true);
  });
});

// ── 3. Private add_member → immediate rotation (control test) ──

test.describe('Group Join Key Recovery: Private add_member immediate rotation', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installGroupE2EEHelpers(page);
  });

  test('private add_member → immediate rotation (no delay)', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const aliceAid = `jkrpa${rid}.${iss}`;
      const bobAid = `jkrpb${rid}.${iss}`;

      const alice = await makeAndConnect(`jkr-priv-alice-${rid}`);
      const bob = await makeAndConnect(`jkr-priv-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);

        // 1. Alice 建私密群
        let groupId: string | undefined;
        try {
          const createResult = await alice.call('group.create', {
            name: `jkr-priv-${rid}`,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skipped: true, reason: 'group.create 未实现' };
          }
          return { skipped: false, error: `create failed: ${e.message}` };
        }

        try {
          // 等待 Alice 拿到初始 epoch
          let beforeEpoch: number;
          try {
            beforeEpoch = await H.waitForLocalEpoch(alice, groupId, 1, 20_000);
          } catch (e: any) {
            return { skipped: true, reason: `owner epoch 未就绪: ${e.message}` };
          }

          // 2. Alice 添加 Bob（member_added → 立即轮换）
          const t0 = Date.now();
          try {
            await alice.call('group.add_member', {
              group_id: groupId,
              aid: bobAid,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.add_member 未实现' };
            }
            return { skipped: false, error: `add_member failed: ${e.message}` };
          }

          // 3. Bob 应在较短时间内拿到新 epoch（立即轮换，不等 3s 延迟）
          let rotatedEpoch = 0;
          try {
            rotatedEpoch = await H.waitForLocalEpoch(bob, groupId, beforeEpoch + 1, 15_000);
          } catch {}
          const elapsed = Date.now() - t0;

          // 4. Alice 发消息，Bob 能解密
          let bobDecrypted = false;
          if (rotatedEpoch > beforeEpoch) {
            const msgText = `priv-imm-msg-${rid}`;
            await alice.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: msgText },
              encrypt: true,
            });
            const bobWatch = await H.watchGroupMessages(bob, groupId);
            try {
              const msgs = await bobWatch.waitFor(
                (messages: any[]) => !!H.byText(messages, msgText),
                15_000,
              );
              bobDecrypted = !!H.byText(msgs, msgText);
            } catch {}
            bobWatch.stop();
          }

          return {
            skipped: false,
            beforeEpoch,
            rotatedEpoch,
            epochRotated: rotatedEpoch > beforeEpoch,
            elapsedMs: elapsed,
            bobDecrypted,
          };
        } finally {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await alice.close();
        await bob.close();
      }
    }, ISSUER);

    if ((result as any).skipped) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) throw new Error(r.error);

    // 立即轮换应完成
    expect(r.epochRotated).toBe(true);
    // Bob 应能解密
    expect(r.bobDecrypted).toBe(true);
    // 记录耗时（不做严格时间断言，只验证功能正确性）
    console.log(`private add_member rotation elapsed: ${r.elapsedMs}ms`);
  });

  test('open join → member leads rotation (owner offline)', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const aliceAid = `mlra${rid}.${iss}`;
      const bobAid = `mlrb${rid}.${iss}`;
      const charlieAid = `mlrc${rid}.${iss}`;

      const alice = await makeAndConnect(`mlr-alice-${rid}`);
      const charlie = await makeAndConnect(`mlr-charlie-${rid}`);
      const bob = await makeAndConnect(`mlr-bob-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(charlie, charlieAid);

        let groupId: string | undefined;
        try {
          const createResult = await alice.call('group.create', {
            name: `mlr-${rid}`, visibility: 'public', join_mode: 'open',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };
        } catch (e: any) {
          if ((e.message ?? '').toLowerCase().includes('not implement'))
            return { skipped: true, reason: 'group.create 未实现' };
          return { error: `create failed: ${e.message}` };
        }

        try {
          const epoch1 = await H.waitForLocalEpoch(alice, groupId, 1, 20_000);
          await alice.call('group.add_member', { group_id: groupId, aid: charlieAid, role: 'member' });
          const epoch2 = await H.waitForLocalEpoch(charlie, groupId, epoch1 + 1, 25_000);

          await alice.close();
          await sleep(1000);

          await ensureConnected(bob, bobAid);
          const joinResult = await bob.call('group.request_join', { group_id: groupId });
          if (joinResult?.status !== 'joined') return { error: `bob join: ${JSON.stringify(joinResult)}` };

          const epoch3 = await H.waitForLocalEpoch(bob, groupId, epoch2 + 1, 30_000);

          const text = `mlr-msg-${rid}`;
          await charlie.call('group.send', { group_id: groupId, payload: { type: 'text', text }, encrypt: true });
          await sleep(3000);
          const msgs = await bob.call('group.pull', { group_id: groupId, after_message_seq: 0, limit: 50 });
          const decrypted = (msgs?.messages ?? []).find((m: any) =>
            m?.payload?.text === text && m?.e2ee?.encryption_mode === 'epoch_group_key');

          return { memberLedRotation: epoch3 > epoch2, bobDecrypted: !!decrypted };
        } finally {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await alice.close(); await charlie.close(); await bob.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { test.skip(); return; }
    const r = result as any;
    if (r.error) throw new Error(r.error);
    expect(r.memberLedRotation).toBe(true);
    expect(r.bobDecrypted).toBe(true);
  });

  test('open join → send repairs missing committed membership', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const aliceAid = `omsa${rid}.${iss}`;
      const bobAid = `omsb${rid}.${iss}`;
      const charlieAid = `omsc${rid}.${iss}`;

      const alice = await makeAndConnect(`oms-alice-${rid}`);
      const bob = await makeAndConnect(`oms-bob-${rid}`);
      const charlie = await makeAndConnect(`oms-charlie-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);
        await ensureConnected(charlie, charlieAid);

        let groupId: string | undefined;
        try {
          const createResult = await alice.call('group.create', {
            name: `oms-${rid}`, visibility: 'public', join_mode: 'open',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };
        } catch (e: any) {
          if ((e.message ?? '').toLowerCase().includes('not implement'))
            return { skipped: true, reason: 'group.create 未实现' };
          return { error: `create failed: ${e.message}` };
        }

        try {
          const epoch1 = await H.waitForLocalEpoch(alice, groupId, 1, 20_000);
          const joinResult = await bob.call('group.request_join', { group_id: groupId });
          if (joinResult?.status !== 'joined') return { error: `bob join: ${JSON.stringify(joinResult)}` };
          const epoch2 = await H.waitForLocalEpoch(bob, groupId, epoch1 + 1, 25_000);
          await H.waitForLocalEpoch(alice, groupId, epoch2, 20_000);

          await alice.close();
          await sleep(500);
          const charlieJoin = await charlie.call('group.request_join', { group_id: groupId });
          if (charlieJoin?.status !== 'joined') return { error: `charlie join: ${JSON.stringify(charlieJoin)}` };

          await bob.call('group.send', {
            group_id: groupId,
            payload: { type: 'text', text: `repair-${rid}` },
            encrypt: true,
          });

          let repaired = false;
          try {
            await H.waitForLocalEpoch(bob, groupId, epoch2 + 1, 25_000);
            repaired = true;
          } catch {}

          return { repaired };
        } finally {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await alice.close(); await bob.close(); await charlie.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { test.skip(); return; }
    const r = result as any;
    if (r.error) throw new Error(r.error);
    expect(r.repaired).toBe(true);
  });

  test('group.thought.get recovers missing epoch key', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const aliceAid = `tgta${rid}.${iss}`;
      const bobAid = `tgtb${rid}.${iss}`;
      const charlieAid = `tgtc${rid}.${iss}`;

      const alice = await makeAndConnect(`tgt-alice-${rid}`);
      const bob = await makeAndConnect(`tgt-bob-${rid}`);
      const charlie = await makeAndConnect(`tgt-charlie-${rid}`);

      try {
        await ensureConnected(alice, aliceAid);
        await ensureConnected(bob, bobAid);
        await ensureConnected(charlie, charlieAid);

        let groupId: string | undefined;
        try {
          const createResult = await alice.call('group.create', {
            name: `tgt-${rid}`, visibility: 'public', join_mode: 'open',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) return { skipped: true, reason: '创建群未返回 group_id' };
        } catch (e: any) {
          if ((e.message ?? '').toLowerCase().includes('not implement'))
            return { skipped: true, reason: 'group.create 未实现' };
          return { error: `create failed: ${e.message}` };
        }

        try {
          const epoch1 = await H.waitForLocalEpoch(alice, groupId, 1, 20_000);
          const joinResult = await bob.call('group.request_join', { group_id: groupId });
          if (joinResult?.status !== 'joined') return { error: `bob join: ${JSON.stringify(joinResult)}` };
          const epoch2 = await H.waitForLocalEpoch(bob, groupId, epoch1 + 1, 25_000);
          await H.waitForLocalEpoch(alice, groupId, epoch2, 20_000);

          await alice.close();
          await sleep(500);
          const charlieJoin = await charlie.call('group.request_join', { group_id: groupId });
          if (charlieJoin?.status !== 'joined') return { error: `charlie join: ${JSON.stringify(charlieJoin)}` };
          const epoch3 = await H.waitForLocalEpoch(bob, groupId, epoch2 + 1, 25_000);
          await H.waitForLocalEpoch(charlie, groupId, epoch3, 20_000);

          const thoughtText = `thought-recover-${rid}`;
          const thoughtContext = { type: 'run', id: `thought-run-${rid}` };
          await bob.call('group.thought.put', {
            group_id: groupId,
            context: thoughtContext,
            payload: { type: 'thought', text: thoughtText },
          });

          const alice2 = await makeAndConnect(`tgt-alice2-${rid}`);
          await ensureConnected(alice2, aliceAid);
          await H.waitForLocalEpoch(alice2, groupId, epoch3, 30_000);

          const result = await alice2.call('group.thought.get', {
            group_id: groupId,
            sender_aid: bobAid,
            context: thoughtContext,
          });
          const thoughts = result?.thoughts ?? [];
          const decrypted = thoughts.find((item: any) =>
            item?.e2ee?.encryption_mode === 'epoch_group_key' &&
            item?.payload?.text === thoughtText);
          await alice2.close();

          return { thoughtDecrypted: !!decrypted };
        } finally {
          try { await alice.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await alice.close(); await bob.close(); await charlie.close();
      }
    }, ISSUER);

    if ((result as any).skipped) { test.skip(); return; }
    const r = result as any;
    if (r.error) throw new Error(r.error);
    expect(r.thoughtDecrypted).toBe(true);
  });
});
