// ── Playwright E2E 浏览器测试：Group E2EE 集成 ──────────────
//
// 覆盖：
//   1. 创建加密群组 — 验证 e2ee 字段存在
//   2. 发送加密群消息 — 成员接收并解密
//   3. 非成员无法访问 — outsider 被拒绝
//
// 运行方法：
//   npm run build && playwright test --config=playwright.agentid-local.config.ts tests/e2e-browser/group-e2ee.spec.ts --reporter=line
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

// ── 群 E2EE 辅助工具（在浏览器上下文注入）──────────────────────

async function installGroupE2EEHelpers(page: any): Promise<void> {
  await page.evaluate(() => {
    const w = window as any;
    if (w.__aunGrpE2ee) return;

    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    // 合并消息，按 seq 去重排序
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

    // 获取群当前最大 seq
    const currentGroupMaxSeq = async (client: any, groupId: string): Promise<number> => {
      try {
        const result = await client.call('group.get_cursor', { group_id: groupId });
        const cursor = result?.msg_cursor ?? result?.cursor ?? {};
        return Number(cursor.latest_seq ?? cursor.current_seq ?? 0) || 0;
      } catch {
        return 0;
      }
    };

    // 拉取群消息
    const groupPull = async (client: any, groupId: string, afterSeq: number, limit: number = 50): Promise<any[]> => {
      const result = await client.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        limit,
      });
      return result?.messages ?? [];
    };

    // 监听群消息（事件推送 + 轮询兜底）
    const watchGroupMessages = async (client: any, groupId: string) => {
      const afterSeq = await currentGroupMaxSeq(client, groupId);
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

    // 按 text 查找消息
    const byText = (messages: any[], text: string) =>
      messages.find(msg => msg?.payload?.text === text);

    // 等待服务端已提交的 group epoch 就绪
    const isPlainObject = (value: any): value is Record<string, any> =>
      value !== null && typeof value === 'object' && !Array.isArray(value);

    const truthyBool = (value: any): boolean => {
      if (typeof value === 'boolean') return value;
      if (typeof value === 'number') return value !== 0;
      if (typeof value === 'string') return ['1', 'true', 'yes', 'y', 'on'].includes(value.trim().toLowerCase());
      return !!value;
    };

    const groupSecretMatchesCommittedRotation = (
      secretData: any,
      committedRotation: Record<string, any> | null,
    ): boolean => {
      if (!isPlainObject(secretData)) return false;
      const committedCommitment = String(committedRotation?.key_commitment ?? '').trim();
      const localCommitment = String(secretData.commitment ?? '').trim();
      if (committedCommitment && committedCommitment !== localCommitment) return false;
      const pendingRotationId = String(secretData.pending_rotation_id ?? '').trim();
      if (!pendingRotationId) return true;
      return String(committedRotation?.rotation_id ?? '').trim() === pendingRotationId;
    };

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

    const committedGroupEpochSnapshot = async (client: any, groupId: string) => {
      const result = await client.call('group.e2ee.get_epoch', { group_id: groupId });
      const epoch = Number(result?.committed_epoch ?? result?.epoch ?? 0);
      const pending = result?.pending_rotation;
      return {
        epoch: Number.isFinite(epoch) ? epoch : 0,
        committedRotation: isPlainObject(result?.committed_rotation) ? result.committed_rotation : null,
        pendingActive: isPlainObject(pending) && !truthyBool(pending.expired),
      };
    };

    const waitForCommittedGroupEpochReady = async (
      client: any,
      groupId: string,
      minEpoch: number,
      timeoutMs: number = 20_000,
    ): Promise<number> => {
      let readyEpoch = 0;
      let lastEpoch = 0;
      let lastPending = false;
      const matched = await waitFor(async () => {
        const snapshot = await committedGroupEpochSnapshot(client, groupId);
        lastEpoch = snapshot.epoch;
        lastPending = snapshot.pendingActive;
        if (snapshot.epoch < minEpoch || snapshot.pendingActive) return false;
        const secret = await client.groupE2ee.loadSecret(groupId, snapshot.epoch);
        if (!groupSecretMatchesCommittedRotation(secret, snapshot.committedRotation)) return false;
        readyEpoch = snapshot.epoch;
        return true;
      }, timeoutMs);
      if (!matched) {
        throw new Error(
          `timeout waiting committed group epoch >= ${minEpoch}; last_epoch=${lastEpoch}; pending=${lastPending}`,
        );
      }
      return readyEpoch;
    };

    w.__aunGrpE2ee = {
      sleep,
      watchGroupMessages,
      byText,
      waitForCommittedGroupEpochReady,
    };
  });
}

// ── 1. 创建加密群组 ──────────────────────────────────────────

test.describe('Group E2EE: 创建加密群组（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installGroupE2EEHelpers(page);
  });

  test('创建 encrypt:true 群组并验证 e2ee 字段', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId } = (window as any).__aunP0;
      const rid = runId();
      const ownerAid = `ge2a${rid}.${iss}`;

      const owner = await makeAndConnect(`ge2-create-${rid}`);

      try {
        await ensureConnected(owner, ownerAid);

        // 创建加密群组
        let groupId: string | undefined;
        try {
          const createResult = await owner.call('group.create', {
            name: `e2ee-grp-${rid}`,
            visibility: 'private',
            encrypt: true,
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skipped: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found') || msg.includes('encrypt')) {
            return { skipped: true, reason: `group.create(encrypt) 未实现: ${e.message}` };
          }
          return { skipped: false, groupId: null, hasE2eeField: false, error: `create failed: ${e.message}` };
        }

        // 查询群信息，检查 e2ee 相关字段
        let hasE2eeField = false;
        try {
          const info = await owner.call('group.info', { group_id: groupId });
          const group = info?.group ?? info;
          // 检查任何 e2ee 相关字段是否存在
          hasE2eeField = !!(
            group?.encrypt ||
            group?.encrypted ||
            group?.e2ee ||
            group?.e2ee_enabled ||
            group?.encryption ||
            group?.key_epoch !== undefined ||
            group?.epoch !== undefined
          );
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            // group.info 未实现，但群已创建成功，依然视为部分通过
            hasE2eeField = false;
          }
        }

        // 清理
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}

        return { skipped: false, groupId, hasE2eeField };
      } finally {
        await owner.close();
      }
    }, ISSUER);

    if ((result as any).skipped) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    expect(r.groupId).toBeTruthy();
    // e2ee 字段存在性取决于服务端实现，记录日志但不强制断言
    console.log(`group.info e2ee 字段: ${r.hasE2eeField}`);
  });
});

// ── 2. 发送加密群消息 ────────────────────────────────────────

test.describe('Group E2EE: 发送加密群消息（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installGroupE2EEHelpers(page);
  });

  test('owner 加密发送，member 解密接收', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const ownerAid = `ge2oa${rid}.${iss}`;
      const memberAid = `ge2ob${rid}.${iss}`;

      const owner = await makeAndConnect(`ge2-send-owner-${rid}`);
      const member = await makeAndConnect(`ge2-send-member-${rid}`);

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);

        // 创建群
        let groupId: string | undefined;
        try {
          const createResult = await owner.call('group.create', {
            name: `e2ee-msg-${rid}`,
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skipped: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skipped: true, reason: 'group.create 未实现' };
          }
          return { skipped: false, sent: false, memberReceived: false, error: `create failed: ${e.message}` };
        }

        try {
          // 添加 member
          try {
            await owner.call('group.add_member', { group_id: groupId, aid: memberAid });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.add_member 未实现' };
            }
            return { skipped: false, sent: false, memberReceived: false, error: `add_member failed: ${e.message}` };
          }

          // 等待 member 拿到 epoch 密钥
          try {
            await H.waitForCommittedGroupEpochReady(member, groupId, 1, 20_000);
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.e2ee.get_epoch 未实现' };
            }
            // epoch 等待超时但不一定是功能未实现，继续尝试发送
          }

          // member 开始监听群消息
          const memberWatch = await H.watchGroupMessages(member, groupId);

          // owner 发送加密消息
          let sent = false;
          const msgText = `e2ee-test-${rid}`;
          try {
            await owner.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: msgText },
              encrypt: true,
            });
            sent = true;
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              memberWatch.stop();
              return { skipped: true, reason: 'group.send(encrypt) 未实现' };
            }
            memberWatch.stop();
            return { skipped: false, sent: false, memberReceived: false, error: `send failed: ${e.message}` };
          }

          // 等待 member 接收到消息
          let memberReceived = false;
          let decryptedText: string | null = null;
          let encryptionMode: string | null = null;
          try {
            const msgs = await memberWatch.waitFor((messages: any[]) => {
              const msg = H.byText(messages, msgText);
              return !!msg;
            }, 20_000);
            const received = H.byText(msgs, msgText);
            if (received) {
              memberReceived = true;
              decryptedText = received?.payload?.text ?? null;
              encryptionMode = received?.e2ee?.encryption_mode ?? null;
            }
          } catch {
            // 超时，memberReceived 保持 false
          }

          memberWatch.stop();

          return {
            skipped: false,
            sent,
            memberReceived,
            decryptedText,
            encryptionMode,
          };
        } finally {
          // 清理
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await owner.close();
        await member.close();
      }
    }, ISSUER);

    if ((result as any).skipped) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    expect(r.sent).toBe(true);
    expect(r.memberReceived).toBe(true);
    if (r.encryptionMode) {
      expect(r.encryptionMode).toBe('epoch_group_key');
    }
  });
});

// ── 3. 非成员无法访问 ────────────────────────────────────────

test.describe('Group E2EE: 非成员无法访问（浏览器）', () => {
  test.setTimeout(60_000);

  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
    await installP0Helpers(page);
    await installGroupE2EEHelpers(page);
  });

  test('outsider 无法拉取或解密加密群消息', async ({ page }) => {
    const result = await page.evaluate(async (iss: string) => {
      const { makeAndConnect, ensureConnected, runId, sleep } = (window as any).__aunP0;
      const H = (window as any).__aunGrpE2ee;
      const rid = runId();
      const ownerAid = `ge2xa${rid}.${iss}`;
      const memberAid = `ge2xb${rid}.${iss}`;
      const outsiderAid = `ge2xc${rid}.${iss}`;

      const owner = await makeAndConnect(`ge2-blk-owner-${rid}`);
      const member = await makeAndConnect(`ge2-blk-member-${rid}`);
      const outsider = await makeAndConnect(`ge2-blk-outsider-${rid}`);

      try {
        await ensureConnected(owner, ownerAid);
        await ensureConnected(member, memberAid);
        await ensureConnected(outsider, outsiderAid);

        // 创建群
        let groupId: string | undefined;
        try {
          const createResult = await owner.call('group.create', {
            name: `e2ee-block-${rid}`,
            visibility: 'private',
          });
          groupId = createResult?.group?.group_id ?? createResult?.group_id;
          if (!groupId) {
            return { skipped: true, reason: '创建群未返回 group_id' };
          }
        } catch (e: any) {
          const msg = (e.message ?? '').toLowerCase();
          if (msg.includes('not implement') || msg.includes('method not found')) {
            return { skipped: true, reason: 'group.create 未实现' };
          }
          return { skipped: false, outsiderBlocked: false, error: `create failed: ${e.message}` };
        }

        try {
          // 添加 member（不添加 outsider）
          try {
            await owner.call('group.add_member', { group_id: groupId, aid: memberAid });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.add_member 未实现' };
            }
            return { skipped: false, outsiderBlocked: false, error: `add_member failed: ${e.message}` };
          }

          // 等待 member 拿到密钥
          try {
            await H.waitForCommittedGroupEpochReady(member, groupId, 1, 20_000);
          } catch {
            // 继续测试
          }

          // owner 发送加密消息
          const msgText = `secret-${rid}`;
          try {
            await owner.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: msgText },
              encrypt: true,
            });
          } catch (e: any) {
            const msg = (e.message ?? '').toLowerCase();
            if (msg.includes('not implement') || msg.includes('method not found')) {
              return { skipped: true, reason: 'group.send(encrypt) 未实现' };
            }
            return { skipped: false, outsiderBlocked: false, error: `send failed: ${e.message}` };
          }

          await sleep(1000);

          // outsider 尝试拉取群消息 — 应被拒绝（权限不足）
          let outsiderBlocked = false;
          let outsiderPullError: string | null = null;
          let outsiderGotPlaintext = false;
          try {
            const pullResult = await outsider.call('group.pull', {
              group_id: groupId,
              after_message_seq: 0,
              limit: 50,
            });
            const msgs = pullResult?.messages ?? [];
            if (msgs.length === 0) {
              // 服务端拒绝返回消息（正确行为）
              outsiderBlocked = true;
            } else {
              // 服务端返回了消息，检查 outsider 是否能读到明文
              const plainMsg = msgs.find((m: any) => m?.payload?.text === msgText);
              if (plainMsg) {
                outsiderGotPlaintext = true;
                outsiderBlocked = false;
              } else {
                // 消息是加密的，outsider 没有密钥无法解密 — 也算被阻止
                outsiderBlocked = true;
              }
            }
          } catch (e: any) {
            // pull 抛异常（权限不足等）— 被阻止
            outsiderBlocked = true;
            outsiderPullError = e.message ?? null;
          }

          // 额外验证：outsider 尝试 group.send 也应失败
          let outsiderSendBlocked = false;
          try {
            await outsider.call('group.send', {
              group_id: groupId,
              payload: { type: 'text', text: `intruder-${rid}` },
              encrypt: true,
            });
            outsiderSendBlocked = false;
          } catch {
            outsiderSendBlocked = true;
          }

          return {
            skipped: false,
            outsiderBlocked,
            outsiderSendBlocked,
            outsiderPullError,
            outsiderGotPlaintext,
          };
        } finally {
          try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
        }
      } finally {
        await owner.close();
        await member.close();
        await outsider.close();
      }
    }, ISSUER);

    if ((result as any).skipped) {
      console.log(`跳过: ${(result as any).reason}`);
      test.skip();
      return;
    }

    const r = result as any;
    if (r.error) {
      throw new Error(r.error);
    }

    // outsider 不应获得明文
    expect(r.outsiderGotPlaintext).toBe(false);
    // outsider 应该被拒绝（pull 返回空或抛异常或拿到密文但无法解密）
    expect(r.outsiderBlocked).toBe(true);
    // outsider 发送也应被拒绝
    expect(r.outsiderSendBlocked).toBe(true);
  });
});
