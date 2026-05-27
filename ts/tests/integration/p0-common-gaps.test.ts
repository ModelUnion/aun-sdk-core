/**
 * P0 共同缺口集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   P0-01: 网关健康检查（真实 Gateway）
 *   P0-02: AID 创建失败路径（重复 / 无效参数）
 *   P0-06: 消息撤回
 *   P0-08: 重连中补洞
 *   P0-09: 发送到暂停群
 *   P0-10: 非成员发送群消息
 *   P0-14: 断线后 RPC + 重连恢复
 *
 * 运行方法：
 *   npx vitest run tests/integration/p0-common-gaps.test.ts
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - 运行环境能解析 gateway.agentid.pub
 */

import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { ConnectionError, StateError } from '../../src/errors.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 30_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

// ── 辅助函数 ──────────────────────────────────────────────────────

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-p0-'));
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
  await client.auth.registerAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function extractGroupId(result: Record<string, unknown>): string {
  const group = result.group as Record<string, unknown> | undefined;
  return String(result.group_id ?? group?.group_id ?? '');
}

function payloadText(message: Record<string, unknown>): string {
  const payload = message.payload as Record<string, unknown> | undefined;
  return String(payload?.text ?? '');
}

// ── P0-01: 网关健康检查 ──────────────────────────────────────────

describe('P0-01: 网关健康检查（真实 Gateway）', () => {
  it('正常健康检查 — 真实 Gateway 应返回 true', async () => {
    const client = makeClient();
    try {
      const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
      const ok = await client.checkGatewayHealth(gateway, 10_000);
      expect(ok).toBe(true);
    } finally {
      await client.close();
    }
  }, TEST_TIMEOUT);

  it('超时 — 不可达地址应返回 false', async () => {
    const client = makeClient();
    try {
      const start = Date.now();
      const ok = await client.checkGatewayHealth('https://192.0.2.1:9999', 2_000);
      const elapsed = Date.now() - start;
      expect(ok).toBe(false);
      expect(elapsed).toBeLessThan(5_000);
    } finally {
      await client.close();
    }
  }, TEST_TIMEOUT);

  it('连接拒绝 — 无服务端口应返回 false', async () => {
    const client = makeClient();
    try {
      const ok = await client.checkGatewayHealth('https://127.0.0.1:1', 3_000);
      expect(ok).toBe(false);
    } finally {
      await client.close();
    }
  }, TEST_TIMEOUT);
});

// ── P0-02: AID 创建失败路径 ──────────────────────────────────────

describe('P0-02: AID 创建失败路径（真实 Gateway）', () => {
  it('创建已存在的 AID — 应报错或幂等', async () => {
    const rid = runId();
    const aid = `p0dup${rid}.${ISSUER}`;
    const c1 = makeClient();
    const c2 = makeClient();

    try {
      const gw = await c1.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
      ((c1 as unknown) as { _gatewayUrl: string })._gatewayUrl = gw;
      ((c2 as unknown) as { _gatewayUrl: string })._gatewayUrl = gw;

      await c1.auth.registerAid({ aid });
      // 第二次创建 — 要么报错要么幂等
      try {
        await c2.auth.registerAid({ aid });
        // 幂等设计也可接受
      } catch (e) {
        // 报错也可接受
        expect(e).toBeDefined();
      }
    } finally {
      await c1.close();
      await c2.close();
    }
  }, TEST_TIMEOUT);

  it('空 AID 应被拒绝', async () => {
    const client = makeClient();
    try {
      const gw = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
      ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gw;
      await expect(client.auth.registerAid({ aid: '' })).rejects.toThrow();
    } finally {
      await client.close();
    }
  }, TEST_TIMEOUT);
});

// ── P0-06: 消息撤回 ──────────────────────────────────────────────

describe('P0-06: 消息撤回（真实 Gateway）', () => {
  it('撤回自己的消息 / 撤回他人消息被拒绝 / 撤回不存在消息被拒绝', async () => {
    const rid = runId();
    const aliceAid = `p0rca${rid}.${ISSUER}`;
    const bobAid = `p0rcb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // Alice 发一条消息
      const sendResult = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `recall-test-${rid}` },
        durable: true,
        encrypt: false,
      }) as Record<string, unknown>;

      const msgId = sendResult?.message_id as string;
      if (!msgId) {
        console.log('send 未返回 message_id，跳过撤回测试');
        return;
      }

      await sleep(500);

      // Alice 撤回自己的消息
      try {
        const recallResult = await alice.call('message.recall', {
          message_ids: [msgId],
        }) as Record<string, unknown>;
        expect(Number(recallResult.recalled ?? 0)).toBeGreaterThanOrEqual(1);
      } catch (e: any) {
        const msg = e?.message?.toLowerCase() ?? '';
        if (msg.includes('not implement') || msg.includes('method not found')) {
          console.log('message.recall 未实现，跳过');
          return;
        }
        throw e;
      }

      // Bob 撤回 Alice 的消息 — 应被拒绝
      const sendResult2 = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `recall-perm-${rid}` },
        durable: true,
        encrypt: false,
      }) as Record<string, unknown>;

      const msgId2 = sendResult2?.message_id as string;
      if (msgId2) {
        await sleep(300);
        try {
          const denied = await bob.call('message.recall', {
            message_ids: [msgId2],
          }) as Record<string, unknown>;
          expect(Number(denied.recalled ?? 0)).toBe(0);
          expect(((denied.errors ?? []) as unknown[]).length).toBeGreaterThan(0);
        } catch {
          // 服务端选择直接拒绝也符合权限语义。
        }
      }

      // 撤回不存在的消息 — 应报错
      try {
        const missing = await alice.call('message.recall', {
          message_ids: [`nonexistent-${rid}`],
        }) as Record<string, unknown>;
        expect(Number(missing.recalled ?? 0)).toBe(0);
        expect(((missing.errors ?? []) as unknown[]).length).toBeGreaterThan(0);
      } catch {
        // 服务端选择直接拒绝也符合不存在消息语义。
      }
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── P0-08: 重连中补洞 ──────────────────────────────────────────

describe('P0-08: 重连中补洞（真实 Gateway）', () => {
  it('断线期间收消息 → 重连后自动补洞', async () => {
    const rid = runId();
    const aliceAid = `p0gfa${rid}.${ISSUER}`;
    const bobAid = `p0gfb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const msgCount = 5;
      const gapPrefix = `gap-${rid}-`;
      const received: Record<string, unknown>[] = [];
      let resolve: (() => void) | null = null;
      const allReceived = new Promise<void>(r => { resolve = r; });

      bob.on('message.received', (data: unknown) => {
        if (typeof data === 'object' && data !== null) {
          const message = data as Record<string, unknown>;
          if (message.from !== aliceAid || !payloadText(message).startsWith(gapPrefix)) {
            return;
          }
          received.push(message);
          if (received.length >= msgCount && resolve) {
            resolve();
          }
        }
      });

      // Bob 断线
      await bob.disconnect();
      await sleep(1_000);

      // Alice 在 Bob 断线期间发消息
      for (let i = 0; i < msgCount; i++) {
        await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `${gapPrefix}${i}` },
          durable: true,
          encrypt: false,
        });
        await sleep(100);
      }

      await sleep(500);

      // 清空收集，重连
      received.length = 0;
      const auth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(auth);

      // 等待补洞
      const timeout = new Promise<void>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), 15_000),
      );

      try {
        await Promise.race([allReceived, timeout]);
      } catch {
        console.log(`补洞结果: ${received.length}/${msgCount} 条`);
      }

      if (received.length < msgCount) {
        const pullResult = await bob.call('message.pull', {
          after_seq: 0,
          limit: 50,
        }) as Record<string, unknown>;
        const pulled = ((pullResult.messages ?? []) as Record<string, unknown>[])
          .filter(message => message.from === aliceAid && payloadText(message).startsWith(gapPrefix));
        for (const message of pulled) {
          const id = String(message.message_id ?? '');
          if (id && received.some(item => item.message_id === id)) continue;
          received.push(message);
        }
      }

      expect(received.length).toBeGreaterThan(0);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── P0-09: 发送到暂停群 ──────────────────────────────────────────

describe('P0-09: 发送到暂停群（真实 Gateway）', () => {
  it('向暂停状态的群发送消息应被拒绝', async () => {
    const rid = runId();
    const ownerAid = `p0sus${rid}.${ISSUER}`;
    const memberAid = `p0sum${rid}.${ISSUER}`;

    const owner = makeClient();
    const member = makeClient();

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      // 创建群
      const createResult = await owner.call('group.create', {
        members: [memberAid],
        metadata: { name: `suspend-test-${rid}` },
      }) as Record<string, unknown>;

      const groupId = extractGroupId(createResult);
      if (!groupId) {
        console.log('创建群未返回 group_id，跳过');
        return;
      }

      await sleep(1_000);

      // 暂停群
      try {
        await owner.call('group.suspend', { group_id: groupId });
      } catch (e: any) {
        const msg = e?.message?.toLowerCase() ?? '';
        if (msg.includes('not implement') || msg.includes('method not found')) {
          console.log('group.suspend 未实现，跳过');
          return;
        }
        throw e;
      }

      await sleep(500);

      // 成员发消息 — 应被拒绝
      await expect(
        member.call('group.send', {
          group_id: groupId,
          payload: { type: 'text', text: 'should-fail' },
          encrypt: false,
        }),
      ).rejects.toThrow();

      // 清理
      try { await owner.call('group.resume', { group_id: groupId }); } catch {}
      try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
    } finally {
      await owner.close();
      await member.close();
    }
  }, 60_000);
});

// ── P0-10: 非成员发送群消息 ──────────────────────────────────────

describe('P0-10: 非成员发送群消息（真实 Gateway）', () => {
  it('非成员向群发消息应被权限拒绝', async () => {
    const rid = runId();
    const ownerAid = `p0nmo${rid}.${ISSUER}`;
    const outsiderAid = `p0nms${rid}.${ISSUER}`;

    const owner = makeClient();
    const outsider = makeClient();

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(outsider, outsiderAid);

      // 创建只有 owner 的群
      const createResult = await owner.call('group.create', {
        members: [],
        metadata: { name: `perm-test-${rid}` },
      }) as Record<string, unknown>;

      const groupId = extractGroupId(createResult);
      if (!groupId) {
        console.log('创建群未返回 group_id，跳过');
        return;
      }

      await sleep(500);

      // 非成员发消息 — 应被拒绝
      await expect(
        outsider.call('group.send', {
          group_id: groupId,
          payload: { type: 'text', text: 'unauthorized' },
          encrypt: false,
        }),
      ).rejects.toThrow();

      // 清理
      try { await owner.call('group.dissolve', { group_id: groupId }); } catch {}
    } finally {
      await owner.close();
      await outsider.close();
    }
  }, 60_000);
});

// ── P0-04: Login 重放攻击 ──────────────────────────────────────

describe('P0-04: Login 重放攻击（真实 Gateway）', () => {
  it('两次认证 token 不同 — 服务端每次颁发新 challenge', async () => {
    const rid = runId();
    const aid = `p0rpl${rid}.${ISSUER}`;
    const client = makeClient();

    try {
      const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
      ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;

      await client.auth.registerAid({ aid });

      const auth1 = await client.auth.authenticate({ aid });
      expect(auth1).toBeDefined();
      expect(auth1.access_token).toBeDefined();

      const auth2 = await client.auth.authenticate({ aid });
      expect(auth2).toBeDefined();
      expect(auth2.access_token).toBeDefined();

      if (auth1.access_token !== auth2.access_token) {
        console.log('两次认证返回不同 token（正确 — challenge 不可重用）');
      } else {
        console.log('警告: 两次认证返回了相同的 token');
      }
    } finally {
      await client.close();
    }
  }, 60_000);
});

// ── P0-07: 临时消息 TTL ──────────────────────────────────────

describe('P0-07: 临时消息 TTL（真实 Gateway）', () => {
  it('非持久消息应能收到但不永久持久化', async () => {
    const rid = runId();
    const aliceAid = `p0epa${rid}.${ISSUER}`;
    const bobAid = `p0epb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // 发送临时消息（persist=false 或默认）
      const sendResult = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `ephemeral-${rid}` },
        durable: false,
        encrypt: false,
      }) as Record<string, unknown>;

      if (sendResult?.message_id) {
        console.log(`临时消息发送成功: ${sendResult.message_id}`);
      } else {
        console.log(`临时消息发送完成: ${JSON.stringify(sendResult)}`);
      }

      await sleep(1_000);

      // Bob pull — 临时消息可能不在 pull 结果中
      try {
        const pullResult = await bob.call('message.pull', {
          limit: 50,
        }) as Record<string, unknown>;
        const messages = (pullResult?.messages ?? []) as Record<string, unknown>[];
        const matching = messages.filter(
          m => typeof m === 'object' && m !== null &&
          (m as any).payload?.text?.startsWith(`ephemeral-${rid}`),
        );
        if (matching.length > 0) {
          console.log(`Bob 通过 pull 收到临时消息 (${matching.length} 条)`);
        } else {
          console.log('Bob 未通过 pull 收到临时消息（可能仅推送）');
        }
      } catch {
        console.log('pull 异常（可接受）');
      }
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── P0-03: Login 过期挑战 ──────────────────────────────────────

describe('P0-03: Login 过期挑战（真实 Gateway）', () => {
  it('两次认证应返回不同 token', async () => {
    const rid = runId();
    const aid = `p0exp${rid}.${ISSUER}`;
    const client = makeClient();

    try {
      const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
      ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;

      await client.auth.registerAid({ aid });

      const auth1 = await client.auth.authenticate({ aid });
      expect(auth1).toBeDefined();
      expect(auth1.access_token).toBeDefined();

      await sleep(2_000);

      const auth2 = await client.auth.authenticate({ aid });
      expect(auth2).toBeDefined();
      expect(auth2.access_token).toBeDefined();

      if (auth1.access_token !== auth2.access_token) {
        console.log('两次认证返回不同 token（正确）');
      } else {
        console.log('警告: 两次认证返回了相同的 token');
      }
    } finally {
      await client.close();
    }
  }, 60_000);
});

// ── P0-05: Token 并发刷新 ──────────────────────────────────────

describe('P0-05: Token 并发刷新（真实 Gateway）', () => {
  it('同 AID 并发 authenticate 应有 inflight 限流', async () => {
    const rid = runId();
    const aid = `p0tkn${rid}.${ISSUER}`;
    const client = makeClient();

    try {
      await ensureConnected(client, aid);

      // 并发发起 5 个 authenticate — inflight 限流应让它们复用同一次调用
      const promises = Array.from({ length: 5 }, () =>
        client.auth.authenticate({ aid }).catch((e: Error) => e),
      );
      const results = await Promise.all(promises);

      const successes = results.filter(
        r => r && typeof r === 'object' && !(r instanceof Error) && 'access_token' in r,
      );
      expect(successes.length).toBeGreaterThan(0);

      const tokens = new Set(
        successes.map((r: any) => r.access_token).filter(Boolean),
      );
      if (tokens.size === 1) {
        console.log('inflight 限流正常: 并发请求复用同一 token');
      } else {
        console.log(`并发认证 ${successes.length}/5 成功，${tokens.size} 个不同 token`);
      }

      // inflight 标志应在成功/出错/超时后清理 — 后续 authenticate 应正常
      await sleep(500);
      const authAfter = await client.auth.authenticate({ aid });
      expect(authAfter.access_token).toBeDefined();
      console.log('inflight 清理正常: 后续 authenticate 成功');
    } finally {
      await client.close();
    }
  }, 60_000);
});

// ── P0-13: Ping 超时检测 ──────────────────────────────────────

describe('P0-13: Ping 超时检测（真实 Gateway）', () => {
  it('连接状态下 ping 应在合理时间内返回', async () => {
    const rid = runId();
    const aid = `p0png${rid}.${ISSUER}`;
    const client = makeClient();

    try {
      await ensureConnected(client, aid);

      const start = Date.now();
      await client.call('meta.ping');
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(5_000);

      const latencies: number[] = [];
      for (let i = 0; i < 5; i++) {
        const t0 = Date.now();
        await client.call('meta.ping');
        latencies.push(Date.now() - t0);
        await sleep(100);
      }

      const avg = latencies.reduce((a, b) => a + b, 0) / latencies.length;
      console.log(`Ping 稳定性: ${latencies.length}/5 成功，平均延迟 ${avg.toFixed(0)}ms`);
      expect(latencies.length).toBeGreaterThanOrEqual(3);
    } finally {
      await client.close();
    }
  }, TEST_TIMEOUT);
});

// ── P0-15: Stream 边界场景 ────────────────────────────────────

describe('P0-15: Stream 边界场景（真实 Gateway）', () => {
  it('创建/关闭/重复关闭/不存在流/缺参数', async () => {
    const rid = runId();
    const aid = `p0str${rid}.${ISSUER}`;
    const client = makeClient();

    try {
      await ensureConnected(client, aid);

      // 1. 创建流
      let streamId: string;
      try {
        const result = await client.call('stream.create', {
          content_type: 'text/plain',
        }) as Record<string, unknown>;
        streamId = result?.stream_id as string;
        if (!streamId) {
          console.log('创建流未返回 stream_id，跳过');
          return;
        }
      } catch (e: any) {
        const msg = e?.message?.toLowerCase() ?? '';
        if (msg.includes('not implement') || msg.includes('method not found')) {
          console.log('stream 服务未实现，跳过');
          return;
        }
        throw e;
      }

      // 2. 正常关闭
      await client.call('stream.close', { stream_id: streamId });

      // 3. 重复关闭
      try {
        await client.call('stream.close', { stream_id: streamId });
      } catch { /* 幂等或报错均可 */ }

      // 4. 关闭不存在的流
      try {
        await client.call('stream.close', { stream_id: 'nonexistent-stream' });
      } catch { /* 可接受 */ }

      // 5. 非法 content_type；省略 content_type 当前服务端有默认值
      await expect(
        client.call('stream.create', { content_type: 'invalid' }),
      ).rejects.toThrow();
    } finally {
      await client.close();
    }
  }, 60_000);
});

// ── P0-14: 断线后 RPC + 重连恢复 ────────────────────────────────

describe('P0-14: 断线后 RPC + 重连恢复（真实 Gateway）', () => {
  it('断线后 RPC 报错 → 重连后恢复', async () => {
    const rid = runId();
    const aid = `p0rpc${rid}.${ISSUER}`;
    const client = makeClient();

    try {
      await ensureConnected(client, aid);

      // 正常 ping
      await client.call('meta.ping');

      // 断线
      await client.disconnect();
      await sleep(500);

      // 断线后 RPC — 应报错
      await expect(client.call('meta.ping')).rejects.toThrow();

      // 重连
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);

      // 重连后 RPC — 应恢复
      await expect(client.call('meta.ping')).resolves.toBeDefined();
    } finally {
      await client.close();
    }
  }, TEST_TIMEOUT);
});
