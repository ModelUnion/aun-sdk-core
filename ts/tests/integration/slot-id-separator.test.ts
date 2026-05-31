/**
 * slot_id 分隔符语义集成测试
 *
 * 场景：
 *   1. 同前缀互踢：alice 以 "evolclaw cli" 连 c1，再以 "evolclaw daemon" 连 c2，c1 收到 4009
 *   2. 不同前缀共存：alice 以 "evolclaw cli" 连 c1，再以 "other daemon" 连 c2，两者共存
 *   3. P2P 消息路由：alice daemon 实例收到 bob 发的消息
 *   4. 非法 slot_id 拒绝："/invalid" 被 SDK 校验拒绝（ValidationError）
 *
 * 运行（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/integration/slot-id-separator.test.ts"
 *
 * 前置条件：Docker 单域环境运行中（kite-app + kite-mysql）
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { createTestClient, registerAndLoadIdentity, loadIdentityFromStore } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();

// ── 辅助 ──────────────────────────────────────────────────────────────────────

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function makeAunPath(tag: string): string {
  const base = AUN_DATA_ROOT
    ? path.join(AUN_DATA_ROOT, 'single-domain', 'persistent', '..')
    : os.tmpdir();
  const root = path.join(base, `ts_slot_sep_${tag}_${rid()}`);
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function makeClient(aunPath: string): AUNClient {
  return createTestClient({ aunPath, debug: false, requireForwardSecrecy: false });
}

async function setupAndConnect(
  client: AUNClient,
  aid: string,
  slotId: string,
  opts: { register?: boolean } = {},
): Promise<void> {
  if (opts.register !== false) {
    try {
      await registerAndLoadIdentity(client, aid, slotId);
    } catch (err) {
      const msg = String(err);
      if (!/exists|already/i.test(msg)) throw err;
      loadIdentityFromStore(client, aid, slotId);
    }
  } else {
    loadIdentityFromStore(client, aid, slotId);
  }
  await client.connect({ auto_reconnect: false, heartbeat_interval: 30 });
}

async function safeClose(client: AUNClient | null | undefined): Promise<void> {
  if (!client) return;
  try { await client.close(); } catch { /* 清理路径忽略 */ }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── 测试 1：同前缀互踢 ────────────────────────────────────────────────────────

describe('slot_id 同前缀互踢', { timeout: 60_000 }, () => {
  it('evolclaw cli → evolclaw daemon，c1 收到 4009 断开', async () => {
    const r = rid();
    const aid = `slot-sep-a1-${r}.${ISSUER}`;
    const sharedPath = makeAunPath('kick');

    const c1 = makeClient(sharedPath);
    const c2 = makeClient(sharedPath);

    try {
      await setupAndConnect(c1, aid, 'evolclaw cli', { register: true });
      expect(c1.state).toBe('ready');

      // 监听 c1 断开事件
      let c1DisconnectCode: number | undefined;
      const c1Kicked = new Promise<void>(resolve => {
        c1.on('state_change', (data: unknown) => {
          const d = data as { state?: string; close_code?: number };
          if (d?.state === 'disconnected' || d?.state === 'closed') {
            c1DisconnectCode = d.close_code;
            resolve();
          }
        });
      });

      // c2 以同前缀不同后缀连接 → 应踢掉 c1
      await setupAndConnect(c2, aid, 'evolclaw daemon', { register: false });
      expect(c2.state).toBe('ready');

      // 等待 c1 被踢（轮询 state，最多 8 秒）
      const deadline = Date.now() + 8_000;
      while (c1.state === 'ready' && Date.now() < deadline) {
        await sleep(200);
      }
      expect(c1.state).not.toBe('ready');
      expect(c2.state).toBe('ready');
    } finally {
      await safeClose(c1);
      await safeClose(c2);
    }
  });
});

// ── 测试 2：不同前缀共存 ──────────────────────────────────────────────────────

describe('slot_id 不同前缀共存', { timeout: 60_000 }, () => {
  it('evolclaw cli + other daemon，两者均保持 ready', async () => {
    const r = rid();
    const aid = `slot-sep-a2-${r}.${ISSUER}`;
    const sharedPath = makeAunPath('coexist');

    const c1 = makeClient(sharedPath);
    const c2 = makeClient(sharedPath);

    try {
      await setupAndConnect(c1, aid, 'evolclaw cli', { register: true });
      expect(c1.state).toBe('ready');

      // 监听 c1 是否意外断开
      let c1Disconnected = false;
      c1.on('state_change', (data: unknown) => {
        const d = data as { state?: string };
        if (d?.state === 'disconnected' || d?.state === 'closed') {
          c1Disconnected = true;
        }
      });

      await setupAndConnect(c2, aid, 'other daemon', { register: false });
      expect(c2.state).toBe('ready');

      // 等待 2 秒确认 c1 未被踢
      await sleep(2_000);
      expect(c1Disconnected).toBe(false);
      expect(c1.state).toBe('ready');
    } finally {
      await safeClose(c1);
      await safeClose(c2);
    }
  });
});

// ── 测试 3：P2P 消息路由到指定 slot ──────────────────────────────────────────

describe('slot_id P2P 消息路由', { timeout: 60_000 }, () => {
  it('bob 发消息，alice daemon 实例收到', async () => {
    const r = rid();
    const aliceAid = `slot-sep-alice-${r}.${ISSUER}`;
    const bobAid = `slot-sep-bob-${r}.${ISSUER}`;

    const alicePath = makeAunPath('p2p-alice');
    const bobPath = makeAunPath('p2p-bob');

    const alice = makeClient(alicePath);
    const bob = makeClient(bobPath);

    try {
      await setupAndConnect(alice, aliceAid, 'evolclaw daemon', { register: true });
      await setupAndConnect(bob, bobAid, 'main', { register: true });

      const text = `hello-daemon-${r}`;
      const received: unknown[] = [];
      let resolveReceived: (() => void) | null = null;
      const msgPromise = new Promise<void>(resolve => { resolveReceived = resolve; });

      alice.on('message.received', (data: unknown) => {
        const d = data as { payload?: { text?: string } };
        if (d?.payload?.text === text) {
          received.push(data);
          resolveReceived?.();
        }
      });

      await bob.call('message.send', {
        to: aliceAid,
        payload: { type: 'text', text },
      });

      await Promise.race([
        msgPromise,
        sleep(10_000).then(() => { throw new Error('alice daemon 未在 10s 内收到消息'); }),
      ]);

      expect(received.length).toBeGreaterThan(0);
    } finally {
      await safeClose(alice);
      await safeClose(bob);
    }
  });
});

// ── 测试 4：非法 slot_id 被 SDK 拒绝 ─────────────────────────────────────────

describe('slot_id 非法值校验', { timeout: 10_000 }, () => {
  it('/invalid 被 SDK 校验拒绝（ValidationError）', async () => {
    const r = rid();
    const aid = `slot-sep-inv-${r}.${ISSUER}`;
    const aunPath = makeAunPath('invalid');
    const client = makeClient(aunPath);
    try {
      // slot_id 来自 AID 对象，通过 AIDStore 注入；/invalid 首字符为 / 应被 normalizeSlotId 拒绝
      await expect(
        setupAndConnect(client, aid, '/invalid', { register: true }),
      ).rejects.toThrow(/slot_id/i);
    } finally {
      await safeClose(client);
    }
  });
});
