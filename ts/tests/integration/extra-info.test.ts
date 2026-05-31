/**
 * extra_info 集成测试 — 验证 connect 时传自定义信息，被踢时收到双方的 extra_info。
 *
 * 用例：
 *   1. 长连接互踢带 extra_info — c1 connect(extra_info={pid:1111})，c2 同槽位
 *      connect(extra_info={pid:2222}) → c1 收到 gateway.disconnect 含
 *      self_extra_info.pid=1111 + new_extra_info.pid=2222
 *   2. 不传 extra_info 时 detail 里不含 extra_info 字段（向后兼容）
 *
 * 运行环境（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/integration/extra-info.test.ts"
 *
 * 前置条件：
 *   - Docker 单域环境运行中（kite-app + kite-mysql）
 *   - kite-ts-tester 容器内 AUN_DATA_ROOT=/data/aun
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { createTestClient, loadIdentityFromStore, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();

// ── 辅助函数 ──────────────────────────────────────────────────────

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function makeAunPath(tag: string): string {
  const base = AUN_DATA_ROOT
    ? path.join(AUN_DATA_ROOT, 'single-domain', 'persistent', '..')
    : os.tmpdir();
  const root = path.join(base, `ts_extra_info_${tag}_${rid()}`);
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function makeClient(tagOrPath: string, isPath: boolean = false): AUNClient {
  const root = isPath ? tagOrPath : makeAunPath(tagOrPath);
  return createTestClient({ aunPath: root, debug: false, requireForwardSecrecy: false });
}

async function connectLongWithExtraInfo(
  client: AUNClient,
  aid: string,
  options: { slotId?: string; registerAid?: boolean; extraInfo?: Record<string, unknown> } = {},
): Promise<void> {
  if (options.registerAid !== false) {
    try {
      await registerAndLoadIdentity(client, aid);
    } catch (err) {
      const msg = String(err);
      if (!/exists|already/i.test(msg)) throw err;
    }
  } else if (!(client as any)._currentAid) {
    loadIdentityFromStore(client, aid);
  }
  const opts: Record<string, unknown> = {
    auto_reconnect: false,
    heartbeat_interval: 30,
  };
  if (options.slotId !== undefined) opts.slot_id = options.slotId;
  if (options.extraInfo !== undefined) opts.extra_info = options.extraInfo;
  await client.connect(opts);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function safeClose(client: AUNClient | null | undefined): Promise<void> {
  if (!client) return;
  try {
    await client.close();
  } catch {
    // 测试清理路径不抛异常
  }
}

// ── 测试 ──────────────────────────────────────────────────────────

describe('extra_info - 长连接互踢带 extra_info', { timeout: 60_000 }, () => {
  it('c1 被 c2 踢时收到 self_extra_info + new_extra_info', async () => {
    const r = rid();
    const aid = `ei-kick-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ei-kick');
    const c1 = makeClient(sharedPath, true);
    const c2 = makeClient(sharedPath, true);

    try {
      // c1 连接，带 extra_info={pid:1111}
      await connectLongWithExtraInfo(c1, aid, {
        slotId: 'main',
        extraInfo: { pid: 1111 },
      });
      expect(c1.state).toBe('ready');

      // 监听 c1 的 gateway.disconnect 事件
      interface DisconnectDetail {
        self_extra_info?: Record<string, unknown>;
        new_extra_info?: Record<string, unknown>;
        [k: string]: unknown;
      }
      const disconnectEvents: DisconnectDetail[] = [];
      let resolveDisconnect: (() => void) | null = null;
      const disconnectReceived = new Promise<void>(resolve => {
        resolveDisconnect = resolve;
      });

      c1.on('gateway.disconnect', (data: unknown) => {
        if (data && typeof data === 'object') {
          const detail = (data as { detail?: DisconnectDetail }).detail ?? (data as DisconnectDetail);
          disconnectEvents.push(detail);
          if (resolveDisconnect) resolveDisconnect();
        }
      });

      // c2 同槽位连接，带 extra_info={pid:2222}，应踢掉 c1
      await connectLongWithExtraInfo(c2, aid, {
        slotId: 'main',
        registerAid: false,
        extraInfo: { pid: 2222 },
      });
      expect(c2.state).toBe('ready');

      // 等待 c1 收到 disconnect 事件
      await Promise.race([
        disconnectReceived,
        sleep(10_000).then(() => {
          throw new Error(`c1 did not receive gateway.disconnect event, captured=${disconnectEvents.length}`);
        }),
      ]);

      expect(disconnectEvents.length).toBeGreaterThan(0);
      const detail = disconnectEvents[0];

      // 验证 self_extra_info（被踢者自己的 extra_info）
      expect(detail.self_extra_info).toBeDefined();
      expect(detail.self_extra_info?.pid).toBe(1111);

      // 验证 new_extra_info（挤掉你的那个连接的 extra_info）
      expect(detail.new_extra_info).toBeDefined();
      expect(detail.new_extra_info?.pid).toBe(2222);
    } finally {
      await safeClose(c1);
      await safeClose(c2);
    }
  });
});

describe('extra_info - 不传 extra_info 时向后兼容', { timeout: 60_000 }, () => {
  it('不传 extra_info 时 disconnect detail 里不含 extra_info 字段', async () => {
    const r = rid();
    const aid = `ei-compat-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ei-compat');
    const c1 = makeClient(sharedPath, true);
    const c2 = makeClient(sharedPath, true);

    try {
      // c1 连接，不传 extra_info
      await connectLongWithExtraInfo(c1, aid, { slotId: 'main' });
      expect(c1.state).toBe('ready');

      // 监听 c1 的 gateway.disconnect 事件
      interface DisconnectDetail {
        self_extra_info?: Record<string, unknown>;
        new_extra_info?: Record<string, unknown>;
        [k: string]: unknown;
      }
      const disconnectEvents: DisconnectDetail[] = [];
      let resolveDisconnect: (() => void) | null = null;
      const disconnectReceived = new Promise<void>(resolve => {
        resolveDisconnect = resolve;
      });

      c1.on('gateway.disconnect', (data: unknown) => {
        if (data && typeof data === 'object') {
          const detail = (data as { detail?: DisconnectDetail }).detail ?? (data as DisconnectDetail);
          disconnectEvents.push(detail);
          if (resolveDisconnect) resolveDisconnect();
        }
      });

      // c2 同槽位连接，也不传 extra_info，应踢掉 c1
      await connectLongWithExtraInfo(c2, aid, { slotId: 'main', registerAid: false });
      expect(c2.state).toBe('ready');

      // 等待 c1 收到 disconnect 事件
      await Promise.race([
        disconnectReceived,
        sleep(10_000).then(() => {
          throw new Error(`c1 did not receive gateway.disconnect event, captured=${disconnectEvents.length}`);
        }),
      ]);

      expect(disconnectEvents.length).toBeGreaterThan(0);
      const detail = disconnectEvents[0];

      // 不传 extra_info 时，detail 里不应有实质内容（undefined 或空对象均可）
      const selfEI = detail.self_extra_info;
      expect(selfEI === undefined || (typeof selfEI === 'object' && selfEI !== null && Object.keys(selfEI).length === 0)).toBe(true);
      const newEI = detail.new_extra_info;
      expect(newEI === undefined || (typeof newEI === 'object' && newEI !== null && Object.keys(newEI).length === 0)).toBe(true);
    } finally {
      await safeClose(c1);
      await safeClose(c2);
    }
  });
});
