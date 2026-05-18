/**
 * 长短连接共存 集成测试 + E2E 测试 — 与 Python SDK 完全对齐。
 *
 * 集成测试（8 个）：
 *   1. 同身份短连接发消息 — alice 长 + alice 短共享 (aid, device, slot)，CLI 给 bob 发
 *   2. 短连接不踢长连接
 *   3. 短连接容量上限 → 4013
 *   4. short_ttl_ms 兜底 → 4014
 *   5. 长连接互踢，短连接不受影响
 *   6. 短连接不发布 client.online
 *   7. hello-ok 回包 connection.kind
 *   8. 短连接禁用 token 刷新
 *
 * E2E 测试（5 个）：
 *   1. CLI 顺序发 5 条
 *   2. 5 个并发 CLI 短连接
 *   3. alice 长连接收 bob 回复
 *   4. CLI 崩溃 + ttl 兜底
 *   5. 短连接生命周期后长连接仍收消息
 *
 * 运行环境（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/integration/long-short.test.ts"
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

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();

// ── 辅助函数 ──────────────────────────────────────────────────────

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

/** 创建一个独立的 aun_path（每个 tag 一个唯一目录） */
function makeAunPath(tag: string): string {
  const base = AUN_DATA_ROOT
    ? path.join(AUN_DATA_ROOT, 'single-domain', 'persistent', '..')
    : os.tmpdir();
  const root = path.join(base, `ts_long_short_${tag}_${rid()}`);
  fs.mkdirSync(root, { recursive: true });
  return root;
}

/**
 * 创建测试客户端。
 * - tagOrPath: tag 名（自动新建独立 path）或已有 aun_path
 * - isPath=true 时复用同一 keystore（CLI 短连接复用守护进程身份）
 */
function makeClient(tagOrPath: string, isPath: boolean = false): AUNClient {
  const root = isPath ? tagOrPath : makeAunPath(tagOrPath);
  const client = new AUNClient({ aun_path: root }, false);
  ((client as unknown) as {
    _configModel: { requireForwardSecrecy: boolean };
  })._configModel.requireForwardSecrecy = false;
  return client;
}

async function resolveGatewayInto(client: AUNClient): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
}

async function connectLong(
  client: AUNClient,
  aid: string,
  options: { slotId?: string; createAid?: boolean } = {},
): Promise<void> {
  await resolveGatewayInto(client);
  if (options.createAid !== false) {
    try {
      await client.auth.createAid({ aid });
    } catch (err) {
      // AID 已存在不报错（共享 keystore 多次创建）
      const msg = String(err);
      if (!/exists|already/i.test(msg)) throw err;
    }
  }
  const auth = await client.auth.authenticate({ aid });
  const opts: Record<string, unknown> = {
    auto_reconnect: false,
    heartbeat_interval: 30,
  };
  if (options.slotId !== undefined) opts.slot_id = options.slotId;
  await client.connect(auth, opts);
}

async function connectShort(
  client: AUNClient,
  aid: string,
  options: { slotId?: string; shortTtlMs?: number } = {},
): Promise<void> {
  await resolveGatewayInto(client);
  const auth = await client.auth.authenticate({ aid });
  const opts: Record<string, unknown> = {
    connection_kind: 'short',
    auto_reconnect: false,
  };
  if (options.slotId !== undefined) opts.slot_id = options.slotId;
  if (options.shortTtlMs !== undefined && options.shortTtlMs > 0) {
    opts.short_ttl_ms = options.shortTtlMs;
  }
  await client.connect(auth, opts);
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

interface MessageData {
  from?: string;
  payload?: { text?: string; type?: string };
  seq?: number;
  [k: string]: unknown;
}

function payloadText(data: unknown): string {
  if (data === null || typeof data !== 'object') return '';
  const m = data as MessageData;
  return String(m.payload?.text ?? '');
}

// ── 集成测试 ──────────────────────────────────────────────────────

describe('长短连接 集成 - 同身份短连接发消息', { timeout: 90_000 }, () => {
  it('CLI 短连接发消息: RPC 原路返回 + bob 收到 + alice 长连接无感', async () => {
    const r = rid();
    const aliceAid = `lst-a1-${r}.${ISSUER}`;
    const bobAid = `lst-b1-${r}.${ISSUER}`;

    const alicePath = makeAunPath('ls1-alice');
    const bobPath = makeAunPath('ls1-bob');
    const aliceLong = makeClient(alicePath, true);
    const aliceShort = makeClient(alicePath, true);
    const bobLong = makeClient(bobPath, true);

    try {
      await connectLong(aliceLong, aliceAid, { slotId: 'main' });
      await connectLong(bobLong, bobAid, { slotId: 'main' });

      const aliceUnexpected: unknown[] = [];
      aliceLong.on('message.received', (data: unknown) => {
        aliceUnexpected.push(data);
      });

      const text = `cli-to-bob-${r}`;
      const bobCaptured: MessageData[] = [];
      let resolveBob: (() => void) | null = null;
      const bobReceived = new Promise<void>(resolve => {
        resolveBob = resolve;
      });

      bobLong.on('message.received', (data: unknown) => {
        if (payloadText(data) === text) {
          bobCaptured.push(data as MessageData);
          if (resolveBob) resolveBob();
        }
      });

      // alice 短连接（同 device, 同 slot）
      await connectShort(aliceShort, aliceAid, { slotId: 'main' });
      expect(aliceShort.state).toBe('connected');

      const result = await aliceShort.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text },
      }) as Record<string, unknown>;

      // 1) RPC 原路返回
      expect(['sent', 'delivered']).toContain(result?.status);

      // 短连接立即关
      await aliceShort.close();

      // 2) bob 收到
      await Promise.race([
        bobReceived,
        sleep(10_000).then(() => {
          throw new Error(`bob did not receive: captured=${bobCaptured.length}`);
        }),
      ]);
      expect(bobCaptured.length).toBeGreaterThan(0);

      // 3) alice 长连接无感（同 device+slot，不 self-sync）
      await sleep(2_000);
      expect(aliceUnexpected.length).toBe(0);

      // 4) alice 长连接仍正常
      await aliceLong.call('meta.ping');
    } finally {
      await safeClose(aliceShort);
      await safeClose(aliceLong);
      await safeClose(bobLong);
    }
  });
});

describe('长短连接 集成 - 短连接不踢长连接', { timeout: 60_000 }, () => {
  it('同 aid/device/slot 短连接进入后，长连接仍 connected', async () => {
    const r = rid();
    const longAid = `lst-l2-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ls2');
    const longClient = makeClient(sharedPath, true);
    const shortClient = makeClient(sharedPath, true);

    try {
      await connectLong(longClient, longAid, { slotId: 'main' });

      const longStates: string[] = [];
      longClient.on('connection.state', (data: unknown) => {
        if (typeof data === 'object' && data !== null) {
          longStates.push(String((data as { state?: string }).state ?? ''));
        }
      });

      await connectShort(shortClient, longAid, { slotId: 'main' });
      await sleep(1_000);

      expect(longClient.state).toBe('connected');

      // 短连接 ping 一次再关
      await shortClient.call('meta.ping');
      await shortClient.close();
      await sleep(500);

      expect(longClient.state).toBe('connected');
      await longClient.call('meta.ping');
    } finally {
      await safeClose(longClient);
      await safeClose(shortClient);
    }
  });
});

describe('长短连接 集成 - 短连接容量上限 → 4013', { timeout: 90_000 }, () => {
  it('同槽位起 10 个短连接，第 11 个应被拒（4013）', async () => {
    const r = rid();
    const aid = `lst-c3-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ls3');
    const setup = makeClient(sharedPath, true);
    const shorts: AUNClient[] = [];
    const overflow = makeClient(sharedPath, true);

    try {
      await resolveGatewayInto(setup);
      await setup.auth.createAid({ aid });
      await setup.close();

      // 起 10 个短连接（共享 keystore）
      for (let i = 0; i < 10; i++) {
        const c = makeClient(sharedPath, true);
        shorts.push(c);
        await connectShort(c, aid, { slotId: 'cap' });
      }
      await sleep(500);

      // 第 11 个应被拒
      let rejected = false;
      let errMsg = '';
      try {
        await connectShort(overflow, aid, { slotId: 'cap' });
      } catch (err) {
        rejected = true;
        errMsg = String(err);
      }

      if (!rejected) {
        throw new Error('11th short connection unexpectedly succeeded');
      }
      expect(
        /short_connection_capacity_exceeded|4013/i.test(errMsg),
        `expected 4013/short_connection_capacity_exceeded, got: ${errMsg}`,
      ).toBe(true);
    } finally {
      for (const c of shorts) await safeClose(c);
      await safeClose(setup);
      await safeClose(overflow);
    }
  });
});

describe('长短连接 集成 - short_ttl_ms 兜底 → 4014', { timeout: 60_000 }, () => {
  it('短连接传 ttl=2000ms，~2s 后服务端关闭', async () => {
    const r = rid();
    const aid = `lst-t4-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ls4');
    const setup = makeClient(sharedPath, true);
    const short = makeClient(sharedPath, true);

    try {
      await resolveGatewayInto(setup);
      await setup.auth.createAid({ aid });
      await setup.close();

      await connectShort(short, aid, { slotId: 'ttl', shortTtlMs: 2000 });
      expect(short.state).toBe('connected');

      // 等 ~5s，服务端应主动关闭
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        if (
          short.state === 'disconnected' ||
          short.state === 'closed' ||
          short.state === 'terminal_failed'
        ) {
          break;
        }
        await sleep(300);
      }
      expect(short.state).not.toBe('connected');
    } finally {
      await safeClose(setup);
      await safeClose(short);
    }
  });
});

describe('长短连接 集成 - 长连接互踢，短连接不受影响', { timeout: 90_000 }, () => {
  it('同槽位旧长被新长踢掉，3 个短连接继续在线', async () => {
    const r = rid();
    const aid = `lst-r5-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ls5');
    const setup = makeClient(sharedPath, true);
    const longOld = makeClient(sharedPath, true);
    const longNew = makeClient(sharedPath, true);
    const shorts: AUNClient[] = [];

    try {
      await resolveGatewayInto(setup);
      await setup.auth.createAid({ aid });
      await setup.close();

      await connectLong(longOld, aid, { slotId: 'slot-x', createAid: false });
      for (let i = 0; i < 3; i++) {
        const c = makeClient(sharedPath, true);
        shorts.push(c);
        await connectShort(c, aid, { slotId: 'slot-x' });
      }
      await sleep(500);

      // 新长连接同槽位进入，应踢旧长
      await connectLong(longNew, aid, { slotId: 'slot-x', createAid: false });
      await sleep(1_500);

      expect(longOld.state).not.toBe('connected');
      expect(longNew.state).toBe('connected');

      // 短连接仍在
      for (let i = 0; i < shorts.length; i++) {
        expect(shorts[i].state, `short[${i}] should be connected`).toBe('connected');
        await shorts[i].call('meta.ping');
      }
    } finally {
      for (const c of shorts) await safeClose(c);
      await safeClose(longOld);
      await safeClose(longNew);
      await safeClose(setup);
    }
  });
});

describe('长短连接 集成 - 短连接不发布 client.online', { timeout: 60_000 }, () => {
  it('observer 用 message.query_online 查短连接 AID 应返回 offline', async () => {
    const r = rid();
    const shortAid = `lst-o6-${r}.${ISSUER}`;
    const observerAid = `lst-q6-${r}.${ISSUER}`;

    const shortPath = makeAunPath('ls6-short');
    const observerPath = makeAunPath('ls6-observer');
    const setup = makeClient(shortPath, true);
    const observer = makeClient(observerPath, true);
    const short = makeClient(shortPath, true);

    try {
      await resolveGatewayInto(setup);
      await setup.auth.createAid({ aid: shortAid });
      await setup.close();

      await connectLong(observer, observerAid, { slotId: 'obs' });
      await connectShort(short, shortAid, { slotId: 'cli' });
      await sleep(500);

      const result = await observer.call('message.query_online', {
        aids: [shortAid],
      }) as Record<string, unknown>;
      const onlineMap = (result?.online ?? {}) as Record<string, boolean>;
      expect(onlineMap[shortAid] === true).toBe(false);
    } finally {
      await safeClose(setup);
      await safeClose(observer);
      await safeClose(short);
    }
  });
});

describe('长短连接 集成 - hello-ok 回包 connection.kind', { timeout: 60_000 }, () => {
  it('短连接 connect 后 _sessionOptions.connection_kind === "short"', async () => {
    const r = rid();
    const aid = `lst-h7-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ls7');
    const setup = makeClient(sharedPath, true);
    const longClient = makeClient(sharedPath, true);
    const shortClient = makeClient(sharedPath, true);

    try {
      await resolveGatewayInto(setup);
      await setup.auth.createAid({ aid });
      await setup.close();

      await connectLong(longClient, aid, { slotId: 'h7-l', createAid: false });
      await longClient.close();

      await connectShort(shortClient, aid, { slotId: 'h7-s' });
      const sessionOpts = (shortClient as unknown as {
        _sessionOptions: { connection_kind?: string };
      })._sessionOptions;
      expect(sessionOpts.connection_kind).toBe('short');
    } finally {
      await safeClose(setup);
      await safeClose(longClient);
      await safeClose(shortClient);
    }
  });
});

describe('长短连接 集成 - 短连接禁用 token 刷新', { timeout: 60_000 }, () => {
  it('短连接 connect 后有心跳/无 token 刷新', async () => {
    const r = rid();
    const aid = `lst-d8-${r}.${ISSUER}`;

    const sharedPath = makeAunPath('ls8');
    const setup = makeClient(sharedPath, true);
    const short = makeClient(sharedPath, true);

    try {
      await resolveGatewayInto(setup);
      await setup.auth.createAid({ aid });
      await setup.close();

      await connectShort(short, aid, { slotId: 'd8' });
      const internals = short as unknown as {
        _sessionOptions: { auto_reconnect?: boolean };
        _heartbeatTimer: unknown;
        _tokenRefreshTimer: unknown;
      };
      expect(internals._heartbeatTimer).not.toBeNull();
      expect(internals._tokenRefreshTimer).toBeNull();
    } finally {
      await safeClose(setup);
      await safeClose(short);
    }
  });
});

// ── E2E 测试 ──────────────────────────────────────────────────────

describe('长短连接 E2E - CLI 顺序发 5 条', { timeout: 120_000 }, () => {
  it('alice CLI 短连接顺序发 5 条给 bob，bob 收齐 + alice 长无感', async () => {
    const r = rid();
    const aliceAid = `e2e1-a-${r}.${ISSUER}`;
    const bobAid = `e2e1-b-${r}.${ISSUER}`;

    const alicePath = makeAunPath('e1-alice');
    const bobPath = makeAunPath('e1-bob');
    const aliceLong = makeClient(alicePath, true);
    const bobLong = makeClient(bobPath, true);

    try {
      await connectLong(aliceLong, aliceAid);
      await connectLong(bobLong, bobAid);

      const aliceUnexpected: unknown[] = [];
      aliceLong.on('message.received', (d: unknown) => {
        aliceUnexpected.push(d);
      });

      const texts = Array.from({ length: 5 }, (_, i) => `e2e1-msg-${i}-${r}`);
      const expected = new Set(texts);
      const bobReceived: string[] = [];
      let resolveAll: (() => void) | null = null;
      const allReceived = new Promise<void>(resolve => {
        resolveAll = resolve;
      });

      bobLong.on('message.received', (data: unknown) => {
        const t = payloadText(data);
        if (expected.has(t) && !bobReceived.includes(t)) {
          bobReceived.push(t);
          if (bobReceived.length >= 5 && resolveAll) resolveAll();
        }
      });

      // 顺序发 5 条短连接消息（每次新建短连接，同 aid/device/slot）
      for (const text of texts) {
        const cli = makeClient(alicePath, true);
        try {
          await connectShort(cli, aliceAid);
          const result = await cli.call('message.send', {
            to: bobAid,
            payload: { type: 'text', text },
          }) as Record<string, unknown>;
          expect(['sent', 'delivered']).toContain(result?.status);
        } finally {
          await safeClose(cli);
        }
      }

      await Promise.race([
        allReceived,
        sleep(15_000).then(() => {
          throw new Error(`bob received ${bobReceived.length}/5: ${bobReceived.join(',')}`);
        }),
      ]);
      expect(bobReceived.length).toBe(5);

      // alice 长连接无感
      await sleep(2_000);
      expect(aliceUnexpected.length).toBe(0);

      // alice 长连接仍活
      await aliceLong.call('meta.ping');
    } finally {
      await safeClose(aliceLong);
      await safeClose(bobLong);
    }
  });
});

describe('长短连接 E2E - 5 个并发短连接', { timeout: 120_000 }, () => {
  it('5 个并发 CLI 短连接同时发，全部成功 + bob 收齐', async () => {
    const r = rid();
    const aliceAid = `e2e2-a-${r}.${ISSUER}`;
    const bobAid = `e2e2-b-${r}.${ISSUER}`;

    const alicePath = makeAunPath('e2-alice');
    const bobPath = makeAunPath('e2-bob');
    const aliceLong = makeClient(alicePath, true);
    const bobLong = makeClient(bobPath, true);

    try {
      await connectLong(aliceLong, aliceAid);
      await connectLong(bobLong, bobAid);

      const expected = new Set(
        Array.from({ length: 5 }, (_, i) => `e2e2-msg-${i}-${r}`),
      );
      const bobReceived: string[] = [];
      let resolveAll: (() => void) | null = null;
      const allReceived = new Promise<void>(resolve => {
        resolveAll = resolve;
      });

      bobLong.on('message.received', (data: unknown) => {
        const t = payloadText(data);
        if (expected.has(t) && !bobReceived.includes(t)) {
          bobReceived.push(t);
          if (bobReceived.length >= 5 && resolveAll) resolveAll();
        }
      });

      // 5 个并发短连接（同 aid，不同 slot 避免容量冲突）
      const sendOne = async (i: number): Promise<Record<string, unknown>> => {
        const cli = makeClient(alicePath, true);
        try {
          await connectShort(cli, aliceAid, { slotId: `cli-${i}` });
          const result = await cli.call('message.send', {
            to: bobAid,
            payload: { type: 'text', text: `e2e2-msg-${i}-${r}` },
          }) as Record<string, unknown>;
          return result;
        } finally {
          await safeClose(cli);
        }
      };

      const results = await Promise.all(
        Array.from({ length: 5 }, (_, i) => sendOne(i)),
      );
      for (const result of results) {
        expect(['sent', 'delivered']).toContain(result?.status);
      }

      await Promise.race([
        allReceived,
        sleep(15_000).then(() => {
          throw new Error(`bob received ${bobReceived.length}/5`);
        }),
      ]);
      expect(bobReceived.length).toBe(5);
    } finally {
      await safeClose(aliceLong);
      await safeClose(bobLong);
    }
  });
});

describe('长短连接 E2E - alice 长连接收 bob 回复', { timeout: 90_000 }, () => {
  it('CLI 先给 bob 发，bob 回复后 alice 长连接收到', async () => {
    const r = rid();
    const aliceAid = `e2e3-a-${r}.${ISSUER}`;
    const bobAid = `e2e3-b-${r}.${ISSUER}`;

    const alicePath = makeAunPath('e3-alice');
    const bobPath = makeAunPath('e3-bob');
    const aliceLong = makeClient(alicePath, true);
    const bobLong = makeClient(bobPath, true);

    try {
      await connectLong(aliceLong, aliceAid);
      await connectLong(bobLong, bobAid);

      // alice 用短连接给 bob 发一条（建立 prekey 交换）
      const cli = makeClient(alicePath, true);
      try {
        await connectShort(cli, aliceAid);
        await cli.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `e2e3-init-${r}` },
        });
      } finally {
        await safeClose(cli);
      }

      await sleep(1_000);

      // bob 回复 alice
      const replyText = `e2e3-reply-${r}`;
      const aliceCaptured: MessageData[] = [];
      let resolveReply: (() => void) | null = null;
      const aliceReceived = new Promise<void>(resolve => {
        resolveReply = resolve;
      });

      aliceLong.on('message.received', (data: unknown) => {
        if (payloadText(data) === replyText) {
          aliceCaptured.push(data as MessageData);
          if (resolveReply) resolveReply();
        }
      });

      const result = await bobLong.call('message.send', {
        to: aliceAid,
        payload: { type: 'text', text: replyText },
      }) as Record<string, unknown>;
      expect(['sent', 'delivered']).toContain(result?.status);

      await Promise.race([
        aliceReceived,
        sleep(10_000).then(() => {
          throw new Error('alice long timed out waiting for bob reply');
        }),
      ]);
      expect(aliceCaptured.length).toBeGreaterThan(0);
    } finally {
      await safeClose(aliceLong);
      await safeClose(bobLong);
    }
  });
});

describe('长短连接 E2E - CLI 崩溃 + ttl 兜底', { timeout: 90_000 }, () => {
  it('短连接不 close，ttl 兜底关闭，alice 长连接不受影响', async () => {
    const r = rid();
    const aliceAid = `e2e4-a-${r}.${ISSUER}`;
    const bobAid = `e2e4-b-${r}.${ISSUER}`;

    const alicePath = makeAunPath('e4-alice');
    const bobPath = makeAunPath('e4-bob');
    const aliceLong = makeClient(alicePath, true);
    const bobLong = makeClient(bobPath, true);
    let cliCrash: AUNClient | null = null;

    try {
      await connectLong(aliceLong, aliceAid);
      await connectLong(bobLong, bobAid);

      // CLI 短连接：建立但不 close（模拟崩溃），ttl=2s
      cliCrash = makeClient(alicePath, true);
      await connectShort(cliCrash, aliceAid, { shortTtlMs: 2000 });
      expect(cliCrash.state).toBe('connected');

      // 等 ttl 触发
      const deadline = Date.now() + 5_000;
      while (Date.now() < deadline) {
        if (
          cliCrash.state === 'disconnected' ||
          cliCrash.state === 'closed' ||
          cliCrash.state === 'terminal_failed'
        ) {
          break;
        }
        await sleep(300);
      }
      expect(cliCrash.state).not.toBe('connected');

      // alice 长连接仍活
      await aliceLong.call('meta.ping');

      // bob 给 alice 发，alice 长连接应收到
      const replyText = `e2e4-after-crash-${r}`;
      const aliceCaptured: MessageData[] = [];
      let resolveReply: (() => void) | null = null;
      const aliceReceived = new Promise<void>(resolve => {
        resolveReply = resolve;
      });

      aliceLong.on('message.received', (data: unknown) => {
        if (payloadText(data) === replyText) {
          aliceCaptured.push(data as MessageData);
          if (resolveReply) resolveReply();
        }
      });

      await bobLong.call('message.send', {
        to: aliceAid,
        payload: { type: 'text', text: replyText },
      });

      await Promise.race([
        aliceReceived,
        sleep(10_000).then(() => {
          throw new Error('alice long timed out after CLI crash');
        }),
      ]);
      expect(aliceCaptured.length).toBeGreaterThan(0);
    } finally {
      await safeClose(cliCrash);
      await safeClose(aliceLong);
      await safeClose(bobLong);
    }
  });
});

describe('长短连接 E2E - 短连接生命周期后长连接仍收消息', { timeout: 90_000 }, () => {
  it('CLI 发 → 断 → bob 回复 → alice 长连接收到', async () => {
    const r = rid();
    const aliceAid = `e2e5-a-${r}.${ISSUER}`;
    const bobAid = `e2e5-b-${r}.${ISSUER}`;

    const alicePath = makeAunPath('e5-alice');
    const bobPath = makeAunPath('e5-bob');
    const aliceLong = makeClient(alicePath, true);
    const bobLong = makeClient(bobPath, true);

    try {
      await connectLong(aliceLong, aliceAid);
      await connectLong(bobLong, bobAid);

      // Phase 1: CLI 短连接发消息给 bob
      const cli = makeClient(alicePath, true);
      try {
        await connectShort(cli, aliceAid);
        const result = await cli.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `e2e5-outbound-${r}` },
        }) as Record<string, unknown>;
        expect(['sent', 'delivered']).toContain(result?.status);
      } finally {
        await safeClose(cli);
      }

      await sleep(1_000);

      // Phase 2: bob 回复 alice
      const replyText = `e2e5-reply-${r}`;
      const aliceCaptured: MessageData[] = [];
      let resolveReply: (() => void) | null = null;
      const aliceReceived = new Promise<void>(resolve => {
        resolveReply = resolve;
      });

      aliceLong.on('message.received', (data: unknown) => {
        if (payloadText(data) === replyText) {
          aliceCaptured.push(data as MessageData);
          if (resolveReply) resolveReply();
        }
      });

      await bobLong.call('message.send', {
        to: aliceAid,
        payload: { type: 'text', text: replyText },
      });

      await Promise.race([
        aliceReceived,
        sleep(10_000).then(() => {
          throw new Error('alice long timed out waiting for reply after short lifecycle');
        }),
      ]);
      expect(aliceCaptured.length).toBeGreaterThan(0);
    } finally {
      await safeClose(aliceLong);
      await safeClose(bobLong);
    }
  });
});
