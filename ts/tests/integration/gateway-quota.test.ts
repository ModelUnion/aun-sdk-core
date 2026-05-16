/**
 * Gateway 长连接配额 + 短连接空闲 TTL 滑动窗口 集成测试 — 与 Python 单元测试对齐。
 *
 * 4 个用例：
 *   1. (aid, device) → slot 配额超限 — 同 aid+device 起 11 个长连接（不同 slot），
 *      第 11 个进入时第 1 个被服务端 4015 关闭，detail.quota_kind === "aid_device_slot_quota_exceeded"
 *   2. aid → device 配额超限 — 同 aid 占满 10 个 device，第 11 个 device 进入时第 1 个 device 被踢
 *   3. device → aid 配额超限 — 同 device 上挂 10 个 aid，第 11 个 aid 进入时第 1 个 aid 被踢
 *   4. 短连接空闲 TTL 滑动窗口 — short_ttl_ms=2000，每秒 ping 保活 → 不应被踢；
 *      停 ping → ~2s 后被 4014 踢
 *
 * 运行环境（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/integration/gateway-quota.test.ts"
 *
 * 前置条件：
 *   - Docker 单域环境运行中（kite-app + kite-mysql）
 *   - 服务端配额默认值 GATEWAY_LONG_*=10
 *   - kite-ts-tester 容器内 AUN_DATA_ROOT=/data/aun
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import { AUNClient } from '../../src/client.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();
const REQUIRED_HOSTS = [ISSUER, GATEWAY_DISCOVERY_AID];

// ── 网络可达性探测：DNS 能解析 + 端口能连即可 ────────────────────────

function canConnect(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (ok: boolean): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function hostResolves(host: string): Promise<boolean> {
  try {
    await dns.lookup(host);
    return true;
  } catch {
    return false;
  }
}

async function canReachGateway(): Promise<boolean> {
  const resolved = await Promise.all(REQUIRED_HOSTS.map(h => hostResolves(h)));
  if (resolved.some(ok => !ok)) return false;
  for (const port of [443, 20001]) {
    const checks = await Promise.all(REQUIRED_HOSTS.map(h => canConnect(h, port)));
    if (checks.every(Boolean)) return true;
  }
  return false;
}

// ── 辅助函数 ──────────────────────────────────────────────────────

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function makeAunPath(tag: string): string {
  const base = AUN_DATA_ROOT
    ? path.join(AUN_DATA_ROOT, 'single-domain', 'persistent', '..')
    : os.tmpdir();
  const root = path.join(base, `ts_quota_${tag}_${rid()}`);
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function makeClient(aunPath: string): AUNClient {
  const client = new AUNClient({ aun_path: aunPath }, false);
  ((client as unknown) as {
    _configModel: { requireForwardSecrecy: boolean };
  })._configModel.requireForwardSecrecy = false;
  return client;
}

function setDeviceId(client: AUNClient, deviceId: string): void {
  ((client as unknown) as { _deviceId: string })._deviceId = deviceId;
}

async function resolveGatewayInto(client: AUNClient): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
}

async function connectLong(
  client: AUNClient,
  aid: string,
  options: { slotId?: string; createAid?: boolean; deviceId?: string } = {},
): Promise<void> {
  if (options.deviceId) setDeviceId(client, options.deviceId);
  await resolveGatewayInto(client);
  if (options.createAid !== false) {
    try {
      await client.auth.createAid({ aid });
    } catch (err) {
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
  options: { slotId?: string; shortTtlMs?: number; deviceId?: string } = {},
): Promise<void> {
  if (options.deviceId) setDeviceId(client, options.deviceId);
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

interface DisconnectInfo {
  code?: number;
  reason?: string;
  detail?: Record<string, unknown>;
}

/** 订阅 gateway.disconnect，返回最近一次的 disconnect 信息（数组形式按到达顺序追加）。 */
function captureDisconnect(client: AUNClient): DisconnectInfo[] {
  const captured: DisconnectInfo[] = [];
  client.on('gateway.disconnect', (data: unknown) => {
    if (data && typeof data === 'object') {
      const d = data as DisconnectInfo;
      captured.push({
        code: typeof d.code === 'number' ? d.code : undefined,
        reason: typeof d.reason === 'string' ? d.reason : '',
        detail: (d.detail && typeof d.detail === 'object' && !Array.isArray(d.detail))
          ? (d.detail as Record<string, unknown>)
          : {},
      });
    }
  });
  return captured;
}

async function waitFor(predicate: () => boolean, timeoutMs: number, pollMs = 100): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await sleep(pollMs);
  }
  return predicate();
}

// ── 配额上限：与服务端默认 GATEWAY_LONG_*_QUOTA 对齐 ────────────────

const QUOTA_LIMIT = 10;

// ── 测试用例 ──────────────────────────────────────────────────────

describe('Gateway 长连接配额 + 短连接空闲 TTL 集成测试', () => {
  let canRun = false;

  beforeAll(async () => {
    canRun = await canReachGateway();
    if (!canRun) {
      console.log(`SKIP: 无法解析或连接 ${REQUIRED_HOSTS.join(' / ')}（443/20001 端口），用例不具备运行条件`);
    }
  });

  function shouldSkip(): boolean {
    return !canRun;
  }

  it('1. (aid, device) slot 配额超限 — 第 11 个进入踢最早 slot (4015)', async () => {
    if (shouldSkip()) return;
    const r = rid();
    const aid = `q1-${r}.${ISSUER}`;
    const sharedPath = makeAunPath('q1');

    // setup：注册 aid（共享 keystore，所有客户端复用）
    const setup = makeClient(sharedPath);
    await resolveGatewayInto(setup);
    await setup.auth.createAid({ aid });
    await safeClose(setup);

    const longs: Array<{ client: AUNClient; slotId: string; captured: DisconnectInfo[] }> = [];
    let overflow: AUNClient | null = null;

    try {
      // 占满 10 个 slot（同 aid+device，因为共用 sharedPath → 同 .device_id）
      for (let i = 0; i < QUOTA_LIMIT; i++) {
        const c = makeClient(sharedPath);
        const captured = captureDisconnect(c);
        const slotId = `slot-${i}`;
        await connectLong(c, aid, { slotId, createAid: false });
        longs.push({ client: c, slotId, captured });
      }
      await sleep(500);
      // 此时全部应为 connected
      for (let i = 0; i < longs.length; i++) {
        expect(longs[i].client.state, `setup long[${i}] state`).toBe('connected');
      }

      // 第 11 个 slot 进入 — 应踢掉 slot-0
      overflow = makeClient(sharedPath);
      await connectLong(overflow, aid, { slotId: 'slot-NEW', createAid: false });
      expect(overflow.state).toBe('connected');

      // 等 long[0] 收到 4015 disconnect
      const evicted = longs[0];
      const ok = await waitFor(() => evicted.captured.length > 0, 5000);
      expect(ok, `long[0] (slot-0) should be evicted within 5s`).toBe(true);
      const ev = evicted.captured[0];
      expect(ev.code).toBe(4015);
      expect(ev.detail?.quota_kind).toBe('aid_device_slot_quota_exceeded');
      expect(ev.detail?.aid).toBe(aid);
      expect(ev.detail?.slot_id).toBe('slot-0');
      const evictedBy = ev.detail?.evicted_by as Record<string, unknown> | undefined;
      expect(evictedBy?.slot_id).toBe('slot-NEW');

      // 验证不重连（4015 在 _NO_RECONNECT_CODES 中）
      await sleep(800);
      expect(evicted.client.state).not.toBe('connected');
      expect(evicted.client.state).not.toBe('reconnecting');

      // 其他 slot 不受影响
      for (let i = 1; i < longs.length; i++) {
        expect(longs[i].client.state, `long[${i}] should remain connected`).toBe('connected');
      }
    } finally {
      for (const e of longs) await safeClose(e.client);
      await safeClose(overflow);
    }
  }, 120_000);

  it('2. aid → device 配额超限 — 第 11 个 device 进入踢最早 device (4015)', async () => {
    if (shouldSkip()) return;
    const r = rid();
    const aid = `q2-${r}.${ISSUER}`;
    const setupPath = makeAunPath('q2-setup');

    // setup：注册 aid 一次（cert/key 落到 setupPath/AIDs/<aid>/）
    const setup = makeClient(setupPath);
    await resolveGatewayInto(setup);
    await setup.auth.createAid({ aid });
    await safeClose(setup);

    // 为 11 个 device 准备独立 aun_path（每个都有不同 .device_id），
    // 把 setupPath/AIDs/<aid> 拷贝到每个 device path，确保身份一致
    function safeAid(s: string): string {
      return s.replace(/[/\\:]/g, '_');
    }
    function copyDir(src: string, dst: string): void {
      fs.mkdirSync(dst, { recursive: true });
      for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const sp = path.join(src, entry.name);
        const dp = path.join(dst, entry.name);
        if (entry.isDirectory()) copyDir(sp, dp);
        else fs.copyFileSync(sp, dp);
      }
    }
    const aidDir = path.join(setupPath, 'AIDs', safeAid(aid));

    const longs: Array<{ client: AUNClient; deviceId: string; captured: DisconnectInfo[] }> = [];
    let overflow: AUNClient | null = null;

    try {
      // 占满 10 个 device — 每个独立 aun_path
      for (let i = 0; i < QUOTA_LIMIT; i++) {
        const dPath = makeAunPath(`q2-d${i}`);
        copyDir(aidDir, path.join(dPath, 'AIDs', safeAid(aid)));
        // 复用 setup 的 .seed（保证 SecretStore 主密钥派生一致，否则
        // identity/private_key 解密会失败）
        const setupSeed = path.join(setupPath, '.seed');
        if (fs.existsSync(setupSeed)) {
          fs.copyFileSync(setupSeed, path.join(dPath, '.seed'));
        }
        const c = makeClient(dPath);
        const captured = captureDisconnect(c);
        const deviceId = `q2-dev-${i}-${r}`;
        await connectLong(c, aid, { slotId: 'main', createAid: false, deviceId });
        longs.push({ client: c, deviceId, captured });
      }
      await sleep(500);
      for (let i = 0; i < longs.length; i++) {
        expect(longs[i].client.state, `setup device[${i}] state`).toBe('connected');
      }

      // 第 11 个 device 进入 — 踢最早 device (longs[0])
      const ovPath = makeAunPath('q2-dNEW');
      copyDir(aidDir, path.join(ovPath, 'AIDs', safeAid(aid)));
      const setupSeed = path.join(setupPath, '.seed');
      if (fs.existsSync(setupSeed)) {
        fs.copyFileSync(setupSeed, path.join(ovPath, '.seed'));
      }
      overflow = makeClient(ovPath);
      const newDeviceId = `q2-dev-NEW-${r}`;
      await connectLong(overflow, aid, { slotId: 'main', createAid: false, deviceId: newDeviceId });
      expect(overflow.state).toBe('connected');

      const evicted = longs[0];
      const ok = await waitFor(() => evicted.captured.length > 0, 5000);
      expect(ok, `device[0] should be evicted within 5s`).toBe(true);
      const ev = evicted.captured[0];
      expect(ev.code).toBe(4015);
      expect(ev.detail?.quota_kind).toBe('aid_devices_quota_exceeded');
      expect(ev.detail?.aid).toBe(aid);
      expect(ev.detail?.device_id).toBe(longs[0].deviceId);
      const evictedBy = ev.detail?.evicted_by as Record<string, unknown> | undefined;
      expect(evictedBy?.device_id).toBe(newDeviceId);

      await sleep(800);
      expect(evicted.client.state).not.toBe('connected');
      expect(evicted.client.state).not.toBe('reconnecting');

      for (let i = 1; i < longs.length; i++) {
        expect(longs[i].client.state, `device[${i}] should remain connected`).toBe('connected');
      }
    } finally {
      for (const e of longs) await safeClose(e.client);
      await safeClose(overflow);
    }
  }, 180_000);

  it('3. device → aid 配额超限 — 第 11 个 aid 进入踢最早 aid (4015)', async () => {
    if (shouldSkip()) return;
    const r = rid();
    const sharedPath = makeAunPath('q3');

    // setup：在同一 path（同一 device）下注册 11 个不同 aid
    const setup = makeClient(sharedPath);
    await resolveGatewayInto(setup);
    const aids: string[] = [];
    for (let i = 0; i <= QUOTA_LIMIT; i++) {
      const aid = `q3-a${i}-${r}.${ISSUER}`;
      await setup.auth.createAid({ aid });
      aids.push(aid);
    }
    await safeClose(setup);

    const longs: Array<{ client: AUNClient; aid: string; captured: DisconnectInfo[] }> = [];
    let overflow: AUNClient | null = null;

    try {
      // 占满 10 个 aid（同 device，共享 sharedPath → 同 .device_id）
      for (let i = 0; i < QUOTA_LIMIT; i++) {
        const c = makeClient(sharedPath);
        const captured = captureDisconnect(c);
        await connectLong(c, aids[i], { slotId: 'main', createAid: false });
        longs.push({ client: c, aid: aids[i], captured });
      }
      await sleep(500);
      for (let i = 0; i < longs.length; i++) {
        expect(longs[i].client.state, `setup aid[${i}] state`).toBe('connected');
      }

      // 第 11 个 aid 进入 — 踢最早 aid（longs[0]）
      overflow = makeClient(sharedPath);
      const newAid = aids[QUOTA_LIMIT];
      await connectLong(overflow, newAid, { slotId: 'main', createAid: false });
      expect(overflow.state).toBe('connected');

      const evicted = longs[0];
      const ok = await waitFor(() => evicted.captured.length > 0, 5000);
      expect(ok, `aid[0] should be evicted within 5s`).toBe(true);
      const ev = evicted.captured[0];
      expect(ev.code).toBe(4015);
      expect(ev.detail?.quota_kind).toBe('device_aids_quota_exceeded');
      expect(ev.detail?.aid).toBe(longs[0].aid);
      const evictedBy = ev.detail?.evicted_by as Record<string, unknown> | undefined;
      expect(evictedBy?.aid).toBe(newAid);

      await sleep(800);
      expect(evicted.client.state).not.toBe('connected');
      expect(evicted.client.state).not.toBe('reconnecting');

      for (let i = 1; i < longs.length; i++) {
        expect(longs[i].client.state, `aid[${i}] should remain connected`).toBe('connected');
      }
    } finally {
      for (const e of longs) await safeClose(e.client);
      await safeClose(overflow);
    }
  }, 180_000);

  it('4. 短连接空闲 TTL 滑动窗口 — 保活不踢 / 停活 ~2s 后 4014 关闭', async () => {
    if (shouldSkip()) return;
    const r = rid();
    const aid = `q4-${r}.${ISSUER}`;
    const sharedPath = makeAunPath('q4');

    const setup = makeClient(sharedPath);
    await resolveGatewayInto(setup);
    await setup.auth.createAid({ aid });
    await safeClose(setup);

    // Phase A：保活短连接（每秒 ping），ttl=2000ms，活 5s 应不被踢
    const aliveClient = makeClient(sharedPath);
    const aliveCapture = captureDisconnect(aliveClient);
    let stopPinging = false;
    let pingTask: Promise<void> | null = null;

    try {
      await connectShort(aliveClient, aid, { slotId: 'q4-keep', shortTtlMs: 2000 });
      expect(aliveClient.state).toBe('connected');

      // 后台每秒 ping 保活
      pingTask = (async () => {
        while (!stopPinging && aliveClient.state === 'connected') {
          try {
            await aliveClient.call('meta.ping');
          } catch {
            // 已断开就退出
            break;
          }
          await sleep(1000);
        }
      })();

      // 保活 5s（ttl=2s 的 2.5 倍）期间不应被踢
      await sleep(5000);
      expect(aliveCapture.length, `保活期间不应收到 disconnect: got ${JSON.stringify(aliveCapture)}`).toBe(0);
      expect(aliveClient.state).toBe('connected');

      // 停止 ping，等待 ttl 触发
      stopPinging = true;
      if (pingTask) {
        await pingTask.catch(() => { /* ignore */ });
        pingTask = null;
      }

      const ok = await waitFor(() => aliveCapture.length > 0, 6000);
      expect(ok, `停 ping 后 ~2-5s 内应被服务端关闭`).toBe(true);
      const ev = aliveCapture[0];
      expect(ev.code).toBe(4014);
      expect(ev.detail?.aid).toBe(aid);
      expect(typeof ev.detail?.idle_ms).toBe('number');
      expect(ev.detail?.ttl_ms).toBe(2000);
    } finally {
      stopPinging = true;
      if (pingTask) await pingTask.catch(() => { /* ignore */ });
      await safeClose(aliveClient);
    }
  }, 60_000);
});
