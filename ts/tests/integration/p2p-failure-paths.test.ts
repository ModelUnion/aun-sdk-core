/**
 * P2P 消息失败路径集成测试
 *
 * 覆盖：
 *   1. 明文发送不依赖对端 prekey
 *   2. 发送到不存在的 AID 应失败
 *   3. 明文消息可拉取
 *   4. 错误后序号正常递增
 *
 * 运行方法：
 *   npx vitest run tests/integration/p2p-failure-paths.test.ts
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - 运行环境能解析 gateway.agentid.pub
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { registerAndLoadIdentity, setGatewayForClient } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 60_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

// ── 辅助函数 ──────────────────────────────────────────────────────

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-p2p-fail-'));
  const client = new AUNClient({ aun_path: tmpDir, debug: true });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await setGatewayForClient(client, GATEWAY_DISCOVERY_AID);
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function payloadText(message: Record<string, unknown>): string {
  const payload = message.payload as Record<string, unknown> | undefined;
  return String(payload?.text ?? '');
}

function waitForP2pMessages(
  client: AUNClient,
  fromAid: string,
  expectedCount: number,
  timeoutMs: number,
  predicate?: (message: Record<string, unknown>) => boolean,
): Promise<Record<string, unknown>[]> {
  const inbox: Record<string, unknown>[] = [];
  let sub: { unsubscribe: () => void } | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let done = false;

  return new Promise(resolve => {
    const finish = () => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      sub?.unsubscribe();
      resolve(inbox);
    };

    sub = client.on('message.received', (data: unknown) => {
      if (typeof data !== 'object' || data === null) return;
      const message = data as Record<string, unknown>;
      if (message.from !== fromAid) return;
      if (predicate && !predicate(message)) return;
      inbox.push(message);
      if (inbox.length >= expectedCount) finish();
    });

    timer = setTimeout(finish, timeoutMs);
  });
}

// ── 明文发送不依赖对端 prekey ────────────────────────────────────────

describe('明文发送不依赖对端 prekey', () => {
  it('对端未上传 prekey 时，明文发送应成功', async () => {
    const rid = runId();
    const aliceAid = `pfp-a-${rid}.${ISSUER}`;
    const targetAid = `pfp-t-${rid}.${ISSUER}`;

    const alice = makeClient();
    const target = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      // target 创建 AID 并连接（注册设备），但不会主动上传 V2 SPK prekey
      await ensureConnected(target, targetAid);

      // Alice 明文发送给 target（encrypt: false）
      const sendResult = await alice.call('message.send', {
        to: targetAid,
        payload: { type: 'text', text: `plain-no-prekey-${rid}` },
        encrypt: false,
      }) as Record<string, unknown>;

      expect(sendResult).toBeDefined();
      expect(sendResult.message_id).toBeDefined();
    } finally {
      await alice.close();
      await target.close();
    }
  }, TEST_TIMEOUT);
});

// ── 发送到不存在的 AID ──────────────────────────────────────────────

describe('发送到不存在的 AID', () => {
  it('发送到从未创建的 AID 应抛出错误', async () => {
    const rid = runId();
    const aliceAid = `pfp-nx-a-${rid}.${ISSUER}`;
    const nonexistentAid = `nonexistent-${rid}.${ISSUER}`;

    const alice = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      // 发送到从未创建的 AID，应抛出错误
      await expect(
        alice.call('message.send', {
          to: nonexistentAid,
          payload: { type: 'text', text: `should-fail-${rid}` },
          encrypt: false,
        }),
      ).rejects.toThrow();
    } finally {
      await alice.close();
    }
  }, TEST_TIMEOUT);
});

// ── 明文消息可送达 ──────────────────────────────────────────────────

describe('明文消息可送达', () => {
  it('Alice 发送明文持久消息后，Bob 应能在线收到', async () => {
    const rid = runId();
    const aliceAid = `pfp-pull-a-${rid}.${ISSUER}`;
    const bobAid = `pfp-pull-b-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const text = `plaintext-pullable-${rid}`;
      const pushed = waitForP2pMessages(
        bob,
        aliceAid,
        1,
        10_000,
        message => payloadText(message) === text,
      );

      // Alice 发送明文持久消息
      await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text },
        encrypt: false,
        durable: true,
      });

      const matched = await pushed;
      expect(matched.length).toBe(1);
      expect(payloadText(matched[0])).toBe(text);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, TEST_TIMEOUT);
});

// ── 错误后序号正常递增 ──────────────────────────────────────────────

describe('错误后序号正常递增', () => {
  it('发送失败不影响后续有效消息的 seq 递增', async () => {
    const rid = runId();
    const aliceAid = `pfp-seq-a-${rid}.${ISSUER}`;
    const bobAid = `pfp-seq-b-${rid}.${ISSUER}`;
    const nonexistentAid = `nonexistent-seq-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const text1 = `seq-msg1-${rid}`;
      const text2 = `seq-msg2-${rid}`;
      const pushed = waitForP2pMessages(
        bob,
        aliceAid,
        2,
        10_000,
        message => payloadText(message) === text1 || payloadText(message) === text2,
      );

      // 第一条有效消息
      const send1 = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: text1 },
        encrypt: false,
        durable: true,
      }) as Record<string, unknown>;

      // 尝试发送到不存在的 AID（预期失败）
      try {
        await alice.call('message.send', {
          to: nonexistentAid,
          payload: { type: 'text', text: `should-fail-${rid}` },
          encrypt: false,
        });
      } catch {
        // 预期失败，忽略
      }

      // 第二条有效消息
      const send2 = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: text2 },
        encrypt: false,
        durable: true,
      }) as Record<string, unknown>;

      const fromAlice = (await pushed)
        .sort((a, b) => Number(a.seq ?? 0) - Number(b.seq ?? 0));

      // 应至少收到两条来自 Alice 的消息
      expect(fromAlice.length).toBeGreaterThanOrEqual(2);

      // 验证 seq 递增
      const seqs = fromAlice.map(m => Number(m.seq));
      for (let i = 1; i < seqs.length; i++) {
        expect(seqs[i]).toBeGreaterThan(seqs[i - 1]);
      }
    } finally {
      await alice.close();
      await bob.close();
    }
  }, TEST_TIMEOUT);
});
