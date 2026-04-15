/**
 * Group E2EE 完整 E2E 测试 — 需要运行中的 AUN Gateway + Group Service。
 *
 * 覆盖群组加密消息的完整生命周期：建群、密钥分发、加密通信、踢人轮换、密钥恢复。
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - hosts 文件映射 *.agentid.pub → 127.0.0.1
 *   - Gateway 地址由 SDK 通过 AID 的 issuer domain 自动发现
 *
 * 运行方法：
 *   npx vitest run tests/e2e/group-e2ee.test.ts
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import {
  generateGroupSecret,
  buildKeyDistribution,
  handleKeyDistribution,
  loadAllGroupSecrets,
} from '../../src/e2ee-group.js';
import type { JsonObject, KeyStore, Message } from '../../src/types.js';

process.env.AUN_ENV ??= 'development';

// ── 常量 ──────────────────────────────────────────────────────

/** 单条测试超时（毫秒） */
const TEST_TIMEOUT = 60_000;

// ── 辅助函数 ──────────────────────────────────────────────────

/** 生成唯一运行标识（UUID 前 12 位，避免 AID 碰撞） */
function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

/** 创建测试客户端（Gateway 通过 well-known 自动发现） */
function makeClient(): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-e2e-')),
  });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

/** 注册 AID 并连接到 Gateway */
async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

/** 创建群组，返回 group_id */
async function createGroup(client: AUNClient, name: string): Promise<string> {
  const result = await client.call('group.create', { name }) as JsonObject;
  const group = result.group as JsonObject;
  return String(group.group_id ?? '');
}

/** 添加群成员 */
async function addMember(client: AUNClient, groupId: string, memberAid: string): Promise<void> {
  await client.call('group.add_member', { group_id: groupId, aid: memberAid });
}

/** 踢出群成员 */
async function kickMember(client: AUNClient, groupId: string, memberAid: string): Promise<void> {
  await client.call('group.kick', { group_id: groupId, aid: memberAid });
}

/** 获取群成员 AID 列表 */
async function getMembers(client: AUNClient, groupId: string): Promise<string[]> {
  const result = await client.call('group.get_members', { group_id: groupId }) as JsonObject;
  const members = (result.members ?? []) as JsonObject[];
  return members.map(m => String(m.aid ?? ''));
}

/** 拉取群消息（经 client.call 自动解密） */
async function groupPull(
  client: AUNClient,
  groupId: string,
  afterSeq: number = 0,
) : Promise<Message[]> {
  const result = await client.call('group.pull', {
    group_id: groupId,
    after_seq: afterSeq,
  }) as JsonObject;
  return (result.messages ?? []) as Message[];
}

/** 等待指定毫秒 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 轮询等待条件满足。
 * @param fn - 返回 true 表示条件满足
 * @param timeoutMs - 最大等待时间（毫秒）
 * @param intervalMs - 轮询间隔（毫秒）
 * @returns 条件是否在超时前满足
 */
async function waitFor(
  fn: () => boolean | Promise<boolean>,
  timeoutMs: number = 15_000,
  intervalMs: number = 1_000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await fn()) return true;
    await sleep(intervalMs);
  }
  return false;
}

/** 从消息列表中筛选自动解密的群 E2EE 消息 */
function filterDecrypted(msgs: Message[]): Message[] {
  return msgs.filter(m => {
    const e2ee = m.e2ee as JsonObject | undefined;
    return e2ee?.encryption_mode === 'epoch_group_key';
  });
}

/** 从消息列表中筛选指定 epoch 的解密消息 */
function filterByEpoch(msgs: Message[], epoch: number): Message[] {
  return msgs.filter(m => {
    const e2ee = m.e2ee as JsonObject | undefined;
    return Number(e2ee?.epoch ?? 0) === epoch;
  });
}

/** 获取客户端内部 keystore 引用 */
function getKeystore(client: AUNClient): KeyStore {
  return (client as AUNClient & { _keystore: KeyStore })._keystore;
}

// ── 测试用例 ──────────────────────────────────────────────────

describe('Group E2EE E2E 测试', () => {
  /** 每个测试创建的客户端，afterEach 统一关闭 */
  const clients: AUNClient[] = [];

  /** 创建并跟踪客户端 */
  function tracked(): AUNClient {
    const c = makeClient();
    clients.push(c);
    return c;
  }

  afterEach(async () => {
    // 并行关闭所有客户端
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  // ── Test 1: 建群 → 分发密钥 → 加密发送 → 解密接收 ─────────

  it('建群 → 分发密钥 → 加密发送 → 解密接收', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    // Alice 建群（SDK 自动 create_epoch）
    const groupId = await createGroup(alice, `e2ee-test-${rid}`);
    expect(alice.groupE2ee.hasSecret(groupId), 'owner 建群后应有密钥').toBe(true);

    // Alice 加 Bob（SDK 自动分发密钥）
    await addMember(alice, groupId, bAid);
    await sleep(2000); // 等 P2P 密钥分发到达

    // Alice 发送加密群消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '加密群消息' },
      encrypt: true,
    });

    await sleep(1000);

    // Bob 拉取（自动解密）
    const msgs = await groupPull(bob, groupId);
    expect(msgs.length, '应收到至少 1 条消息').toBeGreaterThanOrEqual(1);

    // 验证自动解密成功
    const decrypted = filterDecrypted(msgs);
    expect(decrypted.length, '应有自动解密的消息').toBeGreaterThanOrEqual(1);
    expect((decrypted[0].payload as JsonObject).text).toBe('加密群消息');
  }, TEST_TIMEOUT);

  // ── Test 2: 3人群组，A 发加密消息，B/C 都能解密 ────────────

  it('多成员解密', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();
    const carol = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    const cAid = `ge-c-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);
    await ensureConnected(carol, cAid);

    const groupId = await createGroup(alice, `e2ee-multi-${rid}`);
    await addMember(alice, groupId, bAid);
    await addMember(alice, groupId, cAid);

    // 等 SDK 自动分发密钥给所有成员
    await sleep(2000);

    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '三人群消息' },
      encrypt: true,
    });

    await sleep(1000);

    // Bob 和 Carol 都应能解密
    for (const [name, client] of [['Bob', bob], ['Carol', carol]] as const) {
      const msgs = await groupPull(client, groupId);
      const decrypted = filterDecrypted(msgs);
      expect(decrypted.length, `${name}: 应有自动解密的消息`).toBeGreaterThanOrEqual(1);
      expect(
        (decrypted[0].payload as JsonObject).text,
        `${name}: payload 不匹配`,
      ).toBe('三人群消息');
    }
  }, TEST_TIMEOUT);

  // ── Test 3: 踢人 → epoch 轮换 → 旧成员无法解密新消息 ──────

  it('踢人后 epoch 轮换', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();
    const carol = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    const cAid = `ge-c-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);
    await ensureConnected(carol, cAid);

    const groupId = await createGroup(alice, `e2ee-kick-${rid}`);
    await addMember(alice, groupId, bAid);
    await addMember(alice, groupId, cAid);

    // 等待 SDK 自动分发密钥给 Bob 和 Carol
    await sleep(2000);

    // 踢 Carol
    await kickMember(alice, groupId, cAid);

    // kick 后 SDK 自动 CAS 轮换 + 分发给 Bob，轮询等待 Bob 拿到 epoch 2 密钥
    const bobGotEpoch2 = await waitFor(() => {
      const allBob = loadAllGroupSecrets(getKeystore(bob), bAid, groupId);
      return allBob.has(2);
    }, 15_000);
    expect(bobGotEpoch2, 'Bob 应在 15s 内收到 epoch 2 密钥').toBe(true);

    // Alice 用 epoch 2 发加密消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '踢人后的消息' },
      encrypt: true,
    });

    await sleep(1000);

    // Bob 能解密（有 epoch 2 密钥）
    const msgsBob = await groupPull(bob, groupId);
    const decryptedBob = filterByEpoch(msgsBob, 2);
    expect(decryptedBob.length, 'Bob: 应有 epoch 2 的解密消息').toBeGreaterThanOrEqual(1);
    expect((decryptedBob[0].payload as JsonObject).text).toBe('踢人后的消息');

    // Carol 没有 epoch 2 密钥（被踢后不会收到新密钥）
    const allCarol = loadAllGroupSecrets(getKeystore(carol), cAid, groupId);
    expect(allCarol.has(2), 'Carol 不应有 epoch 2 密钥').toBe(false);
  }, TEST_TIMEOUT);

  // ── Test 4: 加人 → 无 epoch 轮换 → 新成员可解密当前 epoch 消息 ──

  it('新成员加入无 epoch 轮换', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();
    const carol = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    const cAid = `ge-c-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);
    await ensureConnected(carol, cAid);

    const groupId = await createGroup(alice, `e2ee-join-${rid}`);
    await addMember(alice, groupId, bAid);

    // 等待 SDK 自动分发密钥给 Bob
    await sleep(2000);

    // 加 Carol（SDK 自动分发当前密钥）
    await addMember(alice, groupId, cAid);
    await sleep(2000);

    // Alice 用 epoch 1 发消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '新成员能看到' },
      encrypt: true,
    });

    await sleep(1000);

    // Carol 能解密
    const msgs = await groupPull(carol, groupId);
    const decrypted = filterDecrypted(msgs);
    expect(decrypted.length, 'Carol: 应有自动解密的消息').toBeGreaterThanOrEqual(1);
    expect((decrypted[0].payload as JsonObject).text).toBe('新成员能看到');
  }, TEST_TIMEOUT);

  // ── Test 5: 连续发 5 条加密群消息 → 全部解密成功 ──────────

  it('连续加密群消息（burst）', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    const groupId = await createGroup(alice, `e2ee-burst-${rid}`);
    await addMember(alice, groupId, bAid);

    // 等待 SDK 自动分发密钥
    await sleep(2000);

    const N = 5;
    for (let i = 0; i < N; i++) {
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: `burst_${i}`, seq: i },
        encrypt: true,
      });
    }

    await sleep(2000);

    const msgs = await groupPull(bob, groupId);
    const decrypted = filterDecrypted(msgs);
    expect(decrypted.length, `应解密 ${N} 条消息`).toBeGreaterThanOrEqual(N);

    const texts = new Set(decrypted.map(m => String((m.payload as JsonObject).text ?? '')));
    const expected = new Set(Array.from({ length: N }, (_, i) => `burst_${i}`));
    expect(texts, '消息内容应完全匹配').toEqual(expected);
  }, TEST_TIMEOUT);

  // ── Test 6: 同一群中加密和明文消息交替 → 正确处理 ─────────

  it('加密 + 明文混合消息', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    const groupId = await createGroup(alice, `e2ee-mixed-${rid}`);
    await addMember(alice, groupId, bAid);

    // 等待 SDK 自动分发密钥
    await sleep(2000);

    // 明文消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '明文' },
      encrypt: false,
    });
    // 加密消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '密文' },
      encrypt: true,
    });
    // 又一条明文
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '又是明文' },
      encrypt: false,
    });

    await sleep(1000);

    const msgs = await groupPull(bob, groupId);
    expect(msgs.length, '应收到至少 3 条消息').toBeGreaterThanOrEqual(3);

    // 加密消息已自动解密
    const decrypted = filterDecrypted(msgs);
    expect(decrypted.length, '应有加密消息').toBeGreaterThanOrEqual(1);
    expect((decrypted[0].payload as JsonObject).text).toBe('密文');

    // 明文消息直接可读
    const plaintext = msgs.filter(m => {
      if (m.e2ee) return false;
      const payload = m.payload as JsonObject | undefined;
      return payload && typeof payload === 'object' && 'text' in payload;
    });
    const plainTexts = new Set(plaintext.map(m => String((m.payload as JsonObject).text ?? '')));
    expect(plainTexts.has('明文'), '应包含第一条明文').toBe(true);
    expect(plainTexts.has('又是明文'), '应包含第二条明文').toBe(true);
  }, TEST_TIMEOUT);

  // ── Test 7: 篡改 member_aids → commitment 校验失败 ────────

  it('Membership Commitment 防篡改', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    const gs = generateGroupSecret();
    const members = [aAid, bAid];

    // 正常分发
    const dist = buildKeyDistribution('grp_test', 1, gs, members, aAid);
    const ok = handleKeyDistribution(dist, getKeystore(bob), bAid);
    expect(ok, '正常分发应成功').toBe(true);

    // 篡改 member_aids（注入幽灵成员）
    const tampered = { ...dist, member_aids: [...members, 'evil.agentid.pub'] };
    const ok2 = handleKeyDistribution(tampered, getKeystore(bob), bAid);
    expect(ok2, '篡改后应失败').toBe(false);
  }, TEST_TIMEOUT);

  // ── Test 8: 旧 epoch 消息在保留期内仍可解密 ───────────────

  it('旧 epoch 消息仍可解密', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `ge-a-${rid}.agentid.pub`;
    const bAid = `ge-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    const groupId = await createGroup(alice, `e2ee-old-${rid}`);
    await addMember(alice, groupId, bAid);

    // 等待 SDK 自动分发 epoch 1 密钥
    await sleep(2000);

    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: 'epoch1消息' },
      encrypt: true,
    });

    // 手动轮换 epoch 2（模拟踢人后轮换）
    const info = alice.groupE2ee.rotateEpoch(groupId, [aAid, bAid]);
    const distributions = (info.distributions ?? []) as { to: string; payload: JsonObject }[];
    for (const dist of distributions) {
      await alice.call('message.send', {
        to: dist.to,
        payload: dist.payload,
        encrypt: true,
      });
    }
    await sleep(2000);

    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: 'epoch2消息' },
      encrypt: true,
    });

    await sleep(1000);

    // Bob 应能解密两个 epoch 的消息
    const msgs = await groupPull(bob, groupId);
    const decrypted = filterDecrypted(msgs);
    expect(decrypted.length, '应有至少 2 条解密消息').toBeGreaterThanOrEqual(2);

    const texts = new Set(decrypted.map(m => String((m.payload as JsonObject).text ?? '')));
    expect(texts.has('epoch1消息'), '应包含 epoch1 消息').toBe(true);
    expect(texts.has('epoch2消息'), '应包含 epoch2 消息').toBe(true);
  }, TEST_TIMEOUT);

  // ── Test 12: 显式 encrypt=false 可发送明文群消息 ──────────

  it('显式明文发送', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `pt-a-${rid}.agentid.pub`;
    const bAid = `pt-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    // Alice 建群 + 加 Bob
    const groupId = await createGroup(alice, `plaintext-test-${rid}`);
    await addMember(alice, groupId, bAid);
    await sleep(2000);

    // Alice 显式发送明文消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '这是一条明文消息' },
      encrypt: false,
    });

    // Bob 拉取
    await sleep(1000);
    const msgs = await groupPull(bob, groupId);
    const plaintextMsgs = msgs.filter(m => !m.encrypted);
    expect(plaintextMsgs.length, '应有明文消息').toBeGreaterThanOrEqual(1);
    expect((plaintextMsgs[0].payload as JsonObject).text).toBe('这是一条明文消息');

    // Alice 默认加密发送
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '这是一条加密消息' },
    });

    await sleep(1000);
    const lastSeq = (msgs[msgs.length - 1]?.seq as number) ?? 0;
    const msgs2 = await groupPull(bob, groupId, lastSeq);
    const encryptedMsgs = filterDecrypted(msgs2);
    expect(encryptedMsgs.length, '应有加密消息').toBeGreaterThanOrEqual(1);
    expect((encryptedMsgs[0].payload as JsonObject).text).toBe('这是一条加密消息');
  }, TEST_TIMEOUT);

  // ── Test 13: 成员主动退群 → epoch 轮换 ───────────────────

  it('退群后 epoch 轮换', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();
    const carol = tracked();

    const aAid = `lv-a-${rid}.agentid.pub`;
    const bAid = `lv-b-${rid}.agentid.pub`;
    const cAid = `lv-c-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);
    await ensureConnected(carol, cAid);

    const groupId = await createGroup(alice, `e2ee-leave-${rid}`);
    await addMember(alice, groupId, bAid);
    await addMember(alice, groupId, cAid);

    // 等待 SDK 自动分发密钥
    await sleep(2000);

    // 确认三方都有 epoch 1
    expect(alice.groupE2ee.hasSecret(groupId), 'Alice 应有密钥').toBe(true);
    const allGotEpoch1 = await waitFor(() => {
      return bob.groupE2ee.hasSecret(groupId) && carol.groupE2ee.hasSecret(groupId);
    }, 10_000);
    expect(allGotEpoch1, 'Bob/Carol 应在 10s 内收到 epoch 1').toBe(true);

    const oldEpoch = alice.groupE2ee.currentEpoch(groupId);
    expect(oldEpoch, '初始应为 epoch 1').toBe(1);

    // Carol 主动退群
    await carol.call('group.leave', { group_id: groupId });

    // Alice（owner）收到 group.changed(member_left) 事件后应自动 CAS 轮换
    // 轮询等待 Bob 拿到 epoch 2 密钥
    const bobGotEpoch2 = await waitFor(() => {
      const allBob = loadAllGroupSecrets(getKeystore(bob), bAid, groupId);
      return allBob.has(2);
    }, 15_000);
    expect(bobGotEpoch2, 'Bob 应在 15s 内收到 epoch 2 密钥').toBe(true);

    // Alice 也应有 epoch 2
    const allAlice = loadAllGroupSecrets(getKeystore(alice), aAid, groupId);
    expect(allAlice.has(2), 'Alice 应有 epoch 2').toBe(true);

    // Alice 用 epoch 2 发加密消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { text: '退群后的消息' },
    });

    await sleep(1000);

    // Bob 能解密
    const msgsBob = await groupPull(bob, groupId);
    const decryptedBob = filterByEpoch(msgsBob, 2);
    expect(decryptedBob.length, 'Bob: 应有 epoch 2 的解密消息').toBeGreaterThanOrEqual(1);
    expect((decryptedBob[0].payload as JsonObject).text).toBe('退群后的消息');

    // Carol 不应有 epoch 2 密钥
    const allCarol = loadAllGroupSecrets(getKeystore(carol), cAid, groupId);
    expect(allCarol.has(2), 'Carol 不应有 epoch 2 密钥').toBe(false);
  }, TEST_TIMEOUT);
});
