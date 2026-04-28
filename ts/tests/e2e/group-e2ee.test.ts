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
    after_message_seq: afterSeq,
  }) as JsonObject;
  return (result.messages ?? []) as Message[];
}

/** 查询当前群消息最新 seq，供 pull 兜底限定增量范围 */
async function currentGroupMaxSeq(client: AUNClient, groupId: string): Promise<number> {
  const result = await client.call('group.get_cursor', { group_id: groupId }) as JsonObject;
  const cursor = (result.msg_cursor ?? {}) as JsonObject;
  return Number(cursor.latest_seq ?? 0);
}

/** 合并消息并按 seq 去重 */
function mergeMessages(target: Message[], incoming: Message[]): void {
  const seenSeqs = new Set(target.map(msg => Number(msg.seq ?? 0)).filter(seq => seq > 0));
  for (const msg of incoming) {
    const seq = Number(msg.seq ?? 0);
    if (seq > 0) {
      if (seenSeqs.has(seq)) continue;
      seenSeqs.add(seq);
    }
    target.push(msg);
  }
  target.sort((a, b) => Number(a.seq ?? 0) - Number(b.seq ?? 0));
}

/**
 * 在发送前订阅群消息，优先收 push，必要时用 pull 做兜底。
 * 这样不会因为 SDK push 路径 auto-ack 后再 group.pull(0) 被 cursor uplift 吃掉消息。
 */
async function watchGroupMessages(client: AUNClient, groupId: string) {
  const afterSeq = await currentGroupMaxSeq(client, groupId);
  const inbox: Message[] = [];
  const sub = client.on('group.message_created', (evt) => {
    const msg = evt as Message & { group_id?: string };
    if (String(msg.group_id ?? '') !== groupId) return;
    mergeMessages(inbox, [msg]);
  });

  return {
    inbox,
    stop(): void {
      sub.unsubscribe();
    },
    async waitFor(
      predicate: (messages: Message[]) => boolean,
      timeoutMs: number = 15_000,
    ): Promise<Message[]> {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (predicate(inbox)) return [...inbox];
        mergeMessages(inbox, await groupPull(client, groupId, afterSeq));
        if (predicate(inbox)) return [...inbox];
        await sleep(200);
      }
      throw new Error(
        `timeout waiting for group messages group=${groupId}; inbox=${JSON.stringify(inbox)}`,
      );
    },
  };
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

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function truthyBool(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') {
    return ['1', 'true', 'yes', 'y', 'on'].includes(value.trim().toLowerCase());
  }
  return Boolean(value);
}

function groupSecretMatchesCommittedRotation(
  secretData: JsonObject | null,
  committedRotation: JsonObject | null,
): boolean {
  if (!secretData) return false;
  const committedCommitment = String(committedRotation?.key_commitment ?? '').trim();
  const localCommitment = String(secretData.commitment ?? '').trim();
  if (committedCommitment && committedCommitment !== localCommitment) return false;
  const pendingRotationId = String(secretData.pending_rotation_id ?? '').trim();
  if (!pendingRotationId) return true;
  return String(committedRotation?.rotation_id ?? '').trim() === pendingRotationId;
}

async function committedGroupEpochSnapshot(
  client: AUNClient,
  groupId: string,
): Promise<{ epoch: number; committedRotation: JsonObject | null; pendingActive: boolean }> {
  const result = await client.call('group.e2ee.get_epoch', { group_id: groupId }) as JsonObject;
  const epoch = Number(result.committed_epoch ?? result.epoch ?? 0);
  const pending = result.pending_rotation;
  const pendingActive = isPlainObject(pending) && !truthyBool(pending.expired);
  const committedRotation = isPlainObject(result.committed_rotation) ? result.committed_rotation : null;
  return {
    epoch: Number.isFinite(epoch) ? epoch : 0,
    committedRotation,
    pendingActive,
  };
}

async function waitForCommittedGroupEpochReady(
  client: AUNClient,
  groupId: string,
  minEpoch: number,
  timeoutMs: number = 15_000,
): Promise<number> {
  let readyEpoch = 0;
  let lastEpoch = 0;
  let lastPending = false;
  const matched = await waitFor(async () => {
    const snapshot = await committedGroupEpochSnapshot(client, groupId);
    lastEpoch = snapshot.epoch;
    lastPending = snapshot.pendingActive;
    if (snapshot.epoch < minEpoch || snapshot.pendingActive) return false;
    const secret = client.groupE2ee.loadSecret(groupId, snapshot.epoch) as unknown as JsonObject | null;
    if (!groupSecretMatchesCommittedRotation(secret, snapshot.committedRotation)) return false;
    readyEpoch = snapshot.epoch;
    return true;
  }, timeoutMs, 500);
  if (!matched) {
    throw new Error(
      `timeout waiting committed group epoch >= ${minEpoch}; last_epoch=${lastEpoch}; pending=${lastPending}`,
    );
  }
  return readyEpoch;
}

async function waitForCommittedGroupEpochGreaterThan(
  client: AUNClient,
  groupId: string,
  oldEpoch: number,
  timeoutMs: number = 15_000,
): Promise<number> {
  return waitForCommittedGroupEpochReady(client, groupId, oldEpoch + 1, timeoutMs);
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

    // Alice 加 Bob（SDK 自动分发并提交密钥）
    await addMember(alice, groupId, bAid);
    await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);

    // Alice 发送加密群消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '加密群消息' },
      encrypt: true,
    });

    try {
      const msgs = await bobWatch.waitFor((messages) => filterDecrypted(messages).some((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '加密群消息'));
      expect(msgs.length, '应收到至少 1 条消息').toBeGreaterThanOrEqual(1);

      const decrypted = filterDecrypted(msgs).find((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '加密群消息');
      expect(decrypted, '应有自动解密的消息').toBeTruthy();
      expect(((decrypted?.payload as JsonObject | undefined)?.text)).toBe('加密群消息');
    } finally {
      bobWatch.stop();
    }
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

    // 等 SDK 自动分发并提交密钥给所有成员
    const currentEpoch = await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);
    await waitForCommittedGroupEpochReady(carol, groupId, currentEpoch, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);
    const carolWatch = await watchGroupMessages(carol, groupId);

    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '三人群消息' },
      encrypt: true,
    });

    try {
      for (const [name, watch] of [['Bob', bobWatch], ['Carol', carolWatch]] as const) {
        const msgs = await watch.waitFor((messages) => filterDecrypted(messages).some((msg) =>
          String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '三人群消息'));
        const decrypted = filterDecrypted(msgs).find((msg) =>
          String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '三人群消息');
        expect(decrypted, `${name}: 应有自动解密的消息`).toBeTruthy();
        expect(
          ((decrypted?.payload as JsonObject | undefined)?.text),
          `${name}: payload 不匹配`,
        ).toBe('三人群消息');
      }
    } finally {
      bobWatch.stop();
      carolWatch.stop();
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

    // 等待初始成员变更轮换提交，并确认 Bob/Carol 持有已提交密钥。
    const oldEpoch = await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);
    await waitForCommittedGroupEpochReady(carol, groupId, oldEpoch, 20_000);

    // 踢 Carol
    await kickMember(alice, groupId, cAid);

    // kick 后 SDK 自动 CAS 轮换 + 分发给 Bob，等待服务端提交且 Bob 本地密钥匹配。
    const newEpoch = await waitForCommittedGroupEpochGreaterThan(bob, groupId, oldEpoch, 20_000);
    await waitForCommittedGroupEpochReady(alice, groupId, newEpoch, 20_000);


    const bobWatch = await watchGroupMessages(bob, groupId);

    // Alice 用 epoch 2 发加密消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '踢人后的消息' },
      encrypt: true,
    });

    try {
      const msgsBob = await bobWatch.waitFor((messages) => filterByEpoch(messages, newEpoch).some((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '踢人后的消息'));
      const decryptedBob = filterByEpoch(msgsBob, newEpoch).find((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '踢人后的消息');
      expect(decryptedBob, `Bob: 应有 epoch ${newEpoch} 的解密消息`).toBeTruthy();
      expect(((decryptedBob?.payload as JsonObject | undefined)?.text)).toBe('踢人后的消息');
    } finally {
      bobWatch.stop();
    }

    // Carol 没有 epoch 2 密钥（被踢后不会收到新密钥）
    const allCarol = loadAllGroupSecrets(getKeystore(carol), cAid, groupId);
    expect(allCarol.has(newEpoch), `Carol 不应有 epoch ${newEpoch} 密钥`).toBe(false);
  }, TEST_TIMEOUT);

  // ── Test 4: 加人 → epoch 轮换 → 新成员可解密当前已提交 epoch 消息 ──

  it('新成员加入后 epoch 轮换', async () => {
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

    // 等待 SDK 自动分发并提交 Bob 可用的群密钥。
    const beforeCarolJoinEpoch = await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);

    // 加 Carol 后会触发成员变更 epoch 轮换，并向新成员分发已提交的新 epoch key。
    await addMember(alice, groupId, cAid);
    const carolEpoch = await waitForCommittedGroupEpochGreaterThan(carol, groupId, beforeCarolJoinEpoch, 20_000);
    await waitForCommittedGroupEpochReady(alice, groupId, carolEpoch, 20_000);

    const carolWatch = await watchGroupMessages(carol, groupId);

    // Alice 用当前已提交 epoch 发消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '新成员能看到' },
      encrypt: true,
    });

    try {
      const msgs = await carolWatch.waitFor((messages) => filterDecrypted(messages).some((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '新成员能看到'));
      const decrypted = filterDecrypted(msgs).find((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '新成员能看到');
      expect(decrypted, 'Carol: 应有自动解密的消息').toBeTruthy();
      expect(((decrypted?.payload as JsonObject | undefined)?.text)).toBe('新成员能看到');
    } finally {
      carolWatch.stop();
    }
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

    // 等待 SDK 自动分发并提交初始群密钥。
    await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);

    const N = 5;
    for (let i = 0; i < N; i++) {
      await alice.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: `burst_${i}`, seq: i },
        encrypt: true,
      });
    }

    try {
      const msgs = await bobWatch.waitFor((messages) => {
        const texts = new Set(filterDecrypted(messages).map(m => String((m.payload as JsonObject).text ?? '')));
        return Array.from({ length: N }, (_, i) => `burst_${i}`).every(text => texts.has(text));
      }, 20_000);
      const decrypted = filterDecrypted(msgs);
      expect(decrypted.length, `应解密 ${N} 条消息`).toBeGreaterThanOrEqual(N);

      const texts = new Set(decrypted.map(m => String((m.payload as JsonObject).text ?? '')));
      const expected = new Set(Array.from({ length: N }, (_, i) => `burst_${i}`));
      expect(texts, '消息内容应完全匹配').toEqual(expected);
    } finally {
      bobWatch.stop();
    }
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

    // 等待 SDK 自动分发并提交密钥
    await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);

    // 明文消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '明文' },
      encrypt: false,
    });
    // 加密消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '密文' },
      encrypt: true,
    });
    // 又一条明文
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '又是明文' },
      encrypt: false,
    });

    try {
      const msgs = await bobWatch.waitFor((messages) => {
        const texts = new Set(messages.map(m => String(((m.payload as JsonObject | undefined)?.text) ?? '')));
        return texts.has('明文') && texts.has('密文') && texts.has('又是明文');
      });
      expect(msgs.length, '应收到至少 3 条消息').toBeGreaterThanOrEqual(3);

      const decrypted = filterDecrypted(msgs).find((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '密文');
      expect(decrypted, '应有加密消息').toBeTruthy();
      expect(((decrypted?.payload as JsonObject | undefined)?.text)).toBe('密文');

      const plaintext = msgs.filter(m => {
        if (m.e2ee) return false;
        const payload = m.payload as JsonObject | undefined;
        return payload && typeof payload === 'object' && 'text' in payload;
      });
      const plainTexts = new Set(plaintext.map(m => String((m.payload as JsonObject).text ?? '')));
      expect(plainTexts.has('明文'), '应包含第一条明文').toBe(true);
      expect(plainTexts.has('又是明文'), '应包含第二条明文').toBe(true);
    } finally {
      bobWatch.stop();
    }
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

    // 等待 SDK 自动分发并提交初始密钥
    await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);

    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: 'epoch1消息' },
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
      payload: { type: 'text', text: 'epoch2消息' },
      encrypt: true,
    });

    try {
      const msgs = await bobWatch.waitFor((messages) => {
        const texts = new Set(filterDecrypted(messages).map(m => String((m.payload as JsonObject).text ?? '')));
        return texts.has('epoch1消息') && texts.has('epoch2消息');
      }, 20_000);
      const decrypted = filterDecrypted(msgs);
      expect(decrypted.length, '应有至少 2 条解密消息').toBeGreaterThanOrEqual(2);

      const texts = new Set(decrypted.map(m => String((m.payload as JsonObject).text ?? '')));
      expect(texts.has('epoch1消息'), '应包含 epoch1 消息').toBe(true);
      expect(texts.has('epoch2消息'), '应包含 epoch2 消息').toBe(true);
    } finally {
      bobWatch.stop();
    }
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
    await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);

    // Alice 显式发送明文消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '这是一条明文消息' },
      encrypt: false,
    });

    try {
      const msgs = await bobWatch.waitFor((messages) => messages.some((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '这是一条明文消息'));
      const plaintextMsg = msgs.find((msg) => String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '这是一条明文消息');
      expect(plaintextMsg && !plaintextMsg.encrypted, '应有明文消息').toBe(true);
      expect(((plaintextMsg?.payload as JsonObject | undefined)?.text)).toBe('这是一条明文消息');

      await alice.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: '这是一条加密消息' },
      });

      const msgs2 = await bobWatch.waitFor((messages) => filterDecrypted(messages).some((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '这是一条加密消息'));
      const encryptedMsg = filterDecrypted(msgs2).find((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '这是一条加密消息');
      expect(encryptedMsg, '应有加密消息').toBeTruthy();
      expect(((encryptedMsg?.payload as JsonObject | undefined)?.text)).toBe('这是一条加密消息');
    } finally {
      bobWatch.stop();
    }
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

    // 等待 SDK 自动分发/轮换提交，并确认 Bob/Carol 持有已提交密钥。
    const oldEpoch = await waitForCommittedGroupEpochReady(bob, groupId, 1, 20_000);
    await waitForCommittedGroupEpochReady(carol, groupId, oldEpoch, 20_000);

    // 确认 Alice 有退群前的 group secret。
    expect(alice.groupE2ee.hasSecret(groupId), 'Alice 应有密钥').toBe(true);

    // Carol 主动退群
    await carol.call('group.leave', { group_id: groupId });

    // Alice（owner）收到 group.changed(member_left) 事件后应自动 CAS 轮换并提交。
    const newEpoch = await waitForCommittedGroupEpochGreaterThan(bob, groupId, oldEpoch, 20_000);

    // Alice 也应有新 epoch
    await waitForCommittedGroupEpochReady(alice, groupId, newEpoch, 20_000);

    const bobWatch = await watchGroupMessages(bob, groupId);

    // Alice 用 epoch 2 发加密消息
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: '退群后的消息' },
    });

    try {
      const msgsBob = await bobWatch.waitFor((messages) => filterByEpoch(messages, newEpoch).some((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '退群后的消息'));
      const decryptedBob = filterByEpoch(msgsBob, newEpoch).find((msg) =>
        String(((msg.payload as JsonObject | undefined)?.text) ?? '') === '退群后的消息');
      expect(decryptedBob, `Bob: 应有 epoch ${newEpoch} 的解密消息`).toBeTruthy();
      expect(((decryptedBob?.payload as JsonObject | undefined)?.text)).toBe('退群后的消息');
    } finally {
      bobWatch.stop();
    }

    // Carol 不应有 epoch 2 密钥
    const allCarol = loadAllGroupSecrets(getKeystore(carol), cAid, groupId);
    expect(allCarol.has(newEpoch), `Carol 不应有 epoch ${newEpoch} 密钥`).toBe(false);
  }, TEST_TIMEOUT);
});
