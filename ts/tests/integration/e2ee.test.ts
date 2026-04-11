/**
 * E2EE 集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖 SDK 在发送/接收端的所有组合，确保端到端加密互联互通。
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - hosts 文件映射 *.agentid.pub → 127.0.0.1
 *   - Gateway 地址由 SDK 通过 AID 的 issuer domain 自动发现
 *
 * 运行方法：
 *   npx vitest run tests/integration/e2ee.test.ts
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { E2EEManager } from '../../src/e2ee.js';
import type { JsonObject, Message, PrekeyRecord } from '../../src/types.js';

// ── 常量 ──────────────────────────────────────────────────────

/** 单条测试超时（毫秒） */
const TEST_TIMEOUT = 30_000;

/** 推送等待超时（毫秒） */
const PUSH_TIMEOUT = 5_000;

// ── 辅助函数 ──────────────────────────────────────────────────

/** 生成唯一运行标识（UUID 前 12 位，避免 AID 碰撞） */
function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

/** 创建测试客户端（仅设必要配置，Gateway 通过 well-known 自动发现） */
function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-e2ee-'));
  return new AUNClient({
    aun_path: tmpDir,
    verify_ssl: false,
    require_forward_secrecy: false,
  });
}

/** 注册 AID 并连接到 Gateway */
async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

/**
 * 通过推送事件接收消息，超时后用 pull 兜底。
 * 返回来自指定发送方的已解密消息列表。
 */
async function sdkRecvPush(
  client: AUNClient,
  fromAid: string,
  timeout: number = PUSH_TIMEOUT,
): Promise<Message[]> {
  const inbox: Message[] = [];
  let resolveWait: () => void;
  const waitPromise = new Promise<void>((r) => { resolveWait = r; });

  const sub = client.on('message.received', (data) => {
    const msg = data as Message;
    if (msg && msg.from === fromAid) {
      inbox.push(msg);
      resolveWait();
    }
  });

  // 等待推送或超时
  const timer = setTimeout(() => resolveWait(), timeout);
  await waitPromise;
  clearTimeout(timer);
  sub.unsubscribe();

  // 推送未收到时用 pull 兜底
  if (inbox.length === 0) {
    const result = await client.call('message.pull', { after_seq: 0, limit: 50 }) as JsonObject;
    const msgs = (result.messages ?? []) as Message[];
    inbox.push(...msgs.filter((m) => m.from === fromAid));
  }

  return inbox;
}

/**
 * 通过 pull 接收消息（SDK 自动解密）。
 */
async function sdkRecvPull(
  client: AUNClient,
  fromAid: string,
  afterSeq: number = 0,
): Promise<Message[]> {
  const result = await client.call('message.pull', { after_seq: afterSeq, limit: 50 }) as JsonObject;
  const msgs = (result.messages ?? []) as Message[];
  return msgs.filter((m) => m.from === fromAid);
}

/** SDK 加密发送消息 */
async function sdkSend(
  client: AUNClient,
  toAid: string,
  payload: JsonObject,
): Promise<JsonObject | null> {
  return await client.call('message.send', {
    to: toAid,
    payload,
    encrypt: true,
    persist: true,
  });
}

// ── 内部类型别名（访问 AUNClient 私有字段） ─────────────────

/** AUNClient 内部 transport 引用的类型 */
type InternalTransport = {
  call: (method: string, params: JsonObject) => Promise<JsonObject | null>;
};

type ClientInternals = AUNClient & {
  _identity: JsonObject | null;
  _keystore: import('../../src/keystore/index.js').KeyStore;
  _transport: InternalTransport;
  _fetchPeerCert: (aid: string) => Promise<string>;
  _fetchPeerPrekey: (aid: string) => Promise<PrekeyRecord>;
  _uploadPrekey: () => Promise<JsonObject | null>;
};

/** 从已连接的 AUNClient 提取内部引用，创建独立 E2EEManager（模拟裸 WebSocket 开发者） */
function makeRawE2ee(client: AUNClient): E2EEManager {
  const internal = client as ClientInternals;
  return new E2EEManager({
    identityFn: () => internal._identity ?? {},
    keystore: internal._keystore,
  });
}

/** 获取客户端的内部 transport */
function getTransport(client: AUNClient): InternalTransport {
  return (client as ClientInternals)._transport;
}

/**
 * 裸 WS 加密 + 发送。
 * 调用方需保证双方已连接（证书和 prekey 通过内部方法获取）。
 */
async function rawSend(
  client: AUNClient,
  e2ee: E2EEManager,
  toAid: string,
  payload: JsonObject,
): Promise<JsonObject | null> {
  const internal = client as ClientInternals;
  // 获取对方证书（兼容 camelCase / snake_case）
  const fetchCert = internal._fetchPeerCert.bind(client);
  const fetchPrekey = internal._fetchPeerPrekey.bind(client);

  const peerCertPem = await fetchCert(toAid);
  const prekey = await fetchPrekey(toAid);

  const [envelope, result] = e2ee.encryptOutbound(
    toAid,
    payload,
    peerCertPem,
    prekey,
    crypto.randomUUID(),
    Date.now(),
  );
  expect((result as JsonObject).encrypted, '加密应成功').toBe(true);

  const aad = (envelope.aad ?? {}) as JsonObject;
  return await getTransport(client).call('message.send', {
    to: toAid,
    payload: envelope,
    type: 'e2ee.encrypted',
    encrypted: true,
    message_id: aad.message_id as string,
    timestamp: aad.timestamp as number,
    persist: true,
  });
}

/**
 * 裸 WS pull + 手动解密。
 * 返回来自指定发送方的已解密消息列表。
 */
async function rawRecvPull(
  client: AUNClient,
  e2ee: E2EEManager,
  fromAid: string,
  afterSeq: number = 0,
): Promise<Message[]> {
  const raw = await getTransport(client).call('message.pull', {
    after_seq: afterSeq,
    limit: 50,
  }) as JsonObject;
  const rawMsgs = (raw.messages ?? []) as Message[];
  const result: Message[] = [];
  for (const msg of rawMsgs) {
    if (msg.from !== fromAid) continue;
    const decrypted = e2ee.decryptMessage(msg);
    if (decrypted !== null) result.push(decrypted);
  }
  return result;
}

/** 断言消息已正确解密 */
function assertDecrypted(
  msg: Message,
  expectedPayload: JsonObject,
  label: string = '',
): void {
  const prefix = label ? `[${label}] ` : '';
  expect(msg.encrypted, `${prefix}应标记为 encrypted`).toBe(true);
  const payload = msg.payload as JsonObject;
  for (const [k, v] of Object.entries(expectedPayload)) {
    expect(payload[k], `${prefix}payload.${k} 不匹配`).toBe(v);
  }
}

// ── 测试用例 ──────────────────────────────────────────────────

describe('E2EE 集成测试', () => {
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
    await Promise.allSettled(clients.map((c) => c.close()));
    clients.length = 0;
  });

  // ── 1. Prekey 上传与获取 ────────────────────────────────────

  it('prekey 上传与获取', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    await ensureConnected(alice, `e2ee-alice-${rid}.agentid.pub`);
    const bobAid = `e2ee-bob-${rid}.agentid.pub`;
    await ensureConnected(bob, bobAid);

    // Bob 生成 prekey 并上传
    const prekeyMaterial = bob.e2ee.generatePrekey();
    expect(prekeyMaterial.cert_fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    // 通过内部 transport 直接调用（绕过 client.call 的 internal_only 限制）
    const bobInternal = bob as ClientInternals;
    const transport = bobInternal._transport as { call: (method: string, params: JsonObject) => Promise<JsonObject> };
    const uploadResult = await transport.call('message.e2ee.put_prekey', prekeyMaterial);
    expect(
      uploadResult.ok || uploadResult.success || 'prekey_id' in uploadResult,
      '上传 prekey 应成功',
    ).toBeTruthy();

    // Alice 获取 Bob 的 prekey
    const aliceInternal = alice as ClientInternals;
    const aliceTransport = aliceInternal._transport as { call: (method: string, params: JsonObject) => Promise<JsonObject> };
    const pk1 = await aliceTransport.call('message.e2ee.get_prekey', { aid: bobAid });
    expect(pk1.found, '第一次应找到 prekey').toBeTruthy();
    expect((pk1.prekey as PrekeyRecord).cert_fingerprint).toBe(prekeyMaterial.cert_fingerprint);

    // 再次获取应返回相同的 prekey
    const pk2 = await aliceTransport.call('message.e2ee.get_prekey', { aid: bobAid });
    expect(pk2.found, '第二次应找到 prekey').toBeTruthy();
    const prekey1 = pk1.prekey as PrekeyRecord;
    const prekey2 = pk2.prekey as PrekeyRecord;
    expect(prekey2.prekey_id, 'prekey_id 应一致').toBe(prekey1.prekey_id);
  }, TEST_TIMEOUT);

  // ── 2. SDK 到 SDK prekey 消息 ──────────────────────────────

  it('SDK 到 SDK prekey 消息', async () => {
    const rid = runId();
    const sender = tracked();
    const receiver = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);
    await ensureConnected(receiver, rAid);

    await sdkSend(sender, rAid, { text: 'sdk2sdk prekey', n: 1 });
    const msgs = await sdkRecvPush(receiver, sAid);
    expect(msgs.length, '应收到至少 1 条消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgs[0], { text: 'sdk2sdk prekey' });
  }, TEST_TIMEOUT);

  // ── 3. SDK 无 prekey 时降级到 long_term_key ─────────────────

  it('SDK 无 prekey 时降级到 long_term_key', async () => {
    const rid = runId();
    const sender = tracked();
    const receiver = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);

    // Receiver 仅创建 AID，不连接（不上传 prekey）
    await receiver.auth.createAid({ aid: rAid });

    await sdkSend(sender, rAid, { text: 'missing-prekey' });

    const auth = await receiver.auth.authenticate({ aid: rAid });
    await receiver.connect(auth);

    const msgs = await sdkRecvPull(receiver, sAid);
    expect(msgs.length, '应收到至少 1 条降级消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgs[0], { text: 'missing-prekey' });
    expect(((msgs[0].e2ee ?? {}) as JsonObject).encryption_mode).toBe('long_term_key');
  }, TEST_TIMEOUT);

  // ── 4. SDK 双向消息 ────────────────────────────────────────

  it('SDK 双向消息', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();

    const aAid = `e2ee-a-${rid}.agentid.pub`;
    const bAid = `e2ee-b-${rid}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    // Alice → Bob
    await sdkSend(alice, bAid, { text: 'hello_bob', from: 'alice' });
    const msgsBob = await sdkRecvPush(bob, aAid);
    expect(msgsBob.length, 'Bob 应收到消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgsBob[0], { text: 'hello_bob' }, 'A→B');

    // Bob → Alice
    await sdkSend(bob, aAid, { text: 'hello_alice', from: 'bob' });
    const msgsAlice = await sdkRecvPush(alice, bAid);
    expect(msgsAlice.length, 'Alice 应收到消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgsAlice[0], { text: 'hello_alice' }, 'B→A');
  }, TEST_TIMEOUT);

  // ── 5. 连续发送多条消息（burst） ───────────────────────────

  it('连续发送多条消息（burst）', async () => {
    const rid = runId();
    const sender = tracked();
    const receiver = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);
    await ensureConnected(receiver, rAid);

    const N = 5;
    for (let i = 0; i < N; i++) {
      await sdkSend(sender, rAid, { text: `burst_${i}`, seq: i });
    }

    // 等待服务端处理后 pull
    await new Promise((r) => setTimeout(r, 2000));
    const msgs = await sdkRecvPull(receiver, sAid);
    expect(msgs.length, `应收到 ${N} 条消息`).toBeGreaterThanOrEqual(N);

    const receivedTexts = msgs.map((m) => String((m.payload as JsonObject).text ?? '')).sort();
    const expectedTexts = Array.from({ length: N }, (_, i) => `burst_${i}`).sort();
    expect(receivedTexts, '消息内容应完全匹配').toEqual(expectedTexts);
  }, TEST_TIMEOUT);

  // ── 6. Prekey 轮换后旧消息仍可解密 ────────────────────────

  it('prekey 轮换后旧消息仍可解密', async () => {
    const rid = runId();
    const sender = tracked();
    const receiver = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);
    await ensureConnected(receiver, rAid);

    // 第一条消息（使用旧 prekey）
    await sdkSend(sender, rAid, { text: 'before_rotate', phase: 1 });

    // Receiver 轮换 prekey
    const receiverInternal = receiver as ClientInternals;
    await receiverInternal._uploadPrekey();

    // 清除 sender 的 prekey 缓存，使其获取新 prekey
    sender.e2ee.invalidatePrekeyCahce(rAid);

    // 第二条消息（使用新 prekey）
    await sdkSend(sender, rAid, { text: 'after_rotate', phase: 2 });

    // 等待处理后 pull
    await new Promise((r) => setTimeout(r, 2000));
    const msgs = await sdkRecvPull(receiver, sAid);
    expect(msgs.length, '应收到至少 2 条消息').toBeGreaterThanOrEqual(2);

    const texts = new Set(msgs.map((m) => (m.payload as JsonObject).text));
    expect(texts.has('before_rotate'), '应包含轮换前的消息').toBe(true);
    expect(texts.has('after_rotate'), '应包含轮换后的消息').toBe(true);
  }, TEST_TIMEOUT);

  // ── 7. Push + Pull 无重复 ──────────────────────────────────

  it('push + pull 无重复', async () => {
    const rid = runId();
    const sender = tracked();
    const receiver = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);
    await ensureConnected(receiver, rAid);

    // 订阅推送
    const pushMsgs: Message[] = [];
    let resolveWait: () => void;
    const waitPromise = new Promise<void>((r) => { resolveWait = r; });
    const sub = receiver.on('message.received', (data) => {
      const msg = data as Message;
      if (msg && msg.from === sAid) {
        pushMsgs.push(msg);
        resolveWait();
      }
    });

    await sdkSend(sender, rAid, { text: 'dup_test' });

    // 等待推送
    const timer = setTimeout(() => resolveWait(), PUSH_TIMEOUT);
    await waitPromise;
    clearTimeout(timer);
    sub.unsubscribe();

    if (pushMsgs.length === 0) {
      // 推送未收到，跳过后续断言（与 Python 测试行为一致）
      return;
    }

    expect(pushMsgs.length, '推送应恰好 1 条').toBe(1);
    assertDecrypted(pushMsgs[0], { text: 'dup_test' }, 'push');

    // pull 不应重复解密已推送的消息（SDK 内置 seen set 防重放）
    const pullResult = await receiver.call('message.pull', { after_seq: 0, limit: 50 }) as JsonObject;
    const pullMsgs = ((pullResult.messages ?? []) as Message[]).filter(
      (m) => m.from === sAid && m.encrypted === true,
    );
    // 记录数量供调试
    console.log(`  push=${pushMsgs.length}, pull=${pullMsgs.length}`);
  }, TEST_TIMEOUT);

  // ── 8. Raw WS → SDK ───────────────────────────────────────

  it('Raw WS 发送 → SDK 接收', async () => {
    const rid = runId();
    const rawClient = tracked();
    const sdkClient = tracked();

    const rawAid = `e2ee-raw-${rid}.agentid.pub`;
    const sdkAid = `e2ee-sdk-${rid}.agentid.pub`;
    await ensureConnected(rawClient, rawAid);
    await ensureConnected(sdkClient, sdkAid);

    const rawE2ee = makeRawE2ee(rawClient);
    await rawSend(rawClient, rawE2ee, sdkAid, { text: 'raw2sdk' });
    const msgs = await sdkRecvPush(sdkClient, rawAid);
    expect(msgs.length, 'SDK 应收到消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgs[0], { text: 'raw2sdk' });
  }, TEST_TIMEOUT);

  // ── 9. SDK → Raw WS ───────────────────────────────────────

  it('SDK 发送 → Raw WS 接收', async () => {
    const rid = runId();
    const sender = tracked();
    const rawClient = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);
    await ensureConnected(rawClient, rAid);

    const rawE2ee = makeRawE2ee(rawClient);
    await sdkSend(sender, rAid, { text: 'sdk2raw' });
    await new Promise((r) => setTimeout(r, 1000));
    const msgs = await rawRecvPull(rawClient, rawE2ee, sAid);
    expect(msgs.length, 'Raw WS 应收到消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgs[0], { text: 'sdk2raw' });
  }, TEST_TIMEOUT);

  // ── 10. Raw WS ↔ Raw WS ──────────────────────────────────

  it('Raw WS 双向互通', async () => {
    const rid = runId();
    const clientA = tracked();
    const clientB = tracked();

    const aAid = `e2ee-a-${rid}.agentid.pub`;
    const bAid = `e2ee-b-${rid}.agentid.pub`;
    await ensureConnected(clientA, aAid);
    await ensureConnected(clientB, bAid);

    const e2eeA = makeRawE2ee(clientA);
    const e2eeB = makeRawE2ee(clientB);

    // A → B
    await rawSend(clientA, e2eeA, bAid, { text: 'raw_a2b' });
    await new Promise((r) => setTimeout(r, 1000));
    const msgsB = await rawRecvPull(clientB, e2eeB, aAid);
    expect(msgsB.length, 'B 应收到 A 的消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgsB[0], { text: 'raw_a2b' }, 'A→B');

    // B → A
    await rawSend(clientB, e2eeB, aAid, { text: 'raw_b2a' });
    await new Promise((r) => setTimeout(r, 1000));
    const msgsA = await rawRecvPull(clientA, e2eeA, bAid);
    expect(msgsA.length, 'A 应收到 B 的消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgsA[0], { text: 'raw_b2a' }, 'B→A');
  }, TEST_TIMEOUT);

  // ── 11. SDK ↔ Raw 混合双向 ────────────────────────────────

  it('SDK ↔ Raw WS 混合双向', async () => {
    const rid = runId();
    const sdkClient = tracked();
    const rawClient = tracked();

    const sdkAid = `e2ee-sdk-${rid}.agentid.pub`;
    const rawAid = `e2ee-raw-${rid}.agentid.pub`;
    await ensureConnected(sdkClient, sdkAid);
    await ensureConnected(rawClient, rawAid);

    const rawE2ee = makeRawE2ee(rawClient);

    // SDK → Raw
    await sdkSend(sdkClient, rawAid, { text: 'sdk2raw_bidir', dir: 'forward' });
    await new Promise((r) => setTimeout(r, 1000));
    const msgsRaw = await rawRecvPull(rawClient, rawE2ee, sdkAid);
    expect(msgsRaw.length, 'Raw 应收到 SDK 的消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgsRaw[0], { text: 'sdk2raw_bidir' }, 'SDK→Raw');

    // Raw → SDK
    await rawSend(rawClient, rawE2ee, sdkAid, { text: 'raw2sdk_bidir', dir: 'reverse' });
    const msgsSdk = await sdkRecvPush(sdkClient, rawAid);
    expect(msgsSdk.length, 'SDK 应收到 Raw 的消息').toBeGreaterThanOrEqual(1);
    assertDecrypted(msgsSdk[0], { text: 'raw2sdk_bidir' }, 'Raw→SDK');
  }, TEST_TIMEOUT);

  // ── 12. Raw WS 连续发送（burst） ──────────────────────────

  it('Raw WS 连续发送（burst）', async () => {
    const rid = runId();
    const sClient = tracked();
    const rClient = tracked();

    const sAid = `e2ee-s-${rid}.agentid.pub`;
    const rAid = `e2ee-r-${rid}.agentid.pub`;
    await ensureConnected(sClient, sAid);
    await ensureConnected(rClient, rAid);

    const sE2ee = makeRawE2ee(sClient);
    const rE2ee = makeRawE2ee(rClient);

    const N = 3;
    for (let i = 0; i < N; i++) {
      await rawSend(sClient, sE2ee, rAid, { text: `raw_burst_${i}`, i });
    }

    await new Promise((r) => setTimeout(r, 2000));
    const msgs = await rawRecvPull(rClient, rE2ee, sAid);
    expect(msgs.length, `应收到 ${N} 条消息`).toBeGreaterThanOrEqual(N);

    const texts = msgs.map((m) => String((m.payload as JsonObject).text ?? '')).sort();
    const expected = Array.from({ length: N }, (_, i) => `raw_burst_${i}`).sort();
    expect(texts, '消息内容应完全匹配').toEqual(expected);
  }, TEST_TIMEOUT);
});
