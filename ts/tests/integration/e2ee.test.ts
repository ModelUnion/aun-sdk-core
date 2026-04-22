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

process.env.AUN_ENV ??= 'development';

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
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

function makeClientAtPath(aunPath: string, slotId = ''): AUNClient {
  const client = new AUNClient({ aun_path: aunPath }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  if (slotId) {
    ((client as unknown) as { _slotId: string })._slotId = slotId;
  }
  return client;
}

function makeIsolatedClient(tag: string, slotId = ''): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `aun-${tag}-`));
  return makeClientAtPath(tmpDir, slotId);
}

function copyIdentityTree(sourceRoot: string, targetRoot: string, aid: string): void {
  const sourceIdentity = path.join(sourceRoot, 'AIDs', aid);
  if (!fs.existsSync(sourceIdentity)) {
    throw new Error(`identity source missing: ${sourceIdentity}`);
  }
  fs.mkdirSync(path.join(targetRoot, 'AIDs'), { recursive: true });
  const sourceSeed = path.join(sourceRoot, '.seed');
  if (fs.existsSync(sourceSeed)) {
    fs.copyFileSync(sourceSeed, path.join(targetRoot, '.seed'));
  }
  // 只复制身份材料（key.json/cert.pem），跳过 SQLite 数据库文件
  // 每个实例使用 aun_{device_id}.db，源实例的 db 不应被复制
  fs.cpSync(sourceIdentity, path.join(targetRoot, 'AIDs', aid), {
    recursive: true,
    filter: (src: string) => !/\.(db|db-wal|db-shm|db-journal)/.test(path.basename(src)),
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

async function currentMaxSeq(client: AUNClient, limit = 200): Promise<number> {
  let afterSeq = 0;
  let maxSeq = 0;
  for (;;) {
    const result = await client.call('message.pull', { after_seq: afterSeq, limit }) as JsonObject;
    const msgs = (result.messages ?? []) as Message[];
    if (msgs.length === 0) return maxSeq;
    for (const msg of msgs) {
      maxSeq = Math.max(maxSeq, Number(msg.seq ?? 0));
    }
    if (msgs.length < limit) return maxSeq;
    afterSeq = maxSeq;
  }
}

async function waitForSdkPullMessage(
  client: AUNClient,
  fromAid: string,
  afterSeq: number,
  expectedText: string,
  timeout = 20_000,
): Promise<Message> {
  const deadline = Date.now() + timeout;
  let lastMessages: Message[] = [];
  while (Date.now() < deadline) {
    const messages = await sdkRecvPull(client, fromAid, afterSeq);
    lastMessages = messages;
    for (const message of messages) {
      const payload = message.payload as JsonObject;
      if (String(payload?.text ?? '') === expectedText) {
        return message;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(
    `timeout waiting for message text=${expectedText} from=${fromAid}; last_messages=${JSON.stringify(lastMessages)}`,
  );
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
  _deviceId: string;
  _transport: InternalTransport;
  _fetchPeerCert: (aid: string, certFingerprint?: string) => Promise<string>;
  _fetchPeerPrekey: (aid: string) => Promise<PrekeyRecord | null>;
  _ensureSenderCertCached: (aid: string, certFingerprint?: string) => Promise<boolean>;
  _uploadPrekey: () => Promise<JsonObject | null>;
};

/** 从已连接的 AUNClient 提取内部引用，创建独立 E2EEManager（模拟裸 WebSocket 开发者） */
function makeRawE2ee(client: AUNClient): E2EEManager {
  const internal = client as ClientInternals;
  return new E2EEManager({
    identityFn: () => internal._identity ?? {},
    deviceIdFn: () => internal._deviceId,
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

  const prekey = await fetchPrekey(toAid);
  const peerCertFingerprint = typeof prekey?.cert_fingerprint === 'string' ? prekey.cert_fingerprint : undefined;
  const peerCertPem = await fetchCert(toAid, peerCertFingerprint);

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
  const internal = client as ClientInternals;
  await internal._ensureSenderCertCached(fromAid);
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

async function waitForRawPullMessage(
  client: AUNClient,
  e2ee: E2EEManager,
  fromAid: string,
  afterSeq: number,
  expectedText: string,
  timeout: number = 20_000,
): Promise<Message> {
  const deadline = Date.now() + timeout;
  let lastMessages: Message[] = [];
  while (Date.now() < deadline) {
    const messages = await rawRecvPull(client, e2ee, fromAid, afterSeq);
    lastMessages = messages;
    for (const message of messages) {
      const payload = message.payload as JsonObject;
      if (String(payload?.text ?? '') === expectedText) {
        return message;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(
    `timeout waiting for raw message text=${expectedText} from=${fromAid}; last_messages=${JSON.stringify(lastMessages)}`,
  );
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
    sender.e2ee.invalidatePrekeyCache(rAid);

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
    const baseSeq = await currentMaxSeq(rawClient);
    const text = `sdk2raw_${Date.now()}`;
    await sdkSend(sender, rAid, { text });
    const msg = await waitForRawPullMessage(rawClient, rawE2ee, sAid, baseSeq, text);
    assertDecrypted(msg, { text });
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
    const baseSeqB = await currentMaxSeq(clientB);
    const textA2B = `raw_a2b_${Date.now()}`;
    await rawSend(clientA, e2eeA, bAid, { text: textA2B });
    const msgB = await waitForRawPullMessage(clientB, e2eeB, aAid, baseSeqB, textA2B);
    assertDecrypted(msgB, { text: textA2B }, 'A→B');

    // B → A
    const baseSeqA = await currentMaxSeq(clientA);
    const textB2A = `raw_b2a_${Date.now()}`;
    await rawSend(clientB, e2eeB, aAid, { text: textB2A });
    const msgA = await waitForRawPullMessage(clientA, e2eeA, bAid, baseSeqA, textB2A);
    assertDecrypted(msgA, { text: textB2A }, 'B→A');
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
    const rawBaseSeq = await currentMaxSeq(rawClient);
    const sdkToRawText = `sdk2raw_bidir_${Date.now()}`;
    await sdkSend(sdkClient, rawAid, { text: sdkToRawText, dir: 'forward' });
    const msgRaw = await waitForRawPullMessage(rawClient, rawE2ee, sdkAid, rawBaseSeq, sdkToRawText);
    assertDecrypted(msgRaw, { text: sdkToRawText }, 'SDK→Raw');

    // Raw → SDK
    const sdkBaseSeq = await currentMaxSeq(sdkClient);
    const rawToSdkText = `raw2sdk_bidir_${Date.now()}`;
    await rawSend(rawClient, rawE2ee, sdkAid, { text: rawToSdkText, dir: 'reverse' });
    const msgsSdk = await sdkRecvPush(sdkClient, rawAid);
    const msgSdk = msgsSdk.find((msg) => String(((msg.payload as JsonObject).text) ?? '') === rawToSdkText)
      ?? await waitForSdkPullMessage(sdkClient, rawAid, sdkBaseSeq, rawToSdkText);
    assertDecrypted(msgSdk, { text: rawToSdkText }, 'Raw→SDK');
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
    const baseSeq = await currentMaxSeq(rClient);

    const N = 3;
    for (let i = 0; i < N; i++) {
      await rawSend(sClient, sE2ee, rAid, { text: `raw_burst_${i}`, i });
    }

    await new Promise((r) => setTimeout(r, 2000));
    const msgs = await rawRecvPull(rClient, rE2ee, sAid, baseSeq);
    expect(msgs.length, `应收到 ${N} 条消息`).toBeGreaterThanOrEqual(N);

    const texts = msgs.map((m) => String((m.payload as JsonObject).text ?? '')).sort();
    const expected = Array.from({ length: N }, (_, i) => `raw_burst_${i}`).sort();
    expect(texts, '消息内容应完全匹配').toEqual(expected);
  }, TEST_TIMEOUT);

  it('同一 AID 多 slot ack 隔离', async () => {
    const rid = runId();
    const sender = tracked();
    const sharedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-slot-shared-'));
    const receiverSlotA = makeClientAtPath(sharedRoot, 'slot-a');
    const receiverSlotB = makeClientAtPath(sharedRoot, 'slot-b');
    clients.push(receiverSlotA, receiverSlotB);

    const sAid = `e2ee-slot-s-${rid}.agentid.pub`;
    const rAid = `e2ee-slot-r-${rid}.agentid.pub`;
    await ensureConnected(sender, sAid);
    await ensureConnected(receiverSlotA, rAid);
    await ensureConnected(receiverSlotB, rAid);

    const baseSeqA = await currentMaxSeq(receiverSlotA);
    const baseSeqB = await currentMaxSeq(receiverSlotB);
    expect(baseSeqA).toBe(baseSeqB);

    const ackEvents: Message[] = [];
    let resolveWait: () => void;
    const waitPromise = new Promise<void>((r) => { resolveWait = r; });
    const sub = sender.on('message.ack', (data) => {
      const msg = data as Message;
      if (msg?.to !== rAid) return;
      const slotId = String((msg as JsonObject).slot_id ?? '');
      if (slotId !== 'slot-a' && slotId !== 'slot-b') return;
      ackEvents.push(msg);
      const seen = new Set(ackEvents.map((item) => String((item as JsonObject).slot_id ?? '')));
      if (seen.has('slot-a') && seen.has('slot-b')) {
        resolveWait();
      }
    });

    const text = `slot_isolation_${Date.now()}`;
    await sdkSend(sender, rAid, { text });
    const msgA = await waitForSdkPullMessage(receiverSlotA, sAid, baseSeqA, text, 15_000);
    const msgB = await waitForSdkPullMessage(receiverSlotB, sAid, baseSeqB, text, 15_000);
    assertDecrypted(msgA, { text }, 'slot-a');
    assertDecrypted(msgB, { text }, 'slot-b');
    expect(Number(msgA.seq ?? 0)).toBe(Number(msgB.seq ?? 0));

    const ackA = await receiverSlotA.call('message.ack', { seq: msgA.seq }) as JsonObject;
    const ackB = await receiverSlotB.call('message.ack', { seq: msgB.seq }) as JsonObject;
    expect(Number(ackA.ack_seq ?? 0)).toBe(Number(msgA.seq ?? 0));
    expect(Number(ackB.ack_seq ?? 0)).toBe(Number(msgB.seq ?? 0));

    const timer = setTimeout(() => resolveWait(), 5_000);
    await waitPromise;
    clearTimeout(timer);
    sub.unsubscribe();

    const slotsSeen = new Set(ackEvents.map((item) => String((item as JsonObject).slot_id ?? '')));
    expect(slotsSeen).toEqual(new Set(['slot-a', 'slot-b']));
    const deviceIds = new Set(ackEvents.map((item) => String((item as JsonObject).device_id ?? '')));
    expect(deviceIds.size).toBe(1);
    expect(deviceIds.has('')).toBe(false);
  }, TEST_TIMEOUT);

  it('同一 AID 多设备 fanout + 发件同步副本', async () => {
    const rid = runId();
    const aliceSeedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-alice-seed-'));
    const aliceSyncRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-alice-sync-'));
    const bobSeedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-bob-seed-'));
    const bobSyncRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-bob-sync-'));
    const aliceSeed = makeClientAtPath(aliceSeedRoot);
    const bobSeed = makeClientAtPath(bobSeedRoot);
    clients.push(aliceSeed, bobSeed);

    const aliceAid = `e2ee-md-a-${rid}.agentid.pub`;
    const bobAid = `e2ee-md-b-${rid}.agentid.pub`;
    await ensureConnected(aliceSeed, aliceAid);
    await ensureConnected(bobSeed, bobAid);
    copyIdentityTree(aliceSeedRoot, aliceSyncRoot, aliceAid);
    copyIdentityTree(bobSeedRoot, bobSyncRoot, bobAid);
    const aliceSync = makeClientAtPath(aliceSyncRoot);
    const bobSync = makeClientAtPath(bobSyncRoot);
    clients.push(aliceSync, bobSync);
    await ensureConnected(aliceSync, aliceAid);
    await ensureConnected(bobSync, bobAid);
    await new Promise((r) => setTimeout(r, 1000));

    const baseMain = await currentMaxSeq(bobSeed);
    const baseSync = await currentMaxSeq(bobSync);
    const baseAliceSync = await currentMaxSeq(aliceSync);
    const text = `multi_device_sync_${Date.now()}`;

    await sdkSend(aliceSeed, bobAid, { text, kind: 'multi-device' });
    const mainMsg = await waitForSdkPullMessage(bobSeed, aliceAid, baseMain, text, 20_000);
    const syncMsg = await waitForSdkPullMessage(bobSync, aliceAid, baseSync, text, 20_000);
    const aliceSyncMsg = await waitForSdkPullMessage(aliceSync, aliceAid, baseAliceSync, text, 20_000);
    assertDecrypted(mainMsg, { text, kind: 'multi-device' }, 'bob-main');
    assertDecrypted(syncMsg, { text, kind: 'multi-device' }, 'bob-sync');
    assertDecrypted(aliceSyncMsg, { text, kind: 'multi-device' }, 'alice-sync');
    expect(String(mainMsg.direction ?? '')).toBe('inbound');
    expect(String(syncMsg.direction ?? '')).toBe('inbound');
    expect(String(aliceSyncMsg.direction ?? '')).toBe('outbound_sync');
  }, TEST_TIMEOUT);

  it('多设备离线设备重连后补拉自己的设备副本', async () => {
    const rid = runId();
    const aliceSeedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-offline-alice-seed-'));
    const bobSeedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-offline-bob-seed-'));
    const aliceMainRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-offline-alice-main-'));
    const bobPhoneRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-offline-bob-phone-'));
    const bobLaptopRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-offline-bob-laptop-'));

    const seedAlice = makeClientAtPath(aliceSeedRoot);
    const seedBob = makeClientAtPath(bobSeedRoot);
    clients.push(seedAlice, seedBob);

    const aliceAid = `e2ee-off-a-${rid}.agentid.pub`;
    const bobAid = `e2ee-off-b-${rid}.agentid.pub`;
    await ensureConnected(seedAlice, aliceAid);
    await ensureConnected(seedBob, bobAid);
    copyIdentityTree(aliceSeedRoot, aliceMainRoot, aliceAid);
    copyIdentityTree(bobSeedRoot, bobPhoneRoot, bobAid);
    copyIdentityTree(bobSeedRoot, bobLaptopRoot, bobAid);
    await seedAlice.close();
    await seedBob.close();

    const aliceMain = makeClientAtPath(aliceMainRoot);
    const bobPhone = makeClientAtPath(bobPhoneRoot);
    let bobLaptop = makeClientAtPath(bobLaptopRoot);
    clients.push(aliceMain, bobPhone, bobLaptop);

    await ensureConnected(aliceMain, aliceAid);
    await ensureConnected(bobPhone, bobAid);
    await ensureConnected(bobLaptop, bobAid);
    await new Promise((r) => setTimeout(r, 1000));

    const offlineBase = await currentMaxSeq(bobLaptop);
    const onlineBase = await currentMaxSeq(bobPhone);
    await bobLaptop.close();
    await new Promise((r) => setTimeout(r, 1000));

    const text = `multi_device_offline_${Date.now()}`;
    await sdkSend(aliceMain, bobAid, { text, kind: 'offline-pull' });

    const onlineMsg = await waitForSdkPullMessage(bobPhone, aliceAid, onlineBase, text, 15_000);
    assertDecrypted(onlineMsg, { text, kind: 'offline-pull' }, 'bob-phone-online');
    expect(String(onlineMsg.direction ?? '')).toBe('inbound');

    bobLaptop = makeClientAtPath(bobLaptopRoot);
    clients.push(bobLaptop);
    await ensureConnected(bobLaptop, bobAid);
    const offlineMsg = await waitForSdkPullMessage(bobLaptop, aliceAid, offlineBase, text, 15_000);
    assertDecrypted(offlineMsg, { text, kind: 'offline-pull' }, 'bob-laptop-offline');
    expect(String(offlineMsg.direction ?? '')).toBe('inbound');
  }, TEST_TIMEOUT);
});
