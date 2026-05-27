/**
 * AUN E2EE V2: thought.put / thought.get 端到端测试
 *
 * 覆盖：
 * - message.thought.put / message.thought.get（P2P thought，per-device wrap）
 * - group.thought.put / group.thought.get（Group thought，per-device wrap）
 *
 * V2 thought 协议约定：
 * - 服务端依旧仅做内存级 KV，不持久化、不分配 seq、不 ack
 * - SDK 在 V2 ready 时多设备 wrap 出 e2ee.p2p_encrypted / e2ee.group_encrypted envelope
 *   作为 payload 上传，服务端对 envelope 透传，客户端读取后再单设备解密
 * - 单条 thought 服务端只存一份 envelope，envelope 内含多个 device wrap
 *
 * 运行方法（容器内）：
 *   npx vitest run tests/e2e/v2-thought.test.ts --reporter=verbose
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;
const TEST_TIMEOUT = 90_000;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-v2-thought-'));
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function connectClient(client: AUNClient, aid: string): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
  await client.auth.registerAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect({ ...auth, auto_reconnect: false });
  await client.initV2Session();
}

function payloadTexts(result: JsonObject): string[] {
  const thoughts = Array.isArray(result.thoughts) ? result.thoughts : [];
  const texts: string[] = [];
  for (const item of thoughts) {
    const thought = item as JsonObject;
    const payload = thought.payload as JsonObject | undefined;
    const text = typeof payload?.text === 'string' ? payload.text : '';
    if (text) texts.push(text);
  }
  return texts;
}

describe('V2 thought.put / thought.get 端到端测试', { timeout: TEST_TIMEOUT }, () => {
  let alice: AUNClient;
  let bob: AUNClient;
  let ALICE_AID: string;
  let BOB_AID: string;
  let groupId: string;

  // 共享上下文
  let p2pCtx: JsonObject;
  let p2pText: string;
  let groupCtx: JsonObject;
  let groupText: string;

  beforeAll(async () => {
    const rid = runId();
    ALICE_AID = `v2t-a-${rid}.${ISSUER}`;
    BOB_AID = `v2t-b-${rid}.${ISSUER}`;

    alice = makeClient();
    bob = makeClient();

    await connectClient(alice, ALICE_AID);
    await connectClient(bob, BOB_AID);

    console.log(`[setup] Alice V2=${(alice as any)._v2Session != null}, Bob V2=${(bob as any)._v2Session != null}`);

    // 创建 V2 测试群
    const result = await alice.call('group.create', {
      name: `v2-thought-${Date.now()}`,
      visibility: 'private',
    }) as Record<string, unknown>;
    const group = result.group as Record<string, unknown>;
    groupId = String(group.group_id ?? '');
    console.log(`[setup] 创建群: ${groupId}`);

    await alice.call('group.add_member', {
      group_id: groupId,
      aid: BOB_AID,
    });
    await new Promise(r => setTimeout(r, 500));
    console.log(`[setup] Bob 已加入群`);
  });

  afterAll(async () => {
    try { await alice?.close(); } catch { /* ignore */ }
    try { await bob?.close(); } catch { /* ignore */ }
  });

  // ── 场景 1：P2P thought.put 走 V2 加密 ──

  it('P2P thought.put 写 V2 envelope', async () => {
    const rid = runId();
    p2pCtx = { type: 'v2-run', id: `v2-thought-run-${rid}` };
    p2pText = `v2-thought-p2p-${rid}-${Date.now()}`;
    const put = await alice.call('message.thought.put', {
      to: BOB_AID,
      context: p2pCtx,
      thought_id: `mt-v2-${rid}`,
      payload: { type: 'thought', text: p2pText },
    }) as JsonObject;
    expect(Number(put.stored_count ?? 0), `unexpected put result: ${JSON.stringify(put)}`).toBeGreaterThanOrEqual(1);

    // 直接读服务端原始返回，验证 envelope.type 为 V2 P2P 加密格式
    const raw = await ((bob as unknown) as { _transport: { call: (m: string, p: JsonObject) => Promise<JsonObject> } })._transport.call(
      'message.thought.get',
      { sender_aid: ALICE_AID, context: p2pCtx },
    );
    const items = Array.isArray(raw.thoughts) ? raw.thoughts : [];
    expect(items.length, `server raw thoughts empty: ${JSON.stringify(raw)}`).toBeGreaterThanOrEqual(1);
    const firstPayload = (items[0] as JsonObject).payload as JsonObject || {};
    const envType = firstPayload.type;
    expect(envType, `V2 P2P thought payload.type 必须为 e2ee.p2p_encrypted，实际=${String(envType)}`).toBe('e2ee.p2p_encrypted');
    const recipients = firstPayload.recipients;
    expect(Array.isArray(recipients) && (recipients as unknown[]).length > 0,
      `V2 P2P thought envelope 必须包含 recipients[]，实际=${JSON.stringify(firstPayload)}`).toBe(true);
    console.log(`  (envelope.type=${envType}, recipients=${(recipients as unknown[]).length})`);
  });

  // ── 场景 2：P2P thought.get 解密回明文 ──

  it('P2P thought.get 解密', async () => {
    const result = await bob.call('message.thought.get', {
      sender_aid: ALICE_AID,
      context: p2pCtx,
    }) as JsonObject;
    const texts = payloadTexts(result);
    expect(
      texts,
      `V2 P2P thought 解密返回不含期望文本: texts=${JSON.stringify(texts)}`,
    ).toContain(p2pText);
  });

  // ── 场景 3：P2P thought 重复读取不消耗（无 replay guard） ──

  it('P2P thought 重复读取', async () => {
    const result = await bob.call('message.thought.get', {
      sender_aid: ALICE_AID,
      context: p2pCtx,
    }) as JsonObject;
    const texts = payloadTexts(result);
    expect(texts, `重复读 V2 thought 失败: texts=${JSON.stringify(texts)}`).toContain(p2pText);

    // 验证 e2ee.protected_headers 和 e2ee.context 暴露
    const thoughts = Array.isArray(result.thoughts) ? result.thoughts : [];
    const first = thoughts[0] as JsonObject;
    const e2ee = first?.e2ee as JsonObject | undefined;
    expect(e2ee, `e2ee metadata 缺失`).toBeDefined();
    expect(e2ee?.version).toBe('v2');
    // protected_headers 应包含 payload_type（去掉 _auth）
    if (e2ee?.protected_headers) {
      const ph = e2ee.protected_headers as JsonObject;
      expect(ph._auth, `e2ee.protected_headers 不应包含 _auth`).toBeUndefined();
    }
    // context 应包含原始 context 字段（去掉 _auth）
    if (e2ee?.context) {
      const ctx = e2ee.context as JsonObject;
      expect(ctx._auth, `e2ee.context 不应包含 _auth`).toBeUndefined();
      expect(ctx.type).toBe(p2pCtx.type);
      expect(ctx.id).toBe(p2pCtx.id);
    }
  });

  // ── 场景 4：Group thought.put 走 V2 加密 ──

  it('Group thought.put 写 V2 envelope', async () => {
    const rid = runId();
    groupCtx = { type: 'v2-group-run', id: `v2-group-thought-${rid}` };
    groupText = `v2-group-thought-${rid}-${Date.now()}`;
    const put = await alice.call('group.thought.put', {
      group_id: groupId,
      context: groupCtx,
      payload: { type: 'thought', text: groupText },
    }) as JsonObject;
    expect(typeof put === 'object' && put !== null, `group.thought.put 失败: ${JSON.stringify(put)}`).toBe(true);

    const raw = await ((bob as unknown) as { _transport: { call: (m: string, p: JsonObject) => Promise<JsonObject> } })._transport.call(
      'group.thought.get',
      { group_id: groupId, sender_aid: ALICE_AID, context: groupCtx },
    );
    const items = Array.isArray(raw.thoughts) ? raw.thoughts : [];
    expect(items.length, `server raw group thoughts empty: ${JSON.stringify(raw)}`).toBeGreaterThanOrEqual(1);
    const firstPayload = (items[0] as JsonObject).payload as JsonObject || {};
    const envType = firstPayload.type;
    expect(envType, `V2 group thought payload.type 必须为 e2ee.group_encrypted，实际=${String(envType)}`).toBe('e2ee.group_encrypted');
    const recipients = firstPayload.recipients;
    expect(Array.isArray(recipients) && (recipients as unknown[]).length > 0,
      `V2 group thought envelope 必须含 recipients[]，实际=${JSON.stringify(firstPayload)}`).toBe(true);
    console.log(`  (envelope.type=${envType}, recipients=${(recipients as unknown[]).length})`);
  });

  // ── 场景 5：Group thought.get 解密回明文 ──

  it('Group thought.get 解密', async () => {
    const result = await bob.call('group.thought.get', {
      group_id: groupId,
      sender_aid: ALICE_AID,
      context: groupCtx,
    }) as JsonObject;
    const texts = payloadTexts(result);
    expect(
      texts,
      `V2 group thought 解密失败: texts=${JSON.stringify(texts)}`,
    ).toContain(groupText);

    // 验证 e2ee.protected_headers 和 e2ee.context 暴露
    const thoughts = Array.isArray(result.thoughts) ? result.thoughts : [];
    const first = thoughts[0] as JsonObject;
    const e2ee = first?.e2ee as JsonObject | undefined;
    expect(e2ee, `e2ee metadata 缺失`).toBeDefined();
    expect(e2ee?.version).toBe('v2');
    // protected_headers 应包含 payload_type（去掉 _auth）
    if (e2ee?.protected_headers) {
      const ph = e2ee.protected_headers as JsonObject;
      expect(ph._auth, `e2ee.protected_headers 不应包含 _auth`).toBeUndefined();
    }
    // context 应包含原始 context 字段（去掉 _auth）
    if (e2ee?.context) {
      const ctx = e2ee.context as JsonObject;
      expect(ctx._auth, `e2ee.context 不应包含 _auth`).toBeUndefined();
      expect(ctx.type).toBe(groupCtx.type);
      expect(ctx.id).toBe(groupCtx.id);
    }
  });
});
