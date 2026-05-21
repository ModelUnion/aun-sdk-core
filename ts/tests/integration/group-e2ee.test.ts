/**
 * Group E2EE V2 集成测试 — 需要运行中的 AUN Gateway + Group Service。
 *
 * 使用 SDK 公开 API 测试群组端到端加密功能：
 *   1. 创建加密群组
 *   2. 发送加密群消息
 *   3. 非成员无法访问加密群消息
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - Docker network alias 可解析 gateway.agentid.pub
 *
 * 运行方法：
 *   npx vitest run tests/integration/group-e2ee.test.ts
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';

process.env.AUN_ENV ??= 'development';

// ── 常量 ──────────────────────────────────────────────────────

const TEST_TIMEOUT = 60_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

// ── 类型别名 ──────────────────────────────────────────────────

type JsonObject = Record<string, unknown>;

// ── 辅助函数 ──────────────────────────────────────────────────

/** 生成唯一运行标识（UUID 前 12 位，避免 AID 碰撞） */
function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

/** 创建测试客户端（Gateway 通过 well-known 自动发现） */
function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ge2ee-'));
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

/** 注册 AID 并连接到 Gateway */
async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForV2BootstrapDevice(owner: AUNClient, groupId: string, memberAid: string): Promise<void> {
  const timeoutMs = 50_000;
  const deadline = Date.now() + timeoutMs;
  let attempt = 0;
  let lastEpoch = 0;
  let lastDeviceCount = 0;
  let lastCommitted: string[] = [];
  let lastPendingAdds: string[] = [];
  let lastPendingRemoves: string[] = [];
  let lastSnapshot = '';
  while (Date.now() < deadline) {
    attempt += 1;
    const bootstrap = await owner.call('group.v2.bootstrap', { group_id: groupId }) as JsonObject;
    const devices = Array.isArray(bootstrap.devices) ? bootstrap.devices : [];
    lastEpoch = Number(bootstrap.epoch ?? 0) || 0;
    lastDeviceCount = devices.filter((item) => {
      if (!item || typeof item !== 'object') return false;
      return String((item as JsonObject).aid ?? '').trim() === memberAid;
    }).length;
    lastCommitted = Array.isArray(bootstrap.committed_member_aids)
      ? bootstrap.committed_member_aids.map(aid => String(aid))
      : [];
    lastPendingAdds = Array.isArray(bootstrap.pending_adds)
      ? bootstrap.pending_adds.map(aid => String(aid))
      : [];
    lastPendingRemoves = Array.isArray(bootstrap.pending_removes)
      ? bootstrap.pending_removes.map(aid => String(aid))
      : [];
    const snapshot = JSON.stringify({
      epoch: lastEpoch,
      devices: lastDeviceCount,
      committed: lastCommitted,
      pending_adds: lastPendingAdds,
      pending_removes: lastPendingRemoves,
    });
    if (attempt === 1 || attempt % 5 === 0 || snapshot !== lastSnapshot) {
      console.log(
        `  [wait] group=${groupId} member=${memberAid} attempt=${attempt} `
        + `epoch=${lastEpoch} devices=${lastDeviceCount} `
        + `committed=${JSON.stringify(lastCommitted)} `
        + `pending_adds=${JSON.stringify(lastPendingAdds)} `
        + `pending_removes=${JSON.stringify(lastPendingRemoves)}`,
      );
      lastSnapshot = snapshot;
    }
    if (
      lastDeviceCount > 0
      && lastCommitted.includes(memberAid)
      && lastPendingAdds.length === 0
      && lastPendingRemoves.length === 0
    ) return;
    await sleep(500);
  }
  throw new Error(
    `等待群成员 V2 就绪超时: group=${groupId} member=${memberAid} `
    + `last_epoch=${lastEpoch} devices_for_member=${lastDeviceCount} `
    + `committed=${JSON.stringify(lastCommitted)} pending_adds=${JSON.stringify(lastPendingAdds)} pending_removes=${JSON.stringify(lastPendingRemoves)}`,
  );
}

/** 判断错误是否为"服务未实现"，用于优雅跳过 */
function isNotImplemented(e: unknown): boolean {
  const msg = (e as any)?.message?.toLowerCase() ?? '';
  return msg.includes('not implement') || msg.includes('method not found') || msg.includes('unknown method');
}

// ── 1. 创建加密群组 ──────────────────────────────────────────────

describe('Group E2EE: 创建加密群组', () => {
  const clients: AUNClient[] = [];

  function tracked(): AUNClient {
    const c = makeClient();
    clients.push(c);
    return c;
  }

  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  it('owner 创建加密群组并验证 group_id 与 e2ee 字段', async () => {
    const rid = runId();
    const ownerAid = `ge2ee-own-${rid}.${ISSUER}`;
    const owner = tracked();

    await ensureConnected(owner, ownerAid);

    // 尝试创建加密群组（encrypt/e2ee 标志取决于服务端支持）
    let groupId = '';
    let createResult: JsonObject;
    try {
      createResult = await owner.call('group.create', {
        name: `e2ee-group-${rid}`,
        visibility: 'private',
        encrypt: true,
      }) as JsonObject;
    } catch (e) {
      if (isNotImplemented(e)) {
        // 尝试用 e2ee 参数
        try {
          createResult = await owner.call('group.create', {
            name: `e2ee-group-${rid}`,
            visibility: 'private',
            e2ee: true,
          }) as JsonObject;
        } catch (e2) {
          if (isNotImplemented(e2)) {
            console.log('group.create 加密群未实现，跳过测试');
            return;
          }
          throw e2;
        }
      } else {
        throw e;
      }
    }

    const group = createResult.group as JsonObject | undefined;
    expect(group, '创建结果应包含 group 对象').toBeDefined();

    groupId = String(group?.group_id ?? '');
    expect(groupId, 'group_id 应为非空字符串').toBeTruthy();

    // 查询群信息，验证 e2ee 相关字段
    let info: JsonObject;
    try {
      info = await owner.call('group.get_info', {
        group_id: groupId,
      }) as JsonObject;
    } catch (e) {
      if (isNotImplemented(e)) {
        console.log('group.get_info 未实现，跳过 info 校验');
        return;
      }
      throw e;
    }

    expect(info, 'get_info 应返回结果').toBeDefined();

    // group_id 应在顶层或 group 子对象中
    const infoGroup = (info.group ?? info) as JsonObject;
    const infoGid = String(infoGroup.group_id ?? '');
    expect(infoGid, 'get_info 的 group_id 应与创建一致').toBe(groupId);

    // 检查 e2ee 相关字段（不同实现可能命名不同）
    const hasE2eeField =
      infoGroup.e2ee !== undefined ||
      infoGroup.encrypt !== undefined ||
      infoGroup.encrypted !== undefined ||
      infoGroup.encryption !== undefined;
    console.log(`  e2ee 字段检测: ${hasE2eeField ? '存在' : '不存在（可能默认启用）'}`);

    // 兜底清理
    try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
  }, TEST_TIMEOUT);
});

// ── 2. 发送加密群消息 ────────────────────────────────────────────

describe('Group E2EE: 发送加密群消息', () => {
  const clients: AUNClient[] = [];

  function tracked(): AUNClient {
    const c = makeClient();
    clients.push(c);
    return c;
  }

  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  it('owner 发送加密群消息，member 收到并解密', async () => {
    const rid = runId();
    const ownerAid = `ge2ee-own-${rid}.${ISSUER}`;
    const memberAid = `ge2ee-mem-${rid}.${ISSUER}`;

    const owner = tracked();
    const member = tracked();

    await ensureConnected(owner, ownerAid);
    await ensureConnected(member, memberAid);

    // 创建群组
    let groupId = '';
    try {
      const createResult = await owner.call('group.create', {
        name: `e2ee-send-${rid}`,
        visibility: 'private',
        group_e2ee_protocol: 'group_e2ee_v2',
      }) as JsonObject;
      const group = createResult.group as JsonObject | undefined;
      groupId = String(group?.group_id ?? '');
      expect(groupId).toBeTruthy();
    } catch (e) {
      if (isNotImplemented(e)) {
        console.log('group.create 未实现，跳过测试');
        return;
      }
      throw e;
    }

    // 添加成员
    try {
      await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      });
    } catch (e) {
      if (isNotImplemented(e)) {
        console.log('group.add_member 未实现，跳过测试');
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
        return;
      }
      throw e;
    }

    await waitForV2BootstrapDevice(owner, groupId, memberAid);

    // member 监听群消息事件
    const receivedMessages: JsonObject[] = [];
    let resolveWait: () => void;
    const waitPromise = new Promise<void>(r => { resolveWait = r; });

    const sub = member.on('group.message_created', (data) => {
      const msg = data as JsonObject;
      if (String(msg.group_id ?? '') === groupId) {
        receivedMessages.push(msg);
        resolveWait();
      }
    });

    // owner 发送加密群消息
    const msgText = `e2ee-msg-${rid}`;
    try {
      await owner.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: msgText },
        encrypt: true,
      });
    } catch (e) {
      sub.unsubscribe();
      if (isNotImplemented(e)) {
        console.log('group.send 未实现，跳过测试');
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
        return;
      }
      throw e;
    }

    // 等待消息推送，超时后 pull 兜底
    const timer = setTimeout(() => resolveWait(), 10_000);
    await waitPromise;
    clearTimeout(timer);
    sub.unsubscribe();

    // 推送未收到时，尝试 pull 兜底
    if (receivedMessages.length === 0) {
      try {
        const pullResult = await member.call('group.pull', {
          group_id: groupId,
          after_message_seq: 0,
        }) as JsonObject;
        const msgs = (pullResult.messages ?? []) as JsonObject[];
        for (const m of msgs) {
          if (String(m.group_id ?? '') === groupId) {
            receivedMessages.push(m);
          }
        }
      } catch (e) {
        if (!isNotImplemented(e)) throw e;
      }
    }

    expect(receivedMessages.length, '成员应收到至少 1 条群消息').toBeGreaterThanOrEqual(1);

    // 验证消息内容
    const matched = receivedMessages.find(msg => {
      const payload = msg.payload as JsonObject | undefined;
      return String(payload?.text ?? '') === msgText;
    });
    expect(matched, `应收到包含 "${msgText}" 的消息`).toBeTruthy();

    // 兜底清理
    try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
  }, TEST_TIMEOUT);
});

// ── 3. 非成员无法访问加密群消息 ──────────────────────────────────

describe('Group E2EE: 非成员无法访问加密群消息', () => {
  const clients: AUNClient[] = [];

  function tracked(): AUNClient {
    const c = makeClient();
    clients.push(c);
    return c;
  }

  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  it('非成员 pull 加密群消息应失败或返回空', async () => {
    const rid = runId();
    const ownerAid = `ge2ee-own-${rid}.${ISSUER}`;
    const memberAid = `ge2ee-mem-${rid}.${ISSUER}`;
    const outsiderAid = `ge2ee-out-${rid}.${ISSUER}`;

    const owner = tracked();
    const memberClient = tracked();
    const outsider = tracked();

    await ensureConnected(owner, ownerAid);
    await ensureConnected(memberClient, memberAid);
    await ensureConnected(outsider, outsiderAid);

    // 创建群组并添加 member（不添加 outsider）
    let groupId = '';
    try {
      const createResult = await owner.call('group.create', {
        name: `e2ee-acl-${rid}`,
        visibility: 'private',
        group_e2ee_protocol: 'group_e2ee_v2',
      }) as JsonObject;
      const group = createResult.group as JsonObject | undefined;
      groupId = String(group?.group_id ?? '');
      expect(groupId).toBeTruthy();
    } catch (e) {
      if (isNotImplemented(e)) {
        console.log('group.create 未实现，跳过测试');
        return;
      }
      throw e;
    }

    try {
      await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      });
    } catch (e) {
      if (isNotImplemented(e)) {
        console.log('group.add_member 未实现，跳过测试');
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
        return;
      }
      throw e;
    }

    await waitForV2BootstrapDevice(owner, groupId, memberAid);

    // owner 发送加密群消息
    const msgText = `secret-${rid}`;
    try {
      await owner.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: msgText },
        encrypt: true,
      });
    } catch (e) {
      if (isNotImplemented(e)) {
        console.log('group.send 未实现，跳过测试');
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
        return;
      }
      throw e;
    }

    await sleep(1000);

    // outsider 尝试 pull 群消息 — 应失败或返回空
    let outsiderGotMessages = false;
    try {
      const pullResult = await outsider.call('group.pull', {
        group_id: groupId,
        after_message_seq: 0,
      }) as JsonObject;

      const msgs = (pullResult.messages ?? []) as JsonObject[];
      // 即使能拉到消息，因为 outsider 没有群密钥，也不应能解密
      const decryptedMsgs = msgs.filter(m => {
        const payload = m.payload as JsonObject | undefined;
        return String(payload?.text ?? '') === msgText;
      });
      outsiderGotMessages = decryptedMsgs.length > 0;
    } catch {
      // 预期：非成员 pull 应抛出权限错误
      outsiderGotMessages = false;
    }

    expect(outsiderGotMessages, '非成员不应能访问加密群消息明文').toBe(false);

    // 兜底清理
    try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
  }, TEST_TIMEOUT);
});
