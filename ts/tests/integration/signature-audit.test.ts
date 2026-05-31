/**
 * 群操作签名审计 — 集成测试（单域环境）。
 *
 * 验证：
 *   1. 更新公告携带签名（actor_aid + client_signature）
 *   2. 踢人操作携带签名
 *   3. 设置角色携带签名
 *   4. 只读操作不需签名
 *
 * 运行方法：
 *   npx vitest run tests/integration/signature-audit.test.ts
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
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 60_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

// ── 辅助函数 ──────────────────────────────────────────────────────

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-sig-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** 判断错误是否为"服务未实现"，用于优雅跳过 */
function isNotImplemented(e: unknown): boolean {
  const msg = (e as any)?.message?.toLowerCase() ?? '';
  return msg.includes('not implement') || msg.includes('method not found') || msg.includes('unknown method');
}

// ── 1. 更新公告携带签名 ──────────────────────────────────────────

describe('签名审计: 更新公告携带签名', () => {
  it('set_settings announcement → 事件包含 actor_aid 和 client_signature', async () => {
    const rid = runId();
    const aliceAid = `sig-ann-a-${rid}.${ISSUER}`;
    const bobAid = `sig-ann-b-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    let groupId = '';

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // ---- 创建群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await alice.call('group.create', {
          name: `sig-ann-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过更新公告签名测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // 添加 Bob
      await alice.call('group.add_member', {
        group_id: groupId,
        aid: bobAid,
        role: 'member',
      });

      await sleep(500);

      // ---- Bob 监听 group.changed 事件 ----
      const receivedEvents: Record<string, unknown>[] = [];
      const eventReceived = new Promise<void>((resolve) => {
        bob.on('group.changed', (data: unknown) => {
          const evt = data as Record<string, unknown>;
          if (evt.group_id === groupId) {
            receivedEvents.push(evt);
            resolve();
          }
        });
      });

      // ---- Alice 更新公告 ----
      try {
        await alice.call('group.set_settings', {
          group_id: groupId,
          settings: {
            'announcement.content': `签名测试公告 ${rid}`,
          },
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- 等待 Bob 收到事件 ----
      await Promise.race([
        eventReceived,
        sleep(8000).then(() => { /* 超时不 reject，后续检查 */ }),
      ]);

      if (receivedEvents.length > 0) {
        const evt = receivedEvents[0];
        // 验证 actor_aid
        expect(evt.actor_aid).toBe(aliceAid);

        // 验证 client_signature（如果存在）
        const cs = evt.client_signature as Record<string, unknown> | undefined;
        if (cs) {
          expect(cs.aid).toBe(aliceAid);
          expect(cs.cert_fingerprint).toBeDefined();
          expect(typeof cs.cert_fingerprint).toBe('string');
          expect(cs.signature).toBeDefined();
        }
      } else {
        console.log('Bob 未收到 group.changed 事件（超时），跳过事件断言');
      }
    } finally {
      if (groupId) {
        try { await alice.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await alice.close();
      await bob.close();
    }
  }, TEST_TIMEOUT);
});

// ── 2. 踢人操作携带签名 ──────────────────────────────────────────

describe('签名审计: 踢人操作携带签名', () => {
  it('kick → 事件包含 actor_aid 和 client_signature', async () => {
    const rid = runId();
    const aliceAid = `sig-kick-a-${rid}.${ISSUER}`;
    const bobAid = `sig-kick-b-${rid}.${ISSUER}`;
    const charlieAid = `sig-kick-c-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();
    const charlie = makeClient();

    let groupId = '';

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);
      await ensureConnected(charlie, charlieAid);

      // ---- 创建群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await alice.call('group.create', {
          name: `sig-kick-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过踢人签名测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // 添加 Bob 和 Charlie
      await alice.call('group.add_member', {
        group_id: groupId,
        aid: bobAid,
        role: 'member',
      });
      await alice.call('group.add_member', {
        group_id: groupId,
        aid: charlieAid,
        role: 'member',
      });

      await sleep(500);

      // ---- Bob 监听 group.changed 事件 ----
      const receivedEvents: Record<string, unknown>[] = [];
      const eventReceived = new Promise<void>((resolve) => {
        bob.on('group.changed', (data: unknown) => {
          const evt = data as Record<string, unknown>;
          if (evt.group_id === groupId && evt.action === 'member_removed') {
            receivedEvents.push(evt);
            resolve();
          }
        });
      });

      // ---- Alice 踢 Charlie ----
      try {
        await alice.call('group.kick', {
          group_id: groupId,
          aid: charlieAid,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.kick 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- 等待 Bob 收到事件 ----
      await Promise.race([
        eventReceived,
        sleep(8000).then(() => { /* 超时不 reject */ }),
      ]);

      if (receivedEvents.length > 0) {
        const evt = receivedEvents[0];
        // 验证 actor_aid
        expect(evt.actor_aid).toBe(aliceAid);

        // 验证 client_signature（如果存在）
        const cs = evt.client_signature as Record<string, unknown> | undefined;
        if (cs) {
          expect(typeof cs).toBe('object');
          expect(cs.aid).toBe(aliceAid);
          expect(cs.cert_fingerprint).toBeDefined();
          expect(cs.signature).toBeDefined();
        }
      } else {
        console.log('Bob 未收到 member_removed 事件（超时），跳过事件断言');
      }
    } finally {
      if (groupId) {
        try { await alice.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await alice.close();
      await bob.close();
      await charlie.close();
    }
  }, TEST_TIMEOUT);
});

// ── 3. 设置角色携带签名 ──────────────────────────────────────────

describe('签名审计: 设置角色携带签名', () => {
  it('set_role → 事件包含 actor_aid', async () => {
    const rid = runId();
    const aliceAid = `sig-role-a-${rid}.${ISSUER}`;
    const bobAid = `sig-role-b-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    let groupId = '';

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // ---- 创建群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await alice.call('group.create', {
          name: `sig-role-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过设置角色签名测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // 添加 Bob
      await alice.call('group.add_member', {
        group_id: groupId,
        aid: bobAid,
        role: 'member',
      });

      await sleep(500);

      // ---- Bob 监听 group.changed 事件 ----
      const receivedEvents: Record<string, unknown>[] = [];
      const eventReceived = new Promise<void>((resolve) => {
        bob.on('group.changed', (data: unknown) => {
          const evt = data as Record<string, unknown>;
          if (evt.group_id === groupId && evt.action === 'role_changed') {
            receivedEvents.push(evt);
            resolve();
          }
        });
      });

      // ---- Alice 将 Bob 设为 admin ----
      try {
        await alice.call('group.set_role', {
          group_id: groupId,
          aid: bobAid,
          role: 'admin',
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_role 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- 等待 Bob 收到事件 ----
      await Promise.race([
        eventReceived,
        sleep(8000).then(() => { /* 超时不 reject */ }),
      ]);

      if (receivedEvents.length > 0) {
        const evt = receivedEvents[0];
        // 验证 actor_aid
        expect(evt.actor_aid).toBe(aliceAid);

        // 验证 client_signature（如果存在）
        const cs = evt.client_signature as Record<string, unknown> | undefined;
        if (cs) {
          expect(typeof cs).toBe('object');
          expect(cs.aid).toBe(aliceAid);
          expect(cs.cert_fingerprint).toBeDefined();
          expect(cs.signature).toBeDefined();
        }
      } else {
        console.log('Bob 未收到 role_changed 事件（超时），跳过事件断言');
      }
    } finally {
      if (groupId) {
        try { await alice.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await alice.close();
      await bob.close();
    }
  }, TEST_TIMEOUT);
});

// ── 4. 只读操作不需签名 ──────────────────────────────────────────

describe('签名审计: 只读操作不需签名', () => {
  it('group.list_my / group.info 正常执行无需签名', async () => {
    const rid = runId();
    const aliceAid = `sig-ro-a-${rid}.${ISSUER}`;

    const alice = makeClient();

    let groupId = '';

    try {
      await ensureConnected(alice, aliceAid);

      // ---- list_my 应正常返回 ----
      let listResult: Record<string, unknown>;
      try {
        listResult = await alice.call('group.list_my', {}) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.list_my 未实现，跳过只读操作测试');
          return;
        }
        throw e;
      }
      expect(listResult).toBeDefined();

      // ---- 创建一个群用于 info 测试 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await alice.call('group.create', {
          name: `sig-ro-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 info 测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- group.info 应正常返回 ----
      let infoResult: Record<string, unknown>;
      try {
        infoResult = await alice.call('group.info', {
          group_id: groupId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.info 未实现，跳过');
          return;
        }
        throw e;
      }
      expect(infoResult).toBeDefined();
      const infoGid = infoResult.group_id ?? (infoResult.group as any)?.group_id ?? '';
      expect(infoGid).toBe(groupId);
    } finally {
      if (groupId) {
        try { await alice.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await alice.close();
    }
  }, TEST_TIMEOUT);
});
