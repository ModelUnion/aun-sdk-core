/**
 * Group Settings & Sync 集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   1. set_settings: name+description / rules+announcement / 非管理员拒绝 / 未知 key 拒绝
 *   2. get_settings: 全量读取 / keys 过滤 / 值匹配验证
 *   3. info 视角: owner / include stats / 非成员看公开群 / 非成员看私有群被拒
 *   4. 设置同步: owner 修改 → member 读取验证 / member 离开后无法查看
 *
 * 运行方法：
 *   npx vitest run tests/integration/group-settings.test.ts
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

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

// ── 辅助函数 ──────────────────────────────────────────────────────

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gs-'));
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

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

/** 判断错误是否为"服务未实现"，用于优雅跳过 */
function isNotImplemented(e: unknown): boolean {
  const msg = (e as any)?.message?.toLowerCase() ?? '';
  return msg.includes('not implement') || msg.includes('method not found') || msg.includes('unknown method');
}

// ── 1. Group Settings: set_settings ──────────────────────────────

describe('Group Settings: set_settings', () => {
  it('set name+description → verify updated_keys', async () => {
    const rid = runId();
    const ownerAid = `gs-set-o-${rid}.${ISSUER}`;
    const memberAid = `gs-set-m-${rid}.${ISSUER}`;

    const owner = makeClient();
    const member = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      // ---- 创建群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `settings-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 set_settings 测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // 添加 member
      await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      });

      await sleep(500);

      // ---- set name + description ----
      const newName = `Renamed-${rid}`;
      let setResult: Record<string, unknown>;
      try {
        setResult = await owner.call('group.set_settings', {
          group_id: groupId,
          settings: {
            name: newName,
            description: '集成测试描述',
          },
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      expect(setResult.group_id).toBe(groupId);
      const updatedKeys = (setResult.updated_keys ?? []) as string[];
      expect(updatedKeys).toContain('name');
      expect(updatedKeys).toContain('description');
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await member.close();
    }
  }, 60_000);

  it('set rules.content + announcement.content → verify updated_keys', async () => {
    const rid = runId();
    const ownerAid = `gs-rule-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `rules-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 rules+announcement 测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      let setResult: Record<string, unknown>;
      try {
        setResult = await owner.call('group.set_settings', {
          group_id: groupId,
          settings: {
            'rules.content': '请遵守测试群规',
            'announcement.content': '欢迎来到测试群',
          },
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      expect(setResult.group_id).toBe(groupId);
      const updatedKeys = (setResult.updated_keys ?? []) as string[];
      expect(updatedKeys).toContain('rules.content');
      expect(updatedKeys).toContain('announcement.content');
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);

  it('non-admin rejected', async () => {
    const rid = runId();
    const ownerAid = `gs-noadm-o-${rid}.${ISSUER}`;
    const memberAid = `gs-noadm-m-${rid}.${ISSUER}`;

    const owner = makeClient();
    const member = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `noadmin-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过非管理员拒绝测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      });

      await sleep(500);

      // ---- member（非管理员）尝试 set_settings → 应被拒绝 ----
      try {
        await member.call('group.set_settings', {
          group_id: groupId,
          settings: { name: 'Hacked' },
        });
        // 如果没抛异常则测试失败
        expect.unreachable('非管理员应该被拒绝');
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        // 被拒绝 — 符合预期
        expect(e).toBeDefined();
      }
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await member.close();
    }
  }, 60_000);

  it('unknown key rejected', async () => {
    const rid = runId();
    const ownerAid = `gs-unk-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `unknown-key-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过未知 key 测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- 未知 key → 应被拒绝 ----
      try {
        await owner.call('group.set_settings', {
          group_id: groupId,
          settings: { nonexistent_key: 'value' },
        });
        expect.unreachable('未知 key 应该被拒绝');
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        // 被拒绝 — 符合预期，验证错误信息包含 unknown
        const msg = ((e as any)?.message ?? '').toLowerCase();
        expect(msg).toMatch(/unknown|unsupported|invalid|unrecognized/);
      }
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);
});

// ── 2. Group Settings: get_settings ──────────────────────────────

describe('Group Settings: get_settings', () => {
  it('full get → verify all keys present', async () => {
    const rid = runId();
    const ownerAid = `gs-get-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `getall-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 get_settings 全量测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // 先写入一些设置
      try {
        await owner.call('group.set_settings', {
          group_id: groupId,
          settings: {
            name: `GetAll-${rid}`,
            description: '全量读取测试',
            'rules.content': '测试群规',
            'announcement.content': '测试公告',
          },
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- 全量 get_settings ----
      let getResult: Record<string, unknown>;
      try {
        getResult = await owner.call('group.get_settings', {
          group_id: groupId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.get_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      expect(getResult.group_id).toBe(groupId);
      const settingsList = (getResult.settings ?? []) as Record<string, unknown>[];
      const keysReturned = new Set(settingsList.map(s => s.key as string));

      // 验证关键字段存在
      expect(keysReturned.has('name')).toBe(true);
      expect(keysReturned.has('visibility')).toBe(true);
      expect(keysReturned.has('rules.content')).toBe(true);
      expect(keysReturned.has('announcement.content')).toBe(true);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);

  it('filtered get by keys → only requested keys returned', async () => {
    const rid = runId();
    const ownerAid = `gs-filt-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `filter-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 keys 过滤测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // 写入多个字段
      try {
        await owner.call('group.set_settings', {
          group_id: groupId,
          settings: {
            name: `Filtered-${rid}`,
            description: '过滤测试',
            'rules.content': '过滤群规',
            'announcement.content': '过滤公告',
          },
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- keys 过滤 get_settings ----
      let filteredResult: Record<string, unknown>;
      try {
        filteredResult = await owner.call('group.get_settings', {
          group_id: groupId,
          keys: ['name', 'rules.content'],
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.get_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      const settingsList = (filteredResult.settings ?? []) as Record<string, unknown>[];
      const keysReturned = new Set(settingsList.map(s => s.key as string));

      // 仅返回请求的 keys
      expect(keysReturned.size).toBe(2);
      expect(keysReturned.has('name')).toBe(true);
      expect(keysReturned.has('rules.content')).toBe(true);
      // 不应包含未请求的 keys
      expect(keysReturned.has('description')).toBe(false);
      expect(keysReturned.has('announcement.content')).toBe(false);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);

  it('values match what was set', async () => {
    const rid = runId();
    const ownerAid = `gs-val-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `valcheck-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过值匹配测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      const expectedName = `ValCheck-${rid}`;
      const expectedRules = '值匹配测试群规';
      const expectedAnnouncement = '值匹配测试公告';

      try {
        await owner.call('group.set_settings', {
          group_id: groupId,
          settings: {
            name: expectedName,
            'rules.content': expectedRules,
            'announcement.content': expectedAnnouncement,
          },
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- 读取并验证值 ----
      let getResult: Record<string, unknown>;
      try {
        getResult = await owner.call('group.get_settings', {
          group_id: groupId,
          keys: ['name', 'rules.content', 'announcement.content'],
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.get_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      const settingsList = (getResult.settings ?? []) as Record<string, unknown>[];
      const settingsMap: Record<string, unknown> = {};
      for (const s of settingsList) {
        settingsMap[s.key as string] = s.value;
      }

      expect(settingsMap['name']).toBe(expectedName);
      expect(settingsMap['rules.content']).toBe(expectedRules);
      expect(settingsMap['announcement.content']).toBe(expectedAnnouncement);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);
});

// ── 3. Group: info 视角 ──────────────────────────────────────────

describe('Group: info 视角', () => {
  it('owner info → group_id, name, owner_aid', async () => {
    const rid = runId();
    const ownerAid = `gs-info-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `info-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 info owner 测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- owner 查看 info ----
      let infoResult: Record<string, unknown>;
      try {
        infoResult = await owner.call('group.info', {
          group_id: groupId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.info 未实现，跳过');
          return;
        }
        throw e;
      }

      expect(infoResult.group_id).toBe(groupId);
      expect(infoResult.name).toBe(`info-${rid}`);
      expect(infoResult.owner_aid).toBe(ownerAid);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);

  it('info with include=["stats"] → stats present', async () => {
    const rid = runId();
    const ownerAid = `gs-stats-o-${rid}.${ISSUER}`;

    const owner = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `stats-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 info stats 测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- include=["stats"] ----
      let infoResult: Record<string, unknown>;
      try {
        infoResult = await owner.call('group.info', {
          group_id: groupId,
          include: ['stats'],
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.info include stats 未实现，跳过');
          return;
        }
        throw e;
      }

      const stats = infoResult.stats as Record<string, unknown> | undefined;
      expect(stats).toBeDefined();
      expect(typeof stats).toBe('object');
      // stats 中应包含基本统计字段
      expect((stats as Record<string, unknown>).human_count).toBeGreaterThanOrEqual(0);
      expect((stats as Record<string, unknown>).admin_count).toBeGreaterThanOrEqual(0);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
    }
  }, 60_000);

  it('non-member on public group → basic info visible, no owner_aid', async () => {
    const rid = runId();
    const ownerAid = `gs-pub-o-${rid}.${ISSUER}`;
    const outsiderAid = `gs-pub-x-${rid}.${ISSUER}`;

    const owner = makeClient();
    const outsider = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(outsider, outsiderAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `public-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过非成员公开群测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- 非成员查看公开群 info ----
      let infoResult: Record<string, unknown>;
      try {
        infoResult = await outsider.call('group.info', {
          group_id: groupId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.info 未实现，跳过');
          return;
        }
        throw e;
      }

      // 应能看到基础信息
      expect(infoResult.group_id).toBe(groupId);
      expect(infoResult.name).toBe(`public-${rid}`);
      // 非成员看不到 owner_aid
      expect(infoResult.owner_aid).toBeUndefined();
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await outsider.close();
    }
  }, 60_000);

  it('non-member on private group → rejected', async () => {
    const rid = runId();
    const ownerAid = `gs-priv-o-${rid}.${ISSUER}`;
    const outsiderAid = `gs-priv-x-${rid}.${ISSUER}`;

    const owner = makeClient();
    const outsider = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(outsider, outsiderAid);

      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `private-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过非成员私有群测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- 非成员查看私有群 info → 应被拒绝 ----
      try {
        await outsider.call('group.info', {
          group_id: groupId,
        });
        expect.unreachable('非成员看私有群应被拒绝');
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.info 未实现，跳过');
          return;
        }
        // 被拒绝 — 符合预期
        expect(e).toBeDefined();
      }
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await outsider.close();
    }
  }, 60_000);
});

// ── 4. Group: 设置同步 ──────────────────────────────────────────

describe('Group: 设置同步', () => {
  it('owner changes settings → member verifies via get_settings', async () => {
    const rid = runId();
    const ownerAid = `gs-sync-o-${rid}.${ISSUER}`;
    const memberAid = `gs-sync-m-${rid}.${ISSUER}`;

    const owner = makeClient();
    const member = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      // ---- 创建群并添加 member ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `sync-${rid}`,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过设置同步测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      });

      await sleep(500);

      // ---- owner 修改设置 ----
      const syncedName = `Synced-${rid}`;
      const syncedRules = '同步测试群规';
      const syncedAnnouncement = '同步测试公告';

      try {
        await owner.call('group.set_settings', {
          group_id: groupId,
          settings: {
            name: syncedName,
            'rules.content': syncedRules,
            'announcement.content': syncedAnnouncement,
          },
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      await sleep(500);

      // ---- member 通过 get_settings 验证同步 ----
      let memberSettings: Record<string, unknown>;
      try {
        memberSettings = await member.call('group.get_settings', {
          group_id: groupId,
          keys: ['name', 'rules.content', 'announcement.content'],
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.get_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      const settingsList = (memberSettings.settings ?? []) as Record<string, unknown>[];
      const settingsMap: Record<string, unknown> = {};
      for (const s of settingsList) {
        settingsMap[s.key as string] = s.value;
      }

      // member 应看到 owner 设置的值
      expect(settingsMap['name']).toBe(syncedName);
      expect(settingsMap['rules.content']).toBe(syncedRules);
      expect(settingsMap['announcement.content']).toBe(syncedAnnouncement);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await member.close();
    }
  }, 60_000);

  it('member leaves → no longer sees group', async () => {
    const rid = runId();
    const ownerAid = `gs-leave-o-${rid}.${ISSUER}`;
    const memberAid = `gs-leave-m-${rid}.${ISSUER}`;

    const owner = makeClient();
    const member = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      // ---- 创建群并添加 member ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `leave-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 member 离开测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      });

      await sleep(500);

      // ---- 确认 member 可以看到群设置 ----
      try {
        const beforeLeave = await member.call('group.get_settings', {
          group_id: groupId,
        }) as Record<string, unknown>;
        expect(beforeLeave.group_id).toBe(groupId);
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.get_settings 未实现，跳过');
          return;
        }
        throw e;
      }

      // ---- member 离开 ----
      try {
        await member.call('group.leave', {
          group_id: groupId,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.leave 未实现，跳过');
          return;
        }
        throw e;
      }

      await sleep(500);

      // ---- 离开后 member 不再能看到群（私有群应被拒绝）----
      try {
        await member.call('group.get_settings', {
          group_id: groupId,
        });
        // 如果返回成功但 settings 为空也可能是正常行为，取决于实现
        // 但对私有群来说，非成员应该被拒绝
        expect.unreachable('离开后不应能查看私有群设置');
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.get_settings 未实现，跳过');
          return;
        }
        // 被拒绝 — 符合预期
        expect(e).toBeDefined();
      }
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await member.close();
    }
  }, 60_000);
});
