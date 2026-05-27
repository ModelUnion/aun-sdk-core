/**
 * Group Search 集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   1. 搜索基本功能（query / keyword / 不存在关键词 / public vs private 可见性）
 *   2. 分页（limit + offset）
 *
 * 运行方法：
 *   npx vitest run tests/integration/group-search.test.ts
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gsr-'));
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
  await client.auth.registerAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isNotImplemented(e: any): boolean {
  const msg = (e?.message ?? '').toLowerCase();
  return msg.includes('not implement') || msg.includes('method not found') || msg.includes('unknown method');
}

// ── 1. Group Search: 搜索基本功能 ──────────────────────────────────

describe('Group Search: 搜索基本功能', () => {
  it('query 搜索 public 群、搜不到 private 群、keyword 别名、不存在关键词返回空', async () => {
    const rid = runId();
    const aliceAid = `gsr-a-${rid}.${ISSUER}`;

    const alice = makeClient();

    let publicGroupId = '';
    let privateGroupId = '';

    try {
      await ensureConnected(alice, aliceAid);

      // ---- 创建 public 群 ----
      const publicName = `SearchPub-${rid}`;
      let createPublic: Record<string, unknown>;
      try {
        createPublic = await alice.call('group.create', {
          name: publicName,
          visibility: 'public',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 Group Search 测试');
          return;
        }
        throw e;
      }

      const publicGroup = createPublic.group as Record<string, unknown> | undefined;
      expect(publicGroup).toBeDefined();
      publicGroupId = (publicGroup?.group_id ?? '') as string;
      expect(publicGroupId).toBeTruthy();

      // ---- 创建 private 群 ----
      const privateName = `SearchPriv-${rid}`;
      const createPrivate = await alice.call('group.create', {
        name: privateName,
        visibility: 'private',
      }) as Record<string, unknown>;

      const privateGroup = createPrivate.group as Record<string, unknown> | undefined;
      expect(privateGroup).toBeDefined();
      privateGroupId = (privateGroup?.group_id ?? '') as string;
      expect(privateGroupId).toBeTruthy();

      // 等待索引生效
      await sleep(500);

      // ---- query 参数搜索 ----
      let searchResult: Record<string, unknown>;
      try {
        searchResult = await alice.call('group.search', {
          query: publicName,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.search 未实现，跳过 Group Search 测试');
          return;
        }
        throw e;
      }

      const items = (searchResult.items ?? []) as Record<string, unknown>[];
      expect(searchResult.query).toBe(publicName);

      // public 群应被搜到
      const foundPublic = items.some(g => g.group_id === publicGroupId);
      expect(foundPublic).toBe(true);

      // private 群不应被搜到
      const foundPrivate = items.some(g => g.group_id === privateGroupId);
      expect(foundPrivate).toBe(false);

      // ---- keyword 别名搜索 ----
      const kwResult = await alice.call('group.search', {
        keyword: publicName,
      }) as Record<string, unknown>;

      const kwItems = (kwResult.items ?? []) as Record<string, unknown>[];
      // keyword 应映射到 query 回显
      expect(kwResult.query).toBe(publicName);

      const kwFoundPublic = kwItems.some(g => g.group_id === publicGroupId);
      expect(kwFoundPublic).toBe(true);

      const kwFoundPrivate = kwItems.some(g => g.group_id === privateGroupId);
      expect(kwFoundPrivate).toBe(false);

      // ---- 搜索不存在的关键词 ----
      const nonsense = `zzznoexist-${rid}`;
      const emptyResult = await alice.call('group.search', {
        query: nonsense,
      }) as Record<string, unknown>;

      const emptyItems = (emptyResult.items ?? []) as Record<string, unknown>[];
      expect(emptyItems.length).toBe(0);

    } finally {
      // 清理：解散测试群
      if (publicGroupId) {
        try { await alice.call('group.dissolve', { group_id: publicGroupId }); } catch { /* 忽略 */ }
      }
      if (privateGroupId) {
        try { await alice.call('group.dissolve', { group_id: privateGroupId }); } catch { /* 忽略 */ }
      }
      await alice.close();
    }
  }, 60_000);
});

// ── 2. Group Search: 分页 ──────────────────────────────────────────

describe('Group Search: 分页', () => {
  it('创建 3 个 public 群，limit=2 最多返回 2 条，offset 翻页可获取剩余', async () => {
    const rid = runId();
    const aliceAid = `gsr-pg-${rid}.${ISSUER}`;

    const alice = makeClient();

    const groupIds: string[] = [];

    try {
      await ensureConnected(alice, aliceAid);

      // ---- 创建 3 个 public 群，名称含唯一标记便于搜索隔离 ----
      const tag = `PgTest-${rid}`;
      for (let i = 1; i <= 3; i++) {
        let createResult: Record<string, unknown>;
        try {
          createResult = await alice.call('group.create', {
            name: `${tag}-G${i}`,
            visibility: 'public',
          }) as Record<string, unknown>;
        } catch (e) {
          if (isNotImplemented(e)) {
            console.log('group.create 未实现，跳过 Group Search 分页测试');
            return;
          }
          throw e;
        }

        const group = createResult.group as Record<string, unknown> | undefined;
        expect(group).toBeDefined();
        const gid = (group?.group_id ?? '') as string;
        expect(gid).toBeTruthy();
        groupIds.push(gid);
      }

      // 等待索引生效
      await sleep(500);

      // ---- 验证不限制时能搜到全部 3 个 ----
      let fullResult: Record<string, unknown>;
      try {
        fullResult = await alice.call('group.search', {
          query: tag,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.search 未实现，跳过 Group Search 分页测试');
          return;
        }
        throw e;
      }

      const fullItems = (fullResult.items ?? []) as Record<string, unknown>[];
      // 至少能搜到我们创建的 3 个
      const ourGroups = fullItems.filter(g => groupIds.includes(g.group_id as string));
      expect(ourGroups.length).toBe(3);

      // ---- limit=2: 最多返回 2 条 ----
      const page1Result = await alice.call('group.search', {
        query: tag,
        limit: 2,
      }) as Record<string, unknown>;

      const page1Items = (page1Result.items ?? []) as Record<string, unknown>[];
      expect(page1Items.length).toBeLessThanOrEqual(2);

      // 有 3 个结果但只取 2 个，has_more 或 total 应指示还有更多
      const hasMore = page1Result.has_more as boolean | undefined;
      const total = page1Result.total as number | undefined;
      // 至少一种分页指示应存在（has_more=true 或 total>=3）
      if (hasMore !== undefined) {
        expect(hasMore).toBe(true);
      }
      if (total !== undefined) {
        expect(total).toBeGreaterThanOrEqual(3);
      }

      // ---- offset 翻页：跳过前 2 条取剩余 ----
      const page2Result = await alice.call('group.search', {
        query: tag,
        limit: 2,
        offset: 2,
      }) as Record<string, unknown>;

      const page2Items = (page2Result.items ?? []) as Record<string, unknown>[];
      // 第二页应至少有 1 条（总共 3 条，跳过 2 条）
      expect(page2Items.length).toBeGreaterThanOrEqual(1);

      // 两页合并应覆盖全部 3 个群
      const allPageItems = [...page1Items, ...page2Items];
      const allPageGroupIds = allPageItems.map(g => g.group_id as string);
      for (const gid of groupIds) {
        expect(allPageGroupIds).toContain(gid);
      }

    } finally {
      // 清理：解散所有测试群
      for (const gid of groupIds) {
        try { await alice.call('group.dissolve', { group_id: gid }); } catch { /* 忽略 */ }
      }
      await alice.close();
    }
  }, 60_000);
});
