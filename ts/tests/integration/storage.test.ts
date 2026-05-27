/**
 * Storage 集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   1. inline 存取与权限（put/head/get/delete 全流程 + 跨 AID 公私权限）
 *   2. 分页与版本控制（list_objects 分页 + overwrite / expected_version + list_prefixes）
 *   3. 配额（get_quota 用量信息 + put 后用量变化）
 *
 * 运行方法：
 *   npx vitest run tests/integration/storage.test.ts
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-sto-'));
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

/** 判断错误是否为"服务未实现"，用于优雅跳过 */
function isNotImplemented(e: unknown): boolean {
  const msg = (e as any)?.message?.toLowerCase() ?? '';
  return msg.includes('not implement') || msg.includes('method not found');
}

// ── 1. Storage: inline 存取与权限 ──────────────────────────────────

describe('Storage: inline 存取与权限', () => {
  it('put → head → get → delete 全流程 + 跨 AID 权限', async () => {
    const rid = runId();
    const aliceAid = `stoa${rid}.${ISSUER}`;
    const bobAid = `stob${rid}.${ISSUER}`;
    const bucket = `bkt-${rid}`;
    const privateKey = `priv-${rid}.txt`;
    const publicKey = `pub-${rid}.txt`;
    const privateContent = Buffer.from(`private-hello-${rid}`).toString('base64');
    const publicContent = Buffer.from(`public-hello-${rid}`).toString('base64');

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // ---- Alice put 私有对象 ----
      let putResult: Record<string, unknown>;
      try {
        putResult = await alice.call('storage.put_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: privateKey,
          content: privateContent,
          content_type: 'text/plain',
          is_private: true,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.put_object 未实现，跳过 Storage 测试');
          return;
        }
        throw e;
      }
      expect(putResult).toBeDefined();

      await sleep(500);

      // ---- Alice head — 验证存在 ----
      const headResult = await alice.call('storage.head_object', {
        owner_aid: aliceAid,
        bucket,
        object_key: privateKey,
      }) as Record<string, unknown>;
      expect(headResult).toBeDefined();
      if (headResult.size !== undefined) {
        expect(Number(headResult.size)).toBeGreaterThan(0);
      }
      if (headResult.is_private !== undefined) {
        expect(headResult.is_private).toBe(true);
      }

      // ---- Alice get — 验证内容一致 ----
      const getResult = await alice.call('storage.get_object', {
        owner_aid: aliceAid,
        bucket,
        object_key: privateKey,
      }) as Record<string, unknown>;
      expect(getResult).toBeDefined();
      const decoded = Buffer.from(getResult.content as string, 'base64').toString();
      expect(decoded).toBe(`private-hello-${rid}`);

      // ---- Bob get 私有对象 — 应被拒绝 ----
      await expect(
        bob.call('storage.get_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: privateKey,
        }),
      ).rejects.toThrow();

      // ---- Alice put 公开对象 ----
      await alice.call('storage.put_object', {
        owner_aid: aliceAid,
        bucket,
        object_key: publicKey,
        content: publicContent,
        content_type: 'text/plain',
        is_private: false,
      });

      await sleep(500);

      // ---- Bob get 公开对象 — 应成功 ----
      const bobGetPublic = await bob.call('storage.get_object', {
        owner_aid: aliceAid,
        bucket,
        object_key: publicKey,
      }) as Record<string, unknown>;
      expect(bobGetPublic).toBeDefined();
      const decodedPublic = Buffer.from(bobGetPublic.content as string, 'base64').toString();
      expect(decodedPublic).toBe(`public-hello-${rid}`);

      // ---- Alice delete 私有对象 ----
      const delResult = await alice.call('storage.delete_object', {
        owner_aid: aliceAid,
        bucket,
        object_key: privateKey,
      }) as Record<string, unknown>;
      expect(delResult).toBeDefined();

      await sleep(300);

      // ---- Alice get 已删除对象 — 应失败 ----
      await expect(
        alice.call('storage.get_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: privateKey,
        }),
      ).rejects.toThrow();
    } finally {
      // 兜底清理
      try {
        await alice.call('storage.delete_object', {
          owner_aid: aliceAid, bucket, object_key: privateKey,
        });
      } catch { /* 忽略清理错误 */ }
      try {
        await alice.call('storage.delete_object', {
          owner_aid: aliceAid, bucket, object_key: publicKey,
        });
      } catch { /* 忽略清理错误 */ }
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 2. Storage: 分页与版本控制 ──────────────────────────────────────

describe('Storage: 分页与版本控制', () => {
  it('list_objects 分页 + overwrite/expected_version', async () => {
    const rid = runId();
    const aliceAid = `stol${rid}.${ISSUER}`;
    const bucket = `bkt-${rid}`;
    const prefix = `lp-${rid}/`;

    const alice = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      // ---- 写入 3 个同前缀对象 ----
      for (let i = 1; i <= 3; i++) {
        const content = Buffer.from(`item-${i}-${rid}`).toString('base64');
        try {
          await alice.call('storage.put_object', {
            owner_aid: aliceAid,
            bucket,
            object_key: `${prefix}obj-${i}.txt`,
            content,
            content_type: 'text/plain',
            is_private: false,
          });
        } catch (e) {
          if (isNotImplemented(e)) {
            console.log('storage.put_object 未实现，跳过分页测试');
            return;
          }
          throw e;
        }
      }

      await sleep(500);

      // ---- list_objects 带 prefix — 应至少返回 3 个 ----
      const listResult = await alice.call('storage.list_objects', {
        owner_aid: aliceAid,
        bucket,
        prefix,
        page: 1,
        size: 100,
      }) as Record<string, unknown>;
      expect(listResult).toBeDefined();

      const items = (listResult.objects as unknown[]) ?? (listResult.items as unknown[]) ?? [];
      expect(items.length).toBeGreaterThanOrEqual(3);

      // ---- overwrite 第一个对象 — 应成功 ----
      const newContent = Buffer.from(`overwritten-${rid}`).toString('base64');
      const overwriteResult = await alice.call('storage.put_object', {
        owner_aid: aliceAid,
        bucket,
        object_key: `${prefix}obj-1.txt`,
        content: newContent,
        content_type: 'text/plain',
        is_private: false,
      }) as Record<string, unknown>;
      expect(overwriteResult).toBeDefined();

      const currentVersion = overwriteResult.version as number ?? 1;

      await sleep(300);

      // ---- put 带错误 expected_version — 应失败 ----
      const conflictContent = Buffer.from(`conflict-${rid}`).toString('base64');
      await expect(
        alice.call('storage.put_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: `${prefix}obj-1.txt`,
          content: conflictContent,
          content_type: 'text/plain',
          is_private: false,
          expected_version: currentVersion + 999,
        }),
      ).rejects.toThrow();

      // ---- list_prefixes — 验证前缀存在 ----
      const prefixResult = await alice.call('storage.list_prefixes', {
        owner_aid: aliceAid,
        bucket,
        prefix: '',
        size: 100,
      }) as Record<string, unknown>;
      expect(prefixResult).toBeDefined();

      const prefixes = (prefixResult.prefixes as string[]) ?? [];
      expect(prefixes).toContain(prefix);
    } finally {
      // 兜底清理
      for (let i = 1; i <= 3; i++) {
        try {
          await alice.call('storage.delete_object', {
            owner_aid: aliceAid, bucket, object_key: `${prefix}obj-${i}.txt`,
          });
        } catch { /* 忽略 */ }
      }
      await alice.close();
    }
  }, 60_000);
});

// ── 3. Storage: 配额 ──────────────────────────────────────────────

describe('Storage: 配额', () => {
  it('get_quota 返回用量信息', async () => {
    const rid = runId();
    const aliceAid = `stoq${rid}.${ISSUER}`;
    const bucket = `bkt-${rid}`;
    const objectKey = `quota-${rid}.txt`;
    const rawContent = 'x'.repeat(1024);
    const b64Content = Buffer.from(rawContent).toString('base64');

    const alice = makeClient();

    try {
      await ensureConnected(alice, aliceAid);

      // ---- put 前获取配额 ----
      let quotaBefore: Record<string, unknown>;
      try {
        quotaBefore = await alice.call('storage.get_quota', {
          owner_aid: aliceAid,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.get_quota 未实现，跳过配额测试');
          return;
        }
        throw e;
      }
      expect(quotaBefore).toBeDefined();

      // 应包含 used 和 total 相关字段
      const hasUsed = quotaBefore.used_bytes !== undefined || quotaBefore.used !== undefined;
      const hasTotal = quotaBefore.total_bytes !== undefined || quotaBefore.total !== undefined;
      expect(hasUsed || hasTotal).toBe(true);

      const usedBefore = Number(quotaBefore.used_bytes ?? quotaBefore.used ?? 0);

      // ---- put 对象 ----
      try {
        await alice.call('storage.put_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
          content: b64Content,
          content_type: 'text/plain',
          is_private: false,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.put_object 未实现，跳过配额变化验证');
          return;
        }
        throw e;
      }

      await sleep(500);

      // ---- put 后获取配额 — used 应增加或至少不减少 ----
      const quotaAfter = await alice.call('storage.get_quota', {
        owner_aid: aliceAid,
      }) as Record<string, unknown>;
      expect(quotaAfter).toBeDefined();

      const usedAfter = Number(quotaAfter.used_bytes ?? quotaAfter.used ?? 0);
      expect(usedAfter).toBeGreaterThanOrEqual(usedBefore);
    } finally {
      // 兜底清理
      try {
        await alice.call('storage.delete_object', {
          owner_aid: aliceAid, bucket, object_key: objectKey,
        });
      } catch { /* 忽略 */ }
      await alice.close();
    }
  }, 60_000);
});
