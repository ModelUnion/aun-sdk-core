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
import * as http from 'node:http';
import * as https from 'node:https';
import { URL } from 'node:url';
import { AUNClient } from '../../src/client.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

// ── 辅助函数 ──────────────────────────────────────────────────────

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-sto-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function downloadBytes(urlText: string, redirectsLeft: number = 5): Promise<Buffer> {
  const parsed = new URL(urlText);
  const mod = parsed.protocol === 'https:' ? https : http;
  const options = parsed.protocol === 'https:'
    ? ({ rejectUnauthorized: false, timeout: 15_000 } as https.RequestOptions)
    : ({ timeout: 15_000 } as http.RequestOptions);

  return await new Promise<Buffer>((resolve, reject) => {
    const req = mod.get(urlText, options, (res) => {
      const statusCode = res.statusCode ?? 0;
      if ([301, 302, 303, 307, 308].includes(statusCode)) {
        const location = res.headers.location;
        res.resume();
        if (!location) {
          reject(new Error(`HTTP ${statusCode} without Location from ${urlText}`));
          return;
        }
        if (redirectsLeft <= 0) {
          reject(new Error(`too many redirects starting from ${urlText}`));
          return;
        }
        const nextUrl = new URL(location, urlText).toString();
        downloadBytes(nextUrl, redirectsLeft - 1).then(resolve, reject);
        return;
      }
      if (statusCode < 200 || statusCode >= 300) {
        reject(new Error(`HTTP ${statusCode} from ${urlText}`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`timeout fetching ${urlText}`)));
  });
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

// ── 4. Storage: 分享链接与短链接 ──────────────────────────────────

describe('Storage: 分享链接与短链接', () => {
  it('create/list/get/revoke + /s/{share_id} 下载 + allowed_aids/max_uses', async () => {
    const rid = runId();
    const aliceAid = `stosha${rid}.${ISSUER}`;
    const bobAid = `stoshb${rid}.${ISSUER}`;
    const eveAid = `stoshe${rid}.${ISSUER}`;
    const bucket = `bkt-${rid}`;
    const objectKey = `share-${rid}.txt`;
    const rawContent = `share-hello-${rid}`;
    const b64Content = Buffer.from(rawContent).toString('base64');

    const alice = makeClient();
    const bob = makeClient();
    const eve = makeClient();
    const shareIds: string[] = [];

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);
      await ensureConnected(eve, eveAid);

      try {
        await alice.call('storage.put_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
          content: b64Content,
          content_type: 'text/plain',
          is_private: true,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.put_object 未实现，跳过分享链接测试');
          return;
        }
        throw e;
      }

      let publicShare: Record<string, unknown>;
      try {
        publicShare = await alice.call('storage.create_share_link', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
          allowed_aids: ['*'],
          expire_in_seconds: 300,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.create_share_link 未实现，跳过分享链接测试');
          return;
        }
        throw e;
      }

      const publicShareId = String(publicShare.share_id ?? '');
      const publicShareUrl = String(publicShare.share_url ?? '');
      shareIds.push(publicShareId);
      expect(publicShareId).toMatch(/^[0-9A-Za-z]{10}$/);
      expect(publicShareUrl).toContain(`/s/${publicShareId}`);
      expect(publicShareUrl.startsWith('http://') || publicShareUrl.startsWith('https://')).toBe(true);

      const downloaded = await downloadBytes(publicShareUrl);
      expect(downloaded.toString('utf-8')).toBe(rawContent);

      const bobPublicGet = await bob.call('storage.get_by_share', {
        share_id: publicShareId,
      }) as Record<string, unknown>;
      expect(Buffer.from(String(bobPublicGet.content ?? ''), 'base64').toString('utf-8')).toBe(rawContent);

      const restrictedShare = await alice.call('storage.create_share_link', {
        owner_aid: aliceAid,
        bucket,
        object_key: objectKey,
        allowed_aids: [bobAid],
        expire_in_seconds: 300,
      }) as Record<string, unknown>;
      const restrictedShareId = String(restrictedShare.share_id ?? '');
      shareIds.push(restrictedShareId);

      const bobRestrictedGet = await bob.call('storage.get_by_share', {
        share_id: restrictedShareId,
      }) as Record<string, unknown>;
      expect(Buffer.from(String(bobRestrictedGet.content ?? ''), 'base64').toString('utf-8')).toBe(rawContent);

      await expect(eve.call('storage.get_by_share', {
        share_id: restrictedShareId,
      })).rejects.toThrow();

      const limitedShare = await alice.call('storage.create_share_link', {
        owner_aid: aliceAid,
        bucket,
        object_key: objectKey,
        allowed_aids: ['*'],
        expire_in_seconds: 300,
        max_uses: 1,
      }) as Record<string, unknown>;
      const limitedShareId = String(limitedShare.share_id ?? '');
      shareIds.push(limitedShareId);

      await bob.call('storage.get_by_share', { share_id: limitedShareId });
      await expect(bob.call('storage.get_by_share', { share_id: limitedShareId })).rejects.toThrow();

      const listed = await alice.call('storage.list_share_links', {
        bucket,
        object_key: objectKey,
      }) as Record<string, unknown>;
      const links = Array.isArray(listed.links) ? listed.links as Record<string, unknown>[] : [];
      expect(links.some(link => link.share_id === publicShareId)).toBe(true);
      expect(links.some(link => link.share_id === restrictedShareId)).toBe(true);

      await alice.call('storage.revoke_share_link', { share_id: restrictedShareId });
      await expect(bob.call('storage.get_by_share', {
        share_id: restrictedShareId,
      })).rejects.toThrow();
    } finally {
      for (const share_id of shareIds) {
        try {
          await alice.call('storage.revoke_share_link', { share_id });
        } catch { /* 忽略清理错误 */ }
      }
      try {
        await alice.call('storage.delete_object', {
          owner_aid: aliceAid,
          bucket,
          object_key: objectKey,
        });
      } catch { /* 忽略清理错误 */ }
      await alice.close();
      await bob.close();
      await eve.close();
    }
  }, 90_000);
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
