/**
 * Group Resources 集成测试 -- 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   1. direct_add + list + access + delete 全流程（含权限校验）
 *   2. 审批流（request_add → list_pending → approve_request/reject_request）
 *   3. access_ticket 一次性使用
 *
 * 运行方法：
 *   npx vitest run tests/integration/group-resources.test.ts
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

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

// -- 辅助函数 ------------------------------------------------------------------

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gr-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isNotImplemented(e: any): boolean {
  const msg = (e?.message ?? '').toLowerCase();
  return msg.includes('not implement') || msg.includes('method not found') || msg.includes('unknown method');
}

// -- 1. Group Resources: direct_add + list + access + delete ------------------

describe('Group Resources: direct_add + list + access + delete', () => {
  it('owner direct_add, non-owner rejected, member list/get_access, update, delete', async () => {
    const rid = runId();
    const ownerAid = `gr-own-${rid}.${ISSUER}`;
    const memberAid = `gr-mem-${rid}.${ISSUER}`;
    const outsiderAid = `gr-out-${rid}.${ISSUER}`;
    const bucket = `gr-bkt-${rid}`;
    const objectKey = `owner/${rid}/guide.txt`;
    const resourcePath = `files/${rid}/guide.txt`;
    const fileContent = `group-resource-content-${rid}`;
    const b64Content = Buffer.from(fileContent).toString('base64');

    const owner = makeClient();
    const member = makeClient();
    const outsider = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);
      await ensureConnected(outsider, outsiderAid);

      // ---- 创建群并添加成员 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `res-direct-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 Group Resources 测试');
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

      // ---- Owner 上传存储对象 ----
      try {
        await owner.call('storage.put_object', {
          owner_aid: ownerAid,
          bucket,
          object_key: objectKey,
          content: b64Content,
          content_type: 'text/plain',
          is_private: true,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.put_object 未实现，跳过 Group Resources 测试');
          return;
        }
        throw e;
      }

      const storageRef = {
        owner_aid: ownerAid,
        bucket,
        object_key: objectKey,
        filename: 'guide.txt',
      };

      // ---- 非 owner direct_add 被拒绝 ----
      try {
        await expect(
          member.call('group.resources.direct_add', {
            group_id: groupId,
            resource_path: `files/${rid}/not-owner.txt`,
            resource_type: 'file',
            title: 'not owner',
            storage_ref: storageRef,
          }),
        ).rejects.toThrow();
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.direct_add 未实现，跳过 Group Resources 测试');
          return;
        }
        throw e;
      }

      // ---- Owner direct_add 成功 ----
      let directResult: Record<string, unknown>;
      try {
        directResult = await owner.call('group.resources.direct_add', {
          group_id: groupId,
          resource_path: resourcePath,
          resource_type: 'file',
          title: 'Guide',
          storage_ref: storageRef,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.direct_add 未实现，跳过 Group Resources 测试');
          return;
        }
        throw e;
      }
      expect(directResult).toBeDefined();
      const resource = directResult.resource as Record<string, unknown> | undefined;
      expect(resource).toBeDefined();
      expect(resource?.resource_path).toBe(resourcePath);

      await sleep(500);

      // ---- 非成员 list 被拒绝 ----
      await expect(
        outsider.call('group.resources.list', {
          group_id: groupId,
        }),
      ).rejects.toThrow();

      // ---- 成员 list 带过滤条件 ----
      const listResult = await member.call('group.resources.list', {
        group_id: groupId,
        prefix: `files/${rid}/`,
      }) as Record<string, unknown>;
      expect(listResult).toBeDefined();
      const items = (listResult.items ?? []) as Record<string, unknown>[];
      const paths = items.map(item => item.resource_path as string);
      expect(paths).toContain(resourcePath);

      // ---- 成员 get_access 获取下载链接 ----
      const accessResult = await member.call('group.resources.get_access', {
        group_id: groupId,
        resource_path: resourcePath,
      }) as Record<string, unknown>;
      expect(accessResult).toBeDefined();

      const downloadUrl = ((accessResult.download as any)?.download_url ?? '') as string;
      expect(downloadUrl).toBeTruthy();

      // ---- Owner 更新资源标题 ----
      const updateResult = await owner.call('group.resources.update', {
        group_id: groupId,
        resource_path: resourcePath,
        title: 'Guide v2',
      }) as Record<string, unknown>;
      expect(updateResult).toBeDefined();
      const updatedResource = updateResult.resource as Record<string, unknown> | undefined;
      if (updatedResource) {
        expect(updatedResource.title).toBe('Guide v2');
      }

      // ---- Owner 删除资源 ----
      const deleteResult = await owner.call('group.resources.delete', {
        group_id: groupId,
        resource_path: resourcePath,
      }) as Record<string, unknown>;
      expect(deleteResult).toBeDefined();
      expect(deleteResult.deleted).toBe(true);

      await sleep(300);

      // ---- 删除后 get_access 应被拒绝 ----
      await expect(
        member.call('group.resources.get_access', {
          group_id: groupId,
          resource_path: resourcePath,
        }),
      ).rejects.toThrow();
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await outsider.close();
      await member.close();
      await owner.close();
    }
  }, 60_000);
});

// -- 2. Group Resources: 审批流 -----------------------------------------------

describe('Group Resources: 审批流', () => {
  it('member request_add → pending, list_pending, owner approve → accessible, reject → not accessible', async () => {
    const rid = runId();
    const ownerAid = `gr-req-o-${rid}.${ISSUER}`;
    const memberAid = `gr-req-m-${rid}.${ISSUER}`;
    const bucket = `gr-req-bkt-${rid}`;
    const approveObjectKey = `member/${rid}/proposal.txt`;
    const rejectObjectKey = `member/${rid}/reject.txt`;
    const approveBody = `proposal-content-${rid}`;
    const rejectBody = `reject-content-${rid}`;

    const owner = makeClient();
    const member = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      // ---- 创建群并添加成员 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `res-request-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过审批流测试');
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

      // ---- 成员上传存储对象（用于 approve 路径）----
      try {
        await member.call('storage.put_object', {
          owner_aid: memberAid,
          bucket,
          object_key: approveObjectKey,
          content: Buffer.from(approveBody).toString('base64'),
          content_type: 'text/plain',
          is_private: true,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.put_object 未实现，跳过审批流测试');
          return;
        }
        throw e;
      }

      const approveRef = {
        owner_aid: memberAid,
        bucket,
        object_key: approveObjectKey,
        filename: 'proposal.txt',
      };

      // ---- 成员 request_add → pending ----
      let requestResult: Record<string, unknown>;
      try {
        requestResult = await member.call('group.resources.request_add', {
          group_id: groupId,
          resource_path: `requests/${rid}/proposal.txt`,
          resource_type: 'file',
          title: 'Proposal',
          storage_ref: approveRef,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.request_add 未实现，跳过审批流测试');
          return;
        }
        throw e;
      }
      expect(requestResult).toBeDefined();
      const reqObj = requestResult.request as Record<string, unknown> | undefined;
      expect(reqObj).toBeDefined();
      const requestId = (reqObj?.request_id ?? '') as string;
      expect(requestId).toBeTruthy();
      expect(reqObj?.status).toBe('pending');

      await sleep(500);

      // ---- owner list_pending → 找到 pending 请求 ----
      let listReqResult: Record<string, unknown>;
      try {
        listReqResult = await owner.call('group.resources.list_pending', {
          group_id: groupId,
          status: 'pending',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.list_pending 未实现，跳过');
          return;
        }
        throw e;
      }
      expect(listReqResult).toBeDefined();
      const pendingItems = (listReqResult.items ?? []) as Record<string, unknown>[];
      const pendingIds = pendingItems.map(item => (item.request_id ?? '') as string);
      expect(pendingIds).toContain(requestId);

      // ---- owner approve → 资源可访问 ----
      let reviewApprove: Record<string, unknown>;
      try {
        reviewApprove = await owner.call('group.resources.approve_request', {
          request_id: requestId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.approve_request 未实现，跳过');
          return;
        }
        throw e;
      }
      expect(reviewApprove).toBeDefined();
      const approvedReq = reviewApprove.request as Record<string, unknown> | undefined;
      if (approvedReq) {
        expect(approvedReq.status).toBe('approved');
      }

      await sleep(500);

      // ---- 审批通过后资源可访问 ----
      const accessAfterApprove = await owner.call('group.resources.get_access', {
        group_id: groupId,
        resource_path: `requests/${rid}/proposal.txt`,
      }) as Record<string, unknown>;
      expect(accessAfterApprove).toBeDefined();
      const approvedDownloadUrl = ((accessAfterApprove.download as any)?.download_url ?? '') as string;
      expect(approvedDownloadUrl).toBeTruthy();

      // ---- 另一个请求 → reject → 资源不可访问 ----
      await member.call('storage.put_object', {
        owner_aid: memberAid,
        bucket,
        object_key: rejectObjectKey,
        content: Buffer.from(rejectBody).toString('base64'),
        content_type: 'text/plain',
        is_private: true,
      });

      const rejectRef = {
        owner_aid: memberAid,
        bucket,
        object_key: rejectObjectKey,
        filename: 'reject.txt',
      };

      const rejectRequest = await member.call('group.resources.request_add', {
        group_id: groupId,
        resource_path: `requests/${rid}/reject.txt`,
        resource_type: 'file',
        title: 'Reject Me',
        storage_ref: rejectRef,
      }) as Record<string, unknown>;
      const rejectReqObj = rejectRequest.request as Record<string, unknown> | undefined;
      const rejectRequestId = (rejectReqObj?.request_id ?? '') as string;
      expect(rejectRequestId).toBeTruthy();

      // ---- owner reject ----
      const reviewReject = await owner.call('group.resources.reject_request', {
        request_id: rejectRequestId,
      }) as Record<string, unknown>;
      expect(reviewReject).toBeDefined();
      const rejectedReq = reviewReject.request as Record<string, unknown> | undefined;
      if (rejectedReq) {
        expect(rejectedReq.status).toBe('rejected');
      }

      await sleep(300);

      // ---- 被拒绝的资源不可访问 ----
      await expect(
        member.call('group.resources.get_access', {
          group_id: groupId,
          resource_path: `requests/${rid}/reject.txt`,
        }),
      ).rejects.toThrow();
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await member.close();
      await owner.close();
    }
  }, 60_000);
});

// -- 3. Group Resources: access_ticket 一次性 ---------------------------------

describe('Group Resources: access_ticket 一次性', () => {
  it('get_access returns ticket, resolve_access_ticket → download info, second resolve → rejected', async () => {
    const rid = runId();
    const ownerAid = `gr-tkt-o-${rid}.${ISSUER}`;
    const memberAid = `gr-tkt-m-${rid}.${ISSUER}`;
    const bucket = `gr-tkt-bkt-${rid}`;
    const objectKey = `ticket/${rid}/doc.txt`;
    const resourcePath = `ticket-files/${rid}/doc.txt`;
    const fileContent = `ticket-content-${rid}`;

    const owner = makeClient();
    const member = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(member, memberAid);

      // ---- 创建群并添加成员 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `res-ticket-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 access_ticket 测试');
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

      // ---- Owner 上传存储对象 ----
      try {
        await owner.call('storage.put_object', {
          owner_aid: ownerAid,
          bucket,
          object_key: objectKey,
          content: Buffer.from(fileContent).toString('base64'),
          content_type: 'text/plain',
          is_private: true,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('storage.put_object 未实现，跳过 access_ticket 测试');
          return;
        }
        throw e;
      }

      const storageRef = {
        owner_aid: ownerAid,
        bucket,
        object_key: objectKey,
        filename: 'doc.txt',
      };

      // ---- Owner direct_add 资源 ----
      try {
        await owner.call('group.resources.direct_add', {
          group_id: groupId,
          resource_path: resourcePath,
          resource_type: 'file',
          title: 'Ticket Doc',
          storage_ref: storageRef,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.direct_add 未实现，跳过 access_ticket 测试');
          return;
        }
        throw e;
      }

      await sleep(500);

      // ---- 成员 get_access 获取 ticket ----
      const accessResult = await member.call('group.resources.get_access', {
        group_id: groupId,
        resource_path: resourcePath,
      }) as Record<string, unknown>;
      expect(accessResult).toBeDefined();

      // download_url 存在
      const downloadUrl = ((accessResult.download as any)?.download_url ?? '') as string;
      expect(downloadUrl).toBeTruthy();

      // access_ticket 存在
      const ticket = ((accessResult.access_ticket as any)?.ticket ?? accessResult.access_token ?? '') as string;
      expect(ticket).toBeTruthy();

      // ---- 首次 resolve_access_ticket → 成功 ----
      let resolveResult: Record<string, unknown>;
      try {
        resolveResult = await member.call('group.resources.resolve_access_ticket', {
          access_ticket: ticket,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.resources.resolve_access_ticket 未实现，跳过');
          return;
        }
        throw e;
      }
      expect(resolveResult).toBeDefined();
      const resolvedUrl = ((resolveResult.download as any)?.download_url ?? '') as string;
      expect(resolvedUrl).toBeTruthy();

      // ---- 二次 resolve_access_ticket → 被拒绝（一次性） ----
      await expect(
        member.call('group.resources.resolve_access_ticket', {
          access_ticket: ticket,
        }),
      ).rejects.toThrow();
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await member.close();
      await owner.close();
    }
  }, 60_000);
});
