/**
 * Group Management 集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   1. 全生命周期（create → get_info → add_member → get_members → kick → dissolve）
 *   2. 角色与群主转让（set_role admin → transfer_owner → 角色校验）
 *   3. 暂停与恢复（suspend 幂等 → 发送拒绝 → resume 幂等 → 发送恢复）
 *   4. 入群申请与审批（request_join question_required → pending → list → approve/reject）
 *   5. 邀请码（create_invite_code → use → exhausted → revoke → rejected）
 *
 * 运行方法：
 *   npx vitest run tests/integration/group-management.test.ts
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-grp-'));
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

/** 从成员列表中提取指定 AID 的角色 */
function memberRole(members: Record<string, unknown>[], aid: string): string | undefined {
  for (const m of members) {
    if (m.aid === aid) {
      return m.role as string | undefined;
    }
  }
  return undefined;
}

// ── 1. Group: 全生命周期 ──────────────────────────────────────────

describe('Group: 全生命周期', () => {
  it('create → get_info → add_member → get_members → kick → dissolve', async () => {
    const rid = runId();
    const ownerAid = `gm-own-${rid}.${ISSUER}`;
    const memberAid = `gm-mem-${rid}.${ISSUER}`;

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
          name: `lifecycle-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过 Group 全生命周期测试');
          return;
        }
        throw e;
      }

      const group = createResult.group as Record<string, unknown> | undefined;
      expect(group).toBeDefined();
      groupId = (group?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- get_info ----
      const info = await owner.call('group.get_info', {
        group_id: groupId,
      }) as Record<string, unknown>;
      expect(info).toBeDefined();
      // group_id 应在顶层或 group 子对象中
      const infoGid = info.group_id ?? (info.group as any)?.group_id ?? '';
      expect(infoGid).toBe(groupId);

      // ---- add_member ----
      const addResult = await owner.call('group.add_member', {
        group_id: groupId,
        aid: memberAid,
        role: 'member',
      }) as Record<string, unknown>;
      expect(addResult).toBeDefined();
      const addedMember = addResult.member as Record<string, unknown> | undefined;
      if (addedMember) {
        expect(addedMember.aid).toBe(memberAid);
        expect(addedMember.role).toBe('member');
      }

      await sleep(500);

      // ---- get_members ----
      const membersResult = await owner.call('group.get_members', {
        group_id: groupId,
      }) as Record<string, unknown>;
      expect(membersResult).toBeDefined();
      const membersList = (membersResult.members ?? []) as Record<string, unknown>[];
      expect(membersList.length).toBeGreaterThanOrEqual(2); // owner + member
      const aids = membersList.map(m => m.aid as string);
      expect(aids).toContain(memberAid);

      // ---- kick ----
      const kickResult = await owner.call('group.kick', {
        group_id: groupId,
        aid: memberAid,
      }) as Record<string, unknown>;
      expect(kickResult).toBeDefined();

      await sleep(500);

      // 验证踢出后成员列表不再包含 memberAid
      const afterKick = await owner.call('group.get_members', {
        group_id: groupId,
      }) as Record<string, unknown>;
      const afterKickList = (afterKick.members ?? []) as Record<string, unknown>[];
      const afterKickAids = afterKickList.map(m => m.aid as string);
      expect(afterKickAids).not.toContain(memberAid);

      // ---- dissolve ----
      const dissolveResult = await owner.call('group.dissolve', {
        group_id: groupId,
      }) as Record<string, unknown>;
      expect(dissolveResult).toBeDefined();
      groupId = ''; // 已解散，不需要清理
    } finally {
      // 兜底清理
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await member.close();
    }
  }, 60_000);
});

// ── 2. Group: 角色与群主转让 ──────────────────────────────────────

describe('Group: 角色与群主转让', () => {
  it('create, add Bob+Charlie, set_role admin, transfer_owner, verify role changes', async () => {
    const rid = runId();
    const aliceAid = `gm-a-${rid}.${ISSUER}`;
    const bobAid = `gm-b-${rid}.${ISSUER}`;
    const charlieAid = `gm-c-${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();
    const charlie = makeClient();

    let groupId = '';
    let cleanupClient = alice;

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);
      await ensureConnected(charlie, charlieAid);

      // ---- 创建群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await alice.call('group.create', {
          name: `roles-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过角色与群主转让测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- 添加 Bob 和 Charlie ----
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

      // ---- Bob 设为 admin ----
      let setRoleResult: Record<string, unknown>;
      try {
        setRoleResult = await alice.call('group.set_role', {
          group_id: groupId,
          aid: bobAid,
          role: 'admin',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.set_role 未实现，跳过角色测试');
          return;
        }
        throw e;
      }
      expect(setRoleResult).toBeDefined();
      const promotedMember = setRoleResult.member as Record<string, unknown> | undefined;
      if (promotedMember) {
        expect(promotedMember.role).toBe('admin');
      }

      // ---- 验证 get_members 中 Bob 是 admin ----
      const membersAfterRole = await alice.call('group.get_members', {
        group_id: groupId,
      }) as Record<string, unknown>;
      const membersList = (membersAfterRole.members ?? []) as Record<string, unknown>[];
      expect(memberRole(membersList, bobAid)).toBe('admin');
      expect(memberRole(membersList, charlieAid)).toBe('member');

      // ---- 群主转让给 Bob ----
      let transferResult: Record<string, unknown>;
      try {
        transferResult = await alice.call('group.transfer_owner', {
          group_id: groupId,
          new_owner: bobAid,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.transfer_owner 未实现，跳过转让测试');
          return;
        }
        throw e;
      }
      expect(transferResult).toBeDefined();
      cleanupClient = bob; // 转让后 Bob 是 owner

      await sleep(500);

      // ---- 验证转让后角色 ----
      const membersAfterTransfer = await bob.call('group.get_members', {
        group_id: groupId,
      }) as Record<string, unknown>;
      const afterTransferList = (membersAfterTransfer.members ?? []) as Record<string, unknown>[];

      // Bob 应该是 owner
      expect(memberRole(afterTransferList, bobAid)).toBe('owner');
      // Alice 应该降为 admin
      const aliceRole = memberRole(afterTransferList, aliceAid);
      expect(['admin', 'member']).toContain(aliceRole);
    } finally {
      if (groupId) {
        try { await cleanupClient.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await alice.close();
      await bob.close();
      await charlie.close();
    }
  }, 60_000);
});

// ── 3. Group: 暂停与恢复 ──────────────────────────────────────────

describe('Group: 暂停与恢复', () => {
  it('suspend (幂等) → member send rejected → resume (幂等) → member send ok', async () => {
    const rid = runId();
    const ownerAid = `gm-sus-o-${rid}.${ISSUER}`;
    const memberAid = `gm-sus-m-${rid}.${ISSUER}`;

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
          name: `suspend-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过暂停与恢复测试');
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

      // ---- 暂停群 ----
      let suspendResult: Record<string, unknown>;
      try {
        suspendResult = await owner.call('group.suspend', {
          group_id: groupId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.suspend 未实现，跳过暂停测试');
          return;
        }
        throw e;
      }
      expect(suspendResult).toBeDefined();
      expect(suspendResult.status).toBe('suspended');

      // ---- 幂等：再次暂停 ----
      const suspendAgain = await owner.call('group.suspend', {
        group_id: groupId,
      }) as Record<string, unknown>;
      expect(suspendAgain.status).toBe('unchanged');

      await sleep(300);

      // ---- 暂停状态下成员发消息应被拒绝 ----
      await expect(
        member.call('group.send', {
          group_id: groupId,
          payload: { type: 'text', text: `suspended-msg-${rid}` },
          encrypt: false,
        }),
      ).rejects.toThrow();

      // ---- 恢复群 ----
      const resumeResult = await owner.call('group.resume', {
        group_id: groupId,
      }) as Record<string, unknown>;
      expect(resumeResult).toBeDefined();
      expect(resumeResult.status).toBe('active');

      // ---- 幂等：再次恢复 ----
      const resumeAgain = await owner.call('group.resume', {
        group_id: groupId,
      }) as Record<string, unknown>;
      expect(resumeAgain.status).toBe('unchanged');

      await sleep(300);

      // ---- 恢复后成员发消息应成功 ----
      const sendResult = await member.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: `resumed-msg-${rid}` },
        encrypt: false,
      }) as Record<string, unknown>;
      expect(sendResult).toBeDefined();
    } finally {
      if (groupId) {
        try { await owner.call('group.resume', { group_id: groupId }); } catch { /* 忽略 */ }
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await member.close();
    }
  }, 60_000);
});

// ── 4. Group: 入群申请与审批 ──────────────────────────────────────

describe('Group: 入群申请与审批', () => {
  it('request_join question_required → pending → list → approve/reject', async () => {
    const rid = runId();
    const ownerAid = `gm-join-o-${rid}.${ISSUER}`;
    const applicantAid = `gm-join-a-${rid}.${ISSUER}`;
    const applicant2Aid = `gm-join-b-${rid}.${ISSUER}`;

    const owner = makeClient();
    const applicant = makeClient();
    const applicant2 = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(applicant, applicantAid);
      await ensureConnected(applicant2, applicant2Aid);

      // ---- 创建带入群问题的群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `join-review-${rid}`,
          visibility: 'private',
          join_question: '用途是什么？',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过入群申请测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- 不带答案的 request_join → question_required ----
      let requestNoAnswer: Record<string, unknown>;
      try {
        requestNoAnswer = await applicant.call('group.request_join', {
          group_id: groupId,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.request_join 未实现，跳过入群申请测试');
          return;
        }
        throw e;
      }
      expect(requestNoAnswer.status).toBe('question_required');

      // ---- 带答案的 request_join → pending ----
      const requestWithAnswer = await applicant.call('group.request_join', {
        group_id: groupId,
        answer: '用于集成测试',
        message: '请批准',
      }) as Record<string, unknown>;
      expect(requestWithAnswer.status).toBe('pending');

      await sleep(500);

      // ---- owner list_join_requests ----
      const pendingList = await owner.call('group.list_join_requests', {
        group_id: groupId,
        status: 'pending',
      }) as Record<string, unknown>;
      expect(pendingList).toBeDefined();
      const items = (pendingList.items ?? []) as Record<string, unknown>[];
      const hasApplicant = items.some(item => item.aid === applicantAid);
      expect(hasApplicant).toBe(true);

      // ---- 第二个申请者 → pending ----
      const request2 = await applicant2.call('group.request_join', {
        group_id: groupId,
        answer: '也是测试',
        message: '申请加入',
      }) as Record<string, unknown>;
      expect(request2.status).toBe('pending');

      // ---- approve 第一个申请者 ----
      const approveResult = await owner.call('group.review_join_request', {
        group_id: groupId,
        aid: applicantAid,
        approve: true,
      }) as Record<string, unknown>;
      expect(approveResult).toBeDefined();
      // 状态应为 approved 或 joined
      const approveStatus = approveResult.status as string ?? '';
      expect(['approved', 'joined']).toContain(approveStatus);

      // ---- reject 第二个申请者 ----
      const rejectResult = await owner.call('group.review_join_request', {
        group_id: groupId,
        aid: applicant2Aid,
        approve: false,
        reason: '覆盖拒绝路径',
      }) as Record<string, unknown>;
      expect(rejectResult).toBeDefined();
      expect(rejectResult.status).toBe('rejected');

      await sleep(500);

      // ---- 验证成员列表 ----
      const membersResult = await owner.call('group.get_members', {
        group_id: groupId,
      }) as Record<string, unknown>;
      const membersList = (membersResult.members ?? []) as Record<string, unknown>[];
      const memberAids = membersList.map(m => m.aid as string);

      // 被批准的应在成员列表中
      expect(memberAids).toContain(applicantAid);
      // 被拒绝的不应在成员列表中
      expect(memberAids).not.toContain(applicant2Aid);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await applicant.close();
      await applicant2.close();
    }
  }, 60_000);
});

// ── 5. Group: 邀请码 ──────────────────────────────────────────────

describe('Group: 邀请码', () => {
  it('create_invite_code → use → exhausted → revoke → rejected', async () => {
    const rid = runId();
    const ownerAid = `gm-inv-o-${rid}.${ISSUER}`;
    const user1Aid = `gm-inv-u1-${rid}.${ISSUER}`;
    const user2Aid = `gm-inv-u2-${rid}.${ISSUER}`;

    const owner = makeClient();
    const user1 = makeClient();
    const user2 = makeClient();

    let groupId = '';

    try {
      await ensureConnected(owner, ownerAid);
      await ensureConnected(user1, user1Aid);
      await ensureConnected(user2, user2Aid);

      // ---- 创建群 ----
      let createResult: Record<string, unknown>;
      try {
        createResult = await owner.call('group.create', {
          name: `invite-${rid}`,
          visibility: 'private',
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create 未实现，跳过邀请码测试');
          return;
        }
        throw e;
      }

      groupId = ((createResult.group as any)?.group_id ?? '') as string;
      expect(groupId).toBeTruthy();

      // ---- 创建邀请码 (max_uses=1) ----
      const inviteCode = `IC-${rid}`.toUpperCase();
      let inviteResult: Record<string, unknown>;
      try {
        inviteResult = await owner.call('group.create_invite_code', {
          group_id: groupId,
          code: inviteCode,
          max_uses: 1,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.create_invite_code 未实现，跳过邀请码测试');
          return;
        }
        throw e;
      }
      expect(inviteResult).toBeDefined();
      const returnedCode = (inviteResult.invite_code as any)?.code ?? inviteResult.code ?? '';
      expect(returnedCode).toBeTruthy();

      // ---- user1 使用邀请码 ----
      let useResult: Record<string, unknown>;
      try {
        useResult = await user1.call('group.use_invite_code', {
          code: returnedCode,
        }) as Record<string, unknown>;
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.use_invite_code 未实现，跳过');
          return;
        }
        throw e;
      }
      expect(useResult).toBeDefined();
      expect(useResult.status).toBe('joined');

      await sleep(500);

      // ---- user2 使用同一邀请码 — max_uses=1 应已耗尽 ----
      await expect(
        user2.call('group.use_invite_code', {
          code: returnedCode,
        }),
      ).rejects.toThrow();

      // ---- 创建第二个邀请码用于撤销测试 ----
      const revokeCode = `IC-REV-${rid}`;
      const revokeInvite = await owner.call('group.create_invite_code', {
        group_id: groupId,
        code: revokeCode,
        max_uses: 0, // 无限制
      }) as Record<string, unknown>;
      const revokedCode = (revokeInvite.invite_code as any)?.code ?? revokeInvite.code ?? '';
      expect(revokedCode).toBeTruthy();

      // ---- 撤销邀请码 ----
      try {
        await owner.call('group.revoke_invite_code', {
          group_id: groupId,
          code: revokedCode,
        });
      } catch (e) {
        if (isNotImplemented(e)) {
          console.log('group.revoke_invite_code 未实现，跳过撤销测试');
          return;
        }
        throw e;
      }

      await sleep(300);

      // ---- user2 使用已撤销邀请码 — 应被拒绝 ----
      await expect(
        user2.call('group.use_invite_code', {
          code: revokedCode,
        }),
      ).rejects.toThrow();
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
      }
      await owner.close();
      await user1.close();
      await user2.close();
    }
  }, 60_000);
});
