import * as crypto from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import { GroupStateCoordinator } from '../../src/client/group-state.js';
import { ClientRuntime } from '../../src/client/runtime.js';
import { normalizeGroupId } from '../../src/group-id.js';
import { computeStateCommitment } from '../../src/v2/state/index.js';

function stableStringifyForTest(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(obj[key])}`).join(',')}}`;
}

function cacheStateSignature(client: Record<string, any>, args: {
  groupId: string;
  actorAid: string;
  stateVersion: number;
  stateHash: string;
  membershipSnapshot: string;
  signatureB64: string;
}): void {
  const normalizedGroupId = normalizeGroupId(args.groupId) || args.groupId;
  const signPayload = stableStringifyForTest({
    group_id: normalizedGroupId,
    membership_snapshot: args.membershipSnapshot,
    state_hash: args.stateHash,
    state_version: args.stateVersion,
  });
  const actorBytes = Buffer.from(args.actorAid, 'utf-8');
  const payloadBytes = Buffer.from(signPayload, 'utf-8');
  const sigBytes = Buffer.from(args.signatureB64, 'base64');
  const framedPayload = Buffer.concat([
    Buffer.from(`${actorBytes.byteLength}:`, 'ascii'),
    actorBytes,
    Buffer.from(';', 'ascii'),
    Buffer.from(`${payloadBytes.byteLength}:`, 'ascii'),
    payloadBytes,
    Buffer.from(';', 'ascii'),
  ]);
  const cacheKey = crypto.createHash('sha256')
    .update(framedPayload)
    .update(sigBytes)
    .digest('hex');
  client._v2SigCache.set(cacheKey, Date.now() + 60_000);
}

function createCoordinator(overrides: Record<string, any> = {}): {
  coordinator: GroupStateCoordinator;
  client: Record<string, any>;
} {
  const client: Record<string, any> = {
    _aid: 'alice.aid.com',
    _deviceId: 'dev-alice',
    _v2Session: {},
    _v2SigCache: new Map<string, number>(),
    _v2AutoProposeInflight: new Map<string, Promise<void>>(),
    _v2AutoProposePending: new Set<string>(),
    _v2AutoProposeLastSnapshot: new Map<string, string>(),
    _clientLog: { debug: vi.fn(), info: vi.fn(), warn: vi.fn() },
    _dispatcher: { publish: vi.fn(async () => undefined) },
    _safeAsync: vi.fn((promise: Promise<unknown>) => void promise.catch(() => undefined)),
    _extractGroupIdFromResult: vi.fn((result: Record<string, unknown>) => {
      const group = result.group;
      if (group && typeof group === 'object' && 'group_id' in group) {
        return String((group as Record<string, unknown>).group_id ?? '');
      }
      return String(result.group_id ?? '');
    }),
    _v2E2EE: {
      deleteBootstrapCacheEntry: vi.fn(),
      scheduleGroupSpkRegistration: vi.fn(),
      handleGroupChangedSpk: vi.fn(),
    },
    _fetchPeerCert: vi.fn(async () => {
      throw new Error('unexpected cert fetch');
    }),
    call: vi.fn(async () => ({ ok: true })),
    _sleep: vi.fn(async () => undefined),
    _v2LeaderDelayMs: vi.fn(() => 1234),
    _v2ConfirmPendingProposal: vi.fn(async () => false),
    _v2AutoProposeState: vi.fn(async () => undefined),
    ...overrides,
  };
  return { client, coordinator: new GroupStateCoordinator(new ClientRuntime(client)) };
}

describe('GroupStateCoordinator 组件边界', () => {
  it('postprocessResult 在 membership mutation 成功后触发 state propose 和建群 SPK 注册', async () => {
    const { coordinator, client } = createCoordinator();

    const result = { group: { group_id: '12345.agentid.pub' } };

    await expect(coordinator.postprocessResult('group.create', {}, result)).resolves.toBe(result);

    expect(client._v2AutoProposeState).toHaveBeenCalledWith('12345.agentid.pub');
    expect(client._v2E2EE.scheduleGroupSpkRegistration).toHaveBeenCalledWith('12345.agentid.pub', {
      reason: 'group.create',
    });
  });

  it('postprocessResult 跳过非 mutation、错误结果、无 V2 session 和空 group_id', async () => {
    const { coordinator, client } = createCoordinator();

    await coordinator.postprocessResult('message.send', {}, { group_id: 'g1' });
    await coordinator.postprocessResult('group.add_member', { group_id: 'g1' }, { error: { code: -1 } });
    client._v2Session = null;
    await coordinator.postprocessResult('group.add_member', { group_id: 'g2' }, { ok: true });
    client._v2Session = {};
    client._extractGroupIdFromResult = vi.fn(() => '');
    await coordinator.postprocessResult('group.add_member', {}, { ok: true });

    expect(client._v2AutoProposeState).not.toHaveBeenCalled();
    expect(client._v2E2EE.scheduleGroupSpkRegistration).not.toHaveBeenCalled();
  });

  it('handleGroupChangedV2Membership 清 group cache、触发 leader delay propose 并转发 SPK 副作用', () => {
    const { coordinator, client } = createCoordinator();

    coordinator.handleGroupChangedV2Membership({
      group_id: '12345.agentid.pub',
      action: 'member_added',
      aid: 'bob1.aid.com',
    });

    expect(client._v2E2EE.deleteBootstrapCacheEntry).toHaveBeenCalledWith('group:12345.agentid.pub');
    expect(client._safeAsync).toHaveBeenCalled();
    expect(client._v2AutoProposeState).toHaveBeenCalledWith('12345.agentid.pub', { leaderDelay: true });
    expect(client._v2E2EE.handleGroupChangedSpk).toHaveBeenCalledWith(
      expect.objectContaining({ group_id: '12345.agentid.pub', action: 'member_added' }),
      '12345.agentid.pub',
      'member_added',
    );
  });

  it('state proposed/retry/confirmed 事件走组件发布和副作用', async () => {
    const { coordinator, client } = createCoordinator();

    await coordinator.onV2StateProposed({ group_id: '12345.agentid.pub', proposal_id: 'sp-1' });
    await coordinator.onV2StateRetryNeeded({ group_id: '12345.agentid.pub' });
    client._v2AutoProposeLastSnapshot.set('12345.agentid.pub', 'snapshot');
    await coordinator.onV2StateConfirmed({ group_id: '12345.agentid.pub' });

    expect(client._dispatcher.publish).toHaveBeenCalledWith('group.v2.state_proposed', {
      group_id: '12345.agentid.pub',
      proposal_id: 'sp-1',
    });
    expect(client._v2ConfirmPendingProposal).toHaveBeenCalledWith('12345.agentid.pub');
    expect(client._dispatcher.publish).toHaveBeenCalledWith('group.v2.state_retry_needed', {
      group_id: '12345.agentid.pub',
    });
    expect(client._v2AutoProposeState).toHaveBeenCalledWith('12345.agentid.pub', { leaderDelay: true });
    expect(client._v2E2EE.deleteBootstrapCacheEntry).toHaveBeenCalledWith('group:12345.agentid.pub');
    expect(client._v2AutoProposeLastSnapshot.has('12345.agentid.pub')).toBe(false);
    expect(client._dispatcher.publish).toHaveBeenCalledWith('group.v2.state_confirmed', {
      group_id: '12345.agentid.pub',
    });
  });

  it('publishV2GroupSecurityLevel 只在等级变化时发布', async () => {
    const { coordinator, client } = createCoordinator({
      _v2GroupSecurityLevels: new Map<string, string>(),
    });

    await coordinator.publishV2GroupSecurityLevel('12345.agentid.pub', {
      e2ee_security_level: 'degraded',
      e2ee_security_warning: 'missing devices',
    });
    await coordinator.publishV2GroupSecurityLevel('12345.agentid.pub', {
      e2ee_security_level: 'degraded',
      e2ee_security_warning: 'same',
    });
    await coordinator.publishV2GroupSecurityLevel('12345.agentid.pub', {
      e2ee_security_level: 'end_to_end',
    });

    expect(client._dispatcher.publish).toHaveBeenCalledTimes(2);
    expect(client._dispatcher.publish).toHaveBeenNthCalledWith(1, 'group.v2.security_level', {
      group_id: '12345.agentid.pub',
      level: 'degraded',
      warning: 'missing devices',
      previous_level: null,
    });
    expect(client._dispatcher.publish).toHaveBeenNthCalledWith(2, 'group.v2.security_level', {
      group_id: '12345.agentid.pub',
      level: 'end_to_end',
      warning: '',
      previous_level: 'degraded',
    });
  });

  it('verifyStateSignature 命中签名缓存时不重复拉证书，并继续检查成员篡改', async () => {
    const { coordinator, client } = createCoordinator();
    const groupId = '12345.agentid.pub';
    const actorAid = 'owner.aid.com';
    const membershipSnapshot = JSON.stringify(['alice.aid.com']);
    const signatureB64 = Buffer.from('cached-signature').toString('base64');
    cacheStateSignature(client, {
      groupId,
      actorAid,
      stateVersion: 3,
      stateHash: 'hash-3',
      membershipSnapshot,
      signatureB64,
    });
    client.call = vi.fn(async () => ({ settings: [{ key: 'join.mode', value: 'closed' }] }));

    await coordinator.verifyStateSignature(groupId, {
      state_version: 3,
      state_signature: signatureB64,
      state_actor_aid: actorAid,
      state_hash_signed: 'hash-3',
      state_membership_snapshot: membershipSnapshot,
      member_aids: ['alice.aid.com', 'bob1.aid.com'],
    });

    expect(client._fetchPeerCert).not.toHaveBeenCalled();
    expect(client.call).toHaveBeenCalledWith('group.get_settings', { group_id: groupId, keys: ['join.mode'] });
    expect(client._dispatcher.publish).toHaveBeenCalledWith('group.v2.state_tampered', {
      group_id: groupId,
      pending_extra: ['bob1.aid.com'],
      mode: 'closed',
    });
  });

  it('leader delay 只让在线 owner/admin 设备参与选举', async () => {
    const { coordinator, client } = createCoordinator({
      _aid: 'z-owner.aid.com',
      _deviceId: 'dev-z',
    });
    const calls: string[] = [];
    client.call = vi.fn(async (method: string) => {
      calls.push(method);
      if (method === 'group.get_online_members') {
        return {
          members: [
            { aid: 'a-offline-admin.aid.com', role: 'admin', online: false },
            { aid: 'm-member.aid.com', role: 'member', online: true },
            { aid: 'z-owner.aid.com', role: 'owner', online: true },
          ],
        };
      }
      if (method === 'group.v2.bootstrap') {
        return {
          devices: [
            { aid: 'a-offline-admin.aid.com', device_id: 'dev-admin' },
            { aid: 'm-member.aid.com', device_id: 'dev-member' },
            { aid: 'z-owner.aid.com', device_id: 'dev-z' },
          ],
        };
      }
      return { ok: true };
    });

    await expect(coordinator.autoProposeLeaderDelay('group.agentid.pub/12345')).resolves.toBe(true);

    expect(calls).toEqual(['group.get_online_members', 'group.v2.bootstrap']);
    expect(client._v2LeaderDelayMs).not.toHaveBeenCalled();
    expect(client._sleep).not.toHaveBeenCalled();
  });

  it('confirmPendingProposal 通过 committed base 和 proposal hash 校验后才确认', async () => {
    const { coordinator, client } = createCoordinator();
    const groupId = 'group.agentid.pub/12345';
    const basePayload = {
      members: [{ aid: 'alice.aid.com', devices: [] }],
      audit_aids: [],
      admin_set: { admin_aids: ['alice.aid.com'], threshold: 1 },
      join_policy_hash: null,
      recovery_quorum: null,
      history_policy: 'recent_7_days',
      wrap_protocol: '3DH',
    };
    const nextPayload = {
      ...basePayload,
      members: [
        { aid: 'alice.aid.com', devices: [] },
        { aid: 'bob1.aid.com', devices: [] },
      ],
    };
    const baseHash = computeStateCommitment(groupId, 1, basePayload);
    const nextHash = computeStateCommitment(groupId, 2, nextPayload);
    const calls: string[] = [];
    client.call = vi.fn(async (method: string) => {
      calls.push(method);
      if (method === 'group.v2.get_proposal') {
        return {
          proposal: {
            proposal_id: 'sp-1',
            state_version: 2,
            state_hash: nextHash,
            prev_state_hash: baseHash,
            membership_snapshot: JSON.stringify(nextPayload),
          },
        };
      }
      if (method === 'group.get_state') {
        return {
          state_version: 1,
          state_hash: baseHash,
          key_epoch: 0,
          membership_snapshot: JSON.stringify(basePayload),
        };
      }
      return { ok: true };
    });

    await expect(coordinator.confirmPendingProposal(groupId)).resolves.toBe(true);

    expect(calls).toEqual(['group.v2.get_proposal', 'group.get_state', 'group.v2.confirm_state']);
    expect(client.call).toHaveBeenLastCalledWith('group.v2.confirm_state', { proposal_id: 'sp-1' });
  });

  it('confirmPendingProposal 遇到 proposal hash 不匹配时不确认', async () => {
    const { coordinator, client } = createCoordinator();
    const groupId = 'group.agentid.pub/12345';
    const basePayload = {
      members: [{ aid: 'alice.aid.com', devices: [] }],
      audit_aids: [],
      admin_set: { admin_aids: ['alice.aid.com'], threshold: 1 },
      join_policy_hash: null,
      recovery_quorum: null,
      history_policy: 'recent_7_days',
      wrap_protocol: '3DH',
    };
    const nextPayload = {
      ...basePayload,
      members: [
        { aid: 'alice.aid.com', devices: [] },
        { aid: 'bob1.aid.com', devices: [] },
      ],
    };
    const baseHash = computeStateCommitment(groupId, 1, basePayload);
    const calls: string[] = [];
    client.call = vi.fn(async (method: string) => {
      calls.push(method);
      if (method === 'group.v2.get_proposal') {
        return {
          proposal: {
            proposal_id: 'sp-1',
            state_version: 2,
            state_hash: 'bad-hash',
            prev_state_hash: baseHash,
            membership_snapshot: JSON.stringify(nextPayload),
          },
        };
      }
      if (method === 'group.get_state') {
        return {
          state_version: 1,
          state_hash: baseHash,
          key_epoch: 0,
          membership_snapshot: JSON.stringify(basePayload),
        };
      }
      return { ok: true };
    });

    await expect(coordinator.confirmPendingProposal(groupId)).resolves.toBe(false);

    expect(calls).toEqual(['group.v2.get_proposal', 'group.get_state']);
  });

  it('autoConfirmPendingProposals 只处理 owner/admin，并在未确认时触发 propose', async () => {
    const { coordinator, client } = createCoordinator();
    client.call = vi.fn(async (method: string) => {
      if (method === 'group.list_my') {
        return {
          groups: [
            { group_id: 'g-admin', role: 'admin' },
            { group_id: 'g-member', role: 'member' },
            { group_id: 'g-owner', my_role: 'owner' },
          ],
        };
      }
      return { ok: true };
    });
    client._v2ConfirmPendingProposal = vi.fn(async (groupId: string) => groupId === 'g-admin');

    await coordinator.autoConfirmPendingProposals();

    expect(client._v2ConfirmPendingProposal).toHaveBeenCalledWith('g-admin');
    expect(client._v2ConfirmPendingProposal).toHaveBeenCalledWith('g-owner');
    expect(client._v2ConfirmPendingProposal).not.toHaveBeenCalledWith('g-member');
    expect(client._v2AutoProposeState).toHaveBeenCalledWith('g-owner');
    expect(client._v2AutoProposeState).not.toHaveBeenCalledWith('g-admin');
  });
});
