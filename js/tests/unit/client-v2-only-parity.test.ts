// ── JS SDK V2-only 与 Python/TS 编排语义对齐测试 ──────────────
import 'fake-indexeddb/auto';
import { describe, expect, it, vi } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { E2EEError, PermissionError, ValidationError } from '../../src/errors.js';
import { computeStateCommitment } from '../../src/v2/state/index.js';

const encoder = new TextEncoder();

function stableStringifyForTest(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(obj[key])}`).join(',')}}`;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data.slice().buffer));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function cacheStateSignature(client: AUNClient, args: {
  groupId: string;
  actorAid: string;
  stateVersion: number;
  stateHash: string;
  membershipSnapshot: string;
  signatureB64: string;
}): Promise<void> {
  const signPayload = stableStringifyForTest({
    group_id: args.groupId,
    membership_snapshot: args.membershipSnapshot,
    state_hash: args.stateHash,
    state_version: args.stateVersion,
  });
  const sigBytes = Uint8Array.from(atob(args.signatureB64), (ch) => ch.charCodeAt(0));
  const cachePrefix = encoder.encode(`${args.actorAid}\x00${signPayload}\x00`);
  const cacheInput = new Uint8Array(cachePrefix.length + sigBytes.length);
  cacheInput.set(cachePrefix, 0);
  cacheInput.set(sigBytes, cachePrefix.length);
  const cacheKey = await sha256Hex(cacheInput);
  (client as any)._v2SigCache.set(cacheKey, Date.now() + 60_000);
}

function connectedClient(): AUNClient {
  const client = new AUNClient();
  (client as any)._state = 'connected';
  (client as any)._aid = 'alice.aid.com';
  (client as any)._deviceId = 'dev-alice';
  (client as any)._slotId = 'slot-a';
  (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });
  return client;
}

function connectedV2Client(): AUNClient {
  const client = connectedClient();
  (client as any)._v2Session = {
    isCurrentSPK: vi.fn().mockReturnValue(false),
    trackOldSPKMaxSeq: vi.fn(),
    maybeDestroyOldSPKs: vi.fn().mockReturnValue([]),
  };
  (client as any)._safeAsync = vi.fn();
  return client;
}

describe('AUNClient V2-only parity', () => {
  it('legacy E2EE RPC 不应透传到底层 transport', async () => {
    const client = connectedClient();

    await expect(client.call('message.e2ee.get_prekey', { aid: 'bob.aid.com' }))
      .rejects.toThrow(PermissionError);
    await expect(client.call('group.e2ee.get_epoch', { group_id: 'g1' }))
      .rejects.toThrow(PermissionError);
    await expect(client.call('group.rotate_epoch', { group_id: 'g1' }))
      .rejects.toThrow(PermissionError);

    expect((client as any)._transport.call).not.toHaveBeenCalled();
  });

  it('V1 E2EE manager 与旧编排内部方法应从 JS client 清理', () => {
    const client = connectedClient();
    const proto = Object.getPrototypeOf(client) as Record<string, unknown>;

    expect((client as any)._e2ee).toBeUndefined();
    expect((client as any)._groupE2ee).toBeUndefined();
    for (const name of [
      '_sendEncrypted',
      '_sendGroupEncrypted',
      '_putMessageThoughtEncrypted',
      '_putGroupThoughtEncrypted',
      '_fetchPeerPrekeys',
      '_fetchPeerPrekey',
      '_uploadPrekey',
      '_startPrekeyRefresh',
      '_startGroupEpochTasks',
      '_recoverGroupEpochKey',
      '_rotateGroupEpoch',
      '_tryHandleGroupKeyMessage',
      '_decryptSingleMessage',
      '_decryptMessages',
      '_decryptGroupMessage',
      '_decryptGroupMessages',
      '_groupAllowsMemberEpochRotation',
      '_tryRecoverEpochKeyFromServer',
      '_buildEpochEncryptedKeys',
      '_doRecoverGroupEpochKey',
      '_maybeLeadRotateGroupEpoch',
      '_joinedMemberAidsFromPayload',
      '_membershipRotationTriggerId',
      '_delayedRotateAfterJoin',
      '_maybeBackfillKeyToJoinedMember',
      '_distributeKeyToNewMember',
      '_buildRotationSignature',
      '_logE2eeError',
    ]) {
      expect(proto[name], `${name} should be removed in V2-only client`).toBeUndefined();
    }
  });

  it('call(message.pull/group.pull) 走 V2 时应返回 {messages}', async () => {
    const client = connectedClient();
    (client as any)._v2Session = {};
    const p2pMessages = [{ seq: 1, payload: { type: 'text', text: 'p2p' } }];
    const groupMessages = [{ seq: 7, payload: { type: 'text', text: 'group' } }];
    const pullV2 = vi.spyOn(client, 'pullV2').mockResolvedValue(p2pMessages);
    const pullGroupV2 = vi.spyOn(client, 'pullGroupV2').mockResolvedValue(groupMessages);

    await expect(client.call('message.pull', { after_seq: 3, limit: 10 }))
      .resolves.toEqual({ messages: p2pMessages });
    await expect(client.call('group.pull', { group_id: 'g1', after_message_seq: 7, limit: 11 }))
      .resolves.toEqual({ messages: groupMessages });

    expect(pullV2).toHaveBeenCalledWith(3, 10);
    expect(pullGroupV2).toHaveBeenCalledWith('g1', 7, 11);
  });

  it('call(message.ack/group.ack_messages) 走 V2 时应兼容 Python 参数别名', async () => {
    const client = connectedClient();
    (client as any)._v2Session = {};
    const ackV2 = vi.spyOn(client, 'ackV2').mockResolvedValue({ acked: 9 });
    const ackGroupV2 = vi.spyOn(client, 'ackGroupV2').mockResolvedValue({ acked: 12 });

    await expect(client.call('message.ack', { up_to_seq: 9 }))
      .resolves.toEqual({ acked: 9 });
    await expect(client.call('group.ack_messages', { group_id: 'g1', msg_seq: 12 }))
      .resolves.toEqual({ acked: 12 });

    expect(ackV2).toHaveBeenCalledWith(9);
    expect(ackGroupV2).toHaveBeenCalledWith('g1', 12);
  });

  it('group.create 成功时应同步触发 V2 state propose', async () => {
    const client = connectedClient();
    (client as any)._v2Session = {};
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      group: { group_id: 'group-123' },
    });
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.create', { name: 'v2-create' });

    expect(proposeSpy).toHaveBeenCalledWith('group-123');
  });

  it('group.changed upsert 事件触发 V2 state propose 时应启用 leader delay', async () => {
    const client = connectedClient();
    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await (client as any)._onRawGroupChanged({ group_id: 'group-123', action: 'upsert' });

    expect(proposeSpy).toHaveBeenCalledWith('group-123', { leaderDelay: true });
  });

  it('V2 leader delay 仅允许在线 owner/admin 参与 leader 选举', async () => {
    const client = connectedV2Client();
    (client as any)._aid = 'z-owner.aid.com';
    (client as any)._deviceId = 'dev-alice';
    const calls: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.get_online_members') {
        return {
          members: [
            { aid: 'z-owner.aid.com', role: 'owner', online: true },
            { aid: 'm-member.aid.com', role: 'member', online: true },
          ],
        };
      }
      if (method === 'group.get_members') {
        return {
          members: [
            { aid: 'a-offline-admin.aid.com', role: 'admin' },
            { aid: 'z-owner.aid.com', role: 'owner' },
          ],
        };
      }
      if (method === 'group.v2.bootstrap') {
        return {
          devices: [
            { aid: 'a-offline-admin.aid.com', device_id: 'dev-offline', ik_fp: 'ik-a' },
            { aid: 'z-owner.aid.com', device_id: 'dev-alice', ik_fp: 'ik-z' },
          ],
          audit_recipients: [],
        };
      }
      return { ok: true };
    });
    const sleepSpy = vi.spyOn(client as any, '_sleep').mockResolvedValue(undefined);

    await expect((client as any)._v2AutoProposeLeaderDelay('group.agentid.pub/12345')).resolves.toBe(true);

    expect(calls).toEqual(['group.get_online_members', 'group.v2.bootstrap']);
    expect(sleepSpy).not.toHaveBeenCalled();
  });

  it('V2 auto propose 在 sv>0 时必须先验证最后 committed state', async () => {
    const client = connectedV2Client();
    const calls: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.get_members') {
        return { members: [{ aid: 'alice.aid.com', role: 'owner' }, { aid: 'bob.aid.com', role: 'member' }] };
      }
      if (method === 'group.v2.bootstrap') {
        return { devices: [], audit_recipients: [] };
      }
      if (method === 'group.get_state') {
        return {
          state_version: 1,
          state_hash: 'not-a-valid-committed-hash',
          key_epoch: 0,
          membership_snapshot: JSON.stringify({
            members: [{ aid: 'alice.aid.com', devices: [] }],
            audit_aids: [],
            admin_set: { admin_aids: ['alice.aid.com'], threshold: 1 },
            join_policy_hash: null,
            recovery_quorum: null,
            history_policy: 'recent_7_days',
            wrap_protocol: '3DH',
          }),
        };
      }
      return { ok: true };
    });

    await (client as any)._v2AutoProposeState('group.agentid.pub/12345');

    expect(calls).toContain('group.get_state');
    expect(calls).not.toContain('group.v2.propose_state');
    expect(calls).not.toContain('group.v2.confirm_state');
  });

  it('V2 pending proposal 自动确认前必须验证 committed base 和 proposal hash', async () => {
    const client = connectedV2Client();
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
        { aid: 'bob.aid.com', devices: [] },
      ],
    };
    const baseHash = await computeStateCommitment(groupId, 1, basePayload);
    const nextHash = await computeStateCommitment(groupId, 2, nextPayload);
    const calls: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
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

    await expect((client as any)._v2ConfirmPendingProposal(groupId)).resolves.toBe(true);

    expect(calls).toEqual(['group.v2.get_proposal', 'group.get_state', 'group.v2.confirm_state']);
  });

  it('group.v2.state_retry_needed 应触发带 leader delay 的重新提案', async () => {
    const client = connectedV2Client();
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await (client as any)._onV2StateRetryNeeded({ group_id: 'group.agentid.pub/12345' });

    expect(proposeSpy).toHaveBeenCalledWith('group.agentid.pub/12345', { leaderDelay: true });
  });

  it('V2 state 签名校验应通过 PKI 拉证书，失败时阻断 bootstrap 信任', async () => {
    const client = connectedV2Client();
    const callSpy = vi.spyOn(client, 'call').mockResolvedValue({ ok: true } as any);
    const fetchCertSpy = vi.spyOn(client as any, '_fetchPeerCert')
      .mockRejectedValue(new Error('cert unavailable'));

    await expect((client as any)._v2VerifyStateSignature('g1', {
      state_version: 2,
      state_signature: btoa('not-a-real-signature'),
      state_actor_aid: 'owner.aid.com',
      state_hash_signed: 'hash-2',
      state_membership_snapshot: '[]',
      member_aids: [],
    })).rejects.toThrow(E2EEError);

    expect(fetchCertSpy).toHaveBeenCalledWith('owner.aid.com');
    expect(callSpy).not.toHaveBeenCalledWith('ca.get_cert', expect.anything());
  });

  it('V2 state 签名快照 extra 成员应按 Python join mode 分支处理', async () => {
    const client = connectedV2Client();
    const groupId = 'group.agentid.pub/12345';
    const actorAid = 'owner.aid.com';
    const stateVersion = 3;
    const stateHash = 'hash-3';
    const membershipSnapshot = JSON.stringify(['alice.aid.com']);
    const signatureB64 = btoa('cached-signature');
    await cacheStateSignature(client, {
      groupId,
      actorAid,
      stateVersion,
      stateHash,
      membershipSnapshot,
      signatureB64,
    });

    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish');
    const callSpy = vi.spyOn(client, 'call')
      .mockResolvedValueOnce({ mode: 'open' } as any)
      .mockResolvedValueOnce({ mode: 'closed' } as any);
    const bootstrap = {
      state_version: stateVersion,
      state_signature: signatureB64,
      state_actor_aid: actorAid,
      state_hash_signed: stateHash,
      state_membership_snapshot: membershipSnapshot,
      member_aids: ['alice.aid.com', 'bob.aid.com'],
    };

    await (client as any)._v2VerifyStateSignature(groupId, bootstrap);
    expect(publishSpy).not.toHaveBeenCalledWith('group.v2.state_tampered', expect.anything());

    await (client as any)._v2VerifyStateSignature(groupId, bootstrap);
    expect(callSpy).toHaveBeenCalledWith('group.get_join_requirements', { group_id: groupId });
    expect(publishSpy).toHaveBeenCalledWith('group.v2.state_tampered', {
      group_id: groupId,
      pending_extra: ['bob.aid.com'],
      mode: 'closed',
    });
  });

  it('V2 auto propose 非 leader 延迟应使用 Python SHA-256 算法', async () => {
    const client = connectedV2Client();
    const input = 'group.agentid.pub/12345\x00bob.aid.com\x1fdev-bob';
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(input)));
    const expected = 2000 + (new DataView(digest.buffer).getUint32(0, false) % 4000);

    await expect((client as any)._v2LeaderDelayMs(input)).resolves.toBe(expected);
  });

  it('thought.get 应在通用 RPC 后走 V2 thought 解密后处理', async () => {
    const client = connectedClient();
    const rawMessageResult = {
      found: true,
      thoughts: [{ thought_id: 'mt-1', payload: { type: 'e2ee.p2p_encrypted', version: 'v2' } }],
    };
    const rawGroupResult = {
      found: true,
      thoughts: [{ thought_id: 'gt-1', payload: { type: 'e2ee.group_encrypted', version: 'v2' } }],
    };
    const decryptMessageThoughts = vi.spyOn(client as any, '_decryptMessageThoughts')
      .mockResolvedValue({ ...rawMessageResult, thoughts: [{ thought_id: 'mt-1', payload: { text: 'ok' } }] });
    const decryptGroupThoughts = vi.spyOn(client as any, '_decryptGroupThoughts')
      .mockResolvedValue({ ...rawGroupResult, thoughts: [{ thought_id: 'gt-1', payload: { text: 'group-ok' } }] });
    (client as any)._transport.call = vi.fn()
      .mockResolvedValueOnce(rawMessageResult)
      .mockResolvedValueOnce(rawGroupResult);

    await expect(client.call('message.thought.get', {
      sender_aid: 'bob.aid.com',
      context: { type: 'run', id: 'r1' },
    })).resolves.toMatchObject({ thoughts: [{ payload: { text: 'ok' } }] });
    await expect(client.call('group.thought.get', {
      group_id: 'g1',
      sender_aid: 'bob.aid.com',
      context: { type: 'run', id: 'r1' },
    })).resolves.toMatchObject({ thoughts: [{ payload: { text: 'group-ok' } }] });

    expect(decryptMessageThoughts).toHaveBeenCalledWith(rawMessageResult);
    expect(decryptGroupThoughts).toHaveBeenCalledWith(rawGroupResult);
  });

  it('message.v2.pull 应透传服务端合并的 V1 明文行并跳过 V1 E2EE envelope', async () => {
    const client = connectedV2Client();
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          has_more: false,
          messages: [
            {
              version: 'v1',
              message_id: 'm-plain',
              from_aid: 'bob.aid.com',
              seq: 1,
              type: 'message',
              t_server: 123,
              legacy_v1: {
                to: 'alice.aid.com',
                payload: { type: 'text', text: 'legacy plain' },
              },
            },
            {
              version: 'v1',
              message_id: 'm-e2ee',
              from_aid: 'bob.aid.com',
              seq: 2,
              legacy_v1: {
                payload: { type: 'e2ee.encrypted', ciphertext: 'x' },
              },
            },
          ],
        };
      }
      return { ok: true };
    });

    await expect(client.pullV2(0, 10)).resolves.toEqual([expect.objectContaining({
      message_id: 'm-plain',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 1,
      payload: { type: 'text', text: 'legacy plain' },
      encrypted: false,
    })]);
  });


  it('message.v2.pull 批量消息只 ack 一次最终 contiguous_seq', async () => {
    const client = connectedV2Client();
    (client as any)._safeAsync = (promise: Promise<unknown>) => { promise.catch(() => {}); };
    const transportCall = vi.fn().mockImplementation(async (method: string, params: Record<string, unknown> = {}) => {
      if (method === 'message.v2.pull') {
        return {
          has_more: false,
          messages: [1, 2, 3].map((seq) => ({
            version: 'v1',
            seq,
            message_id: `m-${seq}`,
            from_aid: 'bob.aid.com',
            t_server: seq,
            legacy_v1: {
              to: 'alice.aid.com',
              payload: { type: 'text', text: `m-${seq}` },
            },
          })),
        };
      }
      return { ok: true, acked: params.up_to_seq ?? 0 };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullV2(0, 10);
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    const ackCalls = transportCall.mock.calls.filter(([method]) => method === 'message.v2.ack');
    expect(result.map((msg) => (msg as Record<string, unknown>).seq)).toEqual([1, 2, 3]);
    expect(ackCalls).toEqual([['message.v2.ack', { up_to_seq: 3 }]]);
  });

  it('group.v2.pull 批量消息只 ack 一次最终 contiguous_seq', async () => {
    const client = connectedV2Client();
    (client as any)._safeAsync = (promise: Promise<unknown>) => { promise.catch(() => {}); };
    const transportCall = vi.fn().mockImplementation(async (method: string, params: Record<string, unknown> = {}) => {
      if (method === 'group.v2.pull') {
        return {
          has_more: false,
          messages: [1, 2, 3].map((seq) => ({
            version: 'v1',
            seq,
            message_id: `gm-${seq}`,
            from_aid: 'bob.aid.com',
            t_server: seq,
            type: 'message',
            payload: { type: 'text', text: `gm-${seq}` },
          })),
        };
      }
      return { ok: true, acked: params.up_to_seq ?? 0 };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullGroupV2('g1', 0, 10);
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

    const ackCalls = transportCall.mock.calls.filter(([method]) => method === 'group.v2.ack');
    expect(result.map((msg) => (msg as Record<string, unknown>).seq)).toEqual([1, 2, 3]);
    expect(ackCalls).toEqual([['group.v2.ack', { group_id: 'g1', up_to_seq: 3, device_id: 'dev-alice', slot_id: 'slot-a' }]]);
  });

  it('message.v2.pull 分页时应继续拉取并每页 ack 一次 contiguous_seq', async () => {
    const client = connectedV2Client();
    (client as any)._safeAsync = (promise: Promise<unknown>) => { promise.catch(() => {}); };
    const transportCall = vi.fn().mockImplementation(async (method: string, params: Record<string, unknown> = {}) => {
      if (method === 'message.v2.pull') {
        const afterSeq = Number(params.after_seq ?? 0);
        const seqs = afterSeq === 0 ? [1, 2] : afterSeq === 2 ? [3] : [];
        return {
          has_more: afterSeq === 0,
          messages: seqs.map((seq) => ({
            version: 'v1',
            seq,
            message_id: `m-page-${seq}`,
            from_aid: 'bob.aid.com',
            t_server: seq,
            legacy_v1: {
              to: 'alice.aid.com',
              payload: { type: 'text', text: `m-page-${seq}` },
            },
          })),
        };
      }
      return { ok: true, acked: params.up_to_seq ?? 0 };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullV2(0, 2);
    await Promise.resolve();

    const pullCalls = transportCall.mock.calls.filter(([method]) => method === 'message.v2.pull');
    const ackCalls = transportCall.mock.calls.filter(([method]) => method === 'message.v2.ack');
    expect(result.map((msg) => (msg as Record<string, unknown>).seq)).toEqual([1, 2, 3]);
    expect(pullCalls).toEqual([
      ['message.v2.pull', { after_seq: 0, limit: 2 }],
      ['message.v2.pull', { after_seq: 2, limit: 2 }],
    ]);
    expect(ackCalls).toEqual([
      ['message.v2.ack', { up_to_seq: 2 }],
      ['message.v2.ack', { up_to_seq: 3 }],
    ]);
  });

  it('group.v2.pull 分页时应继续拉取并每页 ack 一次 contiguous_seq', async () => {
    const client = connectedV2Client();
    (client as any)._safeAsync = (promise: Promise<unknown>) => { promise.catch(() => {}); };
    const transportCall = vi.fn().mockImplementation(async (method: string, params: Record<string, unknown> = {}) => {
      if (method === 'group.v2.pull') {
        const afterSeq = Number(params.after_seq ?? 0);
        const seqs = afterSeq === 0 ? [1, 2] : afterSeq === 2 ? [3] : [];
        return {
          has_more: afterSeq === 0,
          messages: seqs.map((seq) => ({
            version: 'v1',
            seq,
            message_id: `gm-page-${seq}`,
            from_aid: 'bob.aid.com',
            t_server: seq,
            type: 'message',
            payload: { type: 'text', text: `gm-page-${seq}` },
          })),
        };
      }
      return { ok: true, acked: params.up_to_seq ?? 0 };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullGroupV2('g1', 0, 2);
    await Promise.resolve();

    const pullCalls = transportCall.mock.calls.filter(([method]) => method === 'group.v2.pull');
    const ackCalls = transportCall.mock.calls.filter(([method]) => method === 'group.v2.ack');
    expect(result.map((msg) => (msg as Record<string, unknown>).seq)).toEqual([1, 2, 3]);
    expect(pullCalls).toEqual([
      ['group.v2.pull', expect.objectContaining({ group_id: 'g1', after_seq: 0, limit: 2 })],
      ['group.v2.pull', expect.objectContaining({ group_id: 'g1', after_seq: 2, limit: 2 })],
    ]);
    expect(ackCalls).toEqual([
      ['group.v2.ack', expect.objectContaining({ group_id: 'g1', up_to_seq: 2 })],
      ['group.v2.ack', expect.objectContaining({ group_id: 'g1', up_to_seq: 3 })],
    ]);
  });

  it('message.v2.pull 空页不应 ack 已存在的 contiguous_seq', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.forceContiguousSeq(ns, 5);
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') return { has_more: false, messages: [] };
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullV2(5, 10);
    await Promise.resolve();

    expect(result).toEqual([]);
    expect(transportCall.mock.calls.filter(([method]) => method === 'message.v2.ack')).toEqual([]);
  });

  it('message.v2.pull 陈旧 raw 未推进 contiguous_seq 时不应 ack', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.forceContiguousSeq(ns, 5);
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          has_more: false,
          messages: [{
            version: 'v1',
            seq: 5,
            message_id: 'm-stale-5',
            from_aid: 'bob.aid.com',
            legacy_v1: {
              to: 'alice.aid.com',
              payload: { type: 'text', text: 'old' },
            },
          }],
        };
      }
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullV2(5, 10);
    await Promise.resolve();

    expect(result.map((msg) => (msg as Record<string, unknown>).seq)).toEqual([5]);
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(5);
    expect(transportCall.mock.calls.filter(([method]) => method === 'message.v2.ack')).toEqual([]);
  });

  it('message.v2.pull 发布消息前应先推进 contiguous_seq，避免事件处理器 ack 拉到旧边界', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    const observedContig: number[] = [];
    client.on('message.received', () => {
      observedContig.push((client as any)._seqTracker.getContiguousSeq(ns));
    });
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          has_more: false,
          messages: [{
            version: 'v1',
            seq: 1,
            message_id: 'm-pull-1',
            from_aid: 'bob.aid.com',
            legacy_v1: {
              to: 'alice.aid.com',
              payload: { type: 'text', text: 'pulled' },
            },
          }],
        };
      }
      return { ok: true };
    });

    await client.pullV2(0, 10);

    expect(observedContig).toEqual([1]);
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(1);
  });

  it('group.v2.pull 空页不应 ack 已存在的 contiguous_seq', async () => {
    const client = connectedV2Client();
    const ns = 'group:g1';
    (client as any)._seqTracker.forceContiguousSeq(ns, 5);
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') return { has_more: false, messages: [] };
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullGroupV2('g1', 5, 10);
    await Promise.resolve();

    expect(result).toEqual([]);
    expect(transportCall.mock.calls.filter(([method]) => method === 'group.v2.ack')).toEqual([]);
  });

  it('group.v2.pull 陈旧 raw 未推进 contiguous_seq 时不应 ack', async () => {
    const client = connectedV2Client();
    const ns = 'group:g1';
    (client as any)._seqTracker.forceContiguousSeq(ns, 5);
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          has_more: false,
          messages: [{
            version: 'v1',
            seq: 5,
            message_id: 'gm-stale-5',
            from_aid: 'bob.aid.com',
            payload: { type: 'text', text: 'old' },
          }],
        };
      }
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    const result = await client.pullGroupV2('g1', 5, 10);
    await Promise.resolve();

    expect(result.map((msg) => (msg as Record<string, unknown>).seq)).toEqual([5]);
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(5);
    expect(transportCall.mock.calls.filter(([method]) => method === 'group.v2.ack')).toEqual([]);
  });

  it('group.v2.pull 发布消息前应先推进 contiguous_seq，避免事件处理器 ack 拉到旧边界', async () => {
    const client = connectedV2Client();
    const ns = 'group:g1';
    const observedContig: number[] = [];
    client.on('group.message_created', () => {
      observedContig.push((client as any)._seqTracker.getContiguousSeq(ns));
    });
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          has_more: false,
          messages: [{
            version: 'v1',
            seq: 1,
            message_id: 'gm-pull-1',
            from_aid: 'bob.aid.com',
            type: 'message',
            payload: { type: 'text', text: 'group pulled' },
          }],
        };
      }
      return { ok: true };
    });

    await client.pullGroupV2('g1', 0, 10);

    expect(observedContig).toEqual([1]);
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(1);
  });

  it('V2 P2P 纯 push 通知不应先推进 contiguous_seq 再 pull', async () => {
    const client = connectedV2Client();
    const published: unknown[] = [];
    client.on('message.received', (payload: unknown) => published.push(payload));
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string, params: any = {}) => {
      if (method === 'message.v2.pull') {
        if (Number(params.after_seq ?? 0) !== 0) {
          return { messages: [] };
        }
        return {
          messages: [{
            version: 'v1',
            message_id: 'm-v2-pure-push',
            from_aid: 'bob.aid.com',
            seq: 1,
            t_server: 123,
            legacy_v1: {
              to: 'alice.aid.com',
              payload: { type: 'text', text: 'pulled by v2 pure push' },
            },
          }],
        };
      }
      return { ok: true };
    });

    await (client as any)._onV2PushNotification({
      seq: 1,
      message_id: 'm-v2-pure-push',
      from_aid: 'bob.aid.com',
    });

    expect((client as any)._transport.call).toHaveBeenCalledWith(
      'message.v2.pull',
      expect.objectContaining({ after_seq: 0 }),
    );
    expect(published).toHaveLength(1);
    expect(published[0]).toMatchObject({
      message_id: 'm-v2-pure-push',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 1,
      payload: { type: 'text', text: 'pulled by v2 pure push' },
      encrypted: false,
    });
  });
  it('V2 P2P payload push 发现空洞后仍应 pull 当前 contiguous_seq', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.onMessageSeq(ns, 1);
    vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue({
      message_id: 'm-push-3',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 3,
      payload: { type: 'text', text: 'push-3' },
      encrypted: true,
    });
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') return { messages: [] };
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    await (client as any)._onV2PushNotification({
      seq: 3,
      message_id: 'm-push-3',
      from_aid: 'bob.aid.com',
      envelope_json: '{}',
    });

    expect(transportCall).toHaveBeenCalledWith('message.v2.pull', expect.objectContaining({ after_seq: 1 }));
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(1);
    expect((client as any)._seqTracker.getMaxSeenSeq(ns)).toBe(3);
    expect((client as any)._pendingOrderedMsgs.get(ns)?.has(3)).toBe(true);
  });



  it('V2 P2P payload push 应先修复过大的 contiguous_seq 再返回', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.forceContiguousSeq(ns, 99999);
    vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue({
      message_id: 'm-push-3',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 3,
      payload: { type: 'text', text: 'push-3' },
      encrypted: true,
    });
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await (client as any)._onV2PushNotification({
      seq: 3,
      message_id: 'm-push-3',
      from_aid: 'bob.aid.com',
      envelope_json: '{}',
    });

    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(3);
    expect(transportCall.mock.calls.some(([method]) => method === 'message.v2.pull')).toBe(false);
    expect(transportCall).toHaveBeenCalledWith('message.v2.ack', { up_to_seq: 3 });
  });

  it('V2 P2P payload push 在 contiguous_seq 等于 push_seq 时应幂等忽略', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.forceContiguousSeq(ns, 3);
    const repairSpy = vi.spyOn((client as any)._seqTracker, 'repairContiguousSeq');
    const decryptSpy = vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue({
      message_id: 'm-push-3',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 3,
      payload: { type: 'text', text: 'push-3' },
      encrypted: true,
    });
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await (client as any)._onV2PushNotification({
      seq: 3,
      message_id: 'm-push-3',
      from_aid: 'bob.aid.com',
      envelope_json: '{}',
    });

    expect(repairSpy).not.toHaveBeenCalled();
    expect(decryptSpy).not.toHaveBeenCalled();
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(3);
    expect(transportCall.mock.calls.some(([method]) => method === 'message.v2.pull')).toBe(false);
  });

  it('V2 P2P 纯通知 push 在 contiguous_seq 等于 push_seq 时应幂等忽略', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.forceContiguousSeq(ns, 3);
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') return { has_more: false, messages: [] };
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    await (client as any)._onV2PushNotification({
      seq: 3,
      message_id: 'm-push-3',
      from_aid: 'bob.aid.com',
    });

    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(3);
    expect(transportCall.mock.calls.some(([method]) => method === 'message.v2.pull')).toBe(false);
  });

  it('V2 group 纯通知 push 应修复过大的 contiguous_seq 后再 pull', async () => {
    const client = connectedV2Client();
    const groupId = 'g1';
    const ns = `group:${groupId}`;
    (client as any)._seqTracker.forceContiguousSeq(ns, 99999);
    const transportCall = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') return { has_more: false, messages: [] };
      return { ok: true };
    });
    (client as any)._transport.call = transportCall;

    await (client as any)._onRawGroupV2MessageCreated({
      group_id: groupId,
      seq: 3,
      message_id: 'gm-push-3',
      sender_aid: 'bob.aid.com',
    });

    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(2);
    expect(transportCall).toHaveBeenCalledWith(
      'group.v2.pull',
      expect.objectContaining({ group_id: groupId, after_seq: 2 }),
    );
  });
  it('V2 group 纯通知 push 在 contiguous_seq 等于 push_seq 时应幂等忽略', async () => {
    const client = connectedV2Client();
    const groupId = 'g1';
    const ns = `group:${groupId}`;
    (client as any)._seqTracker.forceContiguousSeq(ns, 3);
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await (client as any)._onRawGroupV2MessageCreated({
      group_id: groupId,
      seq: 3,
      message_id: 'gm-push-3',
      sender_aid: 'bob.aid.com',
    });

    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(3);
    expect(transportCall.mock.calls.some(([method]) => method === 'group.v2.pull')).toBe(false);
  });
  it('message.v2.pull 返回值不应因 push 已发布 seq 而丢失', async () => {
    const client = connectedV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._pushedSeqs.set(ns, new Set([1]));
    const decrypted = {
      message_id: 'm-v2',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 1,
      payload: { type: 'text', text: 'already pushed' },
      encrypted: true,
      e2ee: { version: 'v2' },
    };
    vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue(decrypted);
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          has_more: false,
          messages: [{
            version: 'v2',
            message_id: 'm-v2',
            from_aid: 'bob.aid.com',
            seq: 1,
            envelope_json: '{}',
          }],
        };
      }
      return { ok: true };
    });

    await expect(client.pullV2(0, 10)).resolves.toEqual([decrypted]);
  });

  it('ackV2 应补齐 Python 兼容字段并在 acked=0 时推进到请求 seq', async () => {
    const client = connectedV2Client();
    (client as any)._transport.call = vi.fn().mockResolvedValue({ acked: 0 });

    await expect(client.ackV2(9)).resolves.toMatchObject({
      acked: 9,
      ack_seq: 9,
      success: true,
    });
    expect((client as any)._v2Session.maybeDestroyOldSPKs).toHaveBeenCalledWith(9);
  });

  it('group.v2.pull 应透传 V1 明文行、跳过 V1 E2EE envelope，且返回值不受已发布 seq 去重影响', async () => {
    const client = connectedV2Client();
    const ns = 'group:g1';
    (client as any)._pushedSeqs.set(ns, new Set([3]));
    const decrypted = {
      message_id: 'gm-v2',
      from: 'bob.aid.com',
      seq: 3,
      payload: { type: 'text', text: 'already pushed group' },
      encrypted: true,
      e2ee: { version: 'v2' },
    };
    vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue({ ...decrypted });
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          has_more: false,
          messages: [
            {
              version: 'v1',
              message_id: 'gm-plain',
              from_aid: 'bob.aid.com',
              seq: 1,
              type: 'group.message',
              t_server: 456,
              payload: { type: 'text', text: 'group legacy plain' },
            },
            {
              version: 'v1',
              message_id: 'gm-e2ee',
              from_aid: 'bob.aid.com',
              seq: 2,
              payload: { type: 'e2ee.group_encrypted', ciphertext: 'x' },
            },
            {
              version: 'v2',
              message_id: 'gm-v2',
              from_aid: 'bob.aid.com',
              seq: 3,
              envelope_json: '{}',
            },
          ],
        };
      }
      return { ok: true };
    });

    await expect(client.pullGroupV2('g1', 0, 10)).resolves.toEqual([
      expect.objectContaining({
        message_id: 'gm-plain',
        from: 'bob.aid.com',
        group_id: 'g1',
        seq: 1,
        payload: { type: 'text', text: 'group legacy plain' },
        encrypted: false,
      }),
      { ...decrypted, group_id: 'g1' },
    ]);
  });

  it('message.send content 别名和裸 text payload 应在发送入口归一化', async () => {
    const encrypted = connectedV2Client();
    const sendSpy = vi.spyOn(encrypted, 'sendV2').mockResolvedValue({ ok: true } as any);

    await encrypted.call('message.send', {
      to: 'bob.aid.com',
      content: { text: 'hello' },
    } as any);

    expect(sendSpy).toHaveBeenCalledWith('bob.aid.com', { type: 'text', text: 'hello' }, expect.any(Object));

    const plaintext = connectedV2Client();
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (plaintext as any)._transport.call = transportCall;

    await plaintext.call('message.send', {
      to: 'bob.aid.com',
      content: { text: 'plain' },
      encrypt: false,
    } as any);

    const [, sentParams] = transportCall.mock.calls[0];
    expect(sentParams.content).toBeUndefined();
    expect(sentParams.payload).toEqual({ type: 'text', text: 'plain' });
  });

  it('group.send content 别名和裸 text payload 应在发送入口归一化', async () => {
    const encrypted = connectedV2Client();
    const sendSpy = vi.spyOn(encrypted, 'sendGroupV2').mockResolvedValue({ ok: true } as any);

    await encrypted.call('group.send', {
      group_id: 'g1',
      content: { text: '群密文' },
    } as any);

    expect(sendSpy).toHaveBeenCalledWith('g1', { type: 'text', text: '群密文' }, expect.any(Object));

    const plaintext = connectedV2Client();
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (plaintext as any)._transport.call = transportCall;

    await plaintext.call('group.send', {
      group_id: 'g1',
      payload: { text: '群明文' },
      encrypt: false,
    } as any);

    const [, sentParams] = transportCall.mock.calls[0];
    expect(sentParams.content).toBeUndefined();
    expect(sentParams.payload).toEqual({ type: 'text', text: '群明文' });
  });
  it('message.send/group.send 的 V2 加密 payload 必须是对象且错误不落到底层 transport', async () => {
    const client = connectedV2Client();
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await expect(client.call('message.send', {
      to: 'bob.aid.com',
      payload: 'bad-payload' as any,
    })).rejects.toThrow(ValidationError);
    await expect(client.call('group.send', {
      group_id: 'g1',
      payload: 'bad-payload' as any,
    })).rejects.toThrow(ValidationError);

    expect(transportCall).not.toHaveBeenCalled();
  });

  it('thought.put 应使用 V2 envelope 并附带客户端签名', async () => {
    const client = connectedV2Client();
    const p2pEnvelope = { type: 'e2ee.p2p_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' };
    const groupEnvelope = { type: 'e2ee.group_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' };
    vi.spyOn(client as any, '_buildV2P2PEnvelope').mockResolvedValue(p2pEnvelope);
    vi.spyOn(client as any, '_buildV2GroupEnvelope').mockResolvedValue(groupEnvelope);
    vi.spyOn(client as any, '_signClientOperation').mockImplementation((_method: string, params: any) => {
      params.client_signature = { aid: 'alice.aid.com' };
    });
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await client.call('message.thought.put', {
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: 'p2p-thought' },
    });
    await client.call('group.thought.put', {
      group_id: 'g1',
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: 'group-thought' },
    });

    expect(transportCall).toHaveBeenNthCalledWith(1, 'message.thought.put', expect.objectContaining({
      to: 'bob.aid.com',
      encrypted: true,
      payload: p2pEnvelope,
      thought_id: expect.stringMatching(/^mt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));
    expect(transportCall).toHaveBeenNthCalledWith(2, 'group.thought.put', expect.objectContaining({
      group_id: 'g1',
      encrypted: true,
      payload: groupEnvelope,
      thought_id: expect.stringMatching(/^gt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));
  });
});
