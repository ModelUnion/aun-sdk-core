import { describe, expect, it, vi } from 'vitest';

import { AUNClient } from '../../src/client.js';
import {
  GroupFacade,
  GroupResourcesFacade,
  MessageFacade,
  StreamFacade,
} from '../../src/facades.js';

class FakeClient {
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  aid = 'owner.agentid.pub';
  failMethods = new Set<string>();

  async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.calls.push({ method, params: params ?? {} });
    if (this.failMethods.has(method)) {
      throw new Error(`${method} failed`);
    }
    if (method === 'storage.fs.mkdir') {
      return { folder_id: `folder-${String(params?.path ?? '')}`, path: params?.path };
    }
    if (method === 'group.get') {
      return { group: { group_id: params?.group_id, group_aid: 'team.agentid.pub' } };
    }
    return { method, params: params ?? {} };
  }
}

class FakeSignerClient extends FakeClient {
  connects: Array<Record<string, unknown> | undefined> = [];
  closed = false;

  constructor(readonly signerAid: string) {
    super();
    this.aid = signerAid;
  }

  async connect(options?: Record<string, unknown>): Promise<void> {
    this.connects.push(options);
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

describe('TS SDK facade API 契约', () => {
  it('client.message.* 映射到 message.*，并过滤 null/undefined', async () => {
    const client = new FakeClient();
    const message = new MessageFacade(client);

    await message.send({ to: 'bob.agentid.pub', payload: { text: 'hi' }, encrypt: false });
    await message.pull({ after_seq: 0, limit: 20, device_id: undefined, slot_id: null });
    await message.ack({ seq: 9 });
    await message.recall({ message_id: 'm1', reason: null });
    await message.queryOnline({ aids: ['bob.agentid.pub'] });
    await message.thought.put({ to: 'bob.agentid.pub', context: { type: 'message', id: 'm1' }, payload: { note: 'x' } });
    await message.thought.get({ sender_aid: 'bob.agentid.pub', context: { type: 'message', id: 'm1' } });

    expect(client.calls).toEqual([
      { method: 'message.send', params: { to: 'bob.agentid.pub', payload: { text: 'hi' }, encrypt: false } },
      { method: 'message.pull', params: { after_seq: 0, limit: 20 } },
      { method: 'message.ack', params: { seq: 9 } },
      { method: 'message.recall', params: { message_id: 'm1' } },
      { method: 'message.query_online', params: { aids: ['bob.agentid.pub'] } },
      {
        method: 'message.thought.put',
        params: { to: 'bob.agentid.pub', context: { type: 'message', id: 'm1' }, payload: { note: 'x' } },
      },
      {
        method: 'message.thought.get',
        params: { sender_aid: 'bob.agentid.pub', context: { type: 'message', id: 'm1' } },
      },
    ]);
  });

  it('client.group.* 只映射稳定应用层 group.* RPC，不暴露内部/低层 RPC', async () => {
    const client = new FakeClient();
    const group = new GroupFacade(client);

    await group.create({ name: 'team' });
    await group.bindAid({ group_id: 'g1', aid: 'team.agentid.pub' });
    await group.get({ group_id: 'g1' });
    await group.getInfo({ group_id: 'g1' });
    await group.update({ group_id: 'g1', name: 'team-2' });
    await group.list({ visibility: 'public' });
    await group.listMy({ limit: 10 });
    await group.search({ q: 'team' });
    await group.getPublicInfo({ group_id: 'g1' });
    await group.suspend({ group_id: 'g1' });
    await group.resume({ group_id: 'g1' });
    await group.dissolve({ group_id: 'g1' });
    await group.getStats({ group_id: 'g1' });
    await group.info({ group_id: 'g1' });
    await group.send({ group_id: 'g1', payload: { text: 'hi' }, encrypt: false });
    await group.pull({ group_id: 'g1', after_seq: 0 });
    await group.ackMessages({ group_id: 'g1', msg_seq: 8 });
    await group.pullEvents({ group_id: 'g1', after_event_seq: 3 });
    await group.ackEvents({ group_id: 'g1', event_seq: 4 });
    await group.recall({ group_id: 'g1', message_id: 'm1' });
    await group.addMember({ group_id: 'g1', aid: 'bob.agentid.pub' });
    await group.leave({ group_id: 'g1' });
    await group.kick({ group_id: 'g1', aid: 'mallory.agentid.pub' });
    await group.setRole({ group_id: 'g1', aid: 'bob.agentid.pub', role: 'admin' });
    await group.transferOwner({ group_id: 'g1', aid: 'bob.agentid.pub' });
    await group.completeTransfer({ group_id: 'g1', public_key: 'PUB' });
    await group.getMembers({ group_id: 'g1' });
    await group.getOnlineMembers({ group_id: 'g1' });
    await group.requestJoin({ group_id: 'g1', note: undefined });
    await group.listJoinRequests({ group_id: 'g1' });
    await group.reviewJoinRequest({ request_id: 'req1', decision: 'approve' });
    await group.batchReviewJoinRequest({ group_id: 'g1', request_ids: ['req2'], decision: 'reject' });
    await group.createInviteCode({ group_id: 'g1' });
    await group.listInviteCodes({ group_id: 'g1' });
    await group.useInviteCode({ invite_code: 'abc' });
    await group.revokeInviteCode({ invite_code: 'abc' });
    await group.ban({ group_id: 'g1', aid: 'mallory.agentid.pub' });
    await group.unban({ group_id: 'g1', aid: 'mallory.agentid.pub' });
    await group.getBanlist({ group_id: 'g1' });
    await group.setSettings({ group_id: 'g1', settings: { join: 'request' } });
    await group.getSettings({ group_id: 'g1' });
    await group.getAnnouncement({ group_id: 'g1' });
    await group.updateAnnouncement({ group_id: 'g1', content: 'notice' });
    await group.getRules({ group_id: 'g1' });
    await group.updateRules({ group_id: 'g1', rules: { allow_invite: true } });
    await group.getJoinRequirements({ group_id: 'g1' });
    await group.updateJoinRequirements({ group_id: 'g1', requirements: { approval_required: true } });
    await group.thought.put({ group_id: 'g1', context: { type: 'message', id: 'm1' }, payload: { note: 'x' } });
    await group.thought.get({ group_id: 'g1', sender_aid: 'alice.agentid.pub', context: { type: 'message', id: 'm1' } });

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.create',
      'group.bind_aid',
      'group.get',
      'group.get_info',
      'group.update',
      'group.list',
      'group.list_my',
      'group.search',
      'group.get_public_info',
      'group.suspend',
      'group.resume',
      'group.dissolve',
      'group.get_stats',
      'group.info',
      'group.send',
      'group.pull',
      'group.ack_messages',
      'group.pull_events',
      'group.ack_events',
      'group.recall',
      'group.add_member',
      'group.leave',
      'group.kick',
      'group.set_role',
      'group.transfer_owner',
      'group.complete_transfer',
      'group.get_members',
      'group.get_online_members',
      'group.request_join',
      'group.list_join_requests',
      'group.review_join_request',
      'group.batch_review_join_request',
      'group.create_invite_code',
      'group.list_invite_codes',
      'group.use_invite_code',
      'group.revoke_invite_code',
      'group.ban',
      'group.unban',
      'group.get_banlist',
      'group.set_settings',
      'group.get_settings',
      'group.get_announcement',
      'group.update_announcement',
      'group.get_rules',
      'group.update_rules',
      'group.get_join_requirements',
      'group.update_join_requirements',
      'group.thought.put',
      'group.thought.get',
    ]);
    expect(client.calls.some((c) => c.method.startsWith('group.v2.'))).toBe(false);
    expect(client.calls[28]?.params).toEqual({ group_id: 'g1' });
    for (const internalName of [
      'getState',
      'commitState',
      'getCursor',
      'listDevices',
      'unregisterDevice',
      'removeMember',
      'notifyTargets',
      'getAdmins',
      'getMaster',
      'setFixedAgents',
      'refreshMemberTypes',
      'getSummary',
      'getMetrics',
      'getDispatchLog',
      'ack',
      'updateName',
      'updateAvatar',
      'updateSettings',
      'invite',
      'bootstrap',
      'putGroupPk',
      'v2',
      'e2ee',
    ]) {
      expect(internalName in group).toBe(false);
    }
  });

  it('client.group.resources.* 映射所有 group.resources RPC 方法', async () => {
    const client = new FakeClient();
    const resources = new GroupResourcesFacade(client);

    await resources.put({ group_id: 'g1', resource_path: 'docs/a.txt', storage_ref: { owner_aid: 'alice.agentid.pub' } });
    await resources.createFolder({ group_id: 'g1', path: 'docs', mkdirs: true });
    await resources.listChildren({ group_id: 'g1', path: 'docs', size: 20 });
    await resources.rename({ group_id: 'g1', resource_id: 'r1', new_name: 'b.txt' });
    await resources.move({ group_id: 'g1', resource_id: 'r1', dst_parent_path: 'archive' });
    await resources.mountObject({ group_id: 'g1', path: 'docs/a.txt', storage_ref: { object_key: 'a.txt' } });
    await resources.unmount({ group_id: 'g1', resource_id: 'r1' });
    await resources.resolvePath({ group_id: 'g1', path: 'docs/a.txt' });
    await resources.get({ group_id: 'g1', resource_id: 'r1' });
    await resources.list({ group_id: 'g1', prefix: 'docs' });
    await resources.update({ group_id: 'g1', resource_id: 'r1', title: 'A' });
    await resources.getAccess({ group_id: 'g1', resource_id: 'r1' });
    await resources.resolveAccessTicket({ access_ticket: 'ticket-1' });
    await resources.delete({ group_id: 'g1', resource_id: 'r1', recursive: true });
    await resources.namespaceReady({ group_id: 'g1', folder_ids: { announce: 'folder-announce' } });
    await resources.confirm({ group_id: 'g1', op_id: 'op1', results: { write: { object_id: 'obj1' } } });
    await resources.confirmMount({ group_id: 'g1', mount_id: 'mnt1' });
    await resources.getDf({ group_id: 'g1' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.resources.put',
      'group.resources.create_folder',
      'group.resources.list_children',
      'group.resources.rename',
      'group.resources.move',
      'group.resources.mount_object',
      'group.resources.unmount',
      'group.resources.resolve_path',
      'group.resources.get',
      'group.resources.list',
      'group.resources.update',
      'group.resources.get_access',
      'group.resources.resolve_access_ticket',
      'group.resources.delete',
      'group.resources.namespace_ready',
      'group.resources.confirm',
      'group.resources.confirm_mount',
      'group.resources.get_df',
    ]);
    expect(client.calls[0]?.params).toEqual({
      group_id: 'g1',
      resource_path: 'docs/a.txt',
      storage_ref: { owner_aid: 'alice.agentid.pub' },
    });
    for (const removed of [
      'listRefsByStorage',
      'cleanupByStorageRef',
      'requestMountObject',
      'requestAdd',
      'directAdd',
      'listPending',
      'approveRequest',
      'rejectRequest',
    ]) {
      expect(removed in resources).toBe(false);
    }
  });

  it('initializeNamespace 当前身份匹配时创建 baseline 目录后回调 namespace_ready', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    const result = await resources.initializeNamespace({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mkdir',
      'storage.fs.mkdir',
      'storage.set_visibility',
      'storage.fs.mkdir',
      'storage.fs.mkdir',
      'group.resources.namespace_ready',
    ]);
    expect(client.calls.filter((c) => c.method === 'storage.fs.mkdir').map((c) => c.params.path)).toEqual([
      'announce',
      'public',
      'archive',
      'memberdata',
    ]);
    for (const call of client.calls.filter((c) => c.method === 'storage.fs.mkdir')) {
      expect(call.params).toMatchObject({
        owner_aid: 'team.agentid.pub',
        bucket: 'default',
        parents: true,
      });
    }
    expect(client.calls[2]).toMatchObject({
      method: 'storage.set_visibility',
      params: {
        owner_aid: 'team.agentid.pub',
        bucket: 'default',
        path: 'public',
        visibility: 'public',
      },
    });
    expect(client.calls[5]?.params).toMatchObject({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      folder_ids: {
        announce: 'folder-announce',
        public: 'folder-public',
        archive: 'folder-archive',
        memberdata: 'folder-memberdata',
      },
    });
    expect(result).toMatchObject({
      method: 'group.resources.namespace_ready',
      params: {
        group_id: 'g1',
        group_aid: 'team.agentid.pub',
      },
    });
  });

  it('initializeNamespace 拒绝空 group_id 或 group_aid', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.initializeNamespace({
      group_id: '',
      group_aid: 'team.agentid.pub',
    })).rejects.toThrow(/group_id/);
    await expect(resources.initializeNamespace({
      group_id: 'g1',
      group_aid: '',
    })).rejects.toThrow(/group_aid/);

    expect(client.calls).toEqual([]);
  });

  it('initializeNamespace 目标签名身份不同时要求 aidStore', async () => {
    const client = new FakeClient();
    client.aid = 'owner.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.initializeNamespace({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
    })).rejects.toThrow(/requires aidStore/);

    expect(client.calls).toEqual([]);
  });

  it('initializeNamespace 接受 resource_id/object_id 作为 folder_ids 来源', async () => {
    class ResourceIdClient extends FakeClient {
      async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
        this.calls.push({ method, params: params ?? {} });
        if (method === 'storage.fs.mkdir') {
          if (params?.path === 'announce') return { resource_id: 'res-announce' };
          return { node: { object_id: 'obj-public' } };
        }
        return { method, params: params ?? {} };
      }
    }
    const client = new ResourceIdClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await resources.initializeNamespace({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      baseline_dirs: ['announce', 'public'],
    });

    expect(client.calls[2]).toMatchObject({
      method: 'storage.set_visibility',
      params: {
        owner_aid: 'team.agentid.pub',
        path: 'public',
        visibility: 'public',
      },
    });
    expect(client.calls[3]?.method).toBe('group.resources.namespace_ready');
    expect(client.calls[3]?.params.folder_ids).toEqual({
      announce: 'res-announce',
      public: 'obj-public',
    });
  });

  it('initializeNamespace 支持 paths 覆盖默认 baseline 目录', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await resources.initializeNamespace({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      paths: [' /docs/ ', '', '/memberdata/alice.agentid.pub/'],
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mkdir',
      'storage.fs.mkdir',
      'group.resources.namespace_ready',
    ]);
    expect(client.calls.slice(0, 2).map((c) => c.params.path)).toEqual([
      'docs',
      'memberdata/alice.agentid.pub',
    ]);
    expect(client.calls[2]?.params).toMatchObject({
      folder_ids: {
        docs: 'folder-docs',
        'memberdata/alice.agentid.pub': 'folder-memberdata/alice.agentid.pub',
      },
    });
  });

  it('initializeNamespace 传入 aidStore 时用 group_aid 短连接执行 storage RPC', async () => {
    const client = new FakeClient();
    const signer = new FakeSignerClient('team.agentid.pub');
    const resources = new GroupResourcesFacade(client);

    await resources.initializeNamespace(
      {
        group_id: 'g1',
        group_aid: 'team.agentid.pub',
        baseline_dirs: ['announce', 'public'],
      },
      {
        aidStore: {
          load: vi.fn().mockReturnValue({ ok: true, data: { aid: { aid: 'team.agentid.pub' } } }),
        },
        clientFactory: vi.fn().mockReturnValue(signer),
      },
    );

    expect(signer.connects).toEqual([{
      connection_kind: 'short',
      short_ttl_ms: 30000,
      heartbeat_interval: 0,
    }]);
    expect(signer.closed).toBe(true);
    expect(signer.calls.map((c) => c.method)).toEqual([
      'storage.fs.mkdir',
      'storage.fs.mkdir',
      'storage.set_visibility',
    ]);
    for (const call of signer.calls.filter((c) => c.method === 'storage.fs.mkdir')) {
      expect(call.params.owner_aid).toBe('team.agentid.pub');
      expect(call.params.sign_as).toBeUndefined();
    }
    expect(signer.calls[2]?.params).toMatchObject({
      owner_aid: 'team.agentid.pub',
      path: 'public',
      visibility: 'public',
    });
    expect(client.calls.map((c) => c.method)).toEqual(['group.resources.namespace_ready']);
    expect(client.calls[0]?.params.sign_as).toBeUndefined();
  });

  it('initializeNamespace 尊重显式 connectOptions', async () => {
    const client = new FakeClient();
    const signer = new FakeSignerClient('team.agentid.pub');
    const resources = new GroupResourcesFacade(client);

    await resources.initializeNamespace(
      {
        group_id: 'g1',
        group_aid: 'team.agentid.pub',
        baseline_dirs: ['announce'],
      },
      {
        aidStore: {
          load: vi.fn().mockReturnValue({ ok: true, data: { aid: { aid: 'team.agentid.pub' } } }),
        },
        clientFactory: vi.fn().mockReturnValue(signer),
        connectOptions: { connection_kind: 'long', heartbeat_interval: 15 },
      },
    );

    expect(signer.connects).toEqual([{ connection_kind: 'long', heartbeat_interval: 15 }]);
  });

  it('executePendingOps 当前身份匹配时按 pending_ops 顺序执行并调用 confirm_rpc', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    const result = await resources.executePendingOps({
      mode: 'pending_ops',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      op_id: 'op1',
      resource_path: 'announce/a.txt',
      confirm_rpc: 'group.resources.confirm',
      pending_ops: [
        {
          rpc: 'storage.fs.mkdir',
          params: { owner_aid: 'team.agentid.pub', path: 'announce/docs', parents: true },
          sign_as: 'team.agentid.pub',
          confirm_key: 'mkdir',
        },
        {
          rpc: 'storage.fs.rename',
          params: { owner_aid: 'team.agentid.pub', src: 'announce/tmp.txt', dst: 'announce/a.txt' },
          confirm_key: 'rename',
        },
      ],
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mkdir',
      'storage.fs.rename',
      'group.resources.confirm',
    ]);
    expect(client.calls[0]?.params).toMatchObject({
      owner_aid: 'team.agentid.pub',
      path: 'announce/docs',
      parents: true,
    });
    expect(client.calls[1]?.params).toMatchObject({
      owner_aid: 'team.agentid.pub',
      src: 'announce/tmp.txt',
      dst: 'announce/a.txt',
    });
    expect(client.calls[2]?.params).toMatchObject({
      group_id: 'g1',
      op_id: 'op1',
      storage_results: {
        mkdir: { folder_id: 'folder-announce/docs', path: 'announce/docs' },
        rename: {
          method: 'storage.fs.rename',
        },
      },
      storage_result: {
        method: 'storage.fs.rename',
      },
      confirm_key: 'rename',
    });
    expect(client.calls[2]?.params).not.toHaveProperty('group_aid');
    expect(client.calls[2]?.params).not.toHaveProperty('resource_path');
    expect(client.calls[2]?.params).not.toHaveProperty('results');
    expect(result).toMatchObject({
      storage_results: {
        mkdir: { folder_id: 'folder-announce/docs', path: 'announce/docs' },
        rename: {
          method: 'storage.fs.rename',
        },
      },
      confirmed: {
        method: 'group.resources.confirm',
      },
    });
    expect(result).not.toHaveProperty('confirm');
  });

  it('executePendingOps 拒绝非法 pending_ops 输入', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.executePendingOps({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: 'bad',
    })).rejects.toThrow(/pending_ops array/);
    await expect(resources.executePendingOps({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: ['bad'],
    })).rejects.toThrow(/pending op 0/);
    await expect(resources.executePendingOps({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: [{ params: { path: 'announce' } }],
    })).rejects.toThrow(/pending op 0 missing rpc/);

    expect(client.calls).toEqual([]);
  });

  it('executePendingOps 拒绝不在白名单内的 RPC 字段', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.executePendingOps({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: [{ rpc: 'group.dissolve', params: {}, confirm_key: 'bad' }],
    })).rejects.toThrow(/unsupported pending rpc/);

    await expect(resources.executePendingOps({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      confirm_rpc: 'group.dissolve',
      pending_ops: [],
    })).rejects.toThrow(/unsupported confirm rpc/);

    await expect(resources.executePendingOps({
      mode: 'pending_ops',
      failure_policy: 'compensate_successful_ops_before_confirm',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: [
        {
          rpc: 'storage.fs.mkdir',
          params: { owner_aid: 'team.agentid.pub', path: 'announce' },
          confirm_key: 'mkdir',
          compensation: { rpc: 'group.dissolve', params: {}, confirm_key: 'bad' },
        },
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'public' },
          confirm_key: 'acl',
        },
      ],
    })).rejects.toThrow(/unsupported compensation rpc/);

    expect(client.calls).toEqual([]);
  });

  it('executePendingOps 在 partial failure 时执行服务端声明的补偿且不 confirm', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    client.failMethods.add('storage.set_acl');
    const resources = new GroupResourcesFacade(client);

    await expect(resources.executePendingOps({
      mode: 'pending_ops',
      failure_policy: 'compensate_successful_ops_before_confirm',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      confirm_rpc: 'group.resources.confirm',
      pending_ops: [
        {
          rpc: 'storage.fs.mkdir',
          params: { owner_aid: 'team.agentid.pub', path: 'announce', parents: true },
          sign_as: 'team.agentid.pub',
          confirm_key: 'mkdir',
          compensation: {
            rpc: 'storage.fs.remove',
            params: { owner_aid: 'team.agentid.pub', path: 'announce', recursive: true },
            sign_as: 'team.agentid.pub',
            confirm_key: 'remove:announce',
            depends_on: 'mkdir',
          },
        },
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'public', grantee_aid: 'admin.agentid.pub', perms: 'rwx' },
          sign_as: 'team.agentid.pub',
          confirm_key: 'acl:public',
        },
      ],
    })).rejects.toMatchObject({
      name: 'GroupPendingOpsPartialFailure',
      failedIndex: 1,
      storageResults: { mkdir: { folder_id: 'folder-announce', path: 'announce' } },
      compensationResults: {
        'remove:announce': { method: 'storage.fs.remove' },
      },
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mkdir',
      'storage.set_acl',
      'storage.fs.remove',
    ]);
  });

  it('executePendingOps 记录补偿自身失败且不 confirm', async () => {
    class CompensationFailClient extends FakeClient {
      async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
        this.calls.push({ method, params: params ?? {} });
        if (method === 'storage.set_acl' && params?.path === 'public') throw new Error('storage failed');
        if (method === 'storage.fs.remove') throw new Error('compensation failed');
        return { method, params: params ?? {} };
      }
    }
    const client = new CompensationFailClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.executePendingOps({
      mode: 'pending_ops',
      failure_policy: 'compensate_successful_ops_before_confirm',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      confirm_rpc: 'group.resources.confirm',
      pending_ops: [
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'announce' },
          confirm_key: 'acl:announce',
          compensation: {
            rpc: 'storage.fs.remove',
            params: { owner_aid: 'team.agentid.pub', path: 'announce', recursive: true },
            confirm_key: 'remove:announce',
          },
        },
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'public' },
          confirm_key: 'acl:public',
        },
      ],
    })).rejects.toMatchObject({
      name: 'GroupPendingOpsPartialFailure',
      failedIndex: 1,
      compensationResults: {},
      compensationErrors: [{
        confirm_key: 'remove:announce',
        rpc: 'storage.fs.remove',
        error: 'compensation failed',
      }],
    });

    const error = await resources.executePendingOps({
      mode: 'pending_ops',
      failure_policy: 'compensate_successful_ops_before_confirm',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: [
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'announce' },
          confirm_key: 'acl:announce',
          compensation: {
            rpc: 'storage.fs.remove',
            params: { owner_aid: 'team.agentid.pub', path: 'announce', recursive: true },
            confirm_key: 'remove:announce',
          },
        },
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'public' },
          confirm_key: 'acl:public',
        },
      ],
    }).catch((exc) => exc as { toJSON(): Record<string, unknown> });
    expect(error.toJSON()).toMatchObject({
      failed_index: 1,
      compensation_errors: [{ confirm_key: 'remove:announce' }],
    });
    expect(client.calls.map((c) => c.method)).not.toContain('group.resources.confirm');
  });

  it('executePendingOps 补偿参数支持 storage_results 前缀路径', async () => {
    class TokenClient extends FakeClient {
      async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
        this.calls.push({ method, params: params ?? {} });
        if (method === 'storage.issue_token') return { token: 'source-token' };
        if (method === 'storage.fs.mount') throw new Error('mount failed');
        return { method, params: params ?? {} };
      }
    }
    const client = new TokenClient();
    client.aid = 'alice.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.executePendingOps({
      mode: 'pending_ops',
      failure_policy: 'compensate_successful_ops_before_confirm',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      sign_as: 'alice.agentid.pub',
      confirm_rpc: 'group.resources.confirm_mount',
      pending_ops: [
        {
          rpc: 'storage.issue_token',
          params: { owner_aid: 'alice.agentid.pub', path: 'team-data' },
          sign_as: 'alice.agentid.pub',
          confirm_key: 'source_token',
          compensation: {
            rpc: 'storage.revoke_token',
            params: { owner_aid: 'alice.agentid.pub', path: 'team-data' },
            params_from_results: { token: 'storage_results.source_token.token' },
            confirm_key: 'revoke_source_token',
            depends_on: 'source_token',
          },
        },
        {
          rpc: 'storage.fs.mount',
          params: { owner_aid: 'team.agentid.pub', mount_path: 'memberdata/alice.agentid.pub' },
          sign_as: 'alice.agentid.pub',
          confirm_key: 'mount',
        },
      ],
    })).rejects.toMatchObject({
      name: 'GroupPendingOpsPartialFailure',
      compensationResults: {
        revoke_source_token: { method: 'storage.revoke_token' },
      },
    });

    expect(client.calls[2]).toEqual({
      method: 'storage.revoke_token',
      params: { owner_aid: 'alice.agentid.pub', path: 'team-data', token: 'source-token' },
    });
  });

  it('executePendingOps 目标签名身份不同时要求 aidStore', async () => {
    const client = new FakeClient();
    client.aid = 'owner.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await expect(resources.executePendingOps({
      mode: 'pending_ops',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      pending_ops: [
        {
          rpc: 'storage.fs.mkdir',
          params: { owner_aid: 'team.agentid.pub', path: 'announce/docs', parents: true },
          sign_as: 'team.agentid.pub',
        },
      ],
    })).rejects.toThrow(/requires aidStore/);

    expect(client.calls).toEqual([]);
  });

  it('executePendingOps 传入 aidStore 时按 sign_as 选择短连接执行 storage RPC', async () => {
    const client = new FakeClient();
    const groupSigner = new FakeSignerClient('team.agentid.pub');
    const memberSigner = new FakeSignerClient('alice.agentid.pub');
    const aidStore = {
      load: vi.fn((aid: string) => ({ ok: true, data: { aid: { aid } } })),
    };
    const clientFactory = vi.fn((aidObj: { aid: string }) => {
      if (aidObj.aid === 'team.agentid.pub') return groupSigner;
      if (aidObj.aid === 'alice.agentid.pub') return memberSigner;
      throw new Error(`unexpected signer ${aidObj.aid}`);
    });
    const resources = new GroupResourcesFacade(client);

    await resources.executePendingOps(
      {
        group_id: 'g1',
        group_aid: 'team.agentid.pub',
        confirm_rpc: 'group.resources.confirm',
        pending_ops: [
          {
            rpc: 'storage.fs.mkdir',
            params: { owner_aid: 'team.agentid.pub', path: 'announce/docs', parents: true },
            sign_as: 'team.agentid.pub',
            confirm_key: 'mkdir',
          },
          {
            rpc: 'storage.fs.mount',
            params: { owner_aid: 'team.agentid.pub', mount_path: 'memberdata/alice.agentid.pub' },
            sign_as: 'alice.agentid.pub',
            confirm_key: 'mount',
          },
        ],
      },
      { aidStore, clientFactory },
    );

    expect(aidStore.load).toHaveBeenCalledWith('team.agentid.pub');
    expect(aidStore.load).toHaveBeenCalledWith('alice.agentid.pub');
    expect(groupSigner.calls.map((c) => c.method)).toEqual(['storage.fs.mkdir', 'group.resources.confirm']);
    expect(memberSigner.calls.map((c) => c.method)).toEqual(['storage.fs.mount']);
    expect(groupSigner.calls[0]?.params.sign_as).toBeUndefined();
    expect(groupSigner.calls[1]?.params.sign_as).toBeUndefined();
    expect(memberSigner.calls[0]?.params.sign_as).toBeUndefined();
    expect(groupSigner.closed).toBe(true);
    expect(memberSigner.closed).toBe(true);
    expect(client.calls).toEqual([]);
    expect(groupSigner.calls[1]?.params.storage_results).toMatchObject({
      mkdir: { folder_id: 'folder-announce/docs' },
      mount: { method: 'storage.fs.mount' },
    });
    expect(groupSigner.calls[1]?.params).not.toHaveProperty('results');
    expect(groupSigner.calls[1]?.params.storage_result).toMatchObject({ method: 'storage.fs.mount' });
    expect(groupSigner.calls[1]?.params.confirm_key).toBe('mount');
  });

  it('executePendingOps 保留服务端 confirm_params，用于 ACL 同步确认', async () => {
    const client = new FakeClient();
    client.aid = 'team.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await resources.executePendingOps({
      mode: 'pending_ops',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      op_id: 'acl-op1',
      confirm_rpc: 'group.resources.confirm',
      confirm_params: {
        group_id: 'g1',
        operation: 'acl',
        path: 'announce',
        member_aid: 'admin.agentid.pub',
        acl_action: 'set_acl',
        acl_paths: ['announce', 'public'],
      },
      pending_ops: [
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'announce', grantee_aid: 'admin.agentid.pub', perms: 'rwx' },
          sign_as: 'team.agentid.pub',
          confirm_key: 'acl:announce',
        },
        {
          rpc: 'storage.set_acl',
          params: { owner_aid: 'team.agentid.pub', path: 'public', grantee_aid: 'admin.agentid.pub', perms: 'rwx' },
          confirm_key: 'acl:public',
        },
      ],
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.set_acl',
      'storage.set_acl',
      'group.resources.confirm',
    ]);
    expect(client.calls[2]?.params).toMatchObject({
      group_id: 'g1',
      op_id: 'acl-op1',
      operation: 'acl',
      path: 'announce',
      member_aid: 'admin.agentid.pub',
      acl_action: 'set_acl',
      acl_paths: ['announce', 'public'],
      storage_results: {
        'acl:announce': {
          method: 'storage.set_acl',
        },
        'acl:public': {
          method: 'storage.set_acl',
        },
      },
      storage_result: {
        method: 'storage.set_acl',
      },
      confirm_key: 'acl:public',
    });
    expect(client.calls[2]?.params).not.toHaveProperty('group_aid');
    expect(client.calls[2]?.params).not.toHaveProperty('results');
  });

  it('executePendingOps 支持成员自助挂载并回调 confirm_mount', async () => {
    const client = new FakeClient();
    client.aid = 'alice.agentid.pub';
    const resources = new GroupResourcesFacade(client);

    await resources.executePendingOps({
      mode: 'pending_ops',
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      sign_as: 'alice.agentid.pub',
      confirm_rpc: 'group.resources.confirm_mount',
      confirm_params: {
        group_id: 'g1',
        group_aid: 'team.agentid.pub',
        mount_path: 'memberdata/alice.agentid.pub',
        source_aid: 'alice.agentid.pub',
        source_path: 'team-data',
      },
      pending_ops: [
        {
          rpc: 'storage.fs.mount',
          params: {
            owner_aid: 'team.agentid.pub',
            mount_path: 'memberdata/alice.agentid.pub',
            source_aid: 'alice.agentid.pub',
            source_path: 'team-data',
          },
          sign_as: 'alice.agentid.pub',
          confirm_key: 'mount',
        },
      ],
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mount',
      'group.resources.confirm_mount',
    ]);
    expect(client.calls[0]?.params).toMatchObject({
      owner_aid: 'team.agentid.pub',
      mount_path: 'memberdata/alice.agentid.pub',
      source_aid: 'alice.agentid.pub',
      source_path: 'team-data',
    });
    expect(client.calls[1]?.params).toMatchObject({
      group_id: 'g1',
      group_aid: 'team.agentid.pub',
      mount_path: 'memberdata/alice.agentid.pub',
      source_aid: 'alice.agentid.pub',
      source_path: 'team-data',
      storage_results: {
        mount: {
          method: 'storage.fs.mount',
        },
      },
      storage_result: {
        method: 'storage.fs.mount',
      },
      confirm_key: 'mount',
    });
    expect(client.calls[1]?.params).not.toHaveProperty('results');
  });

  it('client.stream.* 映射到 stream 控制面 RPC', async () => {
    const client = new FakeClient();
    const stream = new StreamFacade(client);

    await stream.create({ content_type: 'text/plain', metadata: null });
    await stream.close({ stream_id: 's1' });
    await stream.getInfo({ stream_id: 's1' });
    await stream.listActive({ limit: 20 });

    expect(client.calls).toEqual([
      { method: 'stream.create', params: { content_type: 'text/plain' } },
      { method: 'stream.close', params: { stream_id: 's1' } },
      { method: 'stream.get_info', params: { stream_id: 's1' } },
      { method: 'stream.list_active', params: { limit: 20 } },
    ]);
  });

  it('AUNClient 暴露惰性缓存 facade getter，且旧 groupResources 入口不再存在', () => {
    const client = new AUNClient();

    expect(client.message).toBeInstanceOf(MessageFacade);
    expect(client.message).toBe(client.message);
    expect(client.group).toBeInstanceOf(GroupFacade);
    expect(client.group).toBe(client.group);
    expect(client.group.resources).toBeInstanceOf(GroupResourcesFacade);
    expect(client.group.resources).toBe(client.group.resources);
    expect(client.stream).toBeInstanceOf(StreamFacade);
    expect(client.stream).toBe(client.stream);
    expect('groupResources' in client).toBe(false);
  });

  it('message.send/group.send facade 必须通过 client.call 进入 RpcPipeline', async () => {
    const client = new AUNClient();
    const callSpy = vi.spyOn(client, 'call').mockResolvedValue({ ok: true });

    await client.message.send({ to: 'bob.agentid.pub', payload: { text: 'hi' } });
    await client.group.send({ group_id: 'group.agentid.pub/g1', payload: { text: 'hi' } });

    expect(callSpy).toHaveBeenNthCalledWith(1, 'message.send', { to: 'bob.agentid.pub', payload: { text: 'hi' } });
    expect(callSpy).toHaveBeenNthCalledWith(2, 'group.send', { group_id: 'group.agentid.pub/g1', payload: { text: 'hi' } });
  });

  describe('memberdata 透明路由：成员对自己挂载区写操作映射到自己 storage 空间', () => {
    it('resolveMemberdataTarget 命中本人槽位时映射为 (self_aid, {self_aid}/{group_id}/{rest})', () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);
      const target = (resources as unknown as {
        resolveMemberdataTarget(g: unknown, p: unknown): [string, string] | null;
      }).resolveMemberdataTarget('g-team.agentid.pub/team', 'memberdata/alice.agentid.pub/docs/x.txt');
      expect(target).toEqual(['alice.agentid.pub', 'alice.agentid.pub/g-team.agentid.pub/team/docs/x.txt']);
    });

    it('resolveMemberdataTarget 槽位根路径映射为 (self_aid, group_id)', () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);
      const target = (resources as unknown as {
        resolveMemberdataTarget(g: unknown, p: unknown): [string, string] | null;
      }).resolveMemberdataTarget('g-team.agentid.pub/team', 'memberdata/alice.agentid.pub');
      expect(target).toEqual(['alice.agentid.pub', 'alice.agentid.pub/g-team.agentid.pub/team']);
    });

    it('resolveMemberdataTarget 群自有区返回 null', () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);
      const target = (resources as unknown as {
        resolveMemberdataTarget(g: unknown, p: unknown): [string, string] | null;
      }).resolveMemberdataTarget('g-team.agentid.pub/team', 'announce/a.txt');
      expect(target).toBeNull();
    });

    it('resolveMemberdataTarget 他人槽位返回 null', () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);
      const target = (resources as unknown as {
        resolveMemberdataTarget(g: unknown, p: unknown): [string, string] | null;
      }).resolveMemberdataTarget('g-team.agentid.pub/team', 'memberdata/bob.agentid.pub/x');
      expect(target).toBeNull();
    });

    it('resolveMemberdataTarget AID 大小写不敏感', () => {
      const client = new FakeClient();
      client.aid = 'Alice.AgentID.pub';
      const resources = new GroupResourcesFacade(client);
      const target = (resources as unknown as {
        resolveMemberdataTarget(g: unknown, p: unknown): [string, string] | null;
      }).resolveMemberdataTarget('g-team.agentid.pub/team', 'memberdata/alice.agentid.pub/x');
      expect(target).not.toBeNull();
      expect(target?.[1]).toBe('Alice.AgentID.pub/g-team.agentid.pub/team/x');
    });

    it('put 命中本人 memberdata 时路由到 storage.put_object', async () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);

      await resources.put({
        group_id: 'g-team.agentid.pub/team',
        resource_path: 'memberdata/alice.agentid.pub/docs/x.txt',
        content: 'aGVsbG8=',
        content_encoding: 'base64',
        content_type: 'text/plain',
        size_bytes: 5,
      });

      expect(client.calls).toHaveLength(2);
      expect(client.calls[0]).toEqual({
        method: 'group.get',
        params: { group_id: 'g-team.agentid.pub/team' },
      });
      expect(client.calls[1]?.method).toBe('storage.put_object');
      expect(client.calls[1]?.params).toMatchObject({
        owner_aid: 'alice.agentid.pub',
        object_key: 'alice.agentid.pub/team.agentid.pub/docs/x.txt',
        content: 'aGVsbG8=',
        content_type: 'text/plain',
        content_encoding: 'base64',
        overwrite: true,
      });
    });

    it('put 命中本人 memberdata 但 group_aid 查找失败时不回退 group_id', async () => {
      class GroupLookupFailClient extends FakeClient {
        async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
          this.calls.push({ method, params: params ?? {} });
          if (method === 'group.get') throw new Error('timeout');
          return { method, params: params ?? {} };
        }
      }
      const client = new GroupLookupFailClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);

      await expect(resources.put({
        group_id: 'g-team.agentid.pub/team',
        resource_path: 'memberdata/alice.agentid.pub/docs/x.txt',
        content: 'aGVsbG8=',
      })).rejects.toMatchObject({
        code: 'ELOOKUP',
      });

      expect(client.calls).toEqual([{
        method: 'group.get',
        params: { group_id: 'g-team.agentid.pub/team' },
      }]);
    });

    it('put 命中本人 memberdata 但 group.get 缺 group_aid 时不回退 group_id', async () => {
      class MissingGroupAidClient extends FakeClient {
        async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
          this.calls.push({ method, params: params ?? {} });
          if (method === 'group.get') return { group: { group_id: params?.group_id } };
          return { method, params: params ?? {} };
        }
      }
      const client = new MissingGroupAidClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);

      await expect(resources.put({
        group_id: 'g-team.agentid.pub/team',
        resource_path: 'memberdata/alice.agentid.pub/docs/x.txt',
        content: 'aGVsbG8=',
      })).rejects.toMatchObject({
        code: 'ELOOKUP',
      });

      expect(client.calls).toEqual([{
        method: 'group.get',
        params: { group_id: 'g-team.agentid.pub/team' },
      }]);
    });

    it('put 群自有区仍调 group.resources.put', async () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);

      await resources.put({
        group_id: 'g-team.agentid.pub/team',
        resource_path: 'announce/a.txt',
        content: 'aGVsbG8=',
      });

      expect(client.calls[0]?.method).toBe('group.resources.put');
    });

    it('delete 命中本人 memberdata 时路由到 storage.fs.remove', async () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);

      await resources.delete({
        group_id: 'g-team.agentid.pub/team',
        resource_path: 'memberdata/alice.agentid.pub/docs/x.txt',
      });

      expect(client.calls[1]?.method).toBe('storage.fs.remove');
      expect(client.calls[1]?.params).toMatchObject({
        owner_aid: 'alice.agentid.pub',
        path: 'alice.agentid.pub/team.agentid.pub/docs/x.txt',
        recursive: false,
      });
    });

    it('createFolder 命中本人 memberdata 时路由到 storage.fs.mkdir', async () => {
      const client = new FakeClient();
      client.aid = 'alice.agentid.pub';
      const resources = new GroupResourcesFacade(client);

      await resources.createFolder({
        group_id: 'g-team.agentid.pub/team',
        resource_path: 'memberdata/alice.agentid.pub/docs',
        resource_type: 'folder',
      });

      expect(client.calls[1]?.method).toBe('storage.fs.mkdir');
      expect(client.calls[1]?.params).toMatchObject({
        owner_aid: 'alice.agentid.pub',
        path: 'alice.agentid.pub/team.agentid.pub/docs',
        parents: true,
      });
    });
  });

  it('低层 group 状态 RPC 仍可通过 client.call 显式访问', async () => {
    const client = new AUNClient();
    const callSpy = vi.spyOn(client, 'call').mockResolvedValue({ ok: true });

    await client.call('group.get_state', { group_id: 'group.agentid.pub/g1' });
    await client.call('group.commit_state', { group_id: 'group.agentid.pub/g1', state_version: 1 });

    expect(callSpy).toHaveBeenNthCalledWith(1, 'group.get_state', { group_id: 'group.agentid.pub/g1' });
    expect(callSpy).toHaveBeenNthCalledWith(2, 'group.commit_state', { group_id: 'group.agentid.pub/g1', state_version: 1 });
  });
});
