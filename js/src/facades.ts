import { GroupFSVFS } from './group-fs.js';
import type { RpcParams, RpcResult } from './types.js';
import { validateGroupIDFormat } from './validators.js';

export { GroupFSVFS, isGroupRemotePath } from './group-fs.js';

export interface FacadeRpcClient {
  call(method: string, params?: RpcParams): Promise<RpcResult>;
  createGroup?(params?: RpcParams): Promise<RpcResult>;
  startGroupTransfer?(params?: RpcParams, options?: { aidStore?: unknown }): Promise<RpcResult>;
  completeGroupTransfer?(params?: RpcParams, options?: { aidStore?: unknown }): Promise<RpcResult>;
}

export type FacadeParams = RpcParams;

function stripNil(params?: FacadeParams | null): RpcParams {
  const out: RpcParams = {};
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

function splitAidStore(params?: FacadeParams | null): { params: RpcParams; aidStore?: unknown } {
  const out = stripNil(params);
  const aidStore = out.aidStore ?? out.aid_store;
  delete out.aidStore;
  delete out.aid_store;
  return { params: out, aidStore };
}

// 将 getSettings 返回的 settings 数组转为 {key: value} 映射
function settingsToMap(result: RpcResult): Record<string, any> {
  const settings: Record<string, any> = {};
  for (const s of (result as any).settings || []) {
    settings[s.key] = s.value;
  }
  return settings;
}

class RpcFacade {
  protected readonly client: FacadeRpcClient;

  constructor(client: FacadeRpcClient) {
    this.client = client;
  }

  protected call(method: string, params?: FacadeParams | null): Promise<RpcResult> {
    return this.client.call(method, stripNil(params));
  }
}

export class MessageThoughtFacade extends RpcFacade {
  put(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.thought.put', params);
  }

  get(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.thought.get', params);
  }
}

export class MessageFacade extends RpcFacade {
  private _thought?: MessageThoughtFacade;

  get thought(): MessageThoughtFacade {
    if (!this._thought) this._thought = new MessageThoughtFacade(this.client);
    return this._thought;
  }

  send(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.send', params);
  }

  pull(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.pull', params);
  }

  ack(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.ack', params);
  }

  recall(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.recall', params);
  }

  queryOnline(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('message.query_online', params);
  }
}

export class GroupThoughtFacade extends RpcFacade {
  put(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.thought.put', params);
  }

  get(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.thought.get', params);
  }
}

export class GroupFacade extends RpcFacade {
  private _fs?: GroupFSVFS;
  private _thought?: GroupThoughtFacade;

  get fs(): GroupFSVFS {
    if (!this._fs) this._fs = new GroupFSVFS(this.client);
    return this._fs;
  }

  get thought(): GroupThoughtFacade {
    if (!this._thought) this._thought = new GroupThoughtFacade(this.client);
    return this._thought;
  }

  create(params?: FacadeParams | null): Promise<RpcResult> {
    const clean = stripNil(params);
    if (clean.group_name && typeof this.client.createGroup === 'function') {
      return this.client.createGroup(clean);
    }
    return this.call('group.create', clean);
  }

  bindAid(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.bind_aid', params);
  }

  bindGroupAid(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.bind_group_aid', params);
  }

  renewGroupAid(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.renew_group_aid', params);
  }

  getInfo(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_info', params);
  }

  update(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.update', params);
  }

  list(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.list', params);
  }

  listMy(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.list_my', params);
  }

  search(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.search', params);
  }

  suspend(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.suspend', params);
  }

  resume(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.resume', params);
  }

  dissolve(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.dissolve', params);
  }

  addMember(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.add_member', params);
  }

  getMembers(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_members', params);
  }

  kick(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.kick', params);
  }

  leave(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.leave', params);
  }

  setRole(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.set_role', params);
  }

  transferOwner(params?: FacadeParams | null): Promise<RpcResult> {
    const split = splitAidStore(params);
    if (split.aidStore && typeof this.client.startGroupTransfer === 'function') {
      return this.client.startGroupTransfer(split.params, { aidStore: split.aidStore });
    }
    return this.call('group.transfer_owner', split.params);
  }

  completeTransfer(params?: FacadeParams | null): Promise<RpcResult> {
    const split = splitAidStore(params);
    if (split.aidStore && typeof this.client.completeGroupTransfer === 'function') {
      return this.client.completeGroupTransfer(split.params, { aidStore: split.aidStore });
    }
    return this.call('group.complete_transfer', split.params);
  }

  ban(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.ban', params);
  }

  unban(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.unban', params);
  }

  getBanlist(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_banlist', params);
  }

  requestJoin(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.request_join', params);
  }

  listJoinRequests(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.list_join_requests', params);
  }

  reviewJoinRequest(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.review_join_request', params);
  }

  batchReviewJoinRequest(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.batch_review_join_request', params);
  }

  createInviteCode(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.create_invite_code', params);
  }

  listInviteCodes(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.list_invite_codes', params);
  }

  useInviteCode(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.use_invite_code', params);
  }

  revokeInviteCode(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.revoke_invite_code', params);
  }

  setSettings(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.set_settings', params);
  }

  getSettings(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_settings', params);
  }

  send(params?: FacadeParams | null): Promise<RpcResult> {
    validateGroupIDFormat(params?.group_id, 'group_id');
    return this.call('group.send', params);
  }

  recall(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.recall', params);
  }

  pull(params?: FacadeParams | null): Promise<RpcResult> {
    validateGroupIDFormat(params?.group_id, 'group_id');
    return this.call('group.pull', params);
  }

  pullEvents(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.pull_events', params);
  }

  ackMessages(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.ack_messages', params);
  }

  ackEvents(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.ack_events', params);
  }

  async getAnnouncement(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 getSettings
    const merged = params || {};
    const groupId = merged.group_id;
    if (!groupId) throw new Error('group_id is required');

    const result = await this.getSettings({
      group_id: groupId,
      keys: ['announcement.content', 'announcement.attachments']
    });

    const settings = settingsToMap(result);
    return {
      group_id: (result as Record<string, any>).group_id,
      announcement: {
        group_id: (result as Record<string, any>).group_id,
        content: settings['announcement.content'] || '',
        attachments: settings['announcement.attachments'] || [],
        updated_by: settings['announcement.content.updated_by'] || '',
        updated_at: settings['announcement.content.updated_at'] || 0
      }
    };
  }

  async updateAnnouncement(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 setSettings
    const merged = params || {};
    const groupId = merged.group_id;
    const content = merged.content;
    const attachments = merged.attachments;

    if (!groupId) throw new Error('group_id is required');
    if (content === undefined) throw new Error('content is required');

    const settingsUpdate: Record<string, any> = { 'announcement.content': content };
    if (attachments !== undefined) {
      settingsUpdate['announcement.attachments'] = attachments;
    }

    const result = await this.setSettings({
      group_id: groupId,
      settings: settingsUpdate
    });

    return {
      group_id: (result as Record<string, any>).group_id,
      announcement: {
        group_id: (result as Record<string, any>).group_id,
        content,
        attachments: attachments || []
      }
    };
  }

  async getRules(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 getSettings
    const merged = params || {};
    const groupId = merged.group_id;
    if (!groupId) throw new Error('group_id is required');

    const result = await this.getSettings({
      group_id: groupId,
      keys: ['rules.content', 'rules.attachments']
    });

    const settings = settingsToMap(result);
    return {
      group_id: (result as Record<string, any>).group_id,
      rules: {
        group_id: (result as Record<string, any>).group_id,
        content: settings['rules.content'] || '',
        attachments: settings['rules.attachments'] || [],
        updated_by: settings['rules.content.updated_by'] || '',
        updated_at: settings['rules.content.updated_at'] || 0
      }
    };
  }

  async updateRules(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 setSettings
    const merged = params || {};
    const groupId = merged.group_id;
    const content = merged.content;
    const attachments = merged.attachments;

    if (!groupId) throw new Error('group_id is required');
    if (content === undefined) throw new Error('content is required');

    const settingsUpdate: Record<string, any> = { 'rules.content': content };
    if (attachments !== undefined) {
      settingsUpdate['rules.attachments'] = attachments;
    }

    const result = await this.setSettings({
      group_id: groupId,
      settings: settingsUpdate
    });

    return {
      group_id: (result as Record<string, any>).group_id,
      rules: {
        group_id: (result as Record<string, any>).group_id,
        content,
        attachments: attachments || []
      }
    };
  }

  async getJoinRequirements(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 getSettings
    const merged = params || {};
    const groupId = merged.group_id;
    if (!groupId) throw new Error('group_id is required');

    const result = await this.getSettings({
      group_id: groupId,
      keys: ['join.mode', 'join.question', 'join.auto_approve_patterns', 'join.max_pending']
    });

    const settings = settingsToMap(result);
    return {
      group_id: (result as Record<string, any>).group_id,
      join_requirements: {
        group_id: (result as Record<string, any>).group_id,
        mode: settings['join.mode'] || 'open',
        question: settings['join.question'] || '',
        auto_approve_patterns: settings['join.auto_approve_patterns'] || [],
        max_pending: settings['join.max_pending'] || 100,
        updated_by: settings['join.mode.updated_by'] || '',
        updated_at: settings['join.mode.updated_at'] || 0
      }
    };
  }

  async updateJoinRequirements(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 setSettings
    const merged = params || {};
    const groupId = merged.group_id;

    if (!groupId) throw new Error('group_id is required');

    const settingsUpdate: Record<string, any> = {};
    if ('mode' in merged) settingsUpdate['join.mode'] = merged.mode;
    if ('question' in merged) settingsUpdate['join.question'] = merged.question;
    if ('auto_approve_patterns' in merged) settingsUpdate['join.auto_approve_patterns'] = merged.auto_approve_patterns;
    if ('max_pending' in merged) settingsUpdate['join.max_pending'] = merged.max_pending;

    if (Object.keys(settingsUpdate).length === 0) {
      throw new Error('at least one field to update is required');
    }

    const result = await this.setSettings({
      group_id: groupId,
      settings: settingsUpdate
    });

    return {
      group_id: (result as Record<string, any>).group_id,
      join_requirements: {
        group_id: (result as Record<string, any>).group_id,
        mode: merged.mode,
        question: merged.question,
        auto_approve_patterns: merged.auto_approve_patterns,
        max_pending: merged.max_pending
      }
    };
  }

  getOnlineMembers(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_online_members', params);
  }
}

export class StreamFacade extends RpcFacade {
  create(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('stream.create', params);
  }

  close(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('stream.close', params);
  }

  getInfo(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('stream.get_info', params);
  }

  listActive(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('stream.list_active', params);
  }
}
