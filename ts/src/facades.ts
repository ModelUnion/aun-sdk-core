import { GroupFSVFS } from './group-fs.js';
import type { RpcParams, RpcResult } from './types.js';
import { validateAIDFormat, validateGroupIDFormat } from './validators.js';

export interface FacadeRpcClient {
  call(method: string, params?: RpcParams): Promise<RpcResult>;
}

export type FacadeParams = RpcParams;

export function stripNil(params: FacadeParams = {}): FacadeParams {
  const out: FacadeParams = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

abstract class RpcFacade {
  protected readonly client: FacadeRpcClient;

  constructor(client: FacadeRpcClient) {
    this.client = client;
  }

  protected call(method: string, params?: FacadeParams): Promise<RpcResult> {
    return this.client.call(method, stripNil(params));
  }
}

export class MessageThoughtFacade extends RpcFacade {
  put(params?: FacadeParams): Promise<RpcResult> {
    if (params?.to) {
      validateAIDFormat(params.to, 'to');
    }
    return this.call('message.thought.put', params);
  }

  get(params?: FacadeParams): Promise<RpcResult> {
    if (params?.sender_aid) {
      validateAIDFormat(params.sender_aid, 'sender_aid');
    }
    return this.call('message.thought.get', params);
  }
}

export class MessageFacade extends RpcFacade {
  private _thought?: MessageThoughtFacade;

  get thought(): MessageThoughtFacade {
    if (!this._thought) this._thought = new MessageThoughtFacade(this.client);
    return this._thought;
  }

  send(params?: FacadeParams): Promise<RpcResult> {
    if (params?.to) {
      validateAIDFormat(params.to, 'to');
    }
    return this.call('message.send', params);
  }

  pull(params?: FacadeParams): Promise<RpcResult> {
    return this.call('message.pull', params);
  }

  ack(params?: FacadeParams): Promise<RpcResult> {
    return this.call('message.ack', params);
  }

  recall(params?: FacadeParams): Promise<RpcResult> {
    return this.call('message.recall', params);
  }

  queryOnline(params?: FacadeParams): Promise<RpcResult> {
    return this.call('message.query_online', params);
  }
}


export class GroupThoughtFacade extends RpcFacade {
  put(params?: FacadeParams): Promise<RpcResult> {
    if (params?.group_id) {
      validateGroupIDFormat(params.group_id, 'group_id');
    }
    return this.call('group.thought.put', params);
  }

  get(params?: FacadeParams): Promise<RpcResult> {
    if (params?.sender_aid) {
      validateAIDFormat(params.sender_aid, 'sender_aid');
    }
    if (params?.group_id) {
      validateGroupIDFormat(params.group_id, 'group_id');
    }
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

  create(params?: FacadeParams): Promise<RpcResult> { return this.call('group.create', params); }
  bindAid(params?: FacadeParams): Promise<RpcResult> { return this.call('group.bind_aid', params); }
  get(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get', params); }
  getInfo(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_info', params); }
  update(params?: FacadeParams): Promise<RpcResult> { return this.call('group.update', params); }
  list(params?: FacadeParams): Promise<RpcResult> { return this.call('group.list', params); }
  listMy(params?: FacadeParams): Promise<RpcResult> { return this.call('group.list_my', params); }
  getMembers(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_members', params); }
  addMember(params?: FacadeParams): Promise<RpcResult> { return this.call('group.add_member', params); }
  leave(params?: FacadeParams): Promise<RpcResult> { return this.call('group.leave', params); }
  kick(params?: FacadeParams): Promise<RpcResult> { return this.call('group.kick', params); }
  setRole(params?: FacadeParams): Promise<RpcResult> { return this.call('group.set_role', params); }
  transferOwner(params?: FacadeParams): Promise<RpcResult> { return this.call('group.transfer_owner', params); }
  completeTransfer(params?: FacadeParams): Promise<RpcResult> { return this.call('group.complete_transfer', params); }
  getRules(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_rules', params); }
  updateRules(params?: FacadeParams): Promise<RpcResult> { return this.call('group.update_rules', params); }
  getAnnouncement(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_announcement', params); }
  updateAnnouncement(params?: FacadeParams): Promise<RpcResult> { return this.call('group.update_announcement', params); }
  requestJoin(params?: FacadeParams): Promise<RpcResult> { return this.call('group.request_join', params); }
  listJoinRequests(params?: FacadeParams): Promise<RpcResult> { return this.call('group.list_join_requests', params); }
  reviewJoinRequest(params?: FacadeParams): Promise<RpcResult> { return this.call('group.review_join_request', params); }
  batchReviewJoinRequest(params?: FacadeParams): Promise<RpcResult> { return this.call('group.batch_review_join_request', params); }
  getJoinRequirements(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_join_requirements', params); }
  updateJoinRequirements(params?: FacadeParams): Promise<RpcResult> { return this.call('group.update_join_requirements', params); }
  createInviteCode(params?: FacadeParams): Promise<RpcResult> { return this.call('group.create_invite_code', params); }
  listInviteCodes(params?: FacadeParams): Promise<RpcResult> { return this.call('group.list_invite_codes', params); }
  useInviteCode(params?: FacadeParams): Promise<RpcResult> { return this.call('group.use_invite_code', params); }
  revokeInviteCode(params?: FacadeParams): Promise<RpcResult> { return this.call('group.revoke_invite_code', params); }
  getBanlist(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_banlist', params); }
  ban(params?: FacadeParams): Promise<RpcResult> { return this.call('group.ban', params); }
  unban(params?: FacadeParams): Promise<RpcResult> { return this.call('group.unban', params); }
  send(params?: FacadeParams): Promise<RpcResult> {
    if (params?.group_id) {
      validateGroupIDFormat(params.group_id, 'group_id');
    }
    return this.call('group.send', params);
  }
  pull(params?: FacadeParams): Promise<RpcResult> { return this.call('group.pull', params); }
  recall(params?: FacadeParams): Promise<RpcResult> { return this.call('group.recall', params); }
  pullEvents(params?: FacadeParams): Promise<RpcResult> { return this.call('group.pull_events', params); }
  ackMessages(params?: FacadeParams): Promise<RpcResult> { return this.call('group.ack_messages', params); }
  ackEvents(params?: FacadeParams): Promise<RpcResult> { return this.call('group.ack_events', params); }
  search(params?: FacadeParams): Promise<RpcResult> { return this.call('group.search', params); }
  getPublicInfo(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_public_info', params); }
  suspend(params?: FacadeParams): Promise<RpcResult> { return this.call('group.suspend', params); }
  resume(params?: FacadeParams): Promise<RpcResult> { return this.call('group.resume', params); }
  dissolve(params?: FacadeParams): Promise<RpcResult> { return this.call('group.dissolve', params); }
  getStats(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_stats', params); }
  setSettings(params?: FacadeParams): Promise<RpcResult> { return this.call('group.set_settings', params); }
  getSettings(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_settings', params); }
  info(params?: FacadeParams): Promise<RpcResult> { return this.call('group.info', params); }
  getOnlineMembers(params?: FacadeParams): Promise<RpcResult> { return this.call('group.get_online_members', params); }
}

export class StreamFacade extends RpcFacade {
  create(params?: FacadeParams): Promise<RpcResult> {
    return this.call('stream.create', params);
  }

  close(params?: FacadeParams): Promise<RpcResult> {
    return this.call('stream.close', params);
  }

  getInfo(params?: FacadeParams): Promise<RpcResult> {
    return this.call('stream.get_info', params);
  }

  listActive(params?: FacadeParams): Promise<RpcResult> {
    return this.call('stream.list_active', params);
  }
}
