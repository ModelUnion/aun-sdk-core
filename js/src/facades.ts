import { GroupPendingOpsPartialFailure, GroupResourcesFacade } from './group-resources.js';
import type { RpcParams, RpcResult } from './types.js';

export { GroupPendingOpsPartialFailure, GroupResourcesFacade } from './group-resources.js';

export interface FacadeRpcClient {
  call(method: string, params?: RpcParams): Promise<RpcResult>;
}

export type FacadeParams = RpcParams;

function stripNil(params?: FacadeParams | null): RpcParams {
  const out: RpcParams = {};
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
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
  private _resources?: GroupResourcesFacade;
  private _thought?: GroupThoughtFacade;

  get resources(): GroupResourcesFacade {
    if (!this._resources) this._resources = new GroupResourcesFacade(this.client);
    return this._resources;
  }

  get thought(): GroupThoughtFacade {
    if (!this._thought) this._thought = new GroupThoughtFacade(this.client);
    return this._thought;
  }

  create(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.create', params);
  }

  bindAid(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.bind_aid', params);
  }

  get(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get', params);
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

  getPublicInfo(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_public_info', params);
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

  getStats(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_stats', params);
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
    return this.call('group.transfer_owner', params);
  }

  completeTransfer(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.complete_transfer', params);
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
    return this.call('group.send', params);
  }

  recall(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.recall', params);
  }

  pull(params?: FacadeParams | null): Promise<RpcResult> {
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

  getAnnouncement(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_announcement', params);
  }

  updateAnnouncement(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.update_announcement', params);
  }

  getRules(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_rules', params);
  }

  updateRules(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.update_rules', params);
  }

  getJoinRequirements(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_join_requirements', params);
  }

  updateJoinRequirements(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.update_join_requirements', params);
  }

  getOnlineMembers(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.get_online_members', params);
  }

  info(params?: FacadeParams | null): Promise<RpcResult> {
    return this.call('group.info', params);
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
