import { GroupFSVFS } from './group-fs.js';
import { GROUP_INDEX_KEY, parseGroupIndex, prepareGroupSettingsWithIndex, verifyGroupIndex } from './group-index.js';
import type { JsonValue, RpcParams, RpcResult } from './types.js';
import { validateGroupIDFormat } from './validators.js';

export { GroupFSVFS, isGroupRemotePath } from './group-fs.js';

export interface FacadeRpcClient {
  call(method: string, params?: RpcParams): Promise<RpcResult>;
  createGroup?(params?: RpcParams): Promise<RpcResult>;
  startGroupTransfer?(params?: RpcParams, options?: { aidStore?: unknown }): Promise<RpcResult>;
  completeGroupTransfer?(params?: RpcParams, options?: { aidStore?: unknown }): Promise<RpcResult>;
}

export type FacadeParams = RpcParams;

const INDEXED_DOCUMENT_SETTING_KEY_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const INDEXED_DOCUMENT_SETTING_RESERVED_BASES = new Set([
  'join',
  'dispatch_mode',
  'duty',
  'e2ee',
  'group',
  'group_index',
  'index',
  'name',
  'description',
  'visibility',
]);

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

function indexUpdateParams(groupId: unknown, settings: Record<string, any>, merged: Record<string, any>): FacadeParams {
  const out: Record<string, any> = { group_id: groupId, settings };
  for (const key of ['signer', 'last_modified', 'max_attempts']) {
    if (key in merged) out[key] = merged[key];
  }
  return out;
}

function indexedDocumentKeyName(params: Record<string, any>): string {
  const raw = 'keyName' in params ? params.keyName : params.key_name;
  const keyName = String(raw ?? '').trim();
  if (!keyName || INDEXED_DOCUMENT_SETTING_RESERVED_BASES.has(keyName.toLowerCase()) || !INDEXED_DOCUMENT_SETTING_KEY_NAME_RE.test(keyName)) {
    throw new Error('keyName must match ^[A-Za-z][A-Za-z0-9_-]{0,63}$');
  }
  return keyName;
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

  async checkGroupIndex(params?: FacadeParams | null): Promise<RpcResult> {
    const merged = stripNil(params);
    const groupAid = String(merged.group_aid ?? merged.group_id ?? '').trim();
    if (!groupAid) throw new Error('group_aid is required');
    const clientAny = this.client as any;
    const stale = typeof clientAny.isGroupIndexStale === 'function'
      ? Boolean(clientAny.isGroupIndexStale(groupAid))
      : false;
    const remoteMeta = typeof clientAny.getGroupIndexRemoteMeta === 'function'
      ? clientAny.getGroupIndexRemoteMeta(groupAid) ?? {}
      : {};
    const localEtag = typeof clientAny.getGroupIndexLocalEtag === 'function'
      ? String(clientAny.getGroupIndexLocalEtag(groupAid) ?? '')
      : '';
    const remoteEtag = String(remoteMeta?.etag ?? '');
    const localFound = Boolean(localEtag);
    const remoteFound = Boolean(remoteEtag);
    const inSync = localFound && remoteFound && localEtag === remoteEtag;
    return {
      group_aid: groupAid,
      local_found: localFound,
      remote_found: remoteFound,
      local_etag: localEtag,
      remote_etag: remoteEtag,
      in_sync: inSync,
      needs_update: Boolean(stale || (remoteFound && !inSync)),
      last_modified: remoteMeta?.last_modified,
      status: remoteFound ? 200 : 404,
      cached: true,
    };
  }

  async getGroupIndex(params?: FacadeParams | null): Promise<RpcResult> {
    const merged = stripNil(params);
    const groupId = String(merged.group_id ?? '').trim();
    if (!groupId) throw new Error('group_id is required');
    const result = await this.getSettings({ group_id: groupId, keys: [GROUP_INDEX_KEY] });
    const groupAid = String((result as Record<string, any>).group_aid ?? groupId);
    let groupIndex: any = null;
    for (const item of (result as Record<string, any>).settings ?? []) {
      if (item?.key !== GROUP_INDEX_KEY) continue;
      groupIndex = item.value;
      break;
    }
    if (!groupIndex) {
      return { group_id: (result as Record<string, any>).group_id, group_aid: groupAid, group_index: null, meta: {}, entries: [] };
    }
    const parsed = parseGroupIndex(groupIndex);
    await this.verifyPulledGroupIndex(groupIndex, parsed);
    const etag = String(parsed.meta.etag ?? '');
    const settings = await this.hydrateGroupIndexSettings(groupId, groupAid, parsed.entries as any, etag, groupIndex);
    const clientAny = this.client as any;
    if (etag && typeof clientAny.markGroupIndexFresh === 'function') {
      clientAny.markGroupIndexFresh(groupAid, { etag });
    }
    return {
      group_id: (result as Record<string, any>).group_id,
      group_aid: groupAid,
      group_index: groupIndex,
      meta: parsed.meta as unknown as JsonValue,
      entries: parsed.entries as unknown as JsonValue,
      settings: settings as JsonValue,
    };
  }

  private async verifyPulledGroupIndex(groupIndex: unknown, parsed: { meta: Record<string, any>; entries: Array<Record<string, any>> }): Promise<void> {
    const signedBy = String(parsed.meta?.signed_by ?? '').trim();
    if (!signedBy) throw new Error('group.index signed_by is required');
    const clientAny = this.client as any;
    let signer = clientAny.currentAid?.aid === signedBy ? clientAny.currentAid : null;
    if (!signer && typeof clientAny.lookupPeer === 'function') {
      signer = await clientAny.lookupPeer(signedBy);
    }
    if (!signer) throw new Error(`group.index signer is unavailable: ${signedBy}`);
    const verified = await verifyGroupIndex(groupIndex as any, signer);
    if (!verified.ok) throw new Error(verified.error.message || 'group.index verification failed');
    if (!verified.data.valid) throw new Error(`group.index verification failed: ${verified.data.reason || 'invalid signature'}`);
  }

  async updateGroupIndex(params?: FacadeParams | null): Promise<RpcResult> {
    const merged = stripNil(params);
    const groupId = String(merged.group_id ?? '').trim();
    const settings = merged.settings;
    if (!groupId) throw new Error('group_id is required');
    if (!settings || typeof settings !== 'object' || Array.isArray(settings) || Object.keys(settings as Record<string, unknown>).length === 0) {
      throw new Error('settings must be a non-empty object');
    }
    const signer = merged.signer ?? (this.client as any).currentAid;
    if (!signer) throw new Error('signer is required');
    const lastModified = Math.trunc(Number(merged.last_modified ?? Date.now()));
    const maxAttempts = Math.max(1, Math.trunc(Number(merged.max_attempts ?? 2)));

    let lastError: unknown = null;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const current = await this.getSettings({ group_id: groupId, keys: [GROUP_INDEX_KEY] });
      const groupAid = String((current as Record<string, any>).group_aid ?? groupId);
      let currentIndex: unknown = null;
      let expectedEtag = '';
      for (const item of (current as Record<string, any>).settings ?? []) {
        if (item?.key !== GROUP_INDEX_KEY) continue;
        currentIndex = item.value;
        if (currentIndex) expectedEtag = String(parseGroupIndex(currentIndex as any).meta.etag ?? '');
        break;
      }
      const signedSettings = await prepareGroupSettingsWithIndex({
        groupAid,
        settings: settings as Record<string, unknown>,
        signer: signer as any,
        lastModified,
        baseIndex: currentIndex as any,
      });
      try {
        const result = await this.setSettings({
          group_id: groupId,
          settings: signedSettings as JsonValue,
          expected_index_etag: expectedEtag,
        });
        const pushedEtag = String(parseGroupIndex((signedSettings as Record<string, unknown>)[GROUP_INDEX_KEY] as any).meta.etag ?? '');
        const clientAny = this.client as any;
        if (pushedEtag && typeof clientAny.markGroupIndexFresh === 'function') {
          clientAny.markGroupIndexFresh(groupAid, { etag: pushedEtag });
        }
        if (typeof clientAny.cacheGroupIndexSettings === 'function') {
          const parsed = parseGroupIndex((signedSettings as Record<string, unknown>)[GROUP_INDEX_KEY] as any);
          await clientAny.cacheGroupIndexSettings(groupAid, settings as Record<string, unknown>, {
            entries: parsed.entries,
            etag: pushedEtag,
            groupIndex: (signedSettings as Record<string, unknown>)[GROUP_INDEX_KEY],
          });
        }
        return result;
      } catch (exc) {
        if (!String((exc as Error)?.message ?? exc).includes('etag conflict')) throw exc;
        lastError = exc;
      }
    }
    if (lastError) throw lastError;
    throw new Error('updateGroupIndex failed');
  }

  private async getIndexedSettings(groupId: string, keys: string[]): Promise<{ groupId: string; settings: Record<string, any> }> {
    const clientAny = this.client as any;
    if (typeof clientAny.getGroupIndexCachedSettings === 'function') {
      const cached = await clientAny.getGroupIndexCachedSettings(groupId, keys);
      if (cached && typeof cached === 'object') return { groupId, settings: cached };
    }
    const result = await this.getSettings({ group_id: groupId, keys });
    const resultMap = result as Record<string, any>;
    const settings = settingsToMap(result);
    if (typeof clientAny.cacheGroupIndexSettings === 'function') {
      const groupAid = String(resultMap.group_aid ?? groupId);
      await clientAny.cacheGroupIndexSettings(groupAid, settings);
      if (groupAid !== groupId) {
        await clientAny.cacheGroupIndexSettings(groupId, settings);
      }
    }
    return { groupId: String(resultMap.group_id ?? groupId), settings };
  }

  private async hydrateGroupIndexSettings(
    groupId: string,
    groupAid: string,
    entries: Array<Record<string, any>>,
    etag: string,
    groupIndex?: unknown,
  ): Promise<Record<string, any>> {
    const keys = entries
      .filter((item) => String(item.source ?? 'db') === 'db' && String(item.key ?? ''))
      .map((item) => String(item.key));
    if (keys.length === 0) return {};
    const clientAny = this.client as any;
    let cached: Record<string, any> = {};
    let missing = [...keys];
    if (typeof clientAny.getGroupIndexCachedSettingsByEntries === 'function') {
      const value = await clientAny.getGroupIndexCachedSettingsByEntries(groupAid, keys, entries);
      cached = { ...(value?.cached ?? {}) };
      missing = [...(value?.missing ?? [])].map((item) => String(item));
    }
    let fetched: Record<string, any> = {};
    if (missing.length > 0) {
      fetched = settingsToMap(await this.getSettings({ group_id: groupId, keys: missing }));
    }
    const settings = { ...cached, ...fetched };
    if (typeof clientAny.cacheGroupIndexSettings === 'function') {
      await clientAny.cacheGroupIndexSettings(groupAid, settings, { entries, etag, groupIndex });
    }
    return settings;
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

  private documentSettingResult(groupId: string, keyName: string, settings: Record<string, any>): RpcResult {
    const contentKey = `${keyName}.content`;
    const attachmentsKey = `${keyName}.attachments`;
    return {
      group_id: groupId,
      setting: {
        group_id: groupId,
        key_name: keyName,
        content: settings[contentKey] ?? '',
        attachments: settings[attachmentsKey] ?? [],
        updated_by: settings[`${contentKey}.updated_by`] ?? '',
        updated_at: settings[`${contentKey}.updated_at`] ?? 0,
      }
    };
  }

  async getSettingWithIndex(params?: FacadeParams | null): Promise<RpcResult> {
    const merged = params || {};
    const groupId = merged.group_id;
    if (!groupId) throw new Error('group_id is required');

    const keyName = indexedDocumentKeyName(merged);
    const { groupId: resultGroupId, settings } = await this.getIndexedSettings(
      String(groupId),
      [`${keyName}.content`, `${keyName}.attachments`],
    );
    return this.documentSettingResult(resultGroupId, keyName, settings);
  }

  async updateSettingWithIndex(params?: FacadeParams | null): Promise<RpcResult> {
    const merged = params || {};
    const groupId = merged.group_id;

    if (!groupId) throw new Error('group_id is required');
    const keyName = indexedDocumentKeyName(merged);
    if (!('content' in merged)) throw new Error('content is required');

    const content = merged.content;
    const attachments = merged.attachments ?? [];
    const settingsUpdate: Record<string, any> = { [`${keyName}.content`]: content };
    if ('attachments' in merged) {
      settingsUpdate[`${keyName}.attachments`] = attachments;
    }

    const result = await this.updateGroupIndex(indexUpdateParams(groupId, settingsUpdate, merged));
    const resultGroupId = String((result as Record<string, any>).group_id ?? groupId);

    return {
      group_id: resultGroupId,
      setting: {
        group_id: resultGroupId,
        key_name: keyName,
        content,
        attachments,
        updated_by: '',
        updated_at: 0
      }
    };
  }

  async getAnnouncement(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 getSettings
    const merged = params || {};
    const result = await this.getSettingWithIndex({ ...merged, keyName: 'announcement' });
    const resultMap = result as Record<string, any>;
    const setting = resultMap.setting;
    return {
      group_id: resultMap.group_id,
      announcement: {
        group_id: setting.group_id,
        content: setting.content,
        attachments: setting.attachments,
        updated_by: setting.updated_by,
        updated_at: setting.updated_at
      }
    };
  }

  async updateAnnouncement(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 setSettings
    const merged = params || {};
    const result = await this.updateSettingWithIndex({ ...merged, keyName: 'announcement' });
    const resultMap = result as Record<string, any>;
    const setting = resultMap.setting;
    return {
      group_id: resultMap.group_id,
      announcement: {
        group_id: resultMap.group_id,
        content: setting.content,
        attachments: setting.attachments
      }
    };
  }

  async getRules(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 getSettings
    const merged = params || {};
    const result = await this.getSettingWithIndex({ ...merged, keyName: 'rules' });
    const resultMap = result as Record<string, any>;
    const setting = resultMap.setting;
    return {
      group_id: resultMap.group_id,
      rules: {
        group_id: setting.group_id,
        content: setting.content,
        attachments: setting.attachments,
        updated_by: setting.updated_by,
        updated_at: setting.updated_at
      }
    };
  }

  async updateRules(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 setSettings
    const merged = params || {};
    const result = await this.updateSettingWithIndex({ ...merged, keyName: 'rules' });
    const resultMap = result as Record<string, any>;
    const setting = resultMap.setting;
    return {
      group_id: resultMap.group_id,
      rules: {
        group_id: resultMap.group_id,
        content: setting.content,
        attachments: setting.attachments
      }
    };
  }

  async getJoinRequirements(params?: FacadeParams | null): Promise<RpcResult> {
    // 便利方法：基于 getSettings
    const merged = params || {};
    const groupId = merged.group_id;
    if (!groupId) throw new Error('group_id is required');

    const { groupId: resultGroupId, settings } = await this.getIndexedSettings(
      String(groupId),
      ['join.mode', 'join.question', 'join.auto_approve_patterns', 'join.max_pending', 'join.attachments'],
    );
    return {
      group_id: resultGroupId,
      join_requirements: {
        group_id: resultGroupId,
        mode: settings['join.mode'] || 'open',
        question: settings['join.question'] || '',
        auto_approve_patterns: settings['join.auto_approve_patterns'] || [],
        max_pending: settings['join.max_pending'] || 100,
        attachments: settings['join.attachments'] || [],
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
    if ('attachments' in merged) settingsUpdate['join.attachments'] = merged.attachments;

    if (Object.keys(settingsUpdate).length === 0) {
      throw new Error('at least one field to update is required');
    }

    const result = await this.updateGroupIndex(indexUpdateParams(groupId, settingsUpdate, merged));

    return {
      group_id: (result as Record<string, any>).group_id,
      join_requirements: {
        group_id: (result as Record<string, any>).group_id,
        mode: merged.mode,
        question: merged.question,
        auto_approve_patterns: merged.auto_approve_patterns,
        max_pending: merged.max_pending,
        attachments: merged.attachments || []
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
