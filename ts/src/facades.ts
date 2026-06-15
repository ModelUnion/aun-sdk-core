import { StorageError } from './storage/errors.js';
import type { RpcParams, RpcResult } from './types.js';

export interface FacadeRpcClient {
  call(method: string, params?: RpcParams): Promise<RpcResult>;
}

export type FacadeParams = RpcParams;

interface GroupResourcesAidStore {
  load(aid: string): unknown | Promise<unknown>;
}

type GroupResourcesSignerClient = FacadeRpcClient & {
  connect(options?: FacadeParams): Promise<void>;
  close(): Promise<void> | void;
  aid?: string | null;
  currentAid?: { aid?: string | null } | null;
};

type GroupResourcesClientFactory = (aid: unknown) => GroupResourcesSignerClient;

interface GroupResourcesOptions {
  aidStore?: GroupResourcesAidStore;
  aid_store?: GroupResourcesAidStore;
  clientFactory?: GroupResourcesClientFactory;
  client_factory?: GroupResourcesClientFactory;
  connectOptions?: FacadeParams;
  connect_options?: FacadeParams;
  sign_as?: unknown;
  signAs?: unknown;
  [key: string]: unknown;
}

const DEFAULT_SIGNER_CONNECT_OPTIONS: FacadeParams = {
  connection_kind: 'short',
  short_ttl_ms: 30000,
  heartbeat_interval: 0,
};

const GROUP_STORAGE_BASELINE_DIRS = ['announce', 'public', 'archive', 'memberdata'] as const;
const GROUP_STORAGE_ALLOWED_PENDING_RPCS = new Set([
  'storage.put_object',
  'storage.create_upload_session',
  'storage.complete_upload',
  'storage.delete_object',
  'storage.fs.mkdir',
  'storage.fs.rename',
  'storage.fs.remove',
  'storage.fs.mount',
  'storage.fs.unmount',
  'storage.issue_token',
  'storage.revoke_token',
  'storage.set_acl',
  'storage.remove_acl',
  'storage.set_visibility',
]);
const GROUP_STORAGE_ALLOWED_CONFIRM_RPCS = new Set([
  'group.resources.confirm',
  'group.resources.confirm_mount',
]);
const GROUP_STORAGE_ALLOWED_COMPENSATION_RPCS = new Set([
  'storage.delete_object',
  'storage.fs.remove',
  'storage.fs.unmount',
  'storage.revoke_token',
  'storage.remove_acl',
  'storage.set_acl',
]);

export class GroupPendingOpsPartialFailure extends Error {
  readonly failedIndex: number;
  readonly failedOp: FacadeParams;
  readonly storageResults: FacadeParams;
  readonly opResults: RpcResult[];
  readonly compensationResults: FacadeParams;
  readonly compensationErrors: FacadeParams[];

  constructor(message: string, details: {
    failedIndex: number;
    failedOp: FacadeParams;
    storageResults: FacadeParams;
    opResults: RpcResult[];
    compensationResults: FacadeParams;
    compensationErrors: FacadeParams[];
    cause?: unknown;
  }) {
    super(message);
    this.name = 'GroupPendingOpsPartialFailure';
    this.failedIndex = details.failedIndex;
    this.failedOp = details.failedOp;
    this.storageResults = details.storageResults;
    this.opResults = details.opResults;
    this.compensationResults = details.compensationResults;
    this.compensationErrors = details.compensationErrors;
    if (details.cause !== undefined) {
      (this as Error & { cause?: unknown }).cause = details.cause;
    }
  }

  toJSON(): FacadeParams {
    return {
      failed_index: this.failedIndex,
      failed_op: this.failedOp,
      storage_results: this.storageResults,
      op_results: this.opResults,
      compensation_results: this.compensationResults,
      compensation_errors: this.compensationErrors,
    };
  }
}

export function stripNil(params: FacadeParams = {}): FacadeParams {
  const out: FacadeParams = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function asFacadeParams(value: unknown): FacadeParams {
  return isRecord(value) ? { ...(value as FacadeParams) } : {};
}

function stringValue(value: unknown): string {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function errorMessage(value: unknown): string {
  if (value instanceof Error) return value.message;
  return String(value || 'unknown error');
}

function memberdataLookupError(groupId: string, detail: string, cause?: unknown): StorageError {
  const error = new StorageError(
    `memberdata namespace lookup failed: ${detail}`,
    'ELOOKUP',
    groupId,
    { group_id: groupId, cause },
  );
  if (cause !== undefined) {
    (error as Error & { cause?: unknown }).cause = cause;
  }
  return error;
}

function normalizeStoragePath(value: unknown): string {
  return stringValue(value).replace(/^\/+/, '').replace(/\/+$/, '');
}

function clientAid(client: unknown): string {
  if (!isRecord(client)) return '';
  const direct = stringValue(client.aid);
  if (direct) return direct;
  const current = client.currentAid;
  if (isRecord(current)) {
    const value = stringValue(current.aid);
    if (value) return value;
  }
  return stringValue(client._aid);
}

function sameAid(left: string, right: string): boolean {
  return Boolean(left && right && left.trim().toLowerCase() === right.trim().toLowerCase());
}

function resultPathValue(source: unknown, path: string): unknown {
  let current: unknown = source;
  for (const part of path.split('.')) {
    if (!part) continue;
    if (Array.isArray(current)) {
      const index = Number(part);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) return undefined;
      current = current[index];
    } else if (isRecord(current)) {
      current = current[part];
    } else {
      return undefined;
    }
    if (current === undefined || current === null) return undefined;
  }
  return current;
}

function extractLoadedAid(result: unknown, signAs: string): unknown {
  if (!isRecord(result) || result.ok !== true || !isRecord(result.data)) {
    const error = isRecord(result) && isRecord(result.error) ? result.error : {};
    throw new Error(stringValue(error.message) || `signer identity not found: ${signAs}`);
  }
  const aid = result.data.aid;
  if (!aid) throw new Error(`signer identity missing AID object: ${signAs}`);
  return aid;
}

function firstResultId(result: RpcResult): string {
  if (!isRecord(result)) return '';
  for (const key of ['folder_id', 'node_id', 'resource_id', 'object_id', 'id']) {
    const value = result[key];
    if (typeof value === 'string' && value.trim()) return value;
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  const node = result.node;
  if (isRecord(node)) {
    for (const key of ['folder_id', 'node_id', 'resource_id', 'object_id', 'id']) {
      const value = node[key];
      if (typeof value === 'string' && value.trim()) return value;
      if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    }
  }
  return '';
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
    return this.call('message.thought.put', params);
  }

  get(params?: FacadeParams): Promise<RpcResult> {
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

export class GroupResourcesFacade extends RpcFacade {
  private readonly groupAidCache = new Map<string, string>();

  private async createSignerClient(aidObj: unknown, options: GroupResourcesOptions): Promise<GroupResourcesSignerClient> {
    const factory = options.clientFactory ?? options.client_factory;
    if (factory) return factory(aidObj);
    const mod = await import('./client.js');
    return new mod.AUNClient(aidObj as never) as unknown as GroupResourcesSignerClient;
  }

  private async signerFor(
    signAs: string,
    options: GroupResourcesOptions,
    cache: Map<string, GroupResourcesSignerClient>,
  ): Promise<FacadeRpcClient> {
    const store = options.aidStore ?? options.aid_store;
    if (!signAs || sameAid(clientAid(this.client), signAs)) return this.client;
    if (!store) throw new Error(`group resources operation requires aidStore to sign as ${signAs}`);
    const cached = cache.get(signAs);
    if (cached) return cached;
    const loaded = await store.load(signAs);
    const aidObj = extractLoadedAid(loaded, signAs);
    const signer = await this.createSignerClient(aidObj, options);
    await signer.connect(options.connectOptions ?? options.connect_options ?? DEFAULT_SIGNER_CONNECT_OPTIONS);
    cache.set(signAs, signer);
    return signer;
  }

  private resourceCall(name: string, params?: FacadeParams): Promise<RpcResult> {
    return this.call(`group.resources.${name}`, params);
  }

  /**
   * 成员挂载区透明路由：memberdata/{self_aid}/{rest} → 成员自己 storage 空间。
   *
   * 协议约定（group-storage 设计 §4.4/§5.3）：成员挂载区的源固定指向成员自己空间的
   * {self_aid}/{group_aid}/{rest}。命中本人槽位时返回
   * [owner_aid=self_aid, object_key={self_aid}/{group_aid}/{rest}]；
   * 他人槽位或群自有区返回 null（不路由，由调用方走原 group.resources 流程）。
   */
  private async memberdataNamespaceKey(params: FacadeParams): Promise<string> {
    const explicit = stringValue(params.group_aid ?? params.groupAid);
    if (explicit) return explicit;
    const groupId = stringValue(params.group_id ?? params.groupId);
    if (!groupId) return '';
    const cached = this.groupAidCache.get(groupId);
    if (cached) return cached;
    let result: RpcResult;
    try {
      result = await this.client.call('group.get', stripNil({ group_id: groupId }));
    } catch (cause) {
      throw memberdataLookupError(groupId, errorMessage(cause), cause);
    }
    const group = isRecord(result) ? result.group : undefined;
    const groupAid = isRecord(group) ? stringValue(group.group_aid) : '';
    if (!groupAid) throw memberdataLookupError(groupId, 'group_aid missing', result);
    this.groupAidCache.set(groupId, groupAid);
    return groupAid;
  }

  private resolveMemberdataTarget(groupKey: unknown, resourcePath: unknown): [string, string] | null {
    const path = stringValue(resourcePath).replace(/^\/+/, '').replace(/\/+$/, '');
    const parts = path.split('/');
    if (parts.length < 2 || parts[0].toLowerCase() !== 'memberdata') return null;
    const slotAid = parts[1].trim();
    const selfAid = clientAid(this.client);
    if (!selfAid || slotAid.toLowerCase() !== selfAid.toLowerCase()) return null;
    const namespaceKey = stringValue(groupKey).replace(/^\/+/, '').replace(/\/+$/, '');
    if (!namespaceKey) return null;
    const rest = parts.slice(2).join('/').replace(/^\/+/, '').replace(/\/+$/, '');
    const sourceRoot = `${selfAid}/${namespaceKey}`;
    const objectKey = rest ? `${sourceRoot}/${rest}` : sourceRoot;
    return [selfAid, objectKey];
  }

  private isMemberdataSelfPath(resourcePath: unknown): boolean {
    const path = normalizeStoragePath(resourcePath);
    if (!path) return false;
    const parts = path.split('/');
    if (parts.length < 2 || parts[0].toLowerCase() !== 'memberdata') return false;
    return sameAid(stringValue(parts[1]), clientAid(this.client));
  }

  private async resolveMemberdataTargetForParams(params: FacadeParams): Promise<[string, string] | null> {
    if (!this.isMemberdataSelfPath(params.resource_path)) return null;
    return this.resolveMemberdataTarget(await this.memberdataNamespaceKey(params), params.resource_path);
  }

  private baselineDirs(params: FacadeParams): string[] {
    const raw = params.paths ?? params.baseline_dirs ?? params.baselineDirs ?? params.directories ?? params.dirs;
    if (!Array.isArray(raw)) return [...GROUP_STORAGE_BASELINE_DIRS];
    const dirs = raw.map((item) => normalizeStoragePath(item)).filter(Boolean);
    return dirs.length > 0 ? dirs : [...GROUP_STORAGE_BASELINE_DIRS];
  }

  async put(params?: FacadeParams): Promise<RpcResult> {
    const merged = stripNil(params);
    const target = await this.resolveMemberdataTargetForParams(merged);
    if (target) {
      const [ownerAid, objectKey] = target;
      const storageParams: FacadeParams = {
        owner_aid: ownerAid,
        object_key: objectKey,
        content: merged.content ?? '',
        overwrite: merged.overwrite ?? true,
      };
      for (const key of ['content_type', 'content_encoding', 'metadata', 'expected_version'] as const) {
        if (merged[key] !== undefined && merged[key] !== null) storageParams[key] = merged[key];
      }
      return this.client.call('storage.put_object', stripNil(storageParams));
    }
    return this.resourceCall('put', params);
  }

  async createFolder(params?: FacadeParams): Promise<RpcResult> {
    const merged = stripNil(params);
    const target = await this.resolveMemberdataTargetForParams(merged);
    if (target) {
      const [ownerAid, path] = target;
      const parents = merged.mkdirs ?? merged.parents ?? true;
      return this.client.call('storage.fs.mkdir', stripNil({
        owner_aid: ownerAid,
        path,
        parents: Boolean(parents),
      }));
    }
    return this.resourceCall('create_folder', params);
  }

  listChildren(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('list_children', params);
  }

  rename(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('rename', params);
  }

  move(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('move', params);
  }

  mountObject(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('mount_object', params);
  }

  unmount(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('unmount', params);
  }

  resolvePath(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('resolve_path', params);
  }

  get(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('get', params);
  }

  list(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('list', params);
  }

  update(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('update', params);
  }

  getAccess(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('get_access', params);
  }

  resolveAccessTicket(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('resolve_access_ticket', params);
  }

  async delete(params?: FacadeParams): Promise<RpcResult> {
    const merged = stripNil(params);
    const target = await this.resolveMemberdataTargetForParams(merged);
    if (target) {
      const [ownerAid, path] = target;
      return this.client.call('storage.fs.remove', stripNil({
        owner_aid: ownerAid,
        path,
        recursive: Boolean(merged.recursive ?? false),
      }));
    }
    return this.resourceCall('delete', params);
  }

  namespaceReady(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('namespace_ready', params);
  }

  confirm(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('confirm', params);
  }

  confirmMount(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('confirm_mount', params);
  }

  getDf(params?: FacadeParams): Promise<RpcResult> {
    return this.resourceCall('get_df', params);
  }

  async initializeNamespace(params: FacadeParams = {}, options: GroupResourcesOptions = {}): Promise<RpcResult> {
    const groupAid = stringValue(params.group_aid ?? params.groupAid ?? params.owner_aid ?? params.owner);
    const groupId = stringValue(params.group_id ?? params.groupId);
    if (!groupAid) throw new Error('initializeNamespace requires group_aid');
    if (!groupId) throw new Error('initializeNamespace requires group_id');
    const bucket = stringValue(params.bucket) || 'default';
    const signAs = stringValue(params.sign_as ?? params.signAs ?? options.sign_as ?? options.signAs ?? groupAid);
    const dirs = this.baselineDirs(params);
    const folderIds: FacadeParams = {};
    const signerCache = new Map<string, GroupResourcesSignerClient>();

    try {
      const storageClient = await this.signerFor(signAs, options, signerCache);
      for (const dir of dirs) {
        const mkdirParams: FacadeParams = {
          owner_aid: groupAid,
          bucket,
          path: dir,
          parents: true,
        };
        const result = await storageClient.call('storage.fs.mkdir', stripNil(mkdirParams));
        const folderId = firstResultId(result);
        if (folderId) folderIds[dir] = folderId;
        if (dir === 'public') {
          await storageClient.call('storage.set_visibility', stripNil({
            owner_aid: groupAid,
            bucket,
            path: dir,
            visibility: 'public',
          }));
        }
      }

      return storageClient.call('group.resources.namespace_ready', {
        group_id: groupId,
        group_aid: groupAid,
        folder_ids: folderIds,
      });
    } finally {
      await Promise.all([...signerCache.values()].map((signer) => signer.close()));
    }
  }

  async executePendingOps(plan: FacadeParams = {}, options: GroupResourcesOptions = {}): Promise<RpcResult> {
    const pendingOpsRaw = plan.pending_ops ?? plan.pendingOps;
    if (pendingOpsRaw !== undefined && pendingOpsRaw !== null && !Array.isArray(pendingOpsRaw)) {
      throw new Error('executePendingOps requires pending_ops array');
    }
    const pendingOps = Array.isArray(pendingOpsRaw) ? pendingOpsRaw : [];
    const confirmRpc = stringValue(plan.confirm_rpc ?? plan.confirmRpc) || 'group.resources.confirm';
    if (!GROUP_STORAGE_ALLOWED_CONFIRM_RPCS.has(confirmRpc)) {
      throw new Error(`unsupported confirm rpc: ${confirmRpc}`);
    }
    for (let index = 0; index < pendingOps.length; index += 1) {
      const rawOp = pendingOps[index];
      if (!isRecord(rawOp)) throw new Error(`pending op ${index} must be an object`);
      const op = asFacadeParams(rawOp);
      const rpc = stringValue(op.rpc ?? op.method);
      if (!rpc) throw new Error(`pending op ${index} missing rpc`);
      if (rpc && !GROUP_STORAGE_ALLOWED_PENDING_RPCS.has(rpc)) {
        throw new Error(`unsupported pending rpc: ${rpc}`);
      }
      const compensation = op.compensation;
      if (isRecord(compensation)) {
        const compensationRpc = stringValue(compensation.rpc ?? compensation.method);
        if (compensationRpc && !GROUP_STORAGE_ALLOWED_COMPENSATION_RPCS.has(compensationRpc)) {
          throw new Error(`unsupported compensation rpc: ${compensationRpc}`);
        }
      }
    }
    const defaultSignAs = stringValue(options.sign_as ?? options.signAs ?? plan.sign_as ?? plan.signAs ?? plan.group_aid ?? plan.groupAid);
    const results: FacadeParams = {};
    const opResults: RpcResult[] = [];
    const successfulOps: Array<{ op: FacadeParams; confirmKey: string; index: number }> = [];
    let lastConfirmKey = '';
    let lastResult: RpcResult | undefined;
    const signerCache = new Map<string, GroupResourcesSignerClient>();

    const runCompensations = async (): Promise<{ compensationResults: FacadeParams; compensationErrors: FacadeParams[] }> => {
      if (stringValue(plan.failure_policy ?? plan.failurePolicy) !== 'compensate_successful_ops_before_confirm') {
        return { compensationResults: {}, compensationErrors: [] };
      }
      const compensationResults: FacadeParams = {};
      const compensationErrors: FacadeParams[] = [];
      for (const item of [...successfulOps].reverse()) {
        const compensation = item.op.compensation;
        if (!isRecord(compensation)) continue;
        const dependsOn = stringValue(compensation.depends_on ?? compensation.dependsOn) || item.confirmKey;
        if (dependsOn && !(dependsOn in results)) continue;
        const params = asFacadeParams(compensation.params);
        const mappings = compensation.params_from_results ?? compensation.paramsFromResults;
        if (isRecord(mappings)) {
          for (const [paramKey, resultPath] of Object.entries(mappings)) {
            const value = resultPathValue({ ...results, results, storage_results: results, op_results: opResults }, stringValue(resultPath));
            if (value !== undefined && value !== null) {
              (params as Record<string, unknown>)[paramKey] = value;
            }
          }
        }
        const rpc = stringValue(compensation.rpc ?? compensation.method);
        if (!rpc) continue;
        const signAs = stringValue(compensation.sign_as ?? compensation.signAs ?? item.op.sign_as ?? item.op.signAs ?? defaultSignAs);
        const confirmKey = stringValue(compensation.confirm_key ?? compensation.confirmKey) || `compensate:${item.confirmKey}`;
        try {
          const client = await this.signerFor(signAs, options, signerCache);
          compensationResults[confirmKey] = await client.call(rpc, stripNil(params));
        } catch (exc) {
          compensationErrors.push({ confirm_key: confirmKey, rpc, error: String(exc instanceof Error ? exc.message : exc) });
        }
      }
      return { compensationResults, compensationErrors };
    };

    try {
      for (let index = 0; index < pendingOps.length; index += 1) {
        if (!isRecord(pendingOps[index])) {
          throw new Error(`pending op ${index} must be an object`);
        }
        const op = asFacadeParams(pendingOps[index]);
        const rpc = stringValue(op.rpc ?? op.method);
        if (!rpc) throw new Error(`pending op ${index} missing rpc`);
        const opParams = asFacadeParams(op.params);
        const opSignAs = stringValue(op.sign_as ?? op.signAs ?? defaultSignAs);
        const storageClient = await this.signerFor(opSignAs, options, signerCache);
        const confirmKey = stringValue(op.confirm_key ?? op.confirmKey) || `op_${index}`;
        let result: RpcResult;
        try {
          result = await storageClient.call(rpc, stripNil(opParams));
        } catch (exc) {
          const compensation = await runCompensations();
          if (successfulOps.length === 0 && Object.keys(compensation.compensationResults).length === 0 && compensation.compensationErrors.length === 0) {
            throw exc;
          }
          throw new GroupPendingOpsPartialFailure(
            exc instanceof Error ? exc.message : String(exc),
            {
              failedIndex: index,
              failedOp: op,
              storageResults: results,
              opResults,
              compensationResults: compensation.compensationResults,
              compensationErrors: compensation.compensationErrors,
              cause: exc,
            },
          );
        }
        opResults.push(result);
        results[confirmKey] = result;
        successfulOps.push({ op, confirmKey, index });
        lastConfirmKey = confirmKey;
        lastResult = result;
      }

      const baseConfirmParams = asFacadeParams(plan.confirm_params ?? plan.confirmParams);
      const confirmParams: FacadeParams = {
        ...baseConfirmParams,
        group_id: baseConfirmParams.group_id ?? baseConfirmParams.groupId ?? plan.group_id ?? plan.groupId,
        op_id: baseConfirmParams.op_id ?? baseConfirmParams.opId ?? plan.op_id ?? plan.opId,
        op_results: opResults,
        storage_results: results,
        storage_result: lastResult,
        confirm_key: baseConfirmParams.confirm_key ?? baseConfirmParams.confirmKey ?? plan.confirm_key ?? plan.confirmKey ?? lastConfirmKey,
      };
      const confirmSignAs = stringValue(
        plan.confirm_sign_as
        ?? plan.confirmSignAs
        ?? plan.sign_as
        ?? plan.signAs
        ?? plan.group_aid
        ?? plan.groupAid
        ?? defaultSignAs,
      );
      const confirmClient = await this.signerFor(confirmSignAs, options, signerCache);
      const confirmResult = await confirmClient.call(confirmRpc, stripNil(confirmParams));
      return {
        storage_results: results,
        confirmed: confirmResult,
      };
    } finally {
      await Promise.all([...signerCache.values()].map((signer) => signer.close()));
    }
  }
}

export class GroupThoughtFacade extends RpcFacade {
  put(params?: FacadeParams): Promise<RpcResult> {
    return this.call('group.thought.put', params);
  }

  get(params?: FacadeParams): Promise<RpcResult> {
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
  send(params?: FacadeParams): Promise<RpcResult> { return this.call('group.send', params); }
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
