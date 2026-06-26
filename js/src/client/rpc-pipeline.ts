import { normalizeSlotId, slotIsolationKey } from '../config.js';
import { ClientSignatureError, ConnectionError, PermissionError, StateError, ValidationError } from '../errors.js';
import { normalizeGroupId } from '../group-id.js';
import { validateAIDFormat, validateGroupIDFormat } from '../validators.js';
import { p1363ToDer, pemToArrayBuffer, uint8ToBase64 } from '../crypto.js';
import {
  isJsonObject,
  type JsonObject,
  type JsonValue,
  type RpcParams,
  type RpcResult,
} from '../types.js';
import type { ClientRuntime } from './runtime.js';

const INTERNAL_ONLY_METHODS = new Set([
  'auth.login1',
  'auth.aid_login1',
  'auth.login2',
  'auth.aid_login2',
  'auth.connect',
  'auth.refresh_token',
  'initialize',
]);

const REMOVED_E2EE_METHODS = new Set([
  'group.rotate_epoch',
]);

const PROTECTED_HEADERS_METHODS = new Set([
  'message.send',
  'group.send',
  'message.thought.put',
  'group.thought.put',
]);

const SIGNED_METHODS = new Set([
  'message.send',
  'message.v2.put_peer_pk', 'message.v2.bootstrap',
  'message.v2.group_bootstrap', 'message.v2.pull',
  'message.v2.ack',
  'group.send',
  'group.v2.put_group_pk', 'group.v2.bootstrap',
  'group.v2.send', 'group.v2.pull', 'group.v2.ack',
  'group.v2.propose_state', 'group.v2.confirm_state',
  'group.v2.get_proposal',
  'group.kick', 'group.add_member',
  'group.leave', 'group.remove_member', 'group.update_rules',
  'group.update', 'group.update_announcement',
  'group.update_join_requirements', 'group.set_role',
  'group.transfer_owner', 'group.bind_group_aid', 'group.renew_group_aid', 'group.complete_transfer',
  'group.review_join_request',
  'group.batch_review_join_request',
  'group.request_join', 'group.use_invite_code',
  'group.thought.put',
  'message.thought.put',
  'group.set_settings',
  'group.fs.mkdir', 'group.fs.rm', 'group.fs.cp', 'group.fs.mv',
  'group.fs.set_acl', 'group.fs.remove_acl',
  'group.fs.mount', 'group.fs.umount',
  'group.fs.check_upload', 'group.fs.create_upload_session',
  'group.fs.complete_upload', 'group.fs.create_download_ticket',
  'storage.put_object', 'storage.delete_object', 'storage.get_by_share',
  'storage.create_share_link', 'storage.revoke_share_link',
  'storage.create_upload_session', 'storage.complete_upload',
  'storage.create_folder', 'storage.rename_folder', 'storage.move_folder',
  'storage.delete_folder', 'storage.move_object', 'storage.copy_object',
  'storage.batch_delete', 'storage.set_object_meta', 'storage.append_object',
  'storage.set_acl', 'storage.remove_acl', 'storage.set_visibility',
  'storage.check_access',
  'storage.issue_token', 'storage.revoke_token',
  'storage.create_symlink', 'storage.atomic_repoint',
  'storage.rename_symlink', 'storage.delete_symlink',
  'storage.fs.mkdir', 'storage.fs.remove', 'storage.fs.rename', 'storage.fs.copy',
  'storage.fs.mount', 'storage.fs.approve', 'storage.fs.reject', 'storage.fs.unmount',
  'storage.fs.invalidate_membership',
  'storage.volume.create', 'storage.volume.renew', 'storage.volume.expire_due',
  'collab.create', 'collab.commit', 'collab.clone',
  'collab.prune', 'collab.unregister',
  'collab.tag.create', 'collab.tag.restore',
  'collab.tag.rm', 'collab.tag.prune',
  'group.commit_state',
  'group.ban', 'group.unban',
  'group.dissolve', 'group.suspend', 'group.resume',
]);

const PULL_GATE_STALE_MS = 30000;
const NON_IDEMPOTENT_TIMEOUT = 35;
const NON_IDEMPOTENT_METHODS = new Set([
  'message.send', 'group.send', 'group.create', 'group.invite',
  'group.kick', 'group.remove_member', 'group.leave', 'group.dissolve',
  'group.update_name', 'group.update_avatar', 'group.update_announcement',
  'group.update_settings',
  'storage.put_object', 'storage.delete_object',
  'storage.create_share_link', 'storage.revoke_share_link',
  'storage.get_by_share',
  'storage.create_upload_session', 'storage.complete_upload',
  'storage.create_folder', 'storage.rename_folder', 'storage.move_folder',
  'storage.delete_folder', 'storage.move_object', 'storage.copy_object',
  'storage.batch_delete', 'storage.set_object_meta', 'storage.append_object',
  'storage.set_acl', 'storage.remove_acl', 'storage.set_visibility',
  'storage.issue_token', 'storage.revoke_token',
  'storage.create_symlink', 'storage.atomic_repoint',
  'storage.rename_symlink', 'storage.delete_symlink',
  'storage.fs.mkdir', 'storage.fs.remove', 'storage.fs.rename', 'storage.fs.copy',
  'storage.fs.mount', 'storage.fs.approve', 'storage.fs.reject', 'storage.fs.unmount',
  'storage.fs.invalidate_membership',
  'storage.volume.create', 'storage.volume.renew', 'storage.volume.expire_due',
  'auth.create_aid', 'auth.renew_cert', 'auth.rekey',
  'message.thought.put', 'group.thought.put',
  'group.add_member', 'group.bind_group_aid', 'group.complete_transfer',
  'group.fs.mkdir', 'group.fs.rm', 'group.fs.cp', 'group.fs.mv',
  'group.fs.set_acl', 'group.fs.remove_acl',
  'group.fs.mount', 'group.fs.umount',
  'group.fs.check_upload', 'group.fs.create_upload_session',
  'group.fs.complete_upload', 'group.fs.create_download_ticket',
  'collab.create', 'collab.commit', 'collab.clone',
  'collab.prune', 'collab.unregister',
  'collab.tag.create', 'collab.tag.restore',
  'collab.tag.rm', 'collab.tag.prune',
]);

export interface RpcPreflightResult {
  params: RpcParams;
  rpcBackground: boolean;
}

export class RpcPipeline {
  private readonly runtime: ClientRuntime;

  constructor(runtime: ClientRuntime) {
    this.runtime = runtime;
  }

  async call(method: string, params?: RpcParams): Promise<RpcResult> {
    const client = this.runtime.client;
    const tStart = Date.now();
    client._clientLog.debug(`call enter: method=${method}`);
    try {
      const result = await this.callImpl(method, params);
      client._clientLog.debug(`call exit: elapsed=${Date.now() - tStart}ms method=${method}`);
      return result;
    } catch (err) {
      client._clientLog.debug(`call exit (error): elapsed=${Date.now() - tStart}ms method=${method} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async callImpl(method: string, params?: RpcParams): Promise<RpcResult> {
    const client = this.runtime.client;
    const preflight = this.preflight(method, params);
    const p = preflight.params;
    const rpcBackground = preflight.rpcBackground;
    const runWithRpcPriority = async <T>(operation: () => Promise<T> | T): Promise<T> => {
      if (!rpcBackground) return await operation();
      return await client._withBackgroundRpc(operation);
    };
    const skipSendResultEnvelope = Boolean((p as Record<string, unknown>)._skip_send_result_envelope);
    delete (p as Record<string, unknown>)._skip_send_result_envelope;

    if (method === 'message.send') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await client._ensureV2SessionReady(
          'message.send',
          'V2 session not initialized; encrypted message.send requires V2 (V1 E2EE removed)',
        );
        client._clientLog.debug('call route: message.send -> V2 encrypted send');
        return await client._sendV2(String(p.to ?? ''), p.payload as Record<string, unknown> ?? {}, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: client._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        }) as RpcResult;
      }
      client._maybeAppendEchoTraceSend(p);
    }

    if (method === 'group.send') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await client._ensureV2SessionReady(
          'group.send',
          'V2 session not initialized; encrypted group.send requires V2 (V1 E2EE removed)',
        );
        client._clientLog.debug('call route: group.send -> V2 encrypted send');
        return await client._sendGroupV2(String(p.group_id ?? ''), p.payload as Record<string, unknown> ?? {}, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: client._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        }) as RpcResult;
      }
      client._maybeAppendEchoTraceSend(p);
    }

    if (method === 'group.thought.put') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await client._ensureV2SessionReady(
          'group.thought.put',
          'V2 session not initialized; encrypted group.thought.put requires V2 (V1 E2EE removed)',
        );
        client._clientLog.debug('call route: group.thought.put -> V2 encrypted put');
        return await client._putGroupThoughtEncryptedV2(p) as RpcResult;
      }
    }

    if (method === 'message.thought.put') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        await client._ensureV2SessionReady(
          'message.thought.put',
          'V2 session not initialized; encrypted message.thought.put requires V2 (V1 E2EE removed)',
        );
        client._clientLog.debug('call route: message.thought.put -> V2 encrypted put');
        return await client._putMessageThoughtEncryptedV2(p) as RpcResult;
      }
    }

    const pullGateKey = this.pullGateKeyForCall(method, p);
    if (pullGateKey) {
      return await this.runPullSerialized(pullGateKey, async () => {
        return await runWithRpcPriority(() => this.callImplInner(method, p, skipSendResultEnvelope));
      });
    }

    return await runWithRpcPriority(() => this.callImplInner(method, p, skipSendResultEnvelope));
  }

  private async callImplInner(method: string, p: RpcParams, skipSendResultEnvelope = false): Promise<RpcResult> {
    const client = this.runtime.client;
    if (method === 'message.pull') {
      await client._ensureV2SessionReady('message.pull');
      client._clientLog.debug('call route: message.pull -> V2 pull');
      const messages = await client._pullV2(Number(p.after_seq ?? 0) || 0, Number(p.limit ?? 50) || 50, { force: p.force === true });
      return { messages } as RpcResult;
    }

    if (method === 'message.ack') {
      await client._ensureV2SessionReady('message.ack');
      client._clientLog.debug('call route: message.ack -> V2 ack');
      return await client._ackV2(Number(p.seq ?? p.up_to_seq ?? 0) || undefined) as RpcResult;
    }

    if (method === 'group.pull' && p.group_id) {
      await client._ensureV2SessionReady('group.pull');
      client._clientLog.debug('call route: group.pull -> V2 pull');
      const hasExplicitAfterSeq = 'after_seq' in p || 'after_message_seq' in p;
      const cursorParams = client._explicitGroupCursorParams(p);
      const ownsCursor = Object.keys(cursorParams).length === 0 || client._groupCursorTargetsCurrentInstance(cursorParams);
      const pullOpts: { explicitAfterSeq?: boolean; cursorParams?: RpcParams; ownsCursor?: boolean } = {};
      if (hasExplicitAfterSeq) pullOpts.explicitAfterSeq = true;
      if (Object.keys(cursorParams).length > 0) pullOpts.cursorParams = cursorParams;
      if (!ownsCursor) pullOpts.ownsCursor = false;
      const messages = await client._pullGroupV2(
        String(p.group_id),
        Number(p.after_seq ?? p.after_message_seq ?? 0) || 0,
        Number(p.limit ?? 50) || 50,
        Object.keys(pullOpts).length > 0 ? pullOpts : undefined,
      );
      return { messages } as RpcResult;
    }

    if (method === 'group.ack_messages' && p.group_id) {
      await client._ensureV2SessionReady('group.ack_messages');
      client._clientLog.debug('call route: group.ack_messages -> V2 ack');
      const cursorParams = client._explicitGroupCursorParams(p);
      const ownsCursor = Object.keys(cursorParams).length === 0 || client._groupCursorTargetsCurrentInstance(cursorParams);
      if (!ownsCursor) {
        return await client._rawGroupAckMessages(p) as RpcResult;
      }
      return await client._ackGroupV2(
        String(p.group_id),
        Number(p.seq ?? p.msg_seq ?? p.up_to_seq ?? 0) || undefined,
      ) as RpcResult;
    }

    await this.applyClientSignature(method, p);

    const callTimeout = NON_IDEMPOTENT_METHODS.has(method) ? NON_IDEMPOTENT_TIMEOUT : undefined;
    const rpcBackground = client._backgroundRpcDepth > 0;
    let result = callTimeout
      ? await client._transport.call(method, p, callTimeout, undefined, rpcBackground)
      : await client._transport.call(method, p, undefined, undefined, rpcBackground);

    result = await this.postprocessResult(method, p, result) as RpcResult;
    if (!skipSendResultEnvelope) {
      result = client._delivery.attachSendResultEnvelope(
        method,
        p,
        result,
        Boolean(p.encrypted),
      ) as RpcResult;
    }
    return result;
  }

  preflight(method: string, params?: RpcParams): RpcPreflightResult {
    const client = this.runtime.client;
    if (client._state !== 'connected') {
      throw new ConnectionError('client is not connected');
    }
    if (INTERNAL_ONLY_METHODS.has(method)) {
      throw new PermissionError(`method is internal_only: ${method}`);
    }
    if (method.startsWith('message.e2ee.') || method.startsWith('group.e2ee.') || REMOVED_E2EE_METHODS.has(method)) {
      throw new PermissionError(`legacy E2EE method is removed in this SDK: ${method}`);
    }

    const p: RpcParams = { ...(params ?? {}) };
    this.mergeInstanceProtectedHeaders(method, p);
    const rpcBackground = Boolean((p as Record<string, unknown>)._rpc_background) || client._backgroundRpcDepth > 0;
    delete (p as Record<string, unknown>)._rpc_background;
    if (method === 'message.send' || method === 'group.send') {
      this.normalizeOutboundMessagePayload(p, method);
    }
    this.validateOutboundCall(method, p);
    this.injectMessageCursorContext(method, p);
    this.captureGroupCursorParams(method, p);
    this.normalizeGroupCallContext(method, p);
    const clampedParams = typeof client._clampAckParams === 'function'
      ? client._clampAckParams(method, p) as RpcParams
      : p;

    return { params: clampedParams, rpcBackground };
  }

  mergeInstanceProtectedHeaders(method: string, params: RpcParams): void {
    const client = this.runtime.client;
    if (!client._instanceProtectedHeaders || !PROTECTED_HEADERS_METHODS.has(method)) {
      return;
    }
    const existingValue = params.protected_headers ?? params.headers;
    const existing = isJsonObject(existingValue) ? existingValue : {};
    params.protected_headers = { ...client._instanceProtectedHeaders, ...existing };
  }

  normalizeOutboundMessagePayload(params: RpcParams, method = ''): void {
    void method;
    if (!Object.prototype.hasOwnProperty.call(params, 'payload') && Object.prototype.hasOwnProperty.call(params, 'content')) {
      params.payload = params.content;
      delete params.content;
    }
    const payload = params.payload;
    if (isJsonObject(payload) && !Object.prototype.hasOwnProperty.call(payload, 'type') && typeof payload.text === 'string') {
      params.payload = { type: 'text', ...payload } as JsonObject;
    }
  }

  validateOutboundCall(method: string, params: RpcParams): void {
    if (method === 'message.send') {
      this.validateMessageRecipient(params.to);
      // 校验目标 AID 格式（拒绝 __system__ 等非法格式）
      validateAIDFormat(params.to, 'message.send.to');
      if ('persist' in params) {
        throw new ValidationError("message.send no longer accepts 'persist'; configure delivery_mode during connect");
      }
      if ('delivery_mode' in params || 'queue_routing' in params || 'affinity_ttl_ms' in params) {
        throw new ValidationError('message.send does not accept delivery_mode; configure delivery_mode during connect');
      }
    }
    if (method === 'group.send') {
      // 校验目标 Group ID 格式
      validateGroupIDFormat(params.group_id, 'group.send.group_id');
      if ('persist' in params) {
        throw new ValidationError("group.send does not accept 'persist'; group messages are always fanout");
      }
      if ('delivery_mode' in params || 'queue_routing' in params || 'affinity_ttl_ms' in params) {
        throw new ValidationError('group.send does not accept delivery_mode; group messages are always fanout');
      }
    }
    if (
      method === 'group.thought.put' || method === 'group.thought.get'
      || method === 'message.thought.put' || method === 'message.thought.get'
    ) {
      const context = isJsonObject(params.context) ? params.context : null;
      const contextType = String(context?.type ?? '').trim();
      const contextId = String(context?.id ?? '').trim();
      const hasContext = contextType.length > 0 && contextId.length > 0;
      if (!hasContext) {
        throw new ValidationError(`${method} requires context.type + context.id`);
      }
    }
    if (method === 'group.thought.put') {
      // 校验目标 Group ID 格式
      validateGroupIDFormat(params.group_id, 'group.thought.put.group_id');
    }
    if (method === 'group.thought.get') {
      if (!String(params.sender_aid ?? '').trim()) {
        throw new ValidationError('group.thought.get requires sender_aid');
      }
      // 校验 sender_aid 格式
      validateAIDFormat(params.sender_aid, 'group.thought.get.sender_aid');
      // 校验目标 Group ID 格式
      validateGroupIDFormat(params.group_id, 'group.thought.get.group_id');
    }
    if (method === 'message.thought.put') {
      this.validateMessageRecipient(params.to);
      if (!String(params.to ?? '').trim()) {
        throw new ValidationError('message.thought.put requires to');
      }
      // 校验目标 AID 格式
      validateAIDFormat(params.to, 'message.thought.put.to');
    }
    if (method === 'message.thought.get') {
      if (!String(params.sender_aid ?? '').trim()) {
        throw new ValidationError('message.thought.get requires sender_aid');
      }
      // 校验 sender_aid 格式
      validateAIDFormat(params.sender_aid, 'message.thought.get.sender_aid');
    }
  }

  injectMessageCursorContext(method: string, params: RpcParams): void {
    if (method !== 'message.pull' && method !== 'message.ack') {
      return;
    }
    const client = this.runtime.client;
    if ('device_id' in params && String(params.device_id ?? '').trim() !== client._deviceId) {
      throw new ValidationError('message.pull/message.ack device_id must match the current client instance');
    }
    const slotId = normalizeSlotId(params.slot_id ?? client._slotId, client._slotId);
    if (slotIsolationKey(slotId) !== slotIsolationKey(client._slotId)) {
      throw new ValidationError('message.pull/message.ack slot_id must match the current client instance');
    }
    params.device_id = client._deviceId;
    params.slot_id = client._slotId;
  }

  async applyClientSignature(method: string, params: RpcParams): Promise<void> {
    try {
      if (!SIGNED_METHODS.has(method)) {
        return;
      }
      if (this.shouldSkipClientSignature(method, params)) {
        delete params.client_signature;
        return;
      }
      await this.runtime.client._signClientOperation(method, params);
    } finally {
      delete (params as Record<string, unknown>)._client_signature_identity;
    }
  }

  shouldSkipClientSignature(method: string, params: RpcParams): boolean {
    if (method !== 'message.send' && method !== 'group.send') return false;
    if (params.encrypted || params.encrypt) return false;
    return this.runtime.client._isEchoPayload(params.payload);
  }

  async signClientOperation(method: string, params: RpcParams): Promise<void> {
    const internal = (params as Record<string, unknown>)._client_signature_identity;
    const currentAid = (internal && typeof internal === 'object')
      ? internal as { aid?: string; privateKeyPem?: string; certPem?: string }
      : this.runtime.client._currentAid;
    if (!currentAid?.privateKeyPem) return;

    try {
      const aid = currentAid.aid;
      const ts = String(Math.floor(Date.now() / 1000));
      const paramsForHash: RpcParams = {};
      for (const [k, v] of Object.entries(params)) {
        if (k !== 'client_signature' && !k.startsWith('_')) {
          paramsForHash[k] = v;
        }
      }
      const paramsJson = stableStringify(paramsForHash);
      const paramsHashBuf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(paramsJson),
      );
      const paramsHash = Array.from(new Uint8Array(paramsHashBuf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

      const signData = new TextEncoder().encode(`${method}|${aid}|${ts}|${paramsHash}`);
      const pkcs8 = pemToArrayBuffer(currentAid.privateKeyPem);
      const cryptoKey = await crypto.subtle.importKey(
        'pkcs8', pkcs8,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false, ['sign'],
      );
      const sigP1363 = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        cryptoKey, signData,
      );
      const sigDer = p1363ToDer(new Uint8Array(sigP1363));

      let certFingerprint = '';
      const certPem = currentAid.certPem;
      if (certPem) {
        const certDer = pemToArrayBuffer(certPem);
        const fpBuf = await crypto.subtle.digest('SHA-256', certDer);
        certFingerprint = 'sha256:' + Array.from(new Uint8Array(fpBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      params.client_signature = {
        aid,
        cert_fingerprint: certFingerprint,
        timestamp: ts,
        params_hash: paramsHash,
        signature: uint8ToBase64(sigDer),
      };
    } catch (exc) {
      throw new ClientSignatureError(`客户端签名失败，拒绝发送无签名请求: ${exc instanceof Error ? exc.message : String(exc)}`);
    }
  }

  // ── Pull Gate（序列化同一 key 的并发 pull）──────────────────

  pullGateKeyForCall(method: string, params: RpcParams): string {
    const client = this.runtime.client;
    if (method === 'message.pull' || method === 'message.v2.pull') {
      return client._aid ? `p2p:${client._aid}` : '';
    }
    if (method === 'group.pull' || method === 'group.v2.pull') {
      const gid = String(params.group_id ?? '').trim();
      return gid ? `group:${gid}` : '';
    }
    if (method === 'group.pull_events') {
      const gid = String(params.group_id ?? '').trim();
      return gid ? `group_event:${gid}` : '';
    }
    return '';
  }

  tryAcquirePullGate(key: string): number | null {
    if (!key) return 0;
    const client = this.runtime.client;
    const now = Date.now();
    const gate = client._pullGates.get(key) ?? { inflight: false, startedAt: 0, token: 0 };
    if (gate.inflight && now - gate.startedAt <= PULL_GATE_STALE_MS) {
      return null;
    }
    if (gate.inflight) {
      client._clientLog?.warn(`pull in-flight stale reset: key=${key} age=${now - gate.startedAt}ms`);
    }
    gate.token += 1;
    gate.inflight = true;
    gate.startedAt = now;
    client._pullGates.set(key, gate);
    return gate.token;
  }

  releasePullGate(key: string, token: number | null): void {
    if (!key || token == null) return;
    const gate = this.runtime.client._pullGates.get(key);
    if (!gate || gate.token !== token) return;
    gate.inflight = false;
    gate.startedAt = 0;
  }

  async runPullSerialized<T>(key: string, operation: () => Promise<T>): Promise<T> {
    let token = this.tryAcquirePullGate(key);
    if (token === null) {
      const deadline = Date.now() + PULL_GATE_STALE_MS + 100;
      while (token === null && Date.now() <= deadline) {
        await this._sleep(25);
        token = this.tryAcquirePullGate(key);
      }
      if (token === null) {
        throw new StateError(`pull already in-flight for ${key}`);
      }
    }
    try {
      return await operation();
    } finally {
      this.releasePullGate(key, token);
    }
  }

  async rawCall(
    method: string,
    params?: RpcParams,
    options?: { timeout?: number; trace?: string; signed?: boolean; background?: boolean },
  ): Promise<unknown> {
    const client = this.runtime.client;
    const payload: RpcParams = { ...(params ?? {}) };
    const rpcBackground = Boolean((payload as Record<string, unknown>)._rpc_background) || client._backgroundRpcDepth > 0 || options?.background === true;
    delete (payload as Record<string, unknown>)._rpc_background;
    const signed = options?.signed ?? true;
    if (signed) {
      await this.applyClientSignature(method, payload);
    }
    const timeout = options?.timeout;
    if (rpcBackground) {
      return await client._transport.call(method, payload, timeout, options?.trace, true);
    }
    if (options?.trace !== undefined) {
      return await client._transport.call(method, payload, timeout, options.trace);
    }
    if (timeout !== undefined) {
      return await client._transport.call(method, payload, timeout);
    }
    return await client._transport.call(method, payload);
  }

  async postprocessResult(
    method: string,
    params: RpcParams,
    result: unknown,
  ): Promise<unknown> {
    const client = this.runtime.client;
    let next = result;

    if (method === 'group.thought.get' && isJsonObject(next)) {
      client._clientLog?.debug?.(`group.thought.get transport result: found=${String(next.found ?? '')}, raw_count=${Array.isArray(next.thoughts) ? next.thoughts.length : 0}`);
      next = await client._decryptGroupThoughts(next);
    }
    if (method === 'message.thought.get' && isJsonObject(next)) {
      client._clientLog?.debug?.(`message.thought.get transport result: found=${String(next.found ?? '')}, raw_count=${Array.isArray(next.thoughts) ? next.thoughts.length : 0}`);
      next = await client._decryptMessageThoughts(next);
    }

    if (method === 'message.pull' && isJsonObject(next)) {
      this.postprocessMessagePull(params, next);
    }
    if (method === 'group.pull' && isJsonObject(next)) {
      this.postprocessGroupPull(params, next);
    }

    next = await client._groupState.postprocessResult(method, params, next);

    return next;
  }

  private _sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private postprocessMessagePull(params: RpcParams, result: JsonObject): void {
    const client = this.runtime.client;
    const messages = result.messages;
    const rawMessages = (Array.isArray(messages) ? messages : []).filter(isJsonObject) as JsonObject[];
    if (!client._aid || !client._seqTracker) {
      return;
    }
    const ns = `p2p:${client._aid}`;
    const contigBefore = client._seqTracker.getContiguousSeq(ns);
    if (rawMessages.length) {
      client._seqTracker.onPullResult(ns, rawMessages, Number(params.after_seq ?? 0) || 0);
    }
    const serverAck = Number(result.server_ack_seq ?? 0);
    if (serverAck > 0) {
      const contig = client._seqTracker.getContiguousSeq(ns);
      if (contig < serverAck) {
        client._clientLog?.info?.(`message.pull retention-floor advance: ns=${ns} contiguous=${contig} -> server_ack_seq=${serverAck}`);
        client._seqTracker.forceContiguousSeq(ns, serverAck);
      }
    }
    if (client._seqTracker.getContiguousSeq(ns) !== contigBefore) {
      client._persistSeq?.(ns);
    }
    result._contig_before = contigBefore;
  }

  private postprocessGroupPull(params: RpcParams, result: JsonObject): void {
    const client = this.runtime.client;
    const gid = String(params.group_id ?? '').trim();
    if (!gid || !client._seqTracker) {
      return;
    }
    const messages = result.messages;
    const rawMessages = (Array.isArray(messages) ? messages : []).filter(isJsonObject) as JsonObject[];
    const ns = `group:${gid}`;
    const contigBefore = client._seqTracker.getContiguousSeq(ns);
    if (rawMessages.length) {
      client._seqTracker.onPullResult(ns, rawMessages, Number(params.after_message_seq ?? params.after_seq ?? 0) || 0);
    }
    const cursor = isJsonObject(result.cursor) ? result.cursor : null;
    const serverAck = Number(cursor?.current_seq ?? 0);
    if (serverAck > 0) {
      const contig = client._seqTracker.getContiguousSeq(ns);
      if (contig < serverAck) {
        client._clientLog?.info?.(`group.pull retention-floor advance: ns=${ns} contiguous=${contig} -> cursor.current_seq=${serverAck}`);
        client._seqTracker.forceContiguousSeq(ns, serverAck);
      }
    }
    if (client._seqTracker.getContiguousSeq(ns) !== contigBefore) {
      client._persistSeq?.(ns);
    }
    result._contig_before = contigBefore;
  }

  private captureGroupCursorParams(method: string, params: RpcParams): void {
    if (!method.startsWith('group.')
      || '_group_cursor_params' in (params as Record<string, unknown>)
      || Boolean((params as Record<string, unknown>)._pull_gate_locked)) {
      return;
    }
    const explicitCursorParams = this.groupCursorParams(params);
    if (Object.keys(explicitCursorParams).length > 0) {
      (params as Record<string, unknown>)._group_cursor_params = explicitCursorParams;
    }
  }

  private normalizeGroupCallContext(method: string, params: RpcParams): void {
    if (!method.startsWith('group.')) {
      return;
    }
    const client = this.runtime.client;
    if (params.group_id !== undefined && params.group_id !== null) {
      const rawGroupId = String(params.group_id);
      const normalizedGroupId = normalizeGroupId(rawGroupId);
      if (normalizedGroupId && normalizedGroupId !== rawGroupId) {
        client._clientLog?.debug?.(`call group_id normalized: ${rawGroupId} -> ${normalizedGroupId} method=${method}`);
      }
      params.group_id = normalizedGroupId;
    }
    if (params.device_id === undefined) {
      params.device_id = client._deviceId;
    }
    if (params.slot_id === undefined) {
      params.slot_id = client._slotId;
    }
  }

  private groupCursorParams(params: RpcParams): RpcParams {
    const cursorParams: RpcParams = {};
    for (const key of ['device_id', 'slot_id', 'device_name', 'device_type']) {
      const value = params[key];
      if (value !== undefined && value !== null) cursorParams[key] = value as JsonValue;
    }
    return cursorParams;
  }

  validateMessageRecipient(toAid: JsonValue | object | undefined): void {
    if (isGroupServiceAid(toAid)) {
      throw new ValidationError('message.send receiver cannot be group.{issuer}; use group.send instead');
    }
  }
}

function isGroupServiceAid(value: JsonValue | object | undefined): boolean {
  const text = String(value ?? '').trim();
  if (!text.includes('.')) return false;
  const [name, ...issuerParts] = text.split('.');
  return name === 'group' && issuerParts.join('.').length > 0;
}

function stableStringify(obj: JsonValue | object | undefined): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => stableStringify(v)).join(',') + ']';
  }
  if (isJsonObject(obj)) {
    const keys = Object.keys(obj).sort();
    const entries = keys.map(k => stableStringify(k) + ':' + stableStringify(obj[k]));
    return '{' + entries.join(',') + '}';
  }
  return JSON.stringify(obj);
}

function formatCaughtError(error: unknown): Error | string {
  return error instanceof Error ? error : String(error);
}
