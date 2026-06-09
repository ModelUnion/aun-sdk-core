import * as crypto from 'node:crypto';

import { normalizeSlotId, slotIsolationKey } from '../config.js';
import { ClientSignatureError, ConnectionError, PermissionError, StateError, ValidationError } from '../errors.js';
import { normalizeGroupId } from '../group-id.js';
import {
  ConnectionState,
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
  'group.e2ee.begin_rotation',
  'group.e2ee.commit_rotation',
  'group.e2ee.abort_rotation',
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
  'group.transfer_owner', 'group.review_join_request',
  'group.batch_review_join_request',
  'group.request_join', 'group.use_invite_code',
  'group.thought.put',
  'message.thought.put',
  'group.set_settings',
  'group.resources.put', 'group.resources.create_folder',
  'group.resources.rename', 'group.resources.move',
  'group.resources.mount_object', 'group.resources.update',
  'group.resources.delete', 'group.resources.cleanup_by_storage_ref',
  'group.resources.request_add', 'group.resources.request_mount_object',
  'group.resources.direct_add', 'group.resources.approve_request',
  'group.resources.reject_request', 'group.resources.unmount',
  'group.resources.get_access', 'group.resources.resolve_access_ticket',
  'storage.put_object', 'storage.delete_object', 'storage.get_by_share',
  'storage.create_share_link', 'storage.revoke_share_link',
  'storage.create_upload_session', 'storage.complete_upload',
  'storage.create_folder', 'storage.rename_folder', 'storage.move_folder',
  'storage.delete_folder', 'storage.move_object', 'storage.copy_object',
  'storage.batch_delete', 'storage.set_object_meta', 'storage.append_object',
  'group.commit_state',
  'group.ban', 'group.unban',
  'group.dissolve', 'group.suspend', 'group.resume',
]);

/** pull-gate 防并发窗口，与 client.ts PULL_GATE_STALE_MS 保持一致 */
const PULL_GATE_STALE_MS = 30000;
const NON_IDEMPOTENT_TIMEOUT_MS = 35_000;
const NON_IDEMPOTENT_METHODS = new Set([
  'message.send', 'group.send', 'group.create', 'group.invite',
  'group.kick', 'group.remove_member', 'group.leave', 'group.dissolve',
  'group.update_name', 'group.update_avatar', 'group.update_announcement',
  'group.update_settings',
  'storage.put_object', 'storage.delete_object', 'storage.get_by_share',
  'storage.create_share_link', 'storage.revoke_share_link',
  'storage.create_upload_session', 'storage.complete_upload',
  'storage.create_folder', 'storage.rename_folder', 'storage.move_folder',
  'storage.delete_folder', 'storage.move_object', 'storage.copy_object',
  'storage.batch_delete', 'storage.set_object_meta', 'storage.append_object',
  'auth.create_aid', 'auth.renew_cert', 'auth.rekey',
  'message.thought.put', 'group.thought.put',
  'group.add_member',
  'group.resources.put', 'group.resources.create_folder',
  'group.resources.rename', 'group.resources.move',
  'group.resources.mount_object', 'group.resources.update',
  'group.resources.delete', 'group.resources.cleanup_by_storage_ref',
  'group.resources.request_add', 'group.resources.request_mount_object',
  'group.resources.direct_add', 'group.resources.approve_request',
  'group.resources.reject_request', 'group.resources.unmount',
  'group.resources.get_access',
  'group.resources.resolve_access_ticket',
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
      const preflight = this.preflight(method, params);
      const p = preflight.params;
      const rpcBackground = preflight.rpcBackground;
      const runWithRpcPriority = async <T>(operation: () => Promise<T> | T): Promise<T> => {
        if (!rpcBackground) return await operation();
        return await client._withBackgroundRpc(operation);
      };

      const pullGateLocked = Boolean((p as Record<string, unknown>)._pull_gate_locked);
      delete (p as Record<string, unknown>)._pull_gate_locked;
      const skipSendResultEnvelope = Boolean((p as Record<string, unknown>)._skip_send_result_envelope);
      delete (p as Record<string, unknown>)._skip_send_result_envelope;
      const pullGateKey = this.pullGateKeyForCall(method, p);
      if (pullGateKey && this.isPullResponseProcessing(pullGateKey)) {
        client._clientLog.debug(`pull skipped while processing pull response: method=${method} key=${pullGateKey}`);
        return client._emptyPullResultForCall(method);
      }
      if (pullGateKey && !pullGateLocked) {
        const lockedParams: RpcParams = { ...p, _pull_gate_locked: true };
        if (rpcBackground) (lockedParams as Record<string, unknown>)._rpc_background = true;
        if (skipSendResultEnvelope) (lockedParams as Record<string, unknown>)._skip_send_result_envelope = true;
        return await this.runPullSerialized(pullGateKey, async () => this.call(method, lockedParams)) as RpcResult;
      }

      if (method === 'message.send') {
        const encrypt = p.encrypt ?? true;
        delete p.encrypt;
        if (encrypt) {
          return await runWithRpcPriority(() => client._sendV2(String(p.to ?? ''), p.payload as Record<string, unknown>, {
            messageId: String(p.message_id ?? '') || undefined,
            timestamp: p.timestamp as number | undefined,
            protectedHeaders: client._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
            context: isJsonObject(p.context) ? p.context : undefined,
          })) as RpcResult;
        }
        client._maybeAppendEchoTraceSend(p);
      }

      if (method === 'group.send') {
        const encrypt = p.encrypt ?? true;
        delete p.encrypt;
        if (encrypt) {
          return await runWithRpcPriority(() => client._sendGroupV2(String(p.group_id ?? ''), p.payload as Record<string, unknown>, {
            messageId: String(p.message_id ?? '') || undefined,
            timestamp: p.timestamp as number | undefined,
            protectedHeaders: client._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
            context: isJsonObject(p.context) ? p.context : undefined,
          })) as RpcResult;
        }
        client._maybeAppendEchoTraceSend(p);
      }

      if (method === 'group.thought.put') {
        const encrypt = p.encrypt ?? true;
        delete p.encrypt;
        if (encrypt) {
          await client._ensureV2SessionReady(
            'group.thought.put',
            'V2 session not initialized; encrypted group.thought.put requires V2 (V1 E2EE removed)',
          );
          if (!String(p.group_id ?? '').trim()) {
            throw new ValidationError('group.thought.put requires group_id');
          }
          return await runWithRpcPriority(() => client._putGroupThoughtEncryptedV2(p)) as RpcResult;
        }
      }

      if (method === 'message.thought.put') {
        const encrypt = p.encrypt ?? true;
        delete p.encrypt;
        if (encrypt) {
          await client._ensureV2SessionReady(
            'message.thought.put',
            'V2 session not initialized; encrypted message.thought.put requires V2 (V1 E2EE removed)',
          );
          return await runWithRpcPriority(() => client._putMessageThoughtEncryptedV2(p)) as RpcResult;
        }
      }

      if (method === 'message.pull' || method === 'message.v2.pull') {
        await client._ensureV2SessionReady('message.pull');
        const skipAutoAck = p._skip_auto_ack === true || p.skip_auto_ack === true;
        const force = p.force === true;
        const afterSeq = Number(p.after_seq ?? 0) || 0;
        const limit = Number(p.limit ?? 50) || 50;
        const messages = skipAutoAck
          ? await runWithRpcPriority(() => client._pullV2(afterSeq, limit, { skipAutoAck: true, gateLocked: true, force }))
          : await runWithRpcPriority(() => client._pullV2(afterSeq, limit, { gateLocked: true, force }));
        return { messages } as RpcResult;
      }

      if (method === 'message.ack' || method === 'message.v2.ack') {
        await client._ensureV2SessionReady('message.ack');
        return await runWithRpcPriority(() => client._ackV2(Number(p.seq ?? p.up_to_seq ?? 0) || undefined)) as RpcResult;
      }

      if (method === 'group.pull' || method === 'group.v2.pull') {
        if (!String(p.group_id ?? '').trim()) {
          throw new ValidationError('group.pull requires group_id');
        }
        await client._ensureV2SessionReady('group.pull');
        const hasExplicitAfterSeq = 'after_seq' in p || 'after_message_seq' in p;
        const cursorParams = client._explicitGroupCursorParams(p);
        const ownsCursor = Object.keys(cursorParams).length === 0 || client._groupCursorTargetsCurrentInstance(cursorParams);
        const pullOpts: { gateLocked: boolean; explicitAfterSeq?: boolean; cursorParams?: RpcParams; ownsCursor?: boolean } = { gateLocked: true };
        if (hasExplicitAfterSeq) pullOpts.explicitAfterSeq = true;
        if (Object.keys(cursorParams).length > 0) pullOpts.cursorParams = cursorParams;
        if (!ownsCursor) pullOpts.ownsCursor = false;
        const messages = await runWithRpcPriority(() => client._pullGroupV2(
          String(p.group_id),
          Number(p.after_seq ?? p.after_message_seq ?? 0) || 0,
          Number(p.limit ?? 50) || 50,
          pullOpts,
        ));
        return { messages } as RpcResult;
      }

      if (method === 'group.ack_messages' || method === 'group.v2.ack') {
        if (!String(p.group_id ?? '').trim()) {
          throw new ValidationError('group.ack_messages requires group_id');
        }
        await client._ensureV2SessionReady('group.ack_messages');
        const cursorParams = client._explicitGroupCursorParams(p);
        const ownsCursor = Object.keys(cursorParams).length === 0 || client._groupCursorTargetsCurrentInstance(cursorParams);
        if (method === 'group.ack_messages' && !ownsCursor) {
          return await runWithRpcPriority(() => client._rawGroupAckMessages(p)) as RpcResult;
        }
        return await runWithRpcPriority(() => client._ackGroupV2(
          String(p.group_id),
          Number(p.seq ?? p.msg_seq ?? p.up_to_seq ?? 0) || undefined,
        )) as RpcResult;
      }

      if (method === 'message.pull') {
        delete p._skip_auto_ack;
        delete p.skip_auto_ack;
      }
      delete (p as Record<string, unknown>)._group_cursor_params;

      this.applyClientSignature(method, p);

      const callTimeout = NON_IDEMPOTENT_METHODS.has(method) ? NON_IDEMPOTENT_TIMEOUT_MS : undefined;
      if (method === 'group.thought.get' || method === 'message.thought.get') {
        client._clientLog.debug(`thought.get transport call start: method=${method}, params=${client._debugJson(client._messageEnvelopeFieldsForDebug(p))}`);
      }
      let result = callTimeout
        ? (
          rpcBackground
            ? await client._transport.call(method, p, callTimeout, undefined, true)
            : await client._transport.call(method, p, callTimeout)
        )
        : (
          rpcBackground
            ? await client._transport.call(method, p, undefined, undefined, true)
            : await client._transport.call(method, p)
        );

      result = await this.postprocessResult(method, p, result) as RpcResult;
      if (!skipSendResultEnvelope) {
        result = client._delivery.attachSendResultEnvelope(
          method,
          p,
          result,
          Boolean(p.encrypted),
        ) as RpcResult;
      }
      client._clientLog.debug(`call exit: method=${method} elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      client._clientLog.debug(`call exit (error): method=${method} elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  preflight(method: string, params?: RpcParams): RpcPreflightResult {
    const client = this.runtime.client;
    if (client.state !== ConnectionState.READY) {
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
      if ('persist' in params) {
        throw new ValidationError("message.send no longer accepts 'persist'; configure delivery_mode during connect");
      }
      if ('delivery_mode' in params || 'queue_routing' in params || 'affinity_ttl_ms' in params) {
        throw new ValidationError('message.send does not accept delivery_mode; configure delivery_mode during connect');
      }
    }
    if (method === 'group.send') {
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
    if (method === 'group.thought.get' && !String(params.sender_aid ?? '').trim()) {
      throw new ValidationError('group.thought.get requires sender_aid');
    }
    if (method === 'message.thought.put') {
      this.validateMessageRecipient(params.to);
      if (!String(params.to ?? '').trim()) {
        throw new ValidationError('message.thought.put requires to');
      }
    }
    if (method === 'message.thought.get' && !String(params.sender_aid ?? '').trim()) {
      throw new ValidationError('message.thought.get requires sender_aid');
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

  applyClientSignature(method: string, params: RpcParams): void {
    if (!SIGNED_METHODS.has(method)) {
      return;
    }
    if (this.shouldSkipClientSignature(method, params)) {
      delete params.client_signature;
      return;
    }
    this.runtime.client._signClientOperation(method, params);
  }

  shouldSkipClientSignature(method: string, params: RpcParams): boolean {
    if (method !== 'message.send' && method !== 'group.send') return false;
    if (params.encrypted || params.encrypt) return false;
    return this.runtime.client._isEchoPayload(params.payload);
  }

  signClientOperation(method: string, params: RpcParams): void {
    const currentAid = this.runtime.client._currentAid;
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
      const paramsHash = crypto.createHash('sha256').update(paramsJson, 'utf-8').digest('hex');

      const signData = Buffer.from(`${method}|${aid}|${ts}|${paramsHash}`, 'utf-8');
      const privateKey = crypto.createPrivateKey(currentAid.privateKeyPem);
      const signature = crypto.sign('SHA256', signData, privateKey);

      let certFingerprint = '';
      const certPem = currentAid.certPem;
      if (certPem) {
        const certObj = new crypto.X509Certificate(certPem);
        certFingerprint = 'sha256:' + certObj.fingerprint256.replace(/:/g, '').toLowerCase();
      }

      params.client_signature = {
        aid,
        cert_fingerprint: certFingerprint,
        timestamp: ts,
        params_hash: paramsHash,
        signature: signature.toString('base64'),
      };
    } catch (exc) {
      throw new ClientSignatureError(`客户端签名失败，拒绝发送无签名请求: ${formatCaughtError(exc)}`);
    }
  }

  // ── pull-gate ──────────────────────────────────────────────────────────────

  pullGateKeyForCall(method: string, params: RpcParams): string {
    const client = this.runtime.client;
    if (method === 'message.pull' || method === 'message.v2.pull') {
      return client._aid ? `p2p:${client._aid}` : '';
    }
    if ((method === 'group.pull' || method === 'group.v2.pull') && String(params.group_id ?? '').trim()) {
      return `group:${String(params.group_id ?? '').trim()}`;
    }
    if (method === 'group.pull_events' && String(params.group_id ?? '').trim()) {
      return `group_event:${String(params.group_id ?? '').trim()}`;
    }
    return '';
  }

  isPullResponseProcessing(key: string): boolean {
    if (!key) return false;
    return (this.runtime.client._pullResponseKeys.get(key) ?? 0) > 0;
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
      client._clientLog.warn(`pull in-flight stale reset: key=${key} age=${now - gate.startedAt}ms`);
    }
    gate.token += 1;
    gate.inflight = true;
    gate.startedAt = now;
    client._pullGates.set(key, gate);
    return gate.token;
  }

  releasePullGate(key: string, token: number | null): void {
    if (!key || token == null) return;
    const client = this.runtime.client;
    const gate = client._pullGates.get(key);
    if (!gate || gate.token !== token) return;
    gate.inflight = false;
    gate.startedAt = 0;
    if (key.startsWith('p2p:')) {
      client._schedulePendingP2pPullIfNeeded(key, 'pull-gate-release');
    }
  }

  async runPullSerialized<T>(key: string, operation: () => Promise<T> | T): Promise<T> {
    if (key && this.isPullResponseProcessing(key)) {
      this.runtime.client._clientLog.debug(`pull skipped while processing pull response: key=${key}`);
      return [] as unknown as T;
    }
    let token = this.tryAcquirePullGate(key);
    if (token === null) {
      const deadline = Date.now() + PULL_GATE_STALE_MS + 100;
      while (token === null && Date.now() <= deadline) {
        await this.runtime.client._sleep(25);
        token = this.tryAcquirePullGate(key);
      }
      if (token === null) {
        throw new StateError(`pull already in-flight for ${key}`);
      }
    }
    try {
      return await this.runtime.client._withBackgroundRpc(operation);
    } finally {
      this.releasePullGate(key, token);
    }
  }

  // ── raw-call ───────────────────────────────────────────────────────────────

  async rawCall(
    method: string,
    params?: RpcParams,
    opts: { timeout?: number; trace?: string; signed?: boolean; background?: boolean } = {},
  ): Promise<unknown> {
    const { timeout, trace, signed = true, background = false } = opts;
    const client = this.runtime.client;
    const payload: RpcParams = params ? { ...params } : {};
    if (signed) {
      this.applyClientSignature(method, payload);
    }
    if (background) {
      return await client._transport.call(method, payload, timeout, trace, true);
    }
    if (trace !== undefined) {
      return await client._transport.call(method, payload, timeout, trace);
    }
    if (timeout !== undefined) {
      return await client._transport.call(method, payload, timeout);
    }
    return await client._transport.call(method, payload);
  }

  // ── postprocess ────────────────────────────────────────────────────────────

  async postprocessResult(method: string, params: RpcParams, result: unknown): Promise<unknown> {
    const client = this.runtime.client;
    let next = result;

    if (method === 'group.thought.get' && isUnknownJsonObject(next)) {
      client._clientLog?.debug?.(`group.thought.get transport result: found=${String(next.found ?? '')}, raw_count=${Array.isArray(next.thoughts) ? next.thoughts.length : 0}`);
      next = await client._decryptGroupThoughts(next);
    }
    if (method === 'message.thought.get' && isUnknownJsonObject(next)) {
      client._clientLog?.debug?.(`message.thought.get transport result: found=${String(next.found ?? '')}, raw_count=${Array.isArray(next.thoughts) ? next.thoughts.length : 0}`);
      next = await client._decryptMessageThoughts(next);
    }

    if (method === 'message.pull' && isUnknownJsonObject(next)) {
      this.postprocessMessagePull(params, next);
    }
    if (method === 'group.pull' && isUnknownJsonObject(next)) {
      this.postprocessGroupPull(params, next);
    }

    next = await client._groupState.postprocessResult(method, params, next);

    return next;
  }

  // ── private helpers ────────────────────────────────────────────────────────

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
      client._saveSeqTrackerState?.();
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
      client._saveSeqTrackerState?.();
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
    const entries = keys
      .filter(k => obj[k] !== undefined)
      .map(k => stableStringify(k) + ':' + stableStringify(obj[k]));
    return '{' + entries.join(',') + '}';
  }
  return JSON.stringify(obj);
}

function formatCaughtError(error: unknown): Error | string {
  return error instanceof Error ? error : String(error);
}

function isUnknownJsonObject(value: unknown): value is JsonObject {
  return isJsonObject(value as JsonValue | object | null | undefined);
}
