import { slotIsolationKey } from '../config.js';
import type { EventPayload } from '../events.js';
import { normalizeGroupId } from '../group-id.js';
import { ConnectionState, isJsonObject, type JsonObject, type JsonValue, type Message, type RpcParams } from '../types.js';
import type { ClientRuntime } from './runtime.js';

const PUSHED_SEQS_LIMIT = 50_000;
const PENDING_ORDERED_LIMIT = 50_000;
const GROUP_RECALL_SEEN_LIMIT = 10_000;
const SEQ_TRACKER_PERSIST_FLUSH_DELAY_MS = 200;
const APP_MESSAGE_ENVELOPE_KEYS = [
  'module_id', 'message_type', 'type', 'kind', 'version',
  'from', 'from_aid', 'sender_aid', 'to', 'to_aid', 'group_id',
  'timestamp', 'created_at', 'encrypted',
  'context', 'protected_headers', 'headers', 'payload_type',
];
const APP_SEND_ENVELOPE_METHODS = new Set([
  'message.send',
  'group.send',
  'message.thought.put',
  'group.thought.put',
]);
const APP_GROUP_EVENT_ENVELOPE_KEYS = [
  'module_id', 'event_id', 'event_seq', 'seq', 'event_type', 'action', 'group_id',
  'actor_aid', 'sender_aid', 'member_aid', 'target_aid', 'operator_aid',
  'created_at', 'timestamp', 't_server', 'status', 'device_id', 'slot_id',
];

function isPromiseLike<T = unknown>(value: unknown): value is PromiseLike<T> {
  return Boolean(value && typeof (value as { then?: unknown }).then === 'function');
}

function formatDeliveryError(error: unknown): Error | string {
  return error instanceof Error ? error : String(error);
}

export class MessageDeliveryEngine {
  private readonly runtime: ClientRuntime;

  constructor(runtime: ClientRuntime) {
    this.runtime = runtime;
  }

  prunePushedSeqs(ns: string): void {
    const client = this.runtime.client;
    const pushed = client._pushedSeqs.get(ns) as Set<number> | undefined;
    if (!pushed) return;
    if (pushed.size > PUSHED_SEQS_LIMIT) {
      const keep = [...pushed].sort((a, b) => a - b).slice(-PUSHED_SEQS_LIMIT);
      client._pushedSeqs.set(ns, new Set(keep));
    }
  }

  markPublishedSeq(ns: string, seq: number): void {
    const client = this.runtime.client;
    let pushed = client._pushedSeqs.get(ns) as Set<number> | undefined;
    if (!pushed) {
      pushed = new Set<number>();
      client._pushedSeqs.set(ns, pushed);
    }
    pushed.add(seq);
    if (pushed.size > PUSHED_SEQS_LIMIT) {
      const keep = [...pushed].sort((a, b) => a - b).slice(-PUSHED_SEQS_LIMIT);
      client._pushedSeqs.set(ns, new Set(keep));
    }
  }

  enqueueOrderedMessage(ns: string, event: string, seq: number, payload: EventPayload): void {
    const client = this.runtime.client;
    let queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    if (!queue) {
      queue = new Map();
      client._pendingOrderedMsgs.set(ns, queue);
    }
    queue.set(seq, { event, payload });
    if (queue.size > PENDING_ORDERED_LIMIT) {
      const drop = [...queue.keys()].sort((a, b) => a - b).slice(0, queue.size - PENDING_ORDERED_LIMIT);
      for (const oldSeq of drop) queue.delete(oldSeq);
    }
  }

  isGroupEventNamespace(ns: string): boolean {
    return ns.startsWith('group_event:');
  }

  async publishOrderedQueueItem(ns: string, event: string, seq: number, payload: EventPayload, source: string, pullResponse = false): Promise<void> {
    const client = this.runtime.client;
    if (event === 'group.changed' && this.isGroupEventNamespace(ns)) {
      await this.publishOrderedGroupChanged(payload, source);
      return;
    }
    if (pullResponse) {
      const published = client._withPullResponseProcessing(ns, () => client._publishAppEvent(event, payload, source));
      if (isPromiseLike(published)) await published;
    } else {
      const published = client._publishAppEvent(event, payload, source);
      if (isPromiseLike(published)) await published;
    }
  }

  async publishOrderedGroupChanged(payload: EventPayload, source = 'ordered'): Promise<void> {
    const client = this.runtime.client;
    if (isJsonObject(payload as JsonValue | object | null | undefined)) {
      const eventPayload = payload as JsonObject;
      client._groupState?.handleGroupChangedV2Membership?.(eventPayload);
      if (eventPayload.action === 'dissolved') {
        const rawGroupId = eventPayload.group_aid ?? eventPayload.group_id ?? '';
        const groupId = normalizeGroupId(String(rawGroupId)) || String(rawGroupId).trim();
        if (groupId) client._cleanupDissolvedGroup?.(groupId);
      }
    }
    const published = client._publishAppEvent('group.changed', payload, source);
    if (isPromiseLike(published)) await published;
  }

  isInstanceScopedMessageEvent(event: string): boolean {
    return event === 'message.received'
      || event === 'message.recalled'
      || event === 'message.undecryptable'
      || event === 'group.message_created'
      || event === 'group.message_recalled'
      || event === 'group.message_undecryptable';
  }

  attachCurrentInstanceContext(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return payload;
    const client = this.runtime.client;
    const result: JsonObject = { ...(payload as JsonObject) };
    if (!('device_id' in result)) {
      result.device_id = client._deviceId;
    }
    if (!('slot_id' in result)) {
      result.slot_id = client._slotId;
    }
    return result;
  }

  normalizePublishedMessagePayload(event: string, payload: EventPayload): EventPayload {
    if (this.isInstanceScopedMessageEvent(event)) {
      return this.attachAppMessageEnvelope(this.stripInternalSenderDeviceFields(this.attachCurrentInstanceContext(payload)));
    }
    if (this.isGroupScopedEvent(event)) {
      return this.attachAppGroupEventEnvelope(this.attachCurrentInstanceContext(payload));
    }
    return payload;
  }

  private envelopeMetadata(value: unknown): JsonObject | undefined {
    let source = value;
    if (source && typeof source === 'object') {
      const maybeHeaders = source as { toObject?: () => unknown };
      if (typeof maybeHeaders.toObject === 'function') source = maybeHeaders.toObject();
    }
    if (!isJsonObject(source as JsonValue | object | null | undefined)) return undefined;
    const sourceObj = source as JsonObject;
    const out: JsonObject = {};
    for (const [key, item] of Object.entries(sourceObj)) {
      if (key === '_auth') continue;
      out[key] = item as JsonValue;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }

  appMessageEnvelope(payload: EventPayload): JsonObject {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return {};
    const message = payload as JsonObject;
    const body = isJsonObject(message.payload as JsonValue | object | null | undefined) ? message.payload as JsonObject : {};
    const envelope: JsonObject = {};

    const firstValue = (...values: unknown[]): unknown => {
      for (const value of values) {
        if (value === undefined || value === null) continue;
        if (typeof value === 'string' && !value.trim()) continue;
        return value;
      }
      return undefined;
    };
    const setIfPresent = (key: string, value: unknown): void => {
      if (value === undefined || value === null) return;
      if (typeof value === 'string' && !value.trim()) return;
      envelope[key] = value as JsonValue;
    };

    setIfPresent('from', firstValue(message.from, message.from_aid, message.sender_aid));
    setIfPresent('to', firstValue(message.to, message.to_aid));
    setIfPresent('group_id', message.group_id);
    setIfPresent('type', firstValue(body.type, message.type, message.message_type, message.payload_type));
    setIfPresent('kind', firstValue(body.kind, message.kind));
    setIfPresent('version', firstValue(body.version, message.version));
    setIfPresent('timestamp', firstValue(message.timestamp, message.created_at, message.t_server));
    if ('encrypted' in message) envelope.encrypted = Boolean(message.encrypted);
    const context = this.envelopeMetadata(message.context);
    if (context) envelope.context = context;
    const protectedHeaders = this.envelopeMetadata(message.protected_headers) ?? this.envelopeMetadata(message.headers);
    if (protectedHeaders) envelope.protected_headers = protectedHeaders;
    setIfPresent('payload_type', firstValue(message.payload_type, protectedHeaders?.payload_type));
    return envelope;
  }

  isGroupScopedEvent(event: string): boolean {
    return event === 'group.changed';
  }

  appGroupEventEnvelope(payload: EventPayload): JsonObject {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return {};
    const groupEvent = payload as JsonObject;
    const envelope: JsonObject = {};
    for (const key of APP_GROUP_EVENT_ENVELOPE_KEYS) {
      if (Object.prototype.hasOwnProperty.call(groupEvent, key)) envelope[key] = groupEvent[key] as JsonValue;
    }
    return envelope;
  }

  attachAppMessageEnvelope(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return payload;
    const result: JsonObject = { ...(payload as JsonObject) };
    // 兼容期保留顶层信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
    result.envelope = this.appMessageEnvelope(result as EventPayload);
    return result as EventPayload;
  }

  sendResultEnvelope(method: string, params: RpcParams, result: unknown, encrypted: boolean): JsonObject {
    if (!APP_SEND_ENVELOPE_METHODS.has(method)) return {};
    const body = isJsonObject(params.payload as JsonValue | object | null | undefined) ? params.payload as JsonObject : {};
    const resultObj = isJsonObject(result as JsonValue | object | null | undefined) ? result as JsonObject : {};
    const envelope: JsonObject = {};
    const firstValue = (...values: unknown[]): unknown => {
      for (const value of values) {
        if (value === undefined || value === null) continue;
        if (typeof value === 'string' && !value.trim()) continue;
        return value;
      }
      return undefined;
    };
    const setIfPresent = (key: string, value: unknown): void => {
      if (value === undefined || value === null) return;
      if (typeof value === 'string' && !value.trim()) return;
      envelope[key] = value as JsonValue;
    };

    setIfPresent('from', this.runtime.client._aid);
    if (method.startsWith('message.')) {
      setIfPresent('to', params.to);
    } else {
      setIfPresent('group_id', params.group_id);
    }
    setIfPresent('type', firstValue(body.type, params.type, params.message_type, params.payload_type));
    setIfPresent('kind', firstValue(body.kind, params.kind));
    setIfPresent('version', firstValue(body.version, params.version));
    setIfPresent('timestamp', firstValue(params.timestamp, resultObj.timestamp, resultObj.created_at, resultObj.t_server, Date.now()));
    envelope.encrypted = Boolean(encrypted);
    const context = this.envelopeMetadata(params.context);
    if (context) envelope.context = context;
    const protectedHeaders = this.envelopeMetadata(params.protected_headers) ?? this.envelopeMetadata(params.headers);
    if (protectedHeaders) envelope.protected_headers = protectedHeaders;
    setIfPresent('payload_type', firstValue(params.payload_type, protectedHeaders?.payload_type, body.type));
    return envelope;
  }

  attachSendResultEnvelope(method: string, params: RpcParams, result: unknown, encrypted: boolean): unknown {
    if (!APP_SEND_ENVELOPE_METHODS.has(method) || !isJsonObject(result as JsonValue | object | null | undefined)) return result;
    const out: JsonObject = { ...(result as JsonObject) };
    out.envelope = this.sendResultEnvelope(method, params, out, encrypted);
    if ('payload' in params) {
      out.payload = params.payload;
    } else if ('content' in params) {
      out.payload = params.content;
    }
    return out;
  }

  attachAppGroupEventEnvelope(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return payload;
    const result: JsonObject = { ...(payload as JsonObject) };
    // 兼容期保留顶层群事件信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
    result.envelope = this.appGroupEventEnvelope(result as EventPayload);
    return result as EventPayload;
  }

  stripInternalSenderDeviceFields(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return payload;
    const result: JsonObject = { ...(payload as JsonObject) };
    delete result.sender_device_id;
    delete result._sender_device_id;
    delete result.from_device_id;
    delete result.from_device;
    return result;
  }

  recallEventFromMessage(message: EventPayload): JsonObject | null {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) return null;
    const msg = message as JsonObject;
    const rawPayload = msg.payload;
    const payload = isJsonObject(rawPayload as JsonValue | object | null | undefined) ? rawPayload as JsonObject : {};
    const msgType = String(msg.type ?? '').trim();
    const payloadType = String(payload.type ?? payload.kind ?? '').trim();
    if (msgType !== 'message.recalled' && payloadType !== 'message.recalled') return null;
    const event: JsonObject = { ...payload };
    for (const key of APP_MESSAGE_ENVELOPE_KEYS) {
      if (Object.prototype.hasOwnProperty.call(msg, key) && !(key in event)) {
        event[key] = msg[key] as JsonValue;
      }
    }
    const rawIds = event.message_ids;
    let messageIds = Array.isArray(rawIds)
      ? rawIds.map((item) => String(item ?? '').trim()).filter(Boolean)
      : [];
    if (messageIds.length === 0) {
      for (const key of ['recalled_message_id', 'target_message_id', 'original_message_id']) {
        const value = String(event[key] ?? '').trim();
        if (value) {
          messageIds = [value];
          break;
        }
      }
    }
    event.type = 'message.recalled';
    event.kind = 'message.recalled';
    event.message_ids = messageIds;
    if (!('from' in event)) event.from = msg.from ?? msg.from_aid ?? '';
    if (!('to' in event)) event.to = msg.to ?? msg.to_aid ?? '';
    if (!('timestamp' in event)) event.timestamp = msg.timestamp ?? msg.t_server ?? event.recalled_at ?? 0;
    if ('seq' in msg && !('seq' in event)) event.seq = msg.seq;
    if ('message_id' in msg) {
      event.message_id = msg.message_id as JsonValue;
      if (!('tombstone_message_id' in event)) event.tombstone_message_id = msg.message_id as JsonValue;
    }
    if ('device_id' in msg && !('device_id' in event)) event.device_id = msg.device_id;
    if ('slot_id' in msg && !('slot_id' in event)) event.slot_id = msg.slot_id;
    return event;
  }

  p2pAppEventForMessage(message: EventPayload): { event: string; payload: EventPayload } {
    const recall = this.recallEventFromMessage(message);
    if (recall) return { event: 'message.recalled', payload: recall as EventPayload };
    return { event: 'message.received', payload: message };
  }

  recallEventFromGroupMessage(message: EventPayload): JsonObject | null {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) return null;
    const msg = message as JsonObject;
    const rawPayload = msg.payload;
    const payload = isJsonObject(rawPayload as JsonValue | object | null | undefined) ? rawPayload as JsonObject : {};
    const msgType = String(msg.type ?? msg.kind ?? msg.message_type ?? '').trim();
    const payloadType = String(payload.type ?? payload.kind ?? '').trim();
    if (msgType !== 'group.message_recalled' && payloadType !== 'group.message_recalled') return null;
    const event: JsonObject = { ...payload };
    for (const key of APP_MESSAGE_ENVELOPE_KEYS) {
      if (Object.prototype.hasOwnProperty.call(msg, key) && !(key in event)) {
        event[key] = msg[key] as JsonValue;
      }
    }
    const rawIds = event.message_ids;
    let messageIds = Array.isArray(rawIds)
      ? rawIds.map((item) => String(item ?? '').trim()).filter(Boolean)
      : [];
    if (messageIds.length === 0) {
      for (const key of ['recalled_message_id', 'target_message_id', 'original_message_id']) {
        const value = String(event[key] ?? '').trim();
        if (value) {
          messageIds = [value];
          break;
        }
      }
    }
    event.type = 'group.message_recalled';
    event.kind = 'group.message_recalled';
    event.message_ids = messageIds;
    if (!('group_id' in event)) event.group_id = msg.group_id ?? '';
    if (!('timestamp' in event)) event.timestamp = msg.timestamp ?? msg.t_server ?? event.recalled_at ?? 0;
    if ('seq' in msg) event.seq = msg.seq;
    if ('message_id' in msg) {
      event.message_id = msg.message_id as JsonValue;
      if (!('tombstone_message_id' in event)) event.tombstone_message_id = msg.message_id as JsonValue;
    }
    return event;
  }

  groupRecallDedupKey(groupId: string, payload: JsonObject): string {
    // 群撤回去重键：group_id + 排序后的 message_ids。
    // 一条消息只能被撤回一次（服务端 group_message_recalls uk_recall_msg_id 唯一约束），
    // (group_id, sorted message_ids) 已能唯一标识一次撤回。
    // 去重键不含 recalled_at：占位/通知 tombstone（pull，事务内时间）与在线 push（事务后重取时间）
    // 三条通道对同一次撤回可能携带不同来源的时间戳，纳入 recalled_at 会使去重失效、回调多次。
    // group_id 归一化一次，使去重键与来源无关（pull 用 normalizeGroupId，push 可能是原始值）。
    const normalizedGroupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    const ids = payload.message_ids;
    const idPart = Array.isArray(ids)
      ? ids.map((i) => String(i ?? '').trim()).filter(Boolean).sort().join(',')
      : String(ids ?? '');
    return `${normalizedGroupId}|${idPart}`;
  }

  async publishGroupRecallTombstone(groupId: string, seq: unknown, message: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const eventPayload = this.recallEventFromGroupMessage(message);
    if (!eventPayload) return false;
    const dedupKey = this.groupRecallDedupKey(groupId, eventPayload);
    let seen = client._groupRecallSeen;
    if (!seen) {
      seen = new Map<string, number>();
      client._groupRecallSeen = seen;
    }
    if (seen.has(dedupKey)) {
      client._clientLog.debug(`group.message_recalled dedup suppressed: group=${groupId} seq=${String(seq)} key=${dedupKey}`);
      return false;
    }
    seen.set(dedupKey, Date.now());
    if (seen.size > GROUP_RECALL_SEEN_LIMIT) {
      const drop = [...seen.entries()].sort((a, b) => a[1] - b[1]).slice(0, seen.size - GROUP_RECALL_SEEN_LIMIT);
      for (const [oldKey] of drop) seen.delete(oldKey);
    }
    await client._publishAppEvent('group.message_recalled', eventPayload as EventPayload, 'group-recall');
    client._clientLog.debug(`group.message_recalled published: group=${groupId} seq=${String(seq)} ids=${JSON.stringify(eventPayload.message_ids)}`);
    return true;
  }

  async onRawGroupMessageRecalled(data: EventPayload): Promise<void> {
    // 在线 push 是实时通道，与 pull 兜底的双 tombstone 互补。push 携带的 seq 是通知
    // tombstone 的 notice_seq；必须像普通群消息 push 一样推进 seqTracker + markPublished +
    // auto-ack，否则该 seq 在本地 contiguous 序列留洞，后续 pull/reconnect 会重复拉到并
    // 重复处理。publishGroupRecallTombstone 内部再按 (group_id, message_ids) 去重，
    // 确保应用层只回调一次。
    const client = this.runtime.client;
    if (!isJsonObject(data as JsonValue | object | null | undefined)) return;
    const src = data as JsonObject;
    const groupId = String(src.group_id ?? '').trim();
    // push 事件 data 本身是 recall payload；包成 recallEventFromGroupMessage 可识别的形状。
    const wrapped: JsonObject = { ...src };
    if (!('type' in wrapped)) wrapped.type = 'group.message_recalled';
    if (!('payload' in wrapped)) {
      wrapped.payload = {
        type: 'group.message_recalled',
        message_ids: src.message_ids ?? [],
        target_message_seqs: src.target_message_seqs ?? [],
        sender_aid: src.sender_aid ?? '',
        recalled_by: src.recalled_by ?? '',
        recalled_at: src.recalled_at ?? src.timestamp ?? 0,
        reason: src.reason ?? '',
        group_id: groupId,
      };
    }
    const seq = src.seq;
    const seqNum = Number(seq);
    // 无 group_id 或无可用 seq 时无法推进 contiguous 序列，仅做去重发布兜底。
    // TS/JS 为单线程事件循环，无需 Python 侧的 ns lock 串行保护。
    if (!groupId || seq === undefined || seq === null || !Number.isFinite(seqNum) || !Number.isInteger(seqNum)) {
      await this.publishGroupRecallTombstone(groupId, seq, wrapped as EventPayload);
      return;
    }
    const ns = `group:${groupId}`;
    if (seqNum > 0) {
      client._seqTracker.updateMaxSeen(ns, seqNum);
      if (client._seqTracker.getContiguousSeq(ns) === seqNum) {
        // 已覆盖（pull 先到并推进过），仍走去重发布兜底，不重复推进 seq。
        await this.publishGroupRecallTombstone(groupId, seq, wrapped as EventPayload);
        return;
      }
      client._repairPushContiguousBound(ns, seqNum, true, '_raw.group.message_recalled');
    }
    // 该 notice_seq 已由 pull 路径处理过（已发布或挂起待发布）时，去重发布兜底后返回。
    const pushed = client._pushedSeqs.get(ns) as Set<number> | undefined;
    const pending = client._pendingOrderedMsgs.get(ns) as Map<number, unknown> | undefined;
    if (pushed?.has(seqNum) || pending?.has(seqNum)) {
      await this.publishGroupRecallTombstone(groupId, seq, wrapped as EventPayload);
      return;
    }
    const contigBefore = client._seqTracker.getContiguousSeq(ns);
    client._seqTracker.onMessageSeq(ns, seqNum);
    await this.publishGroupRecallTombstone(groupId, seq, wrapped as EventPayload);
    this.markPublishedSeq(ns, seqNum);
    client._markOrderedSeqDelivered?.(ns, seqNum);
    const contig = client._seqTracker.getContiguousSeq(ns);
    if (contig > 0) {
      const ackSeq = this.clampAckSeq('group.ack_messages', 'msg_seq', ns, contig);
      client._withBackgroundRpc(() => client._ackGroupV2(groupId, ackSeq))
        .catch((e: unknown) => { client._clientLog.debug(`group recall auto-ack failed: group=${groupId} ${formatDeliveryError(e)}`); });
    }
    if (contig !== contigBefore) this.persistSeq(ns);
  }

  publishAppEvent(event: string, payload: EventPayload, source = 'direct'): void | Promise<void> {
    const client = this.runtime.client;
    if ((event === 'message.received' || event === 'group.message_created') && isJsonObject(payload as JsonValue | object | null | undefined)) {
      client._maybeAppendEchoTraceReceive(payload as Record<string, unknown>);
    }
    this.logAppMessagePublish(event, payload, source);
    if (isJsonObject(payload as JsonValue | object | null | undefined)) {
      try {
        const snapshot = client._agentMdManager.eventSnapshot();
        if (snapshot) {
          const obj = payload as Record<string, unknown>;
          if (!('_agent_md' in obj)) {
            obj._agent_md = snapshot;
          }
        }
      } catch (err) {
        client._clientLog.debug(`agent_md etag inject skipped: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return client._dispatcher.publishSyncAware(event, this.normalizePublishedMessagePayload(event, payload));
  }

  messagePayloadForDebug(message: unknown): unknown {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) return message;
    const msg = message as JsonObject;
    if ('payload' in msg) return msg.payload;
    if ('content' in msg) return msg.content;
    if (typeof msg.envelope_json === 'string' && msg.envelope_json) {
      try {
        return JSON.parse(msg.envelope_json) as unknown;
      } catch {
        return msg.envelope_json;
      }
    }
    if (isJsonObject(msg.legacy_v1 as JsonValue | object | null | undefined)) {
      const legacy = msg.legacy_v1 as JsonObject;
      if ('payload' in legacy) return legacy.payload;
      if ('content' in legacy) return legacy.content;
    }
    return null;
  }

  messageEnvelopeFieldsForDebug(message: unknown): Record<string, unknown> {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) {
      return { value_type: typeof message };
    }
    const msg = message as JsonObject;
    const keys = [
      'message_id', 'id', 'from', 'from_aid', 'sender_aid', 'to', 'to_aid',
      'group_id', 'seq', 'msg_seq', 'type', 'version', 'timestamp', 't_server',
      'device_id', 'slot_id', 'encrypted', 'dispatch_mode', 'dispatch',
      'e2ee', 'headers', 'protected_headers', 'context', 'status',
      '_decrypt_error', '_decrypt_stage',
    ];
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(msg, key)) out[key] = msg[key];
    }
    return out;
  }

  logMessageDebug(
    stage: string,
    source: string,
    event: string,
    message: unknown,
    opts: { payloadOverride?: unknown; extra?: Record<string, unknown> } = {},
  ): void {
    const client = this.runtime.client;
    if (client._isMessageDebugEnabled?.() === false) return;
    const record: Record<string, unknown> = {
      stage,
      source,
      event,
      envelope: this.messageEnvelopeFieldsForDebug(message),
      payload: opts.payloadOverride !== undefined ? opts.payloadOverride : this.messagePayloadForDebug(message),
    };
    if (opts.extra) record.extra = opts.extra;
    client._clientLog.debug(`message.debug ${client._debugJson(record)}`);
  }

  logAppMessagePublish(event: string, payload: unknown, source: string): void {
    if (!['message.received', 'message.undecryptable', 'group.message_created', 'group.message_undecryptable'].includes(event)) {
      return;
    }
    this.logMessageDebug('publish', source, event, payload);
  }

  messageTargetsCurrentInstance(message: EventPayload): boolean {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) return true;
    const client = this.runtime.client;
    const msg = message as JsonObject;
    if ('device_id' in msg) {
      const targetDeviceId = String(msg.device_id ?? '').trim();
      if (targetDeviceId !== client._deviceId) {
        return false;
      }
    }
    if ('slot_id' in msg) {
      const targetSlotId = String(msg.slot_id ?? '').trim();
      if (slotIsolationKey(targetSlotId) !== slotIsolationKey(client._slotId)) {
        return false;
      }
    }
    return true;
  }

  async onRawMessageReceived(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    const tStart = Date.now();
    if (isJsonObject(data as JsonValue | object | null | undefined)) {
      client._logMessageDebug('server-push', '_raw.message.received', 'message.received', data);
      client._clientLog.debug(`_onRawMessageReceived enter: from=${String((data as JsonObject).from ?? '')}, message_id=${String((data as JsonObject).message_id ?? '')}, seq=${String((data as JsonObject).seq ?? '')}`);
    } else {
      client._clientLog.debug('_onRawMessageReceived enter: non-object payload');
    }
    this.processAndPublishMessage(data).catch((exc) => {
      client._clientLog.warn(`P2P message decrypt failed: ${formatDeliveryError(exc)}`);
      if (isJsonObject(data as JsonValue | object | null | undefined)) {
        const src = data as JsonObject;
        const safeEvent: JsonObject = {
          message_id: src.message_id,
          from: src.from,
          to: src.to,
          seq: src.seq,
          timestamp: src.timestamp,
          _decrypt_error: String(exc),
        };
        client._attachV2EnvelopeMetadataFromSource(safeEvent, data);
        Promise.resolve(client._publishAppEvent('message.undecryptable', safeEvent)).catch(() => {});
      }
    });
    client._clientLog.debug(`_onRawMessageReceived exit: elapsed=${Date.now() - tStart}ms (handler dispatched)`);
  }

  async processAndPublishMessage(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (!isJsonObject(data as JsonValue | object | null | undefined)) {
      await client._publishAppEvent('message.received', data, 'push');
      return;
    }
    const msg: Message = { ...(data as JsonObject) };
    if (!this.messageTargetsCurrentInstance(msg)) {
      client._clientLog.debug(`P2P push filtered by instance: message_id=${String(msg.message_id ?? '')}, seq=${String(msg.seq ?? '')}, target_device=${String(msg.device_id ?? '')}, target_slot=${String(msg.slot_id ?? '')}, local_device=${client._deviceId}, local_slot=${client._slotId}`);
      return;
    }

    const encryptedPush = client._isEncryptedPushMessage(msg);
    const seq = msg.seq as number | undefined;
    if (seq !== undefined && seq !== null && client._aid) {
      const ns = `p2p:${client._aid}`;
      if (seq > 0) client._seqTracker.updateMaxSeen(ns, seq);
      const contigBefore = client._seqTracker.getContiguousSeq(ns);
      const published = encryptedPush
        ? await client._publishEncryptedPushMessage('message.received', 'message.undecryptable', ns, seq, msg, false)
        : await this.publishOrderedMessage('message.received', ns, seq, msg);
      const contigAfter = client._seqTracker.getContiguousSeq(ns);
      const needPull = Number(seq) > contigAfter && !published;
      if (needPull) {
        client._clientLog.debug(`P2P seq gap detected: ns=${ns}, seq=${seq}, contiguous=${contigAfter}`);
        this.fillP2pGap().catch((exc) => client._clientLog.warn(`background gap fill trigger failed: ${formatDeliveryError(exc)}`));
      }
      const contig = client._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        const maxSeen = client._seqTracker.getMaxSeenSeq(ns);
        const ackSeq = this.clampAckSeq('message.ack', 'seq', ns, contig);
        client._clientLog.debug(`P2P push auto-ack send: ns=${ns}, seq=${ackSeq}, contiguous=${contig}, max_seen=${maxSeen}`);
        client._withBackgroundRpc(() => client._ackV2(ackSeq))
          .then(() => { client._clientLog.debug(`P2P push auto-ack ok: ns=${ns}, seq=${ackSeq}`); })
          .catch((e: unknown) => { client._clientLog.debug(`P2P auto-ack failed: ${formatDeliveryError(e)}`); });
      }
      if (contigAfter !== contigBefore) this.persistSeq(ns);
      if (encryptedPush) return;
    } else {
      if (encryptedPush) {
        await client._publishEncryptedPushMessage('message.received', 'message.undecryptable', '', seq ?? 0, msg, false);
        return;
      }
      await client._publishAppEvent('message.received', msg, 'push');
    }
  }

  async onRawGroupMessageCreated(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    const tStart = Date.now();
    if (isJsonObject(data as JsonValue | object | null | undefined)) {
      client._logMessageDebug('server-push', '_raw.group.message_created', 'group.message_created', data);
      client._clientLog.debug(`_onRawGroupMessageCreated enter: group_id=${String((data as JsonObject).group_id ?? '')}, message_id=${String((data as JsonObject).message_id ?? '')}, seq=${String((data as JsonObject).seq ?? '')}`);
    } else {
      client._clientLog.debug('_onRawGroupMessageCreated enter: non-object payload');
    }
    this.processAndPublishGroupMessage(data).catch((exc) => {
      client._clientLog.warn(`group message decrypt failed: ${formatDeliveryError(exc)}`);
      if (isJsonObject(data as JsonValue | object | null | undefined)) {
        const src = data as JsonObject;
        const safeEvent: JsonObject = {
          message_id: src.message_id,
          group_id: src.group_id,
          from: src.from,
          seq: src.seq,
          timestamp: src.timestamp,
          _decrypt_error: String(exc),
        };
        client._attachV2EnvelopeMetadataFromSource(safeEvent, data);
        Promise.resolve(client._publishAppEvent('group.message_undecryptable', safeEvent)).catch(() => {});
      }
    });
    client._clientLog.debug(`_onRawGroupMessageCreated exit: elapsed=${Date.now() - tStart}ms (handler dispatched)`);
  }

  async processAndPublishGroupMessage(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (!isJsonObject(data as JsonValue | object | null | undefined)) {
      await client._publishAppEvent('group.message_created', data, 'group-push');
      return;
    }
    const msg: Message = { ...(data as JsonObject) };
    const groupId = String(msg.group_id ?? '');
    const seq = msg.seq as number | undefined;
    const payload = msg.payload;

    if (groupId) {
      client._groupSynced.add(groupId);
    }

    if (payload === undefined || payload === null
      || (typeof payload === 'object' && Object.keys(payload as object).length === 0)) {
      void this.autoPullGroupMessages(msg).catch((exc) => {
        client._clientLog.warn(`auto pull group message task failed: ${formatDeliveryError(exc)}`);
      });
      return;
    }

    const encryptedPush = client._isEncryptedPushMessage(msg);
    if (groupId && seq !== undefined && seq !== null) {
      const ns = `group:${groupId}`;
      if (seq > 0) client._seqTracker.updateMaxSeen(ns, seq);
      const contigBefore = client._seqTracker.getContiguousSeq(ns);
      // 群撤回 tombstone（占位 / 通知）：归一化为 group.message_recalled，仍占 seq 推进 contiguous/ack。
      if (!encryptedPush && this.recallEventFromGroupMessage(msg)) {
        const published = await this.publishOrderedGroupRecall(ns, seq, msg);
        const contigAfter = client._seqTracker.getContiguousSeq(ns);
        const contig = client._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          const ackSeq = this.clampAckSeq('group.ack_messages', 'msg_seq', ns, contig);
          client._withBackgroundRpc(() => client._ackGroupV2(groupId, ackSeq))
            .catch((e: unknown) => { client._clientLog.debug(`group recall auto-ack failed: group=${groupId} ${formatDeliveryError(e)}`); });
        }
        if (contigAfter !== contigBefore) this.persistSeq(ns);
        void published;
        return;
      }
      const published = encryptedPush
        ? await client._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', ns, seq, msg, true)
        : await this.publishOrderedMessage('group.message_created', ns, seq, msg);
      const contigAfter = client._seqTracker.getContiguousSeq(ns);
      const needPull = Number(seq) > contigAfter && !published;
      if (needPull) {
        client._clientLog.debug(`group message seq gap detected: group=${groupId}, seq=${seq}, contiguous=${contigAfter}`);
        this.fillGroupGap(groupId).catch((exc) => client._clientLog.warn(`background gap fill trigger failed: ${formatDeliveryError(exc)}`));
      }
      const contig = client._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        const maxSeen = client._seqTracker.getMaxSeenSeq(ns);
        const ackSeq = this.clampAckSeq('group.ack_messages', 'msg_seq', ns, contig);
        client._clientLog.debug(`group push auto-ack send: group=${groupId}, ns=${ns}, seq=${ackSeq}, contiguous=${contig}, max_seen=${maxSeen}`);
        client._withBackgroundRpc(() => client._ackGroupV2(groupId, ackSeq))
          .then(() => { client._clientLog.debug(`group push auto-ack ok: group=${groupId}, seq=${ackSeq}`); })
          .catch((e: unknown) => { client._clientLog.debug(`group message auto-ack failed: group=${groupId} ${formatDeliveryError(e)}`); });
      }
      if (contigAfter !== contigBefore) this.persistSeq(ns);
      if (encryptedPush) return;
    } else {
      if (encryptedPush) {
        await client._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', '', seq ?? 0, msg, true);
        return;
      }
      await client._publishAppEvent('group.message_created', msg, 'group-push');
    }
  }

  async autoPullGroupMessages(notification: Message): Promise<void> {
    const client = this.runtime.client;
    let groupId = String(notification.group_id ?? '').trim();
    if (!groupId) {
      await client._publishAppEvent('group.message_created', notification);
      return;
    }
    groupId = normalizeGroupId(groupId) || groupId;
    const ns = `group:${groupId}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    client._clientLog.debug(`auto pull group messages start: group=${groupId}, after_seq=${afterSeq}, seq=${String(notification.seq ?? '')}`);
    const started = await client._tryRunBackgroundPull(ns, async () => {
      const pullAfterSeq = client._seqTracker.getContiguousSeq(ns);
      const messages = await client._pullGroupV2(groupId, pullAfterSeq, 50, { gateLocked: true });
      this.prunePushedSeqs(ns);
      return messages.length;
    }, true);
    if (!started) {
      client._clientLog.debug(`auto pull group messages skipped: pull in-flight group=${groupId}`);
    }
  }

  async fillP2pGap(): Promise<void> {
    const client = this.runtime.client;
    if (!client._aid) return;
    const ns = `p2p:${client._aid}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    const dedupKey = `p2p:${afterSeq}`;
    if (client._gapFillDone.has(dedupKey)) return;
    const token = client._tryAcquirePullGate(ns);
    if (token === null) {
      client._clientLog.debug(`P2P message gap fill skipped: pull in-flight ns=${ns}`);
      return;
    }
    client._gapFillDone.set(dedupKey, Date.now());
    client._clientLog.debug(`P2P message gap fill start: after_seq=${afterSeq}`);
    let filled = 0;
    try {
      const messages = await client._withBackgroundRpc(() => client._pullV2(afterSeq, 50, { skipAutoAck: true, gateLocked: true }));
      filled = messages.length;
      this.prunePushedSeqs(ns);
      if (client._seqTracker.getContiguousSeq(ns) !== afterSeq) {
        await this.drainOrderedMessages(ns, undefined, true);
        this.persistSeq(ns);
      }
      const contig = client._seqTracker.getContiguousSeq(ns);
      if (contig > 0 && contig !== afterSeq) {
        await client._withBackgroundRpc(() => client._ackV2(contig));
      }
      client._clientLog.debug(`P2P message gap fill done: after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      client._clientLog.warn(`P2P message gap fill failed: ${formatDeliveryError(exc)}`);
    } finally {
      client._gapFillDone.delete(dedupKey);
      client._releasePullGate(ns, token);
    }
  }

  async fillGroupGap(groupId: string): Promise<void> {
    const client = this.runtime.client;
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!groupId) return;
    const ns = `group:${groupId}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    const dedupKey = `group_msg:${groupId}:${afterSeq}`;
    if (client._gapFillDone.has(dedupKey)) return;
    const token = client._tryAcquirePullGate(ns);
    if (token === null) {
      client._clientLog.debug(`group message gap fill skipped: pull in-flight group=${groupId}`);
      return;
    }
    client._gapFillDone.set(dedupKey, Date.now());
    client._clientLog.debug(`group message gap fill start: group=${groupId}, after_seq=${afterSeq}`);
    let filled = 0;
    try {
      const messages = await client._withBackgroundRpc(() => client._pullGroupV2(groupId, afterSeq, 50, { gateLocked: true }));
      filled = messages.length;
      this.prunePushedSeqs(ns);
      if (client._seqTracker.getContiguousSeq(ns) !== afterSeq) {
        await this.drainOrderedMessages(ns, undefined, true);
        this.persistSeq(ns);
      }
      client._clientLog.debug(`group message gap fill done: group=${groupId}, after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      client._clientLog.warn(`group message gap fill failed: ${formatDeliveryError(exc)}`);
    } finally {
      client._gapFillDone.delete(dedupKey);
      client._releasePullGate(ns, token);
      if (filled > 0 && client._seqTracker.getContiguousSeq(ns) > afterSeq) {
        void this.fillGroupGap(groupId);
      }
    }
  }

  async fillGroupEventGap(groupId: string): Promise<void> {
    const client = this.runtime.client;
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!groupId) return;
    const ns = `group_event:${groupId}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    const dedupKey = `group_evt:${groupId}:${afterSeq}`;
    if (client._gapFillDone.has(dedupKey)) return;
    const token = client._tryAcquirePullGate(ns);
    if (token === null) {
      client._clientLog.debug(`group event gap fill skipped: pull in-flight group=${groupId}`);
      return;
    }
    client._gapFillDone.set(dedupKey, Date.now());
    let filled = 0;
    try {
      let nextAfterSeq = afterSeq;
      const maxPages = 100;
      let pageCount = 0;
      while (pageCount < maxPages) {
        pageCount += 1;
        client._clientLog.debug(`group event gap fill start: group=${groupId}, after_seq=${nextAfterSeq}`);
        const result = await client.call('group.pull_events', {
          group_id: groupId,
          after_event_seq: nextAfterSeq,
          device_id: client._deviceId,
          limit: 50,
          _pull_gate_locked: true,
          _rpc_background: true,
        });
        if (!isJsonObject(result as JsonValue | object | null | undefined)) return;
        const events = (result as JsonObject).events;
        if (!Array.isArray(events)) return;
        const pageContigBefore = client._seqTracker.getContiguousSeq(ns);
        const eventObjects = events.filter((evt): evt is JsonObject => isJsonObject(evt as JsonValue | object | null | undefined));
        if (eventObjects.length > 0) {
          client._seqTracker.onPullResult(ns, eventObjects, nextAfterSeq);
        }
        const cursor = isJsonObject((result as JsonObject).cursor as JsonValue | object | null | undefined)
          ? (result as JsonObject).cursor as JsonObject
          : null;
        const cursorCurrentSeq = Number(cursor?.current_seq ?? 0);
        const retentionFloor = Math.max(
          client._pullRetentionFloor(result as JsonObject, 'retention_floor_event_seq', 'retention_floor_event_seq'),
          Number.isFinite(cursorCurrentSeq) ? cursorCurrentSeq : 0,
        );
        if (retentionFloor > 0) {
          const contigBeforeFloor = client._seqTracker.getContiguousSeq(ns);
          if (contigBeforeFloor < retentionFloor) {
            client._clientLog.info(`group.pull_events cursor/floor advance: ns=${ns} contiguous=${contigBeforeFloor} -> cursor.current_seq=${cursorCurrentSeq} floor=${retentionFloor}`);
            client._seqTracker.forceContiguousSeq(ns, retentionFloor);
          }
        }
        const eventSeqs: number[] = [];
        let hasDissolvedEvent = false;
        for (const evt of eventObjects) {
          const eventSeq = Number(evt.event_seq ?? 0);
          if (Number.isFinite(eventSeq) && eventSeq > 0) eventSeqs.push(eventSeq);
          evt._from_gap_fill = true;
          if (evt.action === 'dissolved') hasDissolvedEvent = true;
          const et = String(evt.event_type ?? '');
          if (et !== 'group.message_created') {
            const cs = evt.client_signature;
            if (cs && isJsonObject(cs as JsonValue | object | null | undefined)) {
              if (client._shouldSkipEventSignature(evt)) {
                delete evt.client_signature;
              } else {
                evt._verified = await client._verifyEventSignatureAsync(evt, cs as JsonObject);
              }
            }
            if (Number.isFinite(eventSeq) && eventSeq > 0 && !client._pushedSeqs.get(ns)?.has(eventSeq)) {
              this.enqueueOrderedMessage(ns, 'group.changed', eventSeq, evt);
            }
          }
          filled += 1;
        }
        const ackContig = client._seqTracker.getContiguousSeq(ns);
        await this.drainOrderedMessages(ns);
        if (ackContig !== pageContigBefore && !hasDissolvedEvent) {
          this.persistSeq(ns);
        }
        if (eventObjects.length > 0 && ackContig > 0 && ackContig !== pageContigBefore) {
          const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, ackContig);
          client._transport.call('group.ack_events', {
            group_id: groupId,
            event_seq: ackSeq,
            device_id: client._deviceId,
            slot_id: client._slotId,
          }, undefined, undefined, true).catch((e: unknown) => {
            client._clientLog.debug(`group event auto-ack failed: group=${groupId} ${formatDeliveryError(e)}`);
          });
        }
        const nextAfter = Math.max(eventSeqs.length > 0 ? Math.max(...eventSeqs) : nextAfterSeq, nextAfterSeq);
        if (eventObjects.length === 0 || nextAfter <= nextAfterSeq || (result as JsonObject).has_more === false) break;
        nextAfterSeq = nextAfter;
      }
      if (pageCount >= maxPages) {
        client._clientLog.warn(`group event gap fill reached max_pages=${maxPages} group=${groupId} after_seq=${nextAfterSeq}`);
      }
      client._clientLog.debug(`group event gap fill done: group=${groupId}, after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      client._clientLog.warn(`group event gap fill failed: ${formatDeliveryError(exc)}`);
    } finally {
      client._gapFillDone.delete(dedupKey);
      client._releasePullGate(ns, token);
      if (filled > 0 && client._seqTracker.getContiguousSeq(ns) > afterSeq) {
        void this.fillGroupEventGap(groupId);
      }
    }
  }

  async handleGroupChangedEventSeq(data: JsonObject, groupId: string): Promise<void> {
    const client = this.runtime.client;
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    let needPull = false;
    const rawEventSeq = data.event_seq;
    const eventSeq = Number(rawEventSeq);
    if (!groupId || !Number.isFinite(eventSeq) || !Number.isInteger(eventSeq) || eventSeq <= 0) {
      await this.publishOrderedGroupChanged(data, 'legacy');
      return;
    }

    const ns = `group_event:${groupId}`;
    if (this.isSelfJoinGroupChanged(data)) {
      const contig = client._seqTracker.getContiguousSeq(ns);
      const maxSeen = client._seqTracker.getMaxSeenSeq(ns);
      if (contig === 0 && maxSeen === 0 && eventSeq > 1) {
        client._clientLog.debug(`group.changed self-join baseline: group=${groupId}, event_seq=${eventSeq}, baseline=${eventSeq - 1}`);
        client._seqTracker.forceContiguousSeq(ns, eventSeq - 1);
      }
    }
    const contigBefore = client._seqTracker.getContiguousSeq(ns);
    if (eventSeq <= contigBefore || client._pushedSeqs.get(ns)?.has(eventSeq)) {
      client._clientLog.debug(`group.changed skipped duplicate/stale: group=${groupId}, event_seq=${eventSeq}, contiguous=${contigBefore}`);
      this.fireGroupEventAck(groupId, Math.min(eventSeq, contigBefore > 0 ? contigBefore : eventSeq), 'covered push');
      return;
    }

    this.enqueueOrderedMessage(ns, 'group.changed', eventSeq, data);
    needPull = client._seqTracker.onMessageSeq(ns, eventSeq);
    const ackContig = client._seqTracker.getContiguousSeq(ns);
    await this.drainOrderedMessages(ns);

    if (ackContig > 0 && ackContig !== contigBefore) {
      if (data.action !== 'dissolved') this.persistSeq(ns);
      const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, ackContig);
      client._transport.call('group.ack_events', {
        group_id: groupId,
        event_seq: ackSeq,
        device_id: client._deviceId,
        slot_id: client._slotId,
      }, undefined, undefined, true).catch((e: unknown) => {
        client._clientLog.debug(`group event push auto-ack failed: group=${groupId} ${formatDeliveryError(e)}`);
      });
    }

    if (needPull && groupId && !data._from_gap_fill) {
      this.fillGroupEventGap(groupId).catch((exc) => {
        client._clientLog.warn(`background gap fill trigger failed: ${formatDeliveryError(exc)}`);
      });
    }
  }

  private fireGroupEventAck(groupId: string, eventSeq: number, reason: string): void {
    const client = this.runtime.client;
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) return;
    const ns = `group_event:${gid}`;
    const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, Number(eventSeq) || 0);
    if (ackSeq <= 0) return;
    const params: RpcParams = {
      group_id: gid,
      event_seq: ackSeq,
      device_id: client._deviceId,
      slot_id: client._slotId,
      _rpc_background: true,
    };
    try {
      Promise.resolve(client.call('group.ack_events', params)).catch((e: unknown) => {
        client._clientLog.debug(`group event ${reason} ack failed: group=${gid} ${formatDeliveryError(e)}`);
      });
    } catch (e) {
      client._clientLog.debug(`group event ${reason} ack failed: group=${gid} ${formatDeliveryError(e)}`);
    }
  }

  private fireGroupV2Ack(groupId: string, upToSeq: number, reason: string): void {
    const client = this.runtime.client;
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) return;
    const ns = `group:${gid}`;
    const ackSeq = this.clampAckSeq('group.v2.ack', 'up_to_seq', ns, Number(upToSeq) || 0);
    if (ackSeq <= 0) return;
    try {
      Promise.resolve(client.call('group.v2.ack', {
        group_id: gid,
        up_to_seq: ackSeq,
        _rpc_background: true,
      })).catch((e: unknown) => {
        client._clientLog.debug(`group.v2 ${reason} ack failed: group=${gid} ${formatDeliveryError(e)}`);
      });
    } catch (e) {
      client._clientLog.debug(`group.v2 ${reason} ack failed: group=${gid} ${formatDeliveryError(e)}`);
    }
  }

  isSelfJoinGroupChanged(data: JsonObject): boolean {
    const action = String(data.action ?? '').trim();
    if (!['member_added', 'joined', 'join_approved', 'invite_code_used'].includes(action)) return false;
    const selfAid = String(this.runtime.client._aid ?? '').trim();
    if (!selfAid) return false;
    const joinedAid = String(data.joined_aid ?? data.member_aid ?? data.aid ?? '').trim();
    if (joinedAid === selfAid) return true;
    const actorAid = String(data.actor_aid ?? '').trim();
    return !joinedAid && ['joined', 'invite_code_used'].includes(action) && actorAid === selfAid;
  }

  async onV2PushNotification(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (!client._v2Session) return;

    const pushSeq = isJsonObject(data as JsonValue | object | null | undefined) ? Number((data as JsonObject).seq ?? 0) || 0 : 0;
    const pushFrom = isJsonObject(data as JsonValue | object | null | undefined) ? String((data as JsonObject).from_aid ?? '') : '';
    const pushMsgId = isJsonObject(data as JsonValue | object | null | undefined) ? String((data as JsonObject).message_id ?? '') : '';
    const envelopeJson = isJsonObject(data as JsonValue | object | null | undefined) ? (data as JsonObject).envelope_json : undefined;
    const hasPayload = !!envelopeJson;

    const ns = client._aid ? `p2p:${client._aid}` : '';
    let contigBefore = ns ? client._seqTracker.getContiguousSeq(ns) : 0;

    client._clientLog.debug(
      `_onV2PushNotification: push_seq=${pushSeq || 'null'} push_from=${pushFrom} push_msg_id=${pushMsgId} has_payload=${hasPayload} contiguous_seq=${contigBefore}`
    );

    if (pushSeq > 0 && ns) {
      client._seqTracker.updateMaxSeen(ns, pushSeq);
      if (contigBefore === pushSeq) {
        client._clientLog.debug(
          `_onV2PushNotification: push seq=${pushSeq} already covered by contiguous_seq=${contigBefore}, ignore duplicate push`
        );
        return;
      }
      contigBefore = client._repairPushContiguousBound(
        ns,
        pushSeq,
        hasPayload,
        '_raw.peer.v2.message_received',
      );
    }

    if (hasPayload && pushSeq > 0 && ns) {
      try {
        const decrypted = await client._decryptV2PushMessage(data);
        if (decrypted) {
          const published = await client._publishOrderedMessage('message.received', ns, pushSeq, decrypted as EventPayload);
          const newContig = client._seqTracker.getContiguousSeq(ns);
          const needPull = pushSeq > newContig && !published;
          if (newContig !== contigBefore) {
            this.persistSeq(ns);
          }
          if (newContig > 0 && newContig !== contigBefore) {
            const ackSeq = this.clampAckSeq('message.v2.ack', 'up_to_seq', ns, newContig);
            try {
              await client.call('message.v2.ack', { up_to_seq: ackSeq, _rpc_background: true });
            } catch (e) {
              client._clientLog.debug(`V2 P2P push-ack failed: ${formatDeliveryError(e)}`);
            }
          }
          client._clientLog.debug(
            `_onV2PushNotification: push 带 payload 解密成功, contiguous_seq=${contigBefore}->${newContig} push_seq=${pushSeq}`
          );
          if (!needPull && (published || newContig >= pushSeq || pushSeq <= contigBefore)) {
            return;
          }
          client._clientLog.debug(
            `_onV2PushNotification: payload push seq=${pushSeq} 因空洞挂起，继续 pull 补齐 after_seq=${newContig}`
          );
        }
      } catch (exc) {
        client._clientLog.debug(`_onV2PushNotification: push payload 解密失败, fallback to pull: ${formatDeliveryError(exc)}`);
      }
    }

    if (pushSeq > 0 && ns) {
      client._clientLog.debug(
        `_onV2PushNotification: 纯通知 push_seq=${pushSeq} > contiguous_seq=${contigBefore}, 触发 pull(after_seq=${contigBefore})`
      );
    }
    if (!ns) return;
    await client._tryRunBackgroundPull(ns, async () => {
      const operationBefore = client._seqTracker.getContiguousSeq(ns);
      const dedupKey = `p2p_pull:${ns}`;
      if (client._gapFillDone.has(dedupKey)) {
        client._recordPendingP2pPull(ns, pushSeq);
        return 0;
      }
      client._gapFillDone.set(dedupKey, Date.now());
      try {
        const pulled = await client._pullV2(0, 50, { gateLocked: true });
        const newContig = client._seqTracker.getContiguousSeq(ns);
        client._clientLog.debug(
          `_onV2PushNotification pull done: contiguous_seq=${contigBefore}->${newContig} (push_seq=${pushSeq || 'null'})`
        );
        if (newContig <= operationBefore) return 0;
        return pulled.length;
      } finally {
        client._gapFillDone.delete(dedupKey);
      }
    }, true, () => client._recordPendingP2pPull(ns, pushSeq)).catch((exc: unknown) => {
      const newContig = client._seqTracker.getContiguousSeq(ns);
      client._clientLog.warn(
        `V2 push auto-pull failed: contiguous_seq=${contigBefore}->${newContig} err=${formatDeliveryError(exc)}`
      );
    });
  }

  enqueueOnlineUnreadHint(data: JsonObject): void {
    const client = this.runtime.client;
    const groupId = String(data.group_id ?? '').trim();
    if (!groupId) return;
    client._onlineUnreadHintQueue.set(groupId, { ...data });
    if (client._onlineUnreadHintTimer || client._onlineUnreadHintDrainActive) return;
    const delayMs = Math.max(0, Number(client._onlineUnreadHintInitialDelayMs ?? 750) || 0);
    this.runtime.delivery.setOnlineUnreadHintTimer(setTimeout(() => {
      this.runtime.delivery.setOnlineUnreadHintTimer(null);
      client._safeAsync(this.drainOnlineUnreadHints());
    }, delayMs));
  }

  async drainOnlineUnreadHints(): Promise<void> {
    const client = this.runtime.client;
    if (client._onlineUnreadHintDrainActive) return;
    this.runtime.delivery.setOnlineUnreadHintDrainActive(true);
    try {
      while (client._onlineUnreadHintQueue.size > 0) {
        if (client.state !== ConnectionState.READY) return;
        if (client._sessionOptions?.background_sync === false) return;
        const groupId = client._onlineUnreadHintQueue.keys().next().value as string | undefined;
        if (!groupId) return;
        const payload = client._onlineUnreadHintQueue.get(groupId) as JsonObject | undefined;
        client._onlineUnreadHintQueue.delete(groupId);
        if (!payload) continue;
        await this.onRawGroupV2MessageCreated({ ...payload, _online_hint_drained: true });
        const intervalMs = Math.max(0, Number(client._onlineUnreadHintIntervalMs ?? 50) || 0);
        if (intervalMs > 0 && client._onlineUnreadHintQueue.size > 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, intervalMs));
        }
      }
    } catch (exc) {
      client._clientLog.debug(`online unread hint drain failed: ${formatDeliveryError(exc)}`);
    } finally {
      this.runtime.delivery.setOnlineUnreadHintDrainActive(false);
    }
  }

  async onRawGroupV2MessageCreated(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (!isJsonObject(data as JsonValue | object | null | undefined) || !client._v2Session) {
      client._clientLog.debug(`_onRawGroupV2MessageCreated skipped: is_object=${String(isJsonObject(data as JsonValue | object | null | undefined))}, has_v2_session=${String(!!client._v2Session)}`);
      return;
    }
    const d = data as JsonObject;
    client._logMessageDebug('server-push', '_raw.group.v2.message_created', 'group.message_created', d);
    const rawGroupId = String(d.group_id ?? '').trim();
    const groupId = normalizeGroupId(rawGroupId) || rawGroupId;
    const seq = Number(d.seq ?? 0);
    if (!groupId || !Number.isFinite(seq) || seq <= 0) {
      client._clientLog.debug(`_onRawGroupV2MessageCreated skipped: group=${groupId || '<empty>'}, seq=${String(d.seq ?? '')}`);
      return;
    }
    const eventKind = String(d.kind ?? '').trim();
    if (eventKind === 'group.online_unread_hint' && !d._online_hint_drained) {
      if (client._sessionOptions?.background_sync === false) {
        client._clientLog.debug(`_onRawGroupV2MessageCreated skipped online unread hint: group=${groupId} background_sync=false`);
        return;
      }
      this.enqueueOnlineUnreadHint(d);
      return;
    }
    const ns = `group:${groupId}`;
    client._seqTracker.updateMaxSeen(ns, seq);
    const contigBefore = client._seqTracker.getContiguousSeq(ns);
    client._clientLog.debug(`_onRawGroupV2MessageCreated enter: group=${groupId}, seq=${seq}, contiguous=${contigBefore}, max_seen=${client._seqTracker.getMaxSeenSeq(ns)}`);
    if (contigBefore === seq || (eventKind === 'group.online_unread_hint' && contigBefore > seq)) {
      client._clientLog.debug(
        `_onRawGroupV2MessageCreated duplicate push already covered: group=${groupId} seq=${seq}`,
      );
      this.fireGroupV2Ack(groupId, seq, 'covered push');
      return;
    }
    const afterSeq = client._repairPushContiguousBound(
      ns,
      seq,
      false,
      '_raw.group.v2.message_created',
    );
    const dedupKey = `v2_group_push:${groupId}:${afterSeq}`;
    const pullTask = client._tryRunBackgroundPull(ns, async () => {
      const pullAfterSeq = client._seqTracker.getContiguousSeq(ns);
      if (client._gapFillDone.has(dedupKey)) {
        client._clientLog.debug(`_onRawGroupV2MessageCreated skipped duplicate in-flight pull: group=${groupId}, dedup=${dedupKey}`);
        return 0;
      }
      client._gapFillDone.set(dedupKey, Date.now());
      try {
        client._clientLog.debug(`_onRawGroupV2MessageCreated auto-pull start: group=${groupId}, after_seq=${pullAfterSeq}, push_seq=${seq}`);
        const pulled = await client._pullGroupV2(groupId, pullAfterSeq, 50, { gateLocked: true });
        const newContig = client._seqTracker.getContiguousSeq(ns);
        client._clientLog.debug(`_onRawGroupV2MessageCreated auto-pull done: group=${groupId}, after_seq=${pullAfterSeq}, push_seq=${seq}, contiguous=${newContig}`);
        if (newContig <= pullAfterSeq) return 0;
        return pulled.length;
      } finally {
        client._gapFillDone.delete(dedupKey);
      }
    }, true).catch((exc: unknown) => {
      client._clientLog.warn(`V2 group push auto-pull failed: group=${groupId} err=${formatDeliveryError(exc)}`);
    });
    if (d._online_hint_drained) {
      await pullTask;
    }
  }

  restoreSeqTrackerState(): void {
    const client = this.runtime.client;
    if (!client._aid) return;
    try {
      const loadAll = client._tokenStore.loadAllSeqs;
      if (typeof loadAll === 'function') {
        let state = loadAll.call(client._tokenStore, client._aid, client._deviceId, client._slotId) as Record<string, number> | undefined;
        if (state && Object.keys(state).length > 0) {
          state = this.migrateSeqStateGroupIds(state);
          client._seqTracker.restoreState(state);
          return;
        }
      }

      const loader = client._tokenStore.loadInstanceState;
      if (typeof loader === 'function') {
        const instanceState = loader.call(client._tokenStore, client._aid, client._deviceId, client._slotId);
        if (instanceState && typeof instanceState.seq_tracker_state === 'object') {
          let state = instanceState.seq_tracker_state as Record<string, number>;
          state = this.migrateSeqStateGroupIds(state);
          client._seqTracker.restoreState(state);
        }
      }
    } catch (exc) {
      const error = formatDeliveryError(exc);
      client._clientLog.warn(`restore SeqTracker state failed: ${error}`);
      client._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'restore',
        aid: client._aid,
        device_id: client._deviceId,
        slot_id: client._slotId,
        error: String(error),
      }).catch(() => {});
    }
  }

  migrateSeqStateGroupIds(state: Record<string, number>): Record<string, number> {
    const client = this.runtime.client;
    if (!state || Object.keys(state).length === 0) return state;
    const renameMap: Record<string, string> = {};
    for (const ns of Object.keys(state)) {
      for (const prefix of ['group_event:', 'group_msg:']) {
        if (ns.startsWith(prefix)) {
          const oldGid = ns.slice(prefix.length);
          const newGid = normalizeGroupId(oldGid);
          if (newGid && newGid !== oldGid) {
            renameMap[ns] = `${prefix}${newGid}`;
          }
          break;
        }
      }
    }
    if (Object.keys(renameMap).length === 0) return state;

    const newState: Record<string, number> = { ...state };
    for (const [oldNs, newNs] of Object.entries(renameMap)) {
      const oldVal = Number(newState[oldNs] ?? 0);
      const curVal = Number(newState[newNs] ?? 0);
      delete newState[oldNs];
      newState[newNs] = Math.max(oldVal, curVal);
    }
    client._clientLog.info(`SeqTracker group_id migration: ${Object.keys(renameMap).length} namespaces rewritten`);

    const saver = client._tokenStore.saveSeq;
    const deleter = client._tokenStore.deleteSeq;
    if (typeof saver === 'function' && client._aid) {
      for (const [oldNs, newNs] of Object.entries(renameMap)) {
        if (typeof deleter === 'function') {
          try {
            deleter.call(client._tokenStore, client._aid, client._deviceId, client._slotId, oldNs);
          } catch (e) {
            client._clientLog.debug(`delete old seq ns failed: ns=${oldNs} err=${formatDeliveryError(e)}`);
          }
        }
        try {
          saver.call(client._tokenStore, client._aid, client._deviceId, client._slotId, newNs, newState[newNs]);
        } catch (e) {
          client._clientLog.debug(`write new seq ns failed: ns=${newNs} err=${formatDeliveryError(e)}`);
        }
      }
    }
    return newState;
  }

  saveSeqTrackerState(): void {
    const client = this.runtime.client;
    const context = this.currentSeqTrackerContext();
    if (!context) {
      this.flushSeqTrackerPending();
      return;
    }
    const state = client._seqTracker.exportState();
    const pending = this.seqTrackerPending();
    if (pending.size > 0 && client._seqTrackerPendingPersistContext === context) {
      const liveNamespaces = new Set(Object.keys(state));
      for (const ns of [...pending.keys()]) {
        if (!liveNamespaces.has(ns)) pending.delete(ns);
      }
      if (pending.size === 0) client._seqTrackerPendingPersistContext = null;
    }
    if (Object.keys(state).length > 0) this.mergeSeqTrackerPending(context, state);
    this.flushSeqTrackerPending();
  }

  persistSeq(ns: string, forceSeq?: number): void {
    const client = this.runtime.client;
    const context = this.currentSeqTrackerContext();
    if (!context) {
      this.flushSeqTrackerPending();
      return;
    }
    const seq = forceSeq ?? client._seqTracker.getContiguousSeq(ns);
    if (!ns || !Number.isFinite(seq) || seq <= 0) return;
    if (forceSeq !== undefined) {
      client._seqTracker.forceContiguousSeq(ns, seq);
    }
    this.mergeSeqTrackerPending(context, { [ns]: seq });
    this.scheduleSeqTrackerFlush();
  }

  flushSeqTrackerPending(): void {
    const client = this.runtime.client;
    this.cancelSeqTrackerFlushTimer();
    const context = client._seqTrackerPendingPersistContext as string | null | undefined;
    const pending = this.seqTrackerPending();
    if (!context || pending.size === 0) {
      client._seqTrackerPendingPersistContext = null;
      return;
    }
    const [aid, deviceId, slotId] = JSON.parse(context) as [string, string, string];
    const state = Object.fromEntries(pending.entries());
    pending.clear();
    client._seqTrackerPendingPersistContext = null;
    this.writeSeqTrackerState(aid, deviceId, slotId, state);
  }

  private dropSeqTrackerPending(ns: string): void {
    const client = this.runtime.client;
    const pending = this.seqTrackerPending();
    pending.delete(ns);
    if (pending.size === 0) {
      client._seqTrackerPendingPersistContext = null;
      this.cancelSeqTrackerFlushTimer();
    }
  }

  private currentSeqTrackerContext(): string | null {
    const client = this.runtime.client;
    if (!client._aid) return null;
    return JSON.stringify([client._aid, client._deviceId, client._slotId]);
  }

  private seqTrackerPending(): Map<string, number> {
    const client = this.runtime.client;
    if (!(client._seqTrackerPendingPersist instanceof Map)) {
      client._seqTrackerPendingPersist = new Map<string, number>();
    }
    return client._seqTrackerPendingPersist as Map<string, number>;
  }

  private mergeSeqTrackerPending(context: string, state: Record<string, number>): void {
    const client = this.runtime.client;
    const pending = this.seqTrackerPending();
    const pendingContext = client._seqTrackerPendingPersistContext as string | null | undefined;
    if (pendingContext && pendingContext !== context && pending.size > 0) {
      this.flushSeqTrackerPending();
    }
    client._seqTrackerPendingPersistContext = context;
    for (const [ns, seq] of Object.entries(state)) {
      const seqNum = Number(seq);
      if (ns && Number.isFinite(seqNum) && seqNum > 0) {
        pending.set(ns, seqNum);
      }
    }
  }

  private scheduleSeqTrackerFlush(): void {
    const client = this.runtime.client;
    const pending = this.seqTrackerPending();
    if (pending.size === 0) return;
    if (client._seqTrackerFlushTimer) return;
    client._seqTrackerFlushTimer = setTimeout(() => {
      client._seqTrackerFlushTimer = null;
      this.flushSeqTrackerPending();
    }, SEQ_TRACKER_PERSIST_FLUSH_DELAY_MS);
  }

  private cancelSeqTrackerFlushTimer(): void {
    const client = this.runtime.client;
    if (client._seqTrackerFlushTimer) {
      clearTimeout(client._seqTrackerFlushTimer);
      client._seqTrackerFlushTimer = null;
    }
  }

  private writeSeqTrackerState(aid: string, deviceId: string, slotId: string, state: Record<string, number>): void {
    const client = this.runtime.client;
    if (!aid || Object.keys(state).length === 0) return;
    try {
      const saveFn = client._tokenStore.saveSeq;
      if (typeof saveFn === 'function') {
        for (const [ns, seq] of Object.entries(state)) {
          saveFn.call(client._tokenStore, aid, deviceId, slotId, ns, seq);
        }
        return;
      }

      const updater = client._tokenStore.updateInstanceState;
      if (typeof updater === 'function') {
        updater.call(client._tokenStore, aid, deviceId, slotId, (metadata: JsonObject) => {
          const existing = isJsonObject(metadata.seq_tracker_state as JsonValue | object | null | undefined)
            ? { ...(metadata.seq_tracker_state as JsonObject) }
            : {};
          metadata.seq_tracker_state = { ...existing, ...state } as unknown as JsonValue;
          return metadata;
        });
      }
    } catch (exc) {
      const error = formatDeliveryError(exc);
      client._clientLog.warn(`save SeqTracker state failed: ${error}`);
      client._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'save',
        aid,
        device_id: deviceId,
        slot_id: slotId,
        error: String(error),
      }).catch(() => {});
    }
  }

  persistRepairedSeq(ns: string): void {
    const client = this.runtime.client;
    if (!client._aid || !ns) return;
    const seq = client._seqTracker.getContiguousSeq(ns);
    this.dropSeqTrackerPending(ns);
    try {
      if (seq > 0 && typeof client._tokenStore.saveSeq === 'function') {
        client._tokenStore.saveSeq(client._aid, client._deviceId, client._slotId, ns, seq);
        return;
      }
      const deleteSeq = client._tokenStore.deleteSeq;
      if (seq <= 0 && typeof deleteSeq === 'function') {
        deleteSeq.call(client._tokenStore, client._aid, client._deviceId, client._slotId, ns);
        return;
      }
      const updater = client._tokenStore.updateInstanceState;
      if (seq <= 0 && typeof updater === 'function') {
        updater.call(client._tokenStore, client._aid, client._deviceId, client._slotId, (metadata: JsonObject) => {
          if (isJsonObject(metadata.seq_tracker_state as JsonValue | object | null | undefined)) {
            const next = { ...(metadata.seq_tracker_state as JsonObject) };
            delete next[ns];
            metadata.seq_tracker_state = next as unknown as JsonValue;
          }
          return metadata;
        });
        return;
      }
      if (seq > 0) {
        this.saveSeqTrackerState();
      }
    } catch (exc) {
      client._clientLog.debug(`persist repaired seq failed: ns=${ns} err=${formatDeliveryError(exc)}`);
    }
  }

  clampAckSeq(method: string, field: string, ns: string, seq: number): number {
    const client = this.runtime.client;
    const original = seq;
    let next = Number(seq);
    if (!Number.isFinite(next)) return 0;
    if (next < 0) next = 0;
    if (ns) {
      const maxSeen = client._seqTracker.getMaxSeenSeq(ns);
      if (maxSeen > 0 && next > maxSeen) {
        client._clientLog.warn(`ack clamp: method=${method} ${field}=${original} > max_seen=${maxSeen}, clamp`);
        next = maxSeen;
      }
    }
    return next;
  }

  clampAckParams(method: string, params: RpcParams): RpcParams {
    const client = this.runtime.client;
    const clampField = (field: string, ns: string): RpcParams => {
      const raw = params[field];
      if (typeof raw !== 'number' || !Number.isFinite(raw)) return params;
      const next = this.clampAckSeq(method, field, ns, raw);
      return next === raw ? params : { ...params, [field]: next };
    };

    if (method === 'message.v2.ack') {
      const ns = client._aid ? `p2p:${client._aid}` : '';
      return clampField('up_to_seq', ns);
    }
    if (method === 'message.ack') {
      const ns = client._aid ? `p2p:${client._aid}` : '';
      return clampField('seq', ns);
    }
    if (method === 'group.v2.ack' || method === 'group.ack_messages' || method === 'group.ack_events') {
      const groupId = normalizeGroupId(String(params.group_id ?? '')) || String(params.group_id ?? '').trim();
      const ns = groupId ? `group:${groupId}` : '';
      if (method === 'group.v2.ack') return clampField('up_to_seq', ns);
      if (method === 'group.ack_messages') return clampField('msg_seq', ns);
      if (method === 'group.ack_events') return clampField('event_seq', groupId ? `group_event:${groupId}` : '');
    }
    return params;
  }

  async drainOrderedMessages(ns: string, beforeSeq?: number, pullResponse = false): Promise<void> {
    const client = this.runtime.client;
    const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    if (!queue || queue.size === 0) return;
    let delivered = false;
    while (true) {
      const contig = client._seqTracker.getContiguousSeq(ns);
      const ready = [...queue.keys()]
        .filter((seq) => seq <= contig && (beforeSeq === undefined || seq < beforeSeq))
        .sort((a, b) => a - b);
      let seq: number | undefined = ready[0];
      if (seq === undefined) {
        const nextSeq = contig + 1;
        if (beforeSeq !== undefined && nextSeq >= beforeSeq) break;
        if (!queue.has(nextSeq)) break;
        seq = nextSeq;
      }
      if (seq === undefined) continue;
      const item = queue.get(seq);
      queue.delete(seq);
      if (!item) continue;
      if (client._pushedSeqs.get(ns)?.has(seq)) {
        client._clientLog.debug(`publish ordered drain skipped duplicate: ns=${ns}, seq=${seq}, event=${item.event}`);
        client._markOrderedSeqDelivered(ns, seq);
        continue;
      }
      await this.publishOrderedQueueItem(ns, item.event, seq, item.payload, 'ordered-drain', pullResponse);
      this.markPublishedSeq(ns, seq);
      client._markOrderedSeqDelivered(ns, seq);
      delivered = true;
      client._clientLog.debug(`publish ordered drain delivered: ns=${ns}, seq=${seq}, event=${item.event}`);
    }
    if (queue.size === 0) {
      client._pendingOrderedMsgs.delete(ns);
      if (delivered) this.saveSeqTrackerState();
    }
  }

  async publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      client._clientLog.debug(`publish ordered direct(no-seq): event=${event}, ns=${ns || '<none>'}, seq=${String(seq)}`);
      await this.publishOrderedQueueItem(ns, event, seqNum, payload, 'ordered');
      return true;
    }
    if (client._pushedSeqs.get(ns)?.has(seqNum)) {
      client._clientLog.debug(`publish ordered skipped duplicate: event=${event}, ns=${ns}, seq=${seqNum}`);
      const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
      queue?.delete(seqNum);
      if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
      return false;
    }

    const contig = client._seqTracker.getContiguousSeq(ns);
    if (seqNum <= contig) {
      client._clientLog.debug(`publish ordered stale covered: event=${event}, ns=${ns}, seq=${seqNum}, contiguous=${contig}`);
      const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
      queue?.delete(seqNum);
      if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
      return false;
    }
    if (seqNum !== contig + 1) {
      client._clientLog.debug(`publish ordered enqueue(gap): event=${event}, ns=${ns}, seq=${seqNum}, contiguous=${contig}`);
      this.enqueueOrderedMessage(ns, event, seqNum, payload);
      return false;
    }

    await this.drainOrderedMessages(ns, seqNum);
    if (client._pushedSeqs.get(ns)?.has(seqNum)) {
      client._clientLog.debug(`publish ordered skipped after-drain duplicate: event=${event}, ns=${ns}, seq=${seqNum}`);
      return false;
    }
    const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    queue?.delete(seqNum);
    if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
    await this.publishOrderedQueueItem(ns, event, seqNum, payload, 'ordered');
    this.markPublishedSeq(ns, seqNum);
    client._markOrderedSeqDelivered(ns, seqNum);
    client._clientLog.debug(`publish ordered delivered: event=${event}, ns=${ns}, seq=${seqNum}`);
    await this.drainOrderedMessages(ns);
    if (!client._pendingOrderedMsgs.get(ns)) this.saveSeqTrackerState();
    return true;
  }

  async publishOrderedGroupRecall(ns: string, seq: unknown, message: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      await this.publishGroupRecallTombstone(ns.replace(/^group:/, ''), seq, message);
      return true;
    }
    // 撤回 tombstone 也占 seq：推进 contiguous 并标记已发布，确保 ack 正常推进、不留空洞。
    if (client._pushedSeqs.get(ns)?.has(seqNum)) {
      await this.publishGroupRecallTombstone(ns.replace(/^group:/, ''), seq, message);
      return false;
    }
    client._seqTracker.onMessageSeq(ns, seqNum);
    await this.publishGroupRecallTombstone(ns.replace(/^group:/, ''), seq, message);
    this.markPublishedSeq(ns, seqNum);
    client._markOrderedSeqDelivered?.(ns, seqNum);
    await this.drainOrderedMessages(ns);
    if (!client._pendingOrderedMsgs.get(ns)) this.saveSeqTrackerState();
    return true;
  }

  async publishPulledMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0 || !ns) {
      client._clientLog.debug(`publish pulled direct(no-seq): event=${event}, ns=${ns || '<none>'}, seq=${String(seq)}`);
      const published = client._withPullResponseProcessing(ns, () => client._publishAppEvent(event, payload, 'pull'));
      if (isPromiseLike(published)) await published;
      return true;
    }
    const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    if (client._pushedSeqs.get(ns)?.has(seqNum)) {
      client._clientLog.debug(`publish pulled skipped duplicate: event=${event}, ns=${ns}, seq=${seqNum}`);
      queue?.delete(seqNum);
      if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
      return false;
    }
    queue?.delete(seqNum);
    if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
    const published = client._withPullResponseProcessing(ns, () => client._publishAppEvent(event, payload, 'pull'));
    if (isPromiseLike(published)) await published;
    this.markPublishedSeq(ns, seqNum);
    client._markPulledSeqDelivered(ns, seqNum);
    await this.drainOrderedMessages(ns, undefined, true);
    client._clientLog.debug(`publish pulled delivered: event=${event}, ns=${ns}, seq=${seqNum}`);
    return true;
  }
}
