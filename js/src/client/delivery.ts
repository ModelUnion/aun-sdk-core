import { slotIsolationKey } from '../config.js';
import type { EventPayload } from '../events.js';
import { normalizeGroupId } from '../group-id.js';
import { isJsonObject, type JsonObject, type JsonValue, type Message, type RpcParams } from '../types.js';
import type { ClientRuntime } from './runtime.js';

const PUSHED_SEQS_LIMIT = 50_000;
const PENDING_ORDERED_LIMIT = 50_000;
const GROUP_RECALL_SEEN_LIMIT = 10_000;
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

  fireGroupEventAck(groupId: string, ns: string, eventSeq: number, label: string): void {
    const client = this.runtime.client;
    const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, eventSeq);
    if (ackSeq <= 0) return;
    void client.call('group.ack_events', {
      group_id: groupId,
      event_seq: ackSeq,
      device_id: client._deviceId,
      slot_id: client._slotId,
      _rpc_background: true,
    }).catch((e: unknown) => {
      client._clientLog.warn(`${label} failed: group=${groupId}`, e);
    });
  }

  fireGroupV2Ack(groupId: string, ns: string, seq: number, label: string): void {
    const client = this.runtime.client;
    const ackSeq = this.clampAckSeq('group.v2.ack', 'up_to_seq', ns, seq);
    if (ackSeq <= 0) return;
    void client._callRawV2Rpc('group.v2.ack', {
      group_id: groupId,
      up_to_seq: ackSeq,
      _rpc_background: true,
    }).catch((e: unknown) => {
      client._clientLog.debug(`${label} failed: group=${groupId} seq=${ackSeq} err=${String(e)}`);
    });
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

  async publishOrderedQueueItem(ns: string, event: string, seq: number, payload: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (event === 'group.changed' && this.isGroupEventNamespace(ns)) {
      await this.publishOrderedGroupChanged(payload);
      return;
    }
    await client._publishAppEvent(event, payload);
  }

  async publishOrderedGroupChanged(payload: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (isJsonObject(payload)) {
      const eventPayload = payload as JsonObject;
      client._groupState?.handleGroupChangedV2Membership?.(eventPayload);
      if (eventPayload.action === 'dissolved') {
        const groupId = normalizeGroupId(String(eventPayload.group_id ?? '')) || String(eventPayload.group_id ?? '').trim();
        if (groupId) client._cleanupDissolvedGroup?.(groupId);
      }
    }
    await client._publishAppEvent('group.changed', payload);
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
    if (!isJsonObject(payload)) return payload;
    const client = this.runtime.client;
    const result: JsonObject = { ...payload };
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
    if (!isJsonObject(source)) return undefined;
    const out: JsonObject = {};
    for (const [key, item] of Object.entries(source)) {
      if (key === '_auth') continue;
      out[key] = item as JsonValue;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }

  appMessageEnvelope(payload: EventPayload): JsonObject {
    if (!isJsonObject(payload)) return {};
    const message = payload as JsonObject;
    const body = isJsonObject(message.payload) ? message.payload as JsonObject : {};
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
    if (!isJsonObject(payload)) return {};
    const groupEvent = payload as JsonObject;
    const envelope: JsonObject = {};
    for (const key of APP_GROUP_EVENT_ENVELOPE_KEYS) {
      if (Object.prototype.hasOwnProperty.call(groupEvent, key)) envelope[key] = groupEvent[key] as JsonValue;
    }
    return envelope;
  }

  attachAppMessageEnvelope(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload)) return payload;
    const result: JsonObject = { ...(payload as JsonObject) };
    // 兼容期保留顶层信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
    result.envelope = this.appMessageEnvelope(result as EventPayload);
    return result as EventPayload;
  }

  sendResultEnvelope(method: string, params: RpcParams, result: unknown, encrypted: boolean): JsonObject {
    if (!APP_SEND_ENVELOPE_METHODS.has(method)) return {};
    const body = isJsonObject(params.payload) ? params.payload as JsonObject : {};
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
    if (!isJsonObject(payload)) return payload;
    const result: JsonObject = { ...(payload as JsonObject) };
    // 兼容期保留顶层群事件信封字段；下一个大版本 0.5.* 将移除这些顶层别名，请通过 envelope.* 访问。
    result.envelope = this.appGroupEventEnvelope(result as EventPayload);
    return result as EventPayload;
  }

  stripInternalSenderDeviceFields(payload: EventPayload): EventPayload {
    if (!isJsonObject(payload)) return payload;
    const result: JsonObject = { ...(payload as JsonObject) };
    delete result.sender_device_id;
    delete result._sender_device_id;
    delete result.from_device_id;
    delete result.from_device;
    return result;
  }

  recallEventFromMessage(message: EventPayload): JsonObject | null {
    if (!isJsonObject(message)) return null;
    const msg = message as JsonObject;
    const rawPayload = msg.payload;
    const payload = isJsonObject(rawPayload) ? rawPayload as JsonObject : {};
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
    if (!isJsonObject(message)) return null;
    const msg = message as JsonObject;
    const rawPayload = msg.payload;
    const payload = isJsonObject(rawPayload) ? rawPayload as JsonObject : {};
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
    // 去重键不含 recalled_at：占位/通知 tombstone（pull）与在线 push 三条通道对同一次撤回
    // 可能携带不同来源的时间戳（push 在事务后重取），纳入 recalled_at 会使去重失效、回调多次。
    const ids = payload.message_ids;
    const idPart = Array.isArray(ids)
      ? ids.map((i) => String(i ?? '').trim()).filter(Boolean).sort().join(',')
      : String(ids ?? '');
    return `${groupId}|${idPart}`;
  }

  async publishGroupRecallTombstone(groupId: string, seq: unknown, message: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const eventPayload = this.recallEventFromGroupMessage(message);
    if (!eventPayload) return false;
    const dedupKey = this.groupRecallDedupKey(groupId, eventPayload);
    let seen = client._groupRecallSeen as Map<string, number> | undefined;
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
    await client._publishAppEvent('group.message_recalled', eventPayload as EventPayload);
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
    if (!isJsonObject(data)) return;
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
    // JS 为浏览器单线程，无需 Python 侧的 ns lock 串行保护。
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
    const contig = client._seqTracker.getContiguousSeq(ns);
    if (contig > 0) {
      const ackSeq = this.clampAckSeq('group.ack_messages', 'msg_seq', ns, contig);
      client._transport.call('group.ack_messages', {
        group_id: groupId,
        msg_seq: ackSeq,
        device_id: client._deviceId,
        slot_id: client._slotId,
        _rpc_background: true,
      }).catch((e: unknown) => { client._clientLog.warn('group recall auto-ack failed: group=' + groupId, e); });
    }
    if (contig !== contigBefore) this.saveSeqTrackerState();
  }

  async publishAppEvent(event: string, payload: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if ((event === 'message.received' || event === 'group.message_created') && isJsonObject(payload)) {
      client._maybeAppendEchoTraceReceive(payload as Record<string, unknown>);
    }
    if (isJsonObject(payload)) {
      try {
        const snapshot = client._agentMdManager.eventSnapshot();
        const localEtag = snapshot?.local_etag || '';
        const remoteEtag = snapshot?.remote_etag || '';
        if ((localEtag || remoteEtag) && (payload as Record<string, unknown>)._agent_md === undefined) {
          (payload as Record<string, unknown>)._agent_md = {
            local_etag: localEtag,
            remote_etag: remoteEtag,
          };
        }
      } catch (exc) {
        client._clientLog.debug(`agent_md etag inject skipped: ${String(exc)}`);
      }
    }
    await client._dispatcher.publish(event, this.normalizePublishedMessagePayload(event, payload));
  }

  messageTargetsCurrentInstance(message: EventPayload): boolean {
    if (!isJsonObject(message)) return true;
    const client = this.runtime.client;
    if ('device_id' in message) {
      const targetDeviceId = String(message.device_id ?? '').trim();
      if (targetDeviceId !== client._deviceId) {
        return false;
      }
    }
    if ('slot_id' in message) {
      const targetSlotId = String(message.slot_id ?? '').trim();
      if (slotIsolationKey(targetSlotId) !== slotIsolationKey(client._slotId)) {
        return false;
      }
    }
    return true;
  }

  onRawMessageReceived(data: EventPayload): void {
    const client = this.runtime.client;
    client._clientLog.debug(`_onRawMessageReceived enter: from=${(data as any)?.from ?? '-'} mid=${(data as any)?.message_id ?? '-'} seq=${(data as any)?.seq ?? '-'}`);
    client._safeAsync(this.processAndPublishMessage(data));
    client._clientLog.debug('_onRawMessageReceived exit: elapsed=0ms (dispatched async)');
  }

  async processAndPublishMessage(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    try {
      if (!isJsonObject(data)) {
        await client._publishAppEvent('message.received', data);
        return;
      }
      const msg: Message = { ...data };
      if (!this.messageTargetsCurrentInstance(msg)) {
        return;
      }

      const seq = msg.seq as number | undefined;
      const encryptedPush = client._isEncryptedPushMessage(msg);
      if (seq !== undefined && seq !== null && client._aid) {
        const ns = `p2p:${client._aid}`;
        if (seq > 0) client._seqTracker.updateMaxSeen(ns, seq);
        const contigBefore = client._seqTracker.getContiguousSeq(ns);
        const seqNeedsPull = client._seqTracker.onMessageSeq(ns, seq);
        const published = encryptedPush
          ? await client._publishEncryptedPushMessage('message.received', 'message.undecryptable', ns, seq, msg, false)
          : await this.publishOrderedMessage('message.received', ns, seq, msg);
        const contigAfter = client._seqTracker.getContiguousSeq(ns);
        const needPull = seqNeedsPull && !published;
        if (needPull) {
          client._safeAsync(this.fillP2pGap());
        }
        const contig = client._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          const ackSeq = this.clampAckSeq('message.ack', 'seq', ns, contig);
          client._transport.call('message.ack', {
            seq: ackSeq,
            device_id: client._deviceId,
            slot_id: client._slotId,
            _rpc_background: true,
          }).catch((e: unknown) => { client._clientLog.warn(`P2P auto-ack failed:${String(e)}`); });
        }
        if (contigAfter !== contigBefore) this.saveSeqTrackerState();
        if (encryptedPush) return;
      } else {
        if (encryptedPush) {
          await client._publishEncryptedPushMessage('message.received', 'message.undecryptable', '', seq ?? 0, msg, false);
          return;
        }
        await client._publishAppEvent('message.received', msg);
      }
    } catch (exc) {
      client._clientLog.warn(`P2P push processing failed:${String(exc)}`);
      if (isJsonObject(data)) {
        const src = data as Record<string, unknown>;
        const safeEvent: { [key: string]: JsonValue } = {
          message_id: (src.message_id ?? null) as JsonValue,
          from: (src.from ?? null) as JsonValue,
          to: (src.to ?? null) as JsonValue,
          seq: (src.seq ?? null) as JsonValue,
          timestamp: (src.timestamp ?? null) as JsonValue,
          _decrypt_error: String(exc),
        };
        client._attachV2EnvelopeMetadataFromSource(safeEvent, data);
        await client._publishAppEvent('message.undecryptable', safeEvent);
      }
    }
  }

  onRawGroupMessageCreated(data: EventPayload): void {
    const client = this.runtime.client;
    client._clientLog.debug(`_onRawGroupMessageCreated enter: group_id=${(data as any)?.group_id ?? '-'} from=${(data as any)?.from ?? '-'} seq=${(data as any)?.seq ?? '-'}`);
    client._safeAsync(this.processAndPublishGroupMessage(data));
    client._clientLog.debug('_onRawGroupMessageCreated exit: elapsed=0ms (dispatched async)');
  }

  async processAndPublishGroupMessage(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    try {
      if (!isJsonObject(data)) {
        await client._publishAppEvent('group.message_created', data);
        return;
      }
      const msg: Message = { ...data };
      const groupId = (msg.group_id ?? '') as string;
      const seq = msg.seq as number | undefined;
      const payload = msg.payload;

      if (groupId) {
        client._groupSynced.add(groupId);
      }

      if (payload === undefined || payload === null
        || (typeof payload === 'object' && Object.keys(payload as object).length === 0)) {
        await this.autoPullGroupMessages(msg);
        return;
      }

      const encryptedPush = client._isEncryptedPushMessage(msg);
      if (groupId && seq !== undefined && seq !== null) {
        const ns = `group:${groupId}`;
        if (seq > 0) client._seqTracker.updateMaxSeen(ns, seq);
        const contigBefore = client._seqTracker.getContiguousSeq(ns);
        const seqNeedsPull = client._seqTracker.onMessageSeq(ns, seq);
        // 群撤回 tombstone（占位 / 通知）：归一化为 group.message_recalled，仍占 seq。
        if (!encryptedPush && this.recallEventFromGroupMessage(msg)) {
          await this.publishGroupRecallTombstone(groupId, seq, msg);
          this.markPublishedSeq(ns, Number(seq));
          const contigAfter = client._seqTracker.getContiguousSeq(ns);
          const contig = client._seqTracker.getContiguousSeq(ns);
          if (contig > 0) {
            const ackSeq = this.clampAckSeq('group.ack_messages', 'msg_seq', ns, contig);
            client._transport.call('group.ack_messages', {
              group_id: groupId,
              msg_seq: ackSeq,
              device_id: client._deviceId,
              slot_id: client._slotId,
              _rpc_background: true,
            }).catch((e: unknown) => { client._clientLog.warn('group recall auto-ack failed: group=' + groupId, e); });
          }
          if (contigAfter !== contigBefore) this.saveSeqTrackerState();
          return;
        }
        const published = encryptedPush
          ? await client._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', ns, seq, msg, true)
          : await this.publishOrderedMessage('group.message_created', ns, seq, msg);
        const contigAfter = client._seqTracker.getContiguousSeq(ns);
        const needPull = seqNeedsPull && !published;
        if (needPull) {
          client._safeAsync(this.fillGroupGap(groupId));
        }
        const contig = client._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          const ackSeq = this.clampAckSeq('group.ack_messages', 'msg_seq', ns, contig);
          client._transport.call('group.ack_messages', {
            group_id: groupId,
            msg_seq: ackSeq,
            device_id: client._deviceId,
            slot_id: client._slotId,
            _rpc_background: true,
          }).catch((e: unknown) => { client._clientLog.warn('group message auto-ack failed: group=' + groupId, e); });
        }
        if (contigAfter !== contigBefore) this.saveSeqTrackerState();
        if (encryptedPush) return;
      } else {
        if (encryptedPush) {
          await client._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', '', seq ?? 0, msg, true);
          return;
        }
        await client._publishAppEvent('group.message_created', msg);
      }
    } catch (exc) {
      client._clientLog.warn(`group push processing failed:${String(exc)}`);
      if (isJsonObject(data)) {
        const src = data as Record<string, unknown>;
        const safeEvent: { [key: string]: JsonValue } = {
          message_id: (src.message_id ?? null) as JsonValue,
          group_id: (src.group_id ?? null) as JsonValue,
          from: (src.from ?? null) as JsonValue,
          seq: (src.seq ?? null) as JsonValue,
          timestamp: (src.timestamp ?? null) as JsonValue,
          _decrypt_error: String(exc),
        };
        client._attachV2EnvelopeMetadataFromSource(safeEvent, data);
        await client._publishAppEvent('group.message_undecryptable', safeEvent);
      }
    }
  }

  async autoPullGroupMessages(notification: Message): Promise<void> {
    const client = this.runtime.client;
    const groupId = (notification.group_id ?? '') as string;
    if (!groupId) {
      await client._publishAppEvent('group.message_created', notification);
      return;
    }
    const ns = `group:${groupId}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    try {
      if (client._v2Session) {
        await client._withBackgroundRpc(() => client._pullGroupV2Internal({ group_id: groupId, after_seq: afterSeq, limit: 50 }));
        return;
      }
      const result = await client.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        device_id: client._deviceId,
        limit: 50,
        _rpc_background: true,
      });
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages)) {
          const pushed = client._pushedSeqs.get(ns) as Set<number> | undefined;
          for (const msg of messages) {
            if (isJsonObject(msg)) {
              const s = (msg as Record<string, unknown>).seq as number | undefined;
              if (pushed && s !== undefined && s !== null && pushed.has(s)) {
                continue;
              }
              // 群撤回 tombstone（占位 / 通知）：归一化为 group.message_recalled 事件，仍占 seq。
              // 与 V2 pull 路径（v2-e2ee.ts pullGroupV2）对齐，避免 legacy 回退路径把撤回
              // tombstone 当普通 group.message_created 投递给应用层。
              if (s !== undefined && s !== null
                  && this.recallEventFromGroupMessage(msg as EventPayload)) {
                await this.publishGroupRecallTombstone(groupId, s, msg as EventPayload);
                this.markPublishedSeq(ns, Number(s));
                continue;
              }
              if (s !== undefined && s !== null) {
                await client._publishPulledMessage('group.message_created', ns, s, msg);
              } else {
                await client._publishAppEvent('group.message_created', msg);
              }
            }
          }
          this.prunePushedSeqs(ns);
          return;
        }
      }
    } catch (exc) {
      client._clientLog.warn(`auto pull group message failed:${String(exc)}`);
    }
    await client._publishAppEvent('group.message_created', notification);
  }

  async fillP2pGap(): Promise<void> {
    const client = this.runtime.client;
    if (client._state !== 'connected' || client._closing) return;
    if (!client._aid) return;
    const ns = `p2p:${client._aid}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    const dedupKey = `p2p_pull:${ns}`;
    if (client._gapFillDone.has(dedupKey)) return;
    client._gapFillDone.add(dedupKey);
    this.runtime.delivery.setGapFillActive(true);
    let filled = 0;
    try {
      const messages = await client._withBackgroundRpc(() => client._pullV2(afterSeq, 50));
      filled = messages.length;
      this.prunePushedSeqs(ns);
    } catch (exc) {
      client._clientLog.warn(`P2P message gap-fill failed:${String(formatDeliveryError(exc))}`);
    } finally {
      client._gapFillDone.delete(dedupKey);
      this.runtime.delivery.setGapFillActive(false);
      if (filled > 0 && client._seqTracker.getContiguousSeq(ns) > afterSeq) {
        client._safeAsync(this.fillP2pGap());
      }
    }
  }

  async fillGroupGap(groupId: string): Promise<void> {
    const client = this.runtime.client;
    if (client._state !== 'connected' || client._closing) return;
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!groupId) return;
    const ns = `group:${groupId}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    const dedupKey = `group_pull:${ns}`;
    if (client._gapFillDone.has(dedupKey)) return;
    client._gapFillDone.add(dedupKey);
    this.runtime.delivery.setGapFillActive(true);
    let filled = 0;
    try {
      const messages = await client._withBackgroundRpc(() => client._pullGroupV2(groupId, afterSeq, 50));
      filled = messages.length;
      this.prunePushedSeqs(ns);
    } catch (exc) {
      client._clientLog.warn(`group message gap-fill failed:${String(exc)}`);
    } finally {
      client._gapFillDone.delete(dedupKey);
      this.runtime.delivery.setGapFillActive(false);
      if (filled > 0 && client._seqTracker.getContiguousSeq(ns) > afterSeq) {
        client._safeAsync(this.fillGroupGap(groupId));
      }
    }
  }

  async fillGroupEventGap(groupId: string): Promise<void> {
    const client = this.runtime.client;
    if (client._state !== 'connected' || client._closing) return;
    const ns = `group_event:${groupId}`;
    const afterSeq = client._seqTracker.getContiguousSeq(ns);
    const dedupKey = `group_event_pull:${ns}`;
    if (client._gapFillDone.has(dedupKey)) return;
    client._gapFillDone.add(dedupKey);
    this.runtime.delivery.setGapFillActive(true);
    try {
      let nextAfterSeq = afterSeq;
      const maxPages = 100;
      let pageCount = 0;
      while (pageCount < maxPages) {
        pageCount += 1;
        const result = await client.call('group.pull_events', {
          group_id: groupId,
          after_event_seq: nextAfterSeq,
          device_id: client._deviceId,
          limit: 50,
          _rpc_background: true,
        });
        if (!isJsonObject(result)) return;
        const events = result.events;
        if (!Array.isArray(events)) return;
        const pageContigBefore = client._seqTracker.getContiguousSeq(ns);
        const eventObjects = events.filter((evt): evt is JsonObject => isJsonObject(evt));
        if (eventObjects.length > 0) {
          client._seqTracker.onPullResult(ns, eventObjects, nextAfterSeq);
        }
        const cursor = isJsonObject(result.cursor) ? result.cursor : null;
        const serverAck = cursor ? Number(cursor.current_seq ?? 0) : 0;
        if (serverAck > 0) {
          const contigBeforeFloor = client._seqTracker.getContiguousSeq(ns);
          if (contigBeforeFloor < serverAck) {
            client._clientLog.info('group.pull_events retention-floor advance: ns=' + ns + ' contiguous=' + contigBeforeFloor + ' -> cursor.current_seq=' + serverAck);
            client._seqTracker.forceContiguousSeq(ns, serverAck);
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
          if (et === 'group.message_created') continue;
          const cs = evt.client_signature;
          if (cs && typeof cs === 'object') {
            if (client._shouldSkipEventSignature(evt)) {
              delete evt.client_signature;
            } else {
              const verified = await client._verifyEventSignature(evt, cs as JsonObject);
              evt._verified = client._isEventSignatureVerified(verified);
            }
          }
          if (Number.isFinite(eventSeq) && eventSeq > 0 && !client._pushedSeqs.get(ns)?.has(eventSeq)) {
            this.enqueueOrderedMessage(ns, 'group.changed', eventSeq, evt);
          }
        }
        const ackContig = client._seqTracker.getContiguousSeq(ns);
        await this.drainOrderedMessages(ns);
        if (ackContig !== pageContigBefore && !hasDissolvedEvent) {
          this.saveSeqTrackerState();
        }
        if (eventObjects.length > 0 && ackContig > 0 && ackContig !== pageContigBefore) {
          const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, ackContig);
          client._transport.call('group.ack_events', {
            group_id: groupId,
            event_seq: ackSeq,
            device_id: client._deviceId,
            slot_id: client._slotId,
            _rpc_background: true,
          }).catch((e: unknown) => { client._clientLog.warn('group event auto-ack failed: group=' + groupId, e); });
        }
        const nextAfter = Math.max(eventSeqs.length > 0 ? Math.max(...eventSeqs) : nextAfterSeq, nextAfterSeq);
        if (eventObjects.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
        nextAfterSeq = nextAfter;
      }
      if (pageCount >= maxPages) {
        client._clientLog.warn(`group event gap fill reached max_pages=${maxPages} group=${groupId} after_seq=${nextAfterSeq}`);
      }
    } catch (exc) {
      client._clientLog.warn(`group event gap-fill failed:${String(exc)}`);
    } finally {
      client._gapFillDone.delete(dedupKey);
      this.runtime.delivery.setGapFillActive(false);
    }
  }

  async handleGroupChangedEventSeq(data: JsonObject, groupId: string): Promise<void> {
    const client = this.runtime.client;
    let needPull = false;
    const rawEventSeq = data.event_seq;
    const eventSeq = Number(rawEventSeq);
    if (!groupId || !Number.isFinite(eventSeq) || !Number.isInteger(eventSeq) || eventSeq <= 0) {
      await this.publishOrderedGroupChanged(data);
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
    const publishedDuplicate = client._pushedSeqs.get(ns)?.has(eventSeq) === true;
    if (eventSeq <= contigBefore || publishedDuplicate) {
      client._clientLog.debug(`group.changed skipped duplicate/stale: group=${groupId}, event_seq=${eventSeq}, contiguous=${contigBefore}`);
      if (eventSeq <= contigBefore) {
        this.fireGroupEventAck(groupId, ns, eventSeq, 'group event covered push ack');
      } else if (contigBefore > 0) {
        this.fireGroupEventAck(groupId, ns, contigBefore, 'group event covered push ack');
      }
      return;
    }

    this.enqueueOrderedMessage(ns, 'group.changed', eventSeq, data);
    needPull = client._seqTracker.onMessageSeq(ns, eventSeq);
    const ackContig = client._seqTracker.getContiguousSeq(ns);
    await this.drainOrderedMessages(ns);

    if (ackContig > 0 && ackContig !== contigBefore) {
      if (data.action !== 'dissolved') this.saveSeqTrackerState();
      const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, ackContig);
      client._transport.call('group.ack_events', {
        group_id: groupId,
        event_seq: ackSeq,
        device_id: client._deviceId,
        slot_id: client._slotId,
        _rpc_background: true,
      }).catch((e: unknown) => {
        client._clientLog.warn('group event push auto-ack failed: group=' + groupId, e);
      });
    }

    if (needPull && groupId && !data._from_gap_fill) {
      client._safeAsync(this.fillGroupEventGap(groupId));
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
        if (client.state !== 'ready') return;
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
    const tStart = Date.now();
    if (!isJsonObject(data)) {
      client._clientLog.debug(`_onRawGroupV2MessageCreated skipped: non-object type=${typeof data}`);
      return;
    }

    const groupId = String(data.group_id ?? '').trim();
    const seq = Number(data.seq ?? 0) || 0;
    const messageId = String(data.message_id ?? '').trim();
    const senderAid = String(data.sender_aid ?? '').trim();
    client._clientLog.debug(`_onRawGroupV2MessageCreated group=${groupId} seq=${seq} message_id=${messageId} sender=${senderAid}`);

    if (!groupId || seq <= 0) {
      client._clientLog.debug('_onRawGroupV2MessageCreated skipped: missing group_id or seq');
      return;
    }
    if (!client._v2Session) {
      client._clientLog.debug('_onRawGroupV2MessageCreated skipped: V2 session not initialized');
      return;
    }
    const eventKind = String(data.kind ?? '').trim();
    if (eventKind === 'group.online_unread_hint' && !data._online_hint_drained) {
      if (client._sessionOptions?.background_sync === false) {
        client._clientLog.debug(`_onRawGroupV2MessageCreated skipped online unread hint: group=${groupId} background_sync=false`);
        return;
      }
      this.enqueueOnlineUnreadHint(data);
      return;
    }

    try {
      const ns = `group:${groupId}`;
      client._seqTracker.updateMaxSeen(ns, seq);
      const contigBefore = client._seqTracker.getContiguousSeq(ns);
      if (contigBefore === seq || (eventKind === 'group.online_unread_hint' && contigBefore > seq)) {
        client._clientLog.debug(`_onRawGroupV2MessageCreated duplicate push already covered: group=${groupId} seq=${seq}`);
        this.fireGroupV2Ack(groupId, ns, seq, 'group v2 covered push ack');
        return;
      }
      const afterSeq = client._repairPushContiguousBound(
        ns,
        seq,
        false,
        '_raw.group.v2.message_created',
      );
      const dedupKey = `group_pull:${ns}`;
      if (client._gapFillDone.has(dedupKey)) {
        client._clientLog.debug(`_onRawGroupV2MessageCreated skipped: dedupKey=${dedupKey} in flight`);
        return;
      }
      client._gapFillDone.add(dedupKey);
      try {
        client._clientLog.debug(`_onRawGroupV2MessageCreated -> group.v2.pull group=${groupId} after_seq=${afterSeq}`);
        const messages = await client._withBackgroundRpc(() => client._pullGroupV2(groupId, afterSeq, 50));
        client._clientLog.debug(`_onRawGroupV2MessageCreated pulled ${messages.length} msgs for group=${groupId}`);
      } finally {
        client._gapFillDone.delete(dedupKey);
      }
    } catch (exc) {
      client._clientLog.warn(`_onRawGroupV2MessageCreated pull failed group=${groupId}: ${String(exc)}`);
    } finally {
      client._clientLog.debug(`_onRawGroupV2MessageCreated exit: elapsed=${Date.now() - tStart}ms`);
    }
  }

  async onV2PushNotification(data: EventPayload): Promise<void> {
    const client = this.runtime.client;
    if (!client._v2Session) return;

    const pushSeq = isJsonObject(data) ? Number(data.seq ?? 0) || 0 : 0;
    const pushFrom = isJsonObject(data) ? String(data.from_aid ?? '') : '';
    const pushMsgId = isJsonObject(data) ? String(data.message_id ?? '') : '';
    const envelopeJson = isJsonObject(data) ? data.envelope_json : undefined;
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
          const needPull = client._seqTracker.onMessageSeq(ns, pushSeq);
          const published = await client._publishOrderedMessage('message.received', ns, pushSeq, decrypted as EventPayload);
          const newContig = client._seqTracker.getContiguousSeq(ns);
          if (newContig !== contigBefore) {
            client._saveSeqTrackerState();
          }
          if (newContig > 0 && newContig !== contigBefore) {
            const ackSeq = this.clampAckSeq('message.v2.ack', 'up_to_seq', ns, newContig);
            try {
              await client._callRawV2Rpc('message.v2.ack', { up_to_seq: ackSeq, _rpc_background: true });
            } catch (e) {
              client._clientLog.debug(`V2 P2P push-ack failed: ${e}`);
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
        client._clientLog.debug(`_onV2PushNotification: push payload 解密失败, fallback to pull: ${exc}`);
      }
    }

    if (pushSeq > 0 && ns) {
      client._clientLog.debug(
        `_onV2PushNotification: 纯通知 push_seq=${pushSeq} > contiguous_seq=${contigBefore}, 触发 pull(after_seq=${contigBefore})`
      );
    }

    if (client._v2PullInflight) {
      this.runtime.delivery.setV2PullPending(true);
      return;
    }
    this.runtime.delivery.setV2PullInflight(true);
    const dedupKey = `p2p_pull:${ns}`;
    client._gapFillDone.add(dedupKey);
    try {
      do {
        this.runtime.delivery.setV2PullPending(false);
        await client._withBackgroundRpc(() => client._pullV2());
        const newContig = ns ? client._seqTracker.getContiguousSeq(ns) : -1;
        client._clientLog.debug(
          `_onV2PushNotification pull done: contiguous_seq=${contigBefore}->${newContig} (push_seq=${pushSeq || 'null'})`
        );
      } while (client._v2PullPending);
    } catch (exc) {
      const newContig = ns ? client._seqTracker.getContiguousSeq(ns) : -1;
      client._clientLog.warn(
        `V2 push auto-pull failed: contiguous_seq=${contigBefore}->${newContig} err=${exc}`
      );
    } finally {
      this.runtime.delivery.setV2PullInflight(false);
      client._gapFillDone.delete(dedupKey);
    }
  }

  async restoreSeqTrackerState(): Promise<void> {
    const client = this.runtime.client;
    if (!client._aid) return;
    const context = client._seqTrackerContext;
    if (!context) return;
    const aid = client._aid;
    const deviceId = client._deviceId;
    const slotId = client._slotId;
    try {
      const loadAll = client._tokenStore.loadAllSeqs?.bind(client._tokenStore);
      if (typeof loadAll === 'function') {
        let state = await loadAll(aid, deviceId, slotId);
        if (client._seqTrackerContext !== context) return;
        if (state && typeof state === 'object' && Object.keys(state).length > 0) {
          state = await this.migrateSeqStateGroupIds(state as Record<string, number>);
          client._seqTracker.restoreState(state);
        }
        return;
      }

      const loader = client._tokenStore.loadInstanceState?.bind(client._tokenStore);
      if (typeof loader !== 'function') return;
      const stateHolder = await loader(aid, deviceId, slotId);
      if (client._seqTrackerContext !== context) return;
      if (stateHolder && typeof stateHolder === 'object') {
        const state = (stateHolder as Record<string, JsonValue>).seq_tracker_state;
        if (isJsonObject(state)) {
          const migrated = await this.migrateSeqStateGroupIds(state as Record<string, number>);
          client._seqTracker.restoreState(migrated);
        }
      }
    } catch (exc) {
      client._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'restore',
        aid,
        device_id: deviceId,
        slot_id: slotId,
        error: String(exc),
      }).catch(() => {});
    }
  }

  async migrateSeqStateGroupIds(state: Record<string, number>): Promise<Record<string, number>> {
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
    if (!client._aid) return newState;

    const aid = client._aid;
    const deviceId = client._deviceId;
    const slotId = client._slotId;
    const saver = client._tokenStore.saveSeq?.bind(client._tokenStore);
    const deleter = client._tokenStore.deleteSeq?.bind(client._tokenStore);
    if (typeof saver === 'function') {
      for (const [oldNs, newNs] of Object.entries(renameMap)) {
        if (typeof deleter === 'function') {
          try {
            await deleter(aid, deviceId, slotId, oldNs);
          } catch (e) {
            client._dispatcher.publish('seq_tracker.persist_error', {
              phase: 'migrate_delete',
              aid,
              device_id: deviceId,
              slot_id: slotId,
              ns: oldNs,
              error: String(e),
            }).catch(() => {});
          }
        }
        try {
          await saver(aid, deviceId, slotId, newNs, newState[newNs]);
        } catch (e) {
          client._dispatcher.publish('seq_tracker.persist_error', {
            phase: 'migrate_save',
            aid,
            device_id: deviceId,
            slot_id: slotId,
            ns: newNs,
            error: String(e),
          }).catch(() => {});
        }
      }
    }
    return newState;
  }

  saveSeqTrackerState(): void {
    const client = this.runtime.client;
    if (!client._aid) return;
    const state = client._seqTracker.exportState();
    if (Object.keys(state).length === 0) return;
    try {
      const saveFn = client._tokenStore.saveSeq?.bind(client._tokenStore);
      if (typeof saveFn === 'function') {
        for (const [ns, seq] of Object.entries(state)) {
          saveFn(client._aid, client._deviceId, client._slotId, ns, seq).catch((exc: unknown) => {
            client._dispatcher.publish('seq_tracker.persist_error', {
              phase: 'save',
              aid: client._aid,
              device_id: client._deviceId,
              slot_id: client._slotId,
              error: String(exc),
            }).catch(() => {});
          });
        }
        return;
      }

      if (typeof client._tokenStore.updateInstanceState === 'function') {
        client._tokenStore.updateInstanceState(client._aid, client._deviceId, client._slotId, (current: JsonObject) => {
          current.seq_tracker_state = state as unknown as JsonValue;
          return current;
        }).catch((exc: unknown) => {
          client._dispatcher.publish('seq_tracker.persist_error', {
            phase: 'save',
            aid: client._aid,
            device_id: client._deviceId,
            slot_id: client._slotId,
            error: String(exc),
          }).catch(() => {});
        });
      }
    } catch (exc) {
      client._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'save',
        aid: client._aid,
        device_id: client._deviceId,
        slot_id: client._slotId,
        error: String(exc),
      }).catch(() => {});
    }
  }

  persistRepairedSeq(ns: string): void {
    const client = this.runtime.client;
    if (!client._aid || !ns) return;
    const seq = client._seqTracker.getContiguousSeq(ns);
    try {
      if (seq > 0 && typeof client._tokenStore.saveSeq === 'function') {
        client._tokenStore.saveSeq(client._aid, client._deviceId, client._slotId, ns, seq).catch((exc: unknown) => {
          client._clientLog.debug(`persist repaired seq failed: ns=${ns} err=${formatDeliveryError(exc)}`);
        });
        return;
      }
      const deleteSeq = client._tokenStore.deleteSeq;
      if (seq <= 0 && typeof deleteSeq === 'function') {
        deleteSeq.call(client._tokenStore, client._aid, client._deviceId, client._slotId, ns).catch((exc: unknown) => {
          client._clientLog.debug(`delete repaired seq failed: ns=${ns} err=${formatDeliveryError(exc)}`);
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

  async drainOrderedMessages(ns: string, beforeSeq?: number): Promise<void> {
    const client = this.runtime.client;
    const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    if (!queue || queue.size === 0) return;
    const contig = client._seqTracker.getContiguousSeq(ns);
    const ready = [...queue.keys()]
      .filter((seq) => seq <= contig && (beforeSeq === undefined || seq < beforeSeq))
      .sort((a, b) => a - b);
    for (const seq of ready) {
      const item = queue.get(seq);
      queue.delete(seq);
      if (!item || client._pushedSeqs.get(ns)?.has(seq)) continue;
      await this.publishOrderedQueueItem(ns, item.event, seq, item.payload);
      this.markPublishedSeq(ns, seq);
    }
    if (queue.size === 0) client._pendingOrderedMsgs.delete(ns);
  }

  async publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      await this.publishOrderedQueueItem(ns, event, seqNum, payload);
      return true;
    }
    if (client._pushedSeqs.get(ns)?.has(seqNum)) {
      const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
      queue?.delete(seqNum);
      if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
      return false;
    }

    const contig = client._seqTracker.getContiguousSeq(ns);
    if (seqNum > contig) {
      this.enqueueOrderedMessage(ns, event, seqNum, payload);
      return false;
    }

    await this.drainOrderedMessages(ns, seqNum);
    if (client._pushedSeqs.get(ns)?.has(seqNum)) return false;
    const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    queue?.delete(seqNum);
    if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
    await this.publishOrderedQueueItem(ns, event, seqNum, payload);
    this.markPublishedSeq(ns, seqNum);
    await this.drainOrderedMessages(ns);
    return true;
  }

  async publishPulledMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0 || !ns) {
      await client._publishAppEvent(event, payload);
      return true;
    }
    const queue = client._pendingOrderedMsgs.get(ns) as Map<number, { event: string; payload: EventPayload }> | undefined;
    if (client._pushedSeqs.get(ns)?.has(seqNum)) {
      queue?.delete(seqNum);
      if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
      return false;
    }
    queue?.delete(seqNum);
    if (queue && queue.size === 0) client._pendingOrderedMsgs.delete(ns);
    await client._publishAppEvent(event, payload);
    this.markPublishedSeq(ns, seqNum);
    return true;
  }
}
