import { slotIsolationKey } from '../config.js';
import type { EventPayload } from '../events.js';
import { normalizeGroupId } from '../group-id.js';
import { isJsonObject, type JsonObject, type JsonValue, type Message, type RpcParams } from '../types.js';
import type { ClientRuntime } from './runtime.js';

const PUSHED_SEQS_LIMIT = 50_000;
const PENDING_ORDERED_LIMIT = 50_000;

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

  isInstanceScopedMessageEvent(event: string): boolean {
    return event === 'message.received'
      || event === 'message.recalled'
      || event === 'message.undecryptable'
      || event === 'group.message_created'
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
    if (!this.isInstanceScopedMessageEvent(event)) return payload;
    return this.stripInternalSenderDeviceFields(this.attachCurrentInstanceContext(payload));
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
    if ('message_id' in msg && !('tombstone_message_id' in event)) event.tombstone_message_id = msg.message_id;
    if ('device_id' in msg && !('device_id' in event)) event.device_id = msg.device_id;
    if ('slot_id' in msg && !('slot_id' in event)) event.slot_id = msg.slot_id;
    return event;
  }

  p2pAppEventForMessage(message: EventPayload): { event: string; payload: EventPayload } {
    const recall = this.recallEventFromMessage(message);
    if (recall) return { event: 'message.recalled', payload: recall as EventPayload };
    return { event: 'message.received', payload: message };
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
      if (contigAfter !== contigBefore) this.saveSeqTrackerState();
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
      if (contigAfter !== contigBefore) this.saveSeqTrackerState();
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
        this.saveSeqTrackerState();
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
      if (filled > 0 && client._seqTracker.getContiguousSeq(ns) > afterSeq) {
        void this.fillP2pGap();
      }
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
        this.saveSeqTrackerState();
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
        });
        if (!isJsonObject(result as JsonValue | object | null | undefined)) return;
        const events = (result as JsonObject).events;
        if (!Array.isArray(events)) return;
        const pageContigBefore = client._seqTracker.getContiguousSeq(ns);
        const eventObjects = events.filter((evt): evt is JsonObject => isJsonObject(evt as JsonValue | object | null | undefined));
        if (eventObjects.length > 0) {
          client._seqTracker.onPullResult(ns, eventObjects, nextAfterSeq);
        }
        const retentionFloor = client._pullRetentionFloor(result as JsonObject, 'retention_floor_event_seq', 'retention_floor_event_seq');
        if (retentionFloor > 0) {
          const contigBeforeFloor = client._seqTracker.getContiguousSeq(ns);
          if (contigBeforeFloor < retentionFloor) {
            client._clientLog.info(`group.pull_events retention-floor advance: ns=${ns} contiguous=${contigBeforeFloor} -> retention_floor=${retentionFloor}`);
            client._seqTracker.forceContiguousSeq(ns, retentionFloor);
          }
        }
        const eventSeqs: number[] = [];
        for (const evt of eventObjects) {
          const eventSeq = Number(evt.event_seq ?? 0);
          if (Number.isFinite(eventSeq) && eventSeq > 0) eventSeqs.push(eventSeq);
          evt._from_gap_fill = true;
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
            await client._dispatcher.publish('group.changed', evt);
          }
          if (Number.isFinite(eventSeq) && eventSeq > 0) {
            client._markPulledSeqDelivered(ns, eventSeq);
          }
          filled += 1;
        }
        const contig = client._seqTracker.getContiguousSeq(ns);
        if (contig !== pageContigBefore) {
          this.saveSeqTrackerState();
        }
        if (eventObjects.length > 0 && contig > 0 && contig !== pageContigBefore) {
          const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, contig);
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

  handleGroupChangedEventSeq(data: JsonObject, groupId: string): void {
    const client = this.runtime.client;
    let needPull = false;
    const rawEventSeq = data.event_seq;
    if (rawEventSeq != null && groupId) {
      const es = Number(rawEventSeq);
      if (Number.isFinite(es) && es > 0) {
        needPull = client._seqTracker.onMessageSeq(`group_event:${groupId}`, es);
      }
      this.saveSeqTrackerState();
      const ns = `group_event:${groupId}`;
      const contig = client._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        const ackSeq = this.clampAckSeq('group.ack_events', 'event_seq', ns, contig);
        client._transport.call('group.ack_events', {
          group_id: groupId,
          event_seq: ackSeq,
          device_id: client._deviceId,
          slot_id: client._slotId,
        }, undefined, undefined, true).catch((e: unknown) => {
          client._clientLog.debug(`group event push auto-ack failed: group=${groupId} ${formatDeliveryError(e)}`);
        });
      }
    }

    if (needPull && groupId && !data._from_gap_fill) {
      this.fillGroupEventGap(groupId).catch((exc) => {
        client._clientLog.warn(`background gap fill trigger failed: ${formatDeliveryError(exc)}`);
      });
    }
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
            client._saveSeqTrackerState();
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
    client._onlineUnreadHintTimer = setTimeout(() => {
      client._onlineUnreadHintTimer = null;
      client._safeAsync(this.drainOnlineUnreadHints());
    }, delayMs);
  }

  async drainOnlineUnreadHints(): Promise<void> {
    const client = this.runtime.client;
    if (client._onlineUnreadHintDrainActive) return;
    client._onlineUnreadHintDrainActive = true;
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
      client._onlineUnreadHintDrainActive = false;
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
    if (contigBefore === seq) {
      client._clientLog.debug(
        `_onRawGroupV2MessageCreated duplicate push already covered: group=${groupId} seq=${seq}`,
      );
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
    if (!client._aid) return;
    const state = client._seqTracker.exportState();
    if (Object.keys(state).length === 0) return;
    try {
      const saveFn = client._tokenStore.saveSeq;
      if (typeof saveFn === 'function') {
        for (const [ns, seq] of Object.entries(state)) {
          saveFn.call(client._tokenStore, client._aid, client._deviceId, client._slotId, ns, seq);
        }
        return;
      }

      const updater = client._tokenStore.updateInstanceState;
      if (typeof updater === 'function') {
        updater.call(client._tokenStore, client._aid, client._deviceId, client._slotId, (metadata: JsonObject) => {
          metadata.seq_tracker_state = state as unknown as JsonValue;
          return metadata;
        });
      }
    } catch (exc) {
      const error = formatDeliveryError(exc);
      client._clientLog.warn(`save SeqTracker state failed: ${error}`);
      client._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'save',
        aid: client._aid,
        device_id: client._deviceId,
        slot_id: client._slotId,
        error: String(error),
      }).catch(() => {});
    }
  }

  persistRepairedSeq(ns: string): void {
    const client = this.runtime.client;
    if (!client._aid || !ns) return;
    const seq = client._seqTracker.getContiguousSeq(ns);
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
      if (pullResponse) {
        const published = client._withPullResponseProcessing(ns, () => client._publishAppEvent(item.event, item.payload, 'ordered-drain'));
        if (isPromiseLike(published)) await published;
      } else {
        const published = client._publishAppEvent(item.event, item.payload, 'ordered-drain');
        if (isPromiseLike(published)) await published;
      }
      this.markPublishedSeq(ns, seq);
      client._markOrderedSeqDelivered(ns, seq);
      client._clientLog.debug(`publish ordered drain delivered: ns=${ns}, seq=${seq}, event=${item.event}`);
    }
    if (queue.size === 0) client._pendingOrderedMsgs.delete(ns);
  }

  async publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      client._clientLog.debug(`publish ordered direct(no-seq): event=${event}, ns=${ns || '<none>'}, seq=${String(seq)}`);
      const published = client._publishAppEvent(event, payload, 'ordered');
      if (isPromiseLike(published)) await published;
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
    const published = client._publishAppEvent(event, payload, 'ordered');
    if (isPromiseLike(published)) await published;
    this.markPublishedSeq(ns, seqNum);
    client._markOrderedSeqDelivered(ns, seqNum);
    client._clientLog.debug(`publish ordered delivered: event=${event}, ns=${ns}, seq=${seqNum}`);
    await this.drainOrderedMessages(ns);
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
