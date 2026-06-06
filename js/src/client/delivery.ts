import { slotIsolationKey } from '../config.js';
import type { EventPayload } from '../events.js';
import { normalizeGroupId } from '../group-id.js';
import { isJsonObject, type JsonObject, type JsonValue, type Message, type RpcParams } from '../types.js';
import type { ClientRuntime } from './runtime.js';

const PUSHED_SEQS_LIMIT = 50_000;
const PENDING_ORDERED_LIMIT = 50_000;
const GROUP_RECALL_SEEN_LIMIT = 10_000;

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
    if (!this.isInstanceScopedMessageEvent(event)) return payload;
    return this.stripInternalSenderDeviceFields(this.attachCurrentInstanceContext(payload));
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

  recallEventFromGroupMessage(message: EventPayload): JsonObject | null {
    if (!isJsonObject(message)) return null;
    const msg = message as JsonObject;
    const rawPayload = msg.payload;
    const payload = isJsonObject(rawPayload) ? rawPayload as JsonObject : {};
    const msgType = String(msg.type ?? msg.kind ?? msg.message_type ?? '').trim();
    const payloadType = String(payload.type ?? payload.kind ?? '').trim();
    if (msgType !== 'group.message_recalled' && payloadType !== 'group.message_recalled') return null;
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
    event.type = 'group.message_recalled';
    event.kind = 'group.message_recalled';
    event.message_ids = messageIds;
    if (!('group_id' in event)) event.group_id = msg.group_id ?? '';
    if (!('timestamp' in event)) event.timestamp = msg.timestamp ?? msg.t_server ?? event.recalled_at ?? 0;
    if ('seq' in msg) event.seq = msg.seq;
    if ('message_id' in msg && !('tombstone_message_id' in event)) event.tombstone_message_id = msg.message_id;
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
        await client._pullGroupV2Internal({ group_id: groupId, after_seq: afterSeq, limit: 50 });
        return;
      }
      const result = await client.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        device_id: client._deviceId,
        limit: 50,
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
      const messages = await client._pullV2(afterSeq, 50);
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
      const messages = await client._pullGroupV2(groupId, afterSeq, 50);
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
        for (const evt of eventObjects) {
          const eventSeq = Number(evt.event_seq ?? 0);
          if (Number.isFinite(eventSeq) && eventSeq > 0) eventSeqs.push(eventSeq);
          evt._from_gap_fill = true;
          const et = String(evt.event_type ?? '');
          if (et === 'group.message_created') continue;
          const cs = evt.client_signature;
          if (cs && typeof cs === 'object') {
            if (client._shouldSkipEventSignature(evt)) {
              delete evt.client_signature;
            } else {
              evt._verified = await client._verifyEventSignature(evt, cs as JsonObject);
            }
          }
          await client._dispatcher.publish('group.changed', evt);
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

  handleGroupChangedEventSeq(data: JsonObject, groupId: string): void {
    const client = this.runtime.client;
    let needPull = false;
    const rawEventSeq = data.event_seq;
    if (rawEventSeq != null && groupId) {
      const es = Number(rawEventSeq);
      if (Number.isFinite(es) && es > 0) {
        needPull = client._seqTracker.onMessageSeq(`group_event:${groupId}`, es);
      }
    }

    if (needPull && groupId && !data._from_gap_fill) {
      client._safeAsync(this.fillGroupEventGap(groupId));
    }
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
      if (contigBefore === seq) {
        client._clientLog.debug(`_onRawGroupV2MessageCreated duplicate push already covered: group=${groupId} seq=${seq}`);
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
        const messages = await client._pullGroupV2(groupId, afterSeq, 50);
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
              await client._callRawV2Rpc('message.v2.ack', { up_to_seq: ackSeq });
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
        await client._pullV2();
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
      await client._publishAppEvent(item.event, item.payload);
      this.markPublishedSeq(ns, seq);
    }
    if (queue.size === 0) client._pendingOrderedMsgs.delete(ns);
  }

  async publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const client = this.runtime.client;
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      await client._publishAppEvent(event, payload);
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
    await client._publishAppEvent(event, payload);
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
