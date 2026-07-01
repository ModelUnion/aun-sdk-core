import { describe, expect, it, vi } from 'vitest';

import { MessageDeliveryEngine } from '../../src/client/delivery.js';
import { ClientRuntime } from '../../src/client/runtime.js';

function createSeqTracker(initial: Record<string, number> = {}) {
  const contiguous = new Map(Object.entries(initial));
  const maxSeen = new Map<string, number>();
  return {
    getContiguousSeq: vi.fn((ns: string) => contiguous.get(ns) ?? 0),
    getMaxSeenSeq: vi.fn((ns: string) => maxSeen.get(ns) ?? 0),
    updateMaxSeen: vi.fn((ns: string, seq: number) => {
      maxSeen.set(ns, Math.max(maxSeen.get(ns) ?? 0, Number(seq) || 0));
    }),
    onMessageSeq: vi.fn((ns: string, seq: number) => {
      const current = contiguous.get(ns) ?? 0;
      const next = Number(seq) || 0;
      if (next > 0) maxSeen.set(ns, Math.max(maxSeen.get(ns) ?? 0, next));
      if (next === current + 1) {
        contiguous.set(ns, next);
        return false;
      }
      return next > current + 1;
    }),
    onPullResult: vi.fn((ns: string, items: Array<Record<string, unknown>>, afterSeq = contiguous.get(ns) ?? 0) => {
      let next = Math.max(contiguous.get(ns) ?? 0, Number(afterSeq) || 0);
      const seqs = items
        .map((item) => Number(item.seq ?? item.event_seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0)
        .sort((a, b) => a - b);
      for (const seq of seqs) {
        maxSeen.set(ns, Math.max(maxSeen.get(ns) ?? 0, seq));
        if (seq === next + 1) {
          next = seq;
        }
      }
      contiguous.set(ns, next);
    }),
    exportState: vi.fn(() => Object.fromEntries(contiguous.entries())),
    restoreState: vi.fn((state: Record<string, number>) => {
      contiguous.clear();
      for (const [ns, seq] of Object.entries(state)) contiguous.set(ns, seq);
    }),
    repairContiguousSeq: vi.fn((ns: string, seq: number) => {
      contiguous.set(ns, Math.max(0, Number(seq) || 0));
    }),
    forceContiguousSeq: vi.fn((ns: string, seq: number) => {
      contiguous.set(ns, Math.max(0, Number(seq) || 0));
    }),
    setContiguousSeq(ns: string, seq: number): void {
      contiguous.set(ns, seq);
    },
    setMaxSeenSeq(ns: string, seq: number): void {
      maxSeen.set(ns, seq);
    },
  };
}

function createEngine(): {
  engine: MessageDeliveryEngine;
  client: Record<string, any>;
  seqTracker: ReturnType<typeof createSeqTracker>;
  published: Array<{ event: string; payload: any }>;
  persistErrors: any[];
} {
  const published: Array<{ event: string; payload: any }> = [];
  const persistErrors: any[] = [];
  const seqTracker = createSeqTracker({ 'p2p:alice.agentid.pub': 1 });
  const client: Record<string, any> = {
    _aid: 'alice.agentid.pub',
    _deviceId: 'device-a',
    _slotId: 'slot-a',
    _seqTracker: seqTracker,
    _v2Session: {},
    _sessionOptions: { background_sync: true },
    _v2PullInflight: false,
    _v2PullPending: false,
    _pushedSeqs: new Map(),
    _pendingOrderedMsgs: new Map(),
    _gapFillDone: new Set(),
    _onlineUnreadHintQueue: new Map(),
    _onlineUnreadHintTimer: null,
    _onlineUnreadHintDrainActive: false,
    _onlineUnreadHintInitialDelayMs: 0,
    _onlineUnreadHintIntervalMs: 0,
    _gapFillActive: false,
    _state: 'connected',
    _closing: false,
    state: 'ready',
    _clientLog: { debug: vi.fn(), info: vi.fn(), warn: vi.fn() },
    _maybeAppendEchoTraceReceive: vi.fn(),
    _agentMdManager: { eventSnapshot: vi.fn(() => ({ local_etag: 'local-1', remote_etag: 'remote-1' })) },
    _dispatcher: {
      publish: vi.fn(async (event: string, payload: any) => {
        if (event === 'seq_tracker.persist_error') {
          persistErrors.push(payload);
          return;
        }
        published.push({ event, payload });
      }),
    },
    _publishAppEvent: vi.fn(async (event: string, payload: any) => {
      published.push({ event, payload });
    }),
    _tokenStore: {
      saveSeq: vi.fn(async () => undefined),
      deleteSeq: vi.fn(async () => undefined),
      loadAllSeqs: vi.fn(),
      loadInstanceState: vi.fn(),
      updateInstanceState: vi.fn(),
    },
    _safeAsync: vi.fn((task: unknown) => {
      void Promise.resolve(task).catch(() => {});
    }),
    _repairPushContiguousBound: vi.fn((ns: string, pushSeq: number) => {
      const contig = seqTracker.getContiguousSeq(ns);
      if (Number.isFinite(pushSeq) && pushSeq > 0 && contig > pushSeq) {
        seqTracker.repairContiguousSeq(ns, pushSeq - 1);
      }
      return seqTracker.getContiguousSeq(ns);
    }),
    _decryptV2PushMessage: vi.fn(),
    _pullV2: vi.fn(async () => []),
    _pullGroupV2: vi.fn(async () => []),
    _callRawV2Rpc: vi.fn(async () => ({ ok: true })),
    _withBackgroundRpc: vi.fn(async (operation: () => unknown) => await operation()),
    _shouldSkipEventSignature: vi.fn(() => false),
    _verifyEventSignature: vi.fn(async () => true),
    _isEventSignatureVerified: vi.fn((value: unknown) => value === true),
    _transport: { call: vi.fn(async () => ({ ok: true })) },
    _rpcPipeline: { postprocessResult: vi.fn(async (_method: string, _params: unknown, result: unknown) => result) },
    call: vi.fn(async () => ({ ok: true })),
  };
  const engine = new MessageDeliveryEngine(new ClientRuntime(client));
  client._publishOrderedMessage = vi.fn((event: string, ns: string, seq: unknown, payload: any) => engine.publishOrderedMessage(event, ns, seq, payload));
  client._saveSeqTrackerState = vi.fn(() => engine.saveSeqTrackerState());
  return { client, seqTracker, published, persistErrors, engine };
}

describe('MessageDeliveryEngine 组件边界', () => {
  it('publishAppEvent 为实例级消息注入 device_id / slot_id，并透传 agent_md 快照', async () => {
    const { engine, published } = createEngine();
    const payload = {
      message_id: 'm-1',
      seq: 7,
      from: 'bob.agentid.pub',
      to: 'alice.agentid.pub',
      payload: { type: 'text', text: 'hello' },
      e2ee: { payload_type: 'text' },
    };

    await engine.publishAppEvent('message.received', payload);

    expect(published).toEqual([{
      event: 'message.received',
      payload: {
        message_id: 'm-1',
        seq: 7,
        from: 'bob.agentid.pub',
        to: 'alice.agentid.pub',
        payload: { type: 'text', text: 'hello' },
        e2ee: { payload_type: 'text' },
        _agent_md: { local_etag: 'local-1', remote_etag: 'remote-1' },
        device_id: 'device-a',
        slot_id: 'slot-a',
        envelope: {
          from: 'bob.agentid.pub',
          to: 'alice.agentid.pub',
          type: 'text',
        },
      },
    }]);
  });

  it('应用层消息 envelope 只保留可转发字段并归一化 headers', () => {
    const { engine } = createEngine();

    const envelope = engine.appMessageEnvelope({
      message_id: 'm-1',
      seq: 7,
      from_aid: 'bob.agentid.pub',
      to_aid: 'alice.agentid.pub',
      created_at: 1234567890000,
      payload: { type: 'text', text: 'hello' },
      headers: { trace_id: 'trace-1', _auth: 'drop' },
      context: { run_id: 'run-1', _auth: 'drop' },
      device_id: 'device-a',
      slot_id: 'slot-a',
    });

    expect(envelope).toEqual({
      from: 'bob.agentid.pub',
      to: 'alice.agentid.pub',
      type: 'text',
      timestamp: 1234567890000,
      context: { run_id: 'run-1' },
      protected_headers: { trace_id: 'trace-1' },
    });
    for (const key of ['message_id', 'seq', 'device_id', 'slot_id', 'headers', 'from_aid', 'to_aid', 'created_at']) {
      expect(envelope).not.toHaveProperty(key);
    }
  });

  it('ready 状态允许 P2P gap-fill，connected 作为兼容别名也允许', async () => {
    for (const rawState of ['ready', 'connected']) {
      const { engine, client } = createEngine();
      client._state = rawState;
      client.state = 'ready';
      await engine.fillP2pGap();

      expect(client._pullV2).toHaveBeenCalledWith(1, 50);
    }
  });

  it('P2P gap-fill 遇到 V2 service plane 暂不可用时应退回普通 message.pull', async () => {
    const { engine, client, seqTracker, published } = createEngine();
    const ns = 'p2p:alice.agentid.pub';
    seqTracker.setContiguousSeq(ns, 1);
    client._pullV2 = vi.fn(async () => {
      throw new Error('Service plane unavailable for message.v2.pull: no_service');
    });
    client._transport.call = vi.fn(async (method: string, params: Record<string, unknown>, _timeout: unknown, _unused: unknown, background: boolean) => {
      expect(method).toBe('message.pull');
      expect(params).toEqual({
        after_seq: 1,
        limit: 50,
        device_id: 'device-a',
        slot_id: 'slot-a',
        _rpc_background: true,
      });
      expect(background).toBe(true);
      return {
        messages: [
          {
            message_id: 'plain-2',
            from: 'bob.agentid.pub',
            to: 'alice.agentid.pub',
            seq: 2,
            payload: { type: 'text', text: 'fallback' },
          },
        ],
      };
    });

    await engine.fillP2pGap();

    expect(client._transport.call).toHaveBeenCalledTimes(1);
    expect(client._rpcPipeline.postprocessResult).toHaveBeenCalledWith('message.pull', {
      after_seq: 1,
      limit: 50,
      device_id: 'device-a',
      slot_id: 'slot-a',
      _rpc_background: true,
    }, expect.any(Object));
    expect(published).toEqual([
      {
        event: 'message.received',
        payload: expect.objectContaining({
          seq: 2,
          payload: { type: 'text', text: 'fallback' },
        }),
      },
    ]);
    expect(client._gapFillDone.has(`p2p_pull:${ns}`)).toBe(false);
  });

  it('publishAppEvent 为群事件注入 envelope 并保留顶层兼容字段', async () => {
    const { engine, published } = createEngine();

    await engine.publishAppEvent('group.changed', {
      module_id: 'group',
      group_id: 'group.agentid.pub/g1',
      event_seq: 8,
      event_type: 'group.member_added',
      action: 'member_added',
      actor_aid: 'alice.agentid.pub',
      member_aid: 'bob.agentid.pub',
    });

    expect(published).toEqual([{
      event: 'group.changed',
      payload: {
        module_id: 'group',
        group_id: 'group.agentid.pub/g1',
        event_seq: 8,
        event_type: 'group.member_added',
        action: 'member_added',
        actor_aid: 'alice.agentid.pub',
        member_aid: 'bob.agentid.pub',
        _agent_md: { local_etag: 'local-1', remote_etag: 'remote-1' },
        device_id: 'device-a',
        slot_id: 'slot-a',
        envelope: {
          module_id: 'group',
          group_id: 'group.agentid.pub/g1',
          event_seq: 8,
          event_type: 'group.member_added',
          action: 'member_added',
          actor_aid: 'alice.agentid.pub',
          member_aid: 'bob.agentid.pub',
          device_id: 'device-a',
          slot_id: 'slot-a',
        },
      },
    }]);
  });

  it('撤回事件发布给应用层时带撤回通知自身 envelope', async () => {
    const { engine, published } = createEngine();

    const p2pRecall = engine.p2pAppEventForMessage({
      message_id: 'recall-1',
      from: 'alice.agentid.pub',
      to: 'bob.agentid.pub',
      seq: 9,
      type: 'message.recalled',
      payload: {
        kind: 'message.recalled',
        message_ids: ['m-1'],
        recalled_at: 123,
      },
    });
    await engine.publishAppEvent(p2pRecall.event, p2pRecall.payload);

    const groupRecall = engine.recallEventFromGroupMessage({
      module_id: 'group',
      group_id: 'g1',
      message_id: 'notice-1',
      seq: 43,
      type: 'group.message_recalled',
      payload: {
        message_ids: ['gm-1'],
        target_message_seqs: [42],
        sender_aid: 'alice.agentid.pub',
        recalled_by: 'owner.agentid.pub',
      },
    });
    expect(groupRecall).not.toBeNull();
    await engine.publishAppEvent('group.message_recalled', groupRecall as any);

    expect(published[0].payload).toEqual(expect.objectContaining({
      message_id: 'recall-1',
      tombstone_message_id: 'recall-1',
      message_ids: ['m-1'],
      envelope: expect.objectContaining({
        from: 'alice.agentid.pub',
        to: 'bob.agentid.pub',
        type: 'message.recalled',
        kind: 'message.recalled',
        timestamp: 123,
      }),
    }));
    for (const key of ['message_id', 'seq', 'device_id', 'slot_id']) {
      expect(published[0].payload.envelope).not.toHaveProperty(key);
    }
    expect(published[1].payload).toEqual(expect.objectContaining({
      module_id: 'group',
      group_id: 'g1',
      message_id: 'notice-1',
      tombstone_message_id: 'notice-1',
      message_ids: ['gm-1'],
      target_message_seqs: [42],
      envelope: expect.objectContaining({
        from: 'alice.agentid.pub',
        group_id: 'g1',
        type: 'group.message_recalled',
        kind: 'group.message_recalled',
      }),
    }));
    for (const key of ['module_id', 'message_id', 'seq', 'device_id', 'slot_id']) {
      expect(published[1].payload.envelope).not.toHaveProperty(key);
    }
  });

  it('messageTargetsCurrentInstance 按 device_id / slot_id 过滤实例消息', () => {
    const { engine } = createEngine();

    expect(engine.messageTargetsCurrentInstance({ device_id: 'device-a', slot_id: 'slot-a' })).toBe(true);
    expect(engine.messageTargetsCurrentInstance({ device_id: 'other-device', slot_id: 'slot-a' })).toBe(false);
    expect(engine.messageTargetsCurrentInstance({ device_id: 'device-a', slot_id: 'other-slot' })).toBe(false);
  });

  it('publishOrderedMessage 对空洞消息排队，并在 contiguous_seq 前进后按顺序发布', async () => {
    const { engine, seqTracker, published, client } = createEngine();
    const ns = 'p2p:alice.agentid.pub';

    await expect(engine.publishOrderedMessage('message.received', ns, 3, { seq: 3 })).resolves.toBe(false);
    expect(published).toEqual([]);
    expect(client._pendingOrderedMsgs.get(ns).has(3)).toBe(true);

    seqTracker.setContiguousSeq(ns, 2);
    await expect(engine.publishOrderedMessage('message.received', ns, 2, { seq: 2 })).resolves.toBe(true);
    expect(published.map((item) => item.payload.seq)).toEqual([2]);

    seqTracker.setContiguousSeq(ns, 3);
    await engine.drainOrderedMessages(ns);
    expect(published.map((item) => item.payload.seq)).toEqual([2, 3]);
    expect(client._pendingOrderedMsgs.has(ns)).toBe(false);
    expect([...client._pushedSeqs.get(ns)]).toEqual([2, 3]);
  });

  it('publishPulledMessage 发布 pull 批内部空洞消息，并保留去重 guard', async () => {
    const { engine, seqTracker, published, client } = createEngine();
    const ns = 'p2p:alice.agentid.pub';

    seqTracker.setContiguousSeq(ns, 2);
    await expect(engine.publishPulledMessage('message.received', ns, 2, { seq: 2 })).resolves.toBe(true);
    await expect(engine.publishPulledMessage('message.received', ns, 4, { seq: 4 })).resolves.toBe(true);
    seqTracker.setContiguousSeq(ns, 4);
    await engine.drainOrderedMessages(ns);

    expect(published.map((item) => item.payload.seq)).toEqual([2, 4]);
    expect([...client._pushedSeqs.get(ns)]).toEqual([2, 4]);
    await expect(engine.publishPulledMessage('message.received', ns, 4, { seq: 4 })).resolves.toBe(false);
    expect(published.map((item) => item.payload.seq)).toEqual([2, 4]);
  });

  it('clampAckParams 按 max_seen 修正过大的 P2P 和群 ack', () => {
    const { engine, seqTracker } = createEngine();
    seqTracker.setMaxSeenSeq('p2p:alice.agentid.pub', 5);
    seqTracker.setMaxSeenSeq('group:g1.agentid.pub', 7);

    expect(engine.clampAckParams('message.ack', { seq: 9 })).toEqual({ seq: 5 });
    expect(engine.clampAckParams('message.v2.ack', { up_to_seq: -2 })).toEqual({ up_to_seq: 0 });
    expect(engine.clampAckParams('group.ack_messages', {
      group_id: 'g1.agentid.pub',
      msg_seq: 10,
    })).toEqual({
      group_id: 'g1.agentid.pub',
      msg_seq: 7,
    });
    expect(engine.clampAckParams('message.send', { seq: 9 })).toEqual({ seq: 9 });
  });

  it('migrateSeqStateGroupIds 归一化旧 group namespace，冲突取最大并落盘新旧 key', async () => {
    const { engine, client } = createEngine();

    const migrated = await engine.migrateSeqStateGroupIds({
      'group_msg:g1.agentid.pub': 3,
      'group_msg:group.agentid.pub/g1': 5,
      'group_event:g2@agentid.pub': 6,
      'p2p:alice.agentid.pub': 9,
    });

    expect(migrated).toEqual({
      'group_msg:g1.agentid.pub': 5,
      'group_event:g2.agentid.pub': 6,
      'p2p:alice.agentid.pub': 9,
    });
    expect(client._tokenStore.deleteSeq).toHaveBeenCalledWith(
      'alice.agentid.pub',
      'device-a',
      'slot-a',
      'group_msg:group.agentid.pub/g1',
    );
    expect(client._tokenStore.saveSeq).toHaveBeenCalledWith(
      'alice.agentid.pub',
      'device-a',
      'slot-a',
      'group_event:g2.agentid.pub',
      6,
    );
  });

  it('saveSeqTrackerState 优先按 namespace 保存，异步失败时发布 persist_error', async () => {
    const { engine, client, persistErrors } = createEngine();
    client._tokenStore.saveSeq = vi.fn(async () => {
      throw new Error('disk full');
    });

    await engine.saveSeqTrackerState();

    expect(client._tokenStore.saveSeq).toHaveBeenCalled();
    expect(persistErrors).toEqual([expect.objectContaining({
      phase: 'save',
      aid: 'alice.agentid.pub',
      device_id: 'device-a',
      slot_id: 'slot-a',
      error: expect.stringContaining('disk full'),
    })]);
  });

  it('restoreSeqTrackerState 从 token store 读取、迁移并恢复 seq tracker', async () => {
    const { engine, client, seqTracker } = createEngine();
    client._seqTrackerContext = 'ctx-1';
    client._tokenStore.loadAllSeqs = vi.fn(async () => ({
      'group_msg:g1.agentid.pub': 3,
      'p2p:alice.agentid.pub': 8,
    }));

    await engine.restoreSeqTrackerState();

    expect(seqTracker.restoreState).toHaveBeenCalledWith({
      'group_msg:g1.agentid.pub': 3,
      'p2p:alice.agentid.pub': 8,
    });
  });

  it('onV2PushNotification 对 payload push 空洞排队并触发 pull', async () => {
    const { engine, client, seqTracker } = createEngine();
    const ns = 'p2p:alice.agentid.pub';
    seqTracker.setContiguousSeq(ns, 1);
    client._decryptV2PushMessage.mockResolvedValue({
      message_id: 'm3',
      from: 'bob.agentid.pub',
      to: 'alice.agentid.pub',
      seq: 3,
      payload: { type: 'text' },
    });

    await engine.onV2PushNotification({
      seq: 3,
      message_id: 'm3',
      from_aid: 'bob.agentid.pub',
      envelope_json: '{}',
    });

    expect(seqTracker.getMaxSeenSeq(ns)).toBe(3);
    expect(seqTracker.getContiguousSeq(ns)).toBe(1);
    expect(client._pendingOrderedMsgs.get(ns)?.has(3)).toBe(true);
    expect(client._pullV2).toHaveBeenCalled();
  });

  it('onV2PushNotification 在 contiguous_seq 已覆盖 push_seq 时幂等忽略', async () => {
    const { engine, client, seqTracker } = createEngine();
    const ns = 'p2p:alice.agentid.pub';
    seqTracker.setContiguousSeq(ns, 3);

    await engine.onV2PushNotification({
      seq: 3,
      message_id: 'm3',
      from_aid: 'bob.agentid.pub',
    });

    expect(client._decryptV2PushMessage).not.toHaveBeenCalled();
    expect(client._pullV2).not.toHaveBeenCalled();
  });

  it('onRawGroupV2MessageCreated 修复过大的 contiguous_seq 后按修复值 pull', async () => {
    const { engine, client, seqTracker } = createEngine();
    const ns = 'group:g1';
    seqTracker.setContiguousSeq(ns, 999);

    await engine.onRawGroupV2MessageCreated({
      group_id: 'g1',
      seq: 3,
      message_id: 'gm3',
      sender_aid: 'bob.agentid.pub',
    });

    expect(seqTracker.getContiguousSeq(ns)).toBe(2);
    expect(client._pullGroupV2).toHaveBeenCalledWith('g1', 2, 50);
  });

  it('onRawGroupV2MessageCreated 本地已覆盖时不 pull，只后台补 group.v2.ack', async () => {
    const { engine, client, seqTracker, published } = createEngine();
    const ns = 'group:g1';
    seqTracker.setContiguousSeq(ns, 3);

    await engine.onRawGroupV2MessageCreated({
      group_id: 'g1',
      seq: 3,
      message_id: 'gm3',
      sender_aid: 'bob.agentid.pub',
    });

    expect(client._pullGroupV2).not.toHaveBeenCalled();
    expect(published).toEqual([]);
    expect(client._callRawV2Rpc).toHaveBeenCalledWith('group.v2.ack', {
      group_id: 'g1',
      up_to_seq: 3,
      _rpc_background: true,
    });
  });

  it('online unread hint 已 drain 且本地覆盖到更高 seq 时不 pull，只补 group.v2.ack', async () => {
    const { engine, client, seqTracker } = createEngine();
    const ns = 'group:g1';
    seqTracker.setContiguousSeq(ns, 9);

    await engine.onRawGroupV2MessageCreated({
      group_id: 'g1',
      seq: 7,
      kind: 'group.online_unread_hint',
      _online_hint_drained: true,
    });

    expect(client._pullGroupV2).not.toHaveBeenCalled();
    expect(client._callRawV2Rpc).toHaveBeenCalledWith('group.v2.ack', {
      group_id: 'g1',
      up_to_seq: 7,
      _rpc_background: true,
    });
  });

  it('online unread hint 延迟 drain，并在 background_sync=false 时跳过', async () => {
    const { engine, client } = createEngine();

    await engine.onRawGroupV2MessageCreated({
      group_id: 'g1',
      seq: 7,
      kind: 'group.online_unread_hint',
    });
    expect(client._pullGroupV2).not.toHaveBeenCalled();
    for (let i = 0; i < 10 && client._pullGroupV2.mock.calls.length === 0; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    expect(client._pullGroupV2).toHaveBeenCalledWith('g1', 0, 50);

    client._pullGroupV2.mockClear();
    client._sessionOptions.background_sync = false;
    await engine.onRawGroupV2MessageCreated({
      group_id: 'g2',
      seq: 8,
      kind: 'group.online_unread_hint',
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(client._pullGroupV2).not.toHaveBeenCalled();
  });

  it('fillGroupEventGap 拉取群事件后标记 gap-fill、跳过消息事件并 ack 最终 contiguous_seq', async () => {
    const { engine, client, seqTracker, published } = createEngine();
    const groupId = 'g1';
    const ns = `group_event:${groupId}`;
    seqTracker.setContiguousSeq(ns, 1);
    client.call = vi.fn(async () => ({
      events: [
        {
          group_id: groupId,
          event_seq: 2,
          event_type: 'group.announcement_updated',
          client_signature: { sig: 's1' },
        },
        {
          group_id: groupId,
          event_seq: 3,
          event_type: 'group.message_created',
        },
      ],
      has_more: false,
    }));

    await engine.fillGroupEventGap(groupId);

    expect(client.call).toHaveBeenCalledWith('group.pull_events', {
      group_id: groupId,
      after_event_seq: 1,
      device_id: 'device-a',
      limit: 50,
      _rpc_background: true,
    });
    expect(published).toEqual([{
      event: 'group.changed',
      payload: expect.objectContaining({
        event_seq: 2,
        _from_gap_fill: true,
        _verified: true,
      }),
    }]);
    expect(seqTracker.getContiguousSeq(ns)).toBe(3);
    expect(client._transport.call).toHaveBeenCalledWith('group.ack_events', {
      group_id: groupId,
      event_seq: 3,
      device_id: 'device-a',
      slot_id: 'slot-a',
      _rpc_background: true,
    });
  });

  it('fillGroupEventGap 空页只按 cursor floor 推进 tracker，不发送 ack_events', async () => {
    const { engine, client, seqTracker } = createEngine();
    const groupId = 'g1';
    const ns = `group_event:${groupId}`;
    seqTracker.setContiguousSeq(ns, 5);
    client.call = vi.fn(async () => ({
      events: [],
      cursor: { current_seq: 9 },
    }));

    await engine.fillGroupEventGap(groupId);

    expect(seqTracker.getContiguousSeq(ns)).toBe(9);
    expect(client._transport.call).not.toHaveBeenCalledWith('group.ack_events', expect.anything());
  });

  it('fillGroupEventGap 在 has_more=true 时按最大 event_seq 翻页', async () => {
    const { engine, client, seqTracker } = createEngine();
    const groupId = 'g1';
    const ns = `group_event:${groupId}`;
    seqTracker.setContiguousSeq(ns, 0);
    client.call = vi.fn()
      .mockResolvedValueOnce({
        events: [{ group_id: groupId, event_seq: 1, event_type: 'group.message_created' }],
        has_more: true,
      })
      .mockResolvedValueOnce({
        events: [{ group_id: groupId, event_seq: 2, event_type: 'group.message_created' }],
        has_more: false,
      });

    await engine.fillGroupEventGap(groupId);

    expect(client.call).toHaveBeenCalledTimes(2);
    expect(client.call.mock.calls[0][1].after_event_seq).toBe(0);
    expect(client.call.mock.calls[1][1].after_event_seq).toBe(1);
    expect(seqTracker.getContiguousSeq(ns)).toBe(2);
  });

  it('handleGroupChangedEventSeq 遇到 _from_gap_fill 事件不递归触发补洞', async () => {
    const { engine, client, seqTracker } = createEngine();
    const groupId = 'g1';
    seqTracker.setContiguousSeq(`group_event:${groupId}`, 1);

    await engine.handleGroupChangedEventSeq({
      group_id: groupId,
      event_seq: 3,
      _from_gap_fill: true,
    }, groupId);

    expect(client._safeAsync).not.toHaveBeenCalled();
    expect(client.call).not.toHaveBeenCalled();
  });

  it('handleGroupChangedEventSeq 本地已覆盖时不 fill/publish，只后台补 ack_events', async () => {
    const { engine, client, seqTracker, published } = createEngine();
    const groupId = 'g1';
    const ns = `group_event:${groupId}`;
    seqTracker.setContiguousSeq(ns, 8);

    await engine.handleGroupChangedEventSeq({
      group_id: groupId,
      event_seq: 7,
      action: 'announcement_updated',
    }, groupId);

    expect(published).toEqual([]);
    expect(client._safeAsync).not.toHaveBeenCalled();
    expect(client.call).toHaveBeenCalledWith('group.ack_events', {
      group_id: groupId,
      event_seq: 7,
      device_id: 'device-a',
      slot_id: 'slot-a',
      _rpc_background: true,
    });
  });

  it('handleGroupChangedEventSeq 连续 push 后持久化并 ack 事件 cursor', async () => {
    const { engine, client, seqTracker } = createEngine();
    const groupId = 'g1';
    const ns = `group_event:${groupId}`;
    seqTracker.setContiguousSeq(ns, 5);

    await engine.handleGroupChangedEventSeq({
      group_id: groupId,
      event_seq: 6,
    }, groupId);

    expect(seqTracker.getContiguousSeq(ns)).toBe(6);
    expect(client._tokenStore.saveSeq).toHaveBeenCalledWith('alice.agentid.pub', 'device-a', 'slot-a', ns, 6);
    expect(client._transport.call).toHaveBeenCalledWith('group.ack_events', {
      group_id: groupId,
      event_seq: 6,
      device_id: 'device-a',
      slot_id: 'slot-a',
      _rpc_background: true,
    });
    expect(client._safeAsync).not.toHaveBeenCalled();
  });
});
