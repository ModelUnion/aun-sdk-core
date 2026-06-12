import { describe, expect, it, vi } from 'vitest';

import { ConnectionError, PermissionError, ValidationError } from '../../src/errors.js';
import { ConnectionState } from '../../src/types.js';
import { RpcPipeline } from '../../src/client/rpc-pipeline.js';
import { ClientRuntime } from '../../src/client/runtime.js';

function createPipeline(overrides: Record<string, unknown> = {}): { pipeline: RpcPipeline; client: Record<string, any> } {
  const client: Record<string, any> = {
    state: ConnectionState.READY,
    _aid: 'alice.agentid.pub',
    _deviceId: 'device-a',
    _slotId: 'slot-a',
    _backgroundRpcDepth: 0,
    _instanceProtectedHeaders: { trace_id: 'instance-trace', priority: 'normal' },
    _pullGates: new Map(),
    _pullResponseKeys: new Map(),
    _clientLog: { debug: vi.fn(), info: vi.fn(), warn: vi.fn() },
    _clampAckParams: vi.fn((_method: string, params: Record<string, unknown>) => params),
    _isEchoPayload: vi.fn((payload: unknown) => Boolean((payload as Record<string, unknown> | null)?.text?.toString().toLowerCase().includes('echo'))),
    _signClientOperation: vi.fn((_method: string, params: Record<string, unknown>) => {
      params.client_signature = { signed: true };
    }),
    _schedulePendingP2pPullIfNeeded: vi.fn(),
    _sleep: vi.fn(async () => undefined),
    _withBackgroundRpc: vi.fn(async (operation: () => unknown) => await operation()),
    // 源码 call() 在发送后调 _delivery.attachSendResultEnvelope 回填 envelope
    _delivery: {
      attachSendResultEnvelope: vi.fn((_method: string, _params: unknown, result: unknown) => result),
    },
    ...overrides,
  };
  return { client, pipeline: new RpcPipeline(new ClientRuntime(client)) };
}

describe('RpcPipeline 组件边界', () => {
  it('preflight 拒绝未连接和 internal-only 方法', () => {
    const disconnected = createPipeline({ state: ConnectionState.DISCONNECTED }).pipeline;
    expect(() => disconnected.preflight('message.send', { to: 'bob.agentid.pub' })).toThrow(ConnectionError);

    const { pipeline } = createPipeline();
    expect(() => pipeline.preflight('auth.connect', {})).toThrow(PermissionError);
  });

  it('preflight 合并 protected_headers 并规范化 outbound payload，且不修改调用方 params', () => {
    const { pipeline } = createPipeline();
    const original = {
      to: 'bob.agentid.pub',
      content: { text: 'hello' },
      protected_headers: { priority: 'urgent' },
    };

    const result = pipeline.preflight('message.send', original);

    expect(result.params.payload).toEqual({ type: 'text', text: 'hello' });
    expect(result.params).not.toHaveProperty('content');
    expect(result.params.protected_headers).toEqual({ trace_id: 'instance-trace', priority: 'urgent' });
    expect(original).toHaveProperty('content');
  });

  it('preflight 为 message cursor 注入当前实例上下文，并拒绝跨实例 cursor', () => {
    const { pipeline } = createPipeline();

    expect(pipeline.preflight('message.pull', { after_seq: 7 }).params).toMatchObject({
      after_seq: 7,
      device_id: 'device-a',
      slot_id: 'slot-a',
    });
    expect(() => pipeline.preflight('message.ack', { device_id: 'other-device' })).toThrow(ValidationError);
  });

  it('preflight 归一化 group_id、保留显式 cursor 参数，并注入默认实例上下文', () => {
    const { pipeline } = createPipeline();

    const explicit = pipeline.preflight('group.pull', {
      group_id: 'g-room.agentid.pub',
      device_id: 'device-x',
      slot_id: 'slot-x',
      device_name: 'laptop',
    }).params;
    expect(explicit.group_id).toBe('group.agentid.pub/g-room');
    expect(explicit._group_cursor_params).toEqual({
      device_id: 'device-x',
      slot_id: 'slot-x',
      device_name: 'laptop',
    });

    const injected = pipeline.preflight('group.send', { group_id: 'room.agentid.pub', payload: { text: 'hi' } }).params;
    expect(injected).toMatchObject({
      group_id: 'group.agentid.pub/room',
      device_id: 'device-a',
      slot_id: 'slot-a',
    });
  });

  it('applyClientSignature 对明文 echo send 跳过签名，对普通关键方法调用签名函数', () => {
    const { client, pipeline } = createPipeline();
    const echoParams = { payload: { text: 'echo ping' }, client_signature: { stale: true } };

    pipeline.applyClientSignature('message.send', echoParams);
    expect(echoParams).not.toHaveProperty('client_signature');
    expect(client._signClientOperation).not.toHaveBeenCalled();

    const normalParams = { to: 'bob.agentid.pub', payload: { text: 'hello' } };
    pipeline.applyClientSignature('message.send', normalParams);
    expect(client._signClientOperation).toHaveBeenCalledWith('message.send', normalParams);
    expect(normalParams.client_signature).toEqual({ signed: true });
  });

  it('storage.get_by_share 实际走签名和非幂等 35 秒超时', async () => {
    const { client, pipeline } = createPipeline({
      _transport: { call: vi.fn().mockResolvedValue({ ok: true }) },
      _groupState: { postprocessResult: vi.fn(async (_method: string, _params: unknown, result: unknown) => result) },
    });

    await pipeline.call('storage.get_by_share', { share_id: 'share-1' });

    expect(client._signClientOperation).toHaveBeenCalledWith(
      'storage.get_by_share',
      expect.objectContaining({ share_id: 'share-1', client_signature: { signed: true } }),
    );
    expect(client._transport.call).toHaveBeenCalledWith(
      'storage.get_by_share',
      expect.objectContaining({ share_id: 'share-1', client_signature: { signed: true } }),
      35_000,
    );
  });

  it('resolve_access_ticket 实际走签名和非幂等 35 秒超时', async () => {
    const { client, pipeline } = createPipeline({
      _transport: { call: vi.fn().mockResolvedValue({ ok: true }) },
      _groupState: { postprocessResult: vi.fn(async (_method: string, _params: unknown, result: unknown) => result) },
    });

    await pipeline.call('group.resources.resolve_access_ticket', { access_ticket: 'ticket-1' });

    expect(client._signClientOperation).toHaveBeenCalledWith(
      'group.resources.resolve_access_ticket',
      expect.objectContaining({ access_ticket: 'ticket-1', client_signature: { signed: true } }),
    );
    expect(client._transport.call).toHaveBeenCalledWith(
      'group.resources.resolve_access_ticket',
      expect.objectContaining({ access_ticket: 'ticket-1', client_signature: { signed: true } }),
      35_000,
    );
  });
});
