import { describe, expect, it, vi } from 'vitest';

import { V2E2EECoordinator } from '../../src/client/v2-e2ee.js';
import { ClientRuntime } from '../../src/client/runtime.js';

function createCoordinator(): { coordinator: V2E2EECoordinator; client: Record<string, any> } {
  const client: Record<string, any> = {
    _aid: 'bob.agentid.pub',
    _deviceId: 'device-b',
    _v2BootstrapCache: new Map(),
    _clientLog: { debug: vi.fn(), info: vi.fn(), warn: vi.fn() },
    _validateMessageRecipient: vi.fn(),
    _protectedHeadersFromParams: vi.fn(() => ({ trace_id: 'trace-1' })),
    _logMessageDebug: vi.fn(),
    _buildV2P2PEnvelope: vi.fn(async ({ useCache }: { useCache: boolean }) => ({
      type: 'e2ee.p2p_encrypted',
      version: 'v2',
      suite: 'P256',
      message_id: 'thought-1',
      use_cache: useCache,
    })),
    _signClientOperation: vi.fn((_method: string, params: Record<string, unknown>) => {
      params.client_signature = { signed: true };
    }),
    _transport: {
      call: vi.fn(async () => ({ ok: true })),
    },
    _decryptV2EnvelopeForThought: vi.fn(async () => null),
    _v2E2eeMeta: vi.fn((envelope: Record<string, unknown>) => ({
      payload_type: envelope.payload_type,
      protected_headers: envelope.protected_headers,
      agent_md: envelope.agent_md,
    })),
    _attachV2EnvelopeMetadata: vi.fn((event: Record<string, unknown>, meta: Record<string, any>) => {
      if (meta.payload_type) event.payload_type = meta.payload_type;
      if (meta.protected_headers) event.protected_headers = { ...meta.protected_headers };
      if (meta.agent_md) event.agent_md = { ...meta.agent_md };
    }),
    _publishOrderedMessage: vi.fn(async () => true),
    _publishAppEvent: vi.fn(async () => true),
    // 源码发送后调 _delivery.attachSendResultEnvelope 回填 envelope
    _delivery: {
      attachSendResultEnvelope: vi.fn((_method: string, _params: unknown, result: unknown) => result),
    },
  };
  return { client, coordinator: new V2E2EECoordinator(new ClientRuntime(client)) };
}

describe('V2E2EECoordinator 组件边界', () => {
  it('bootstrap cache 支持 set/get/delete/clear 和 TTL prune', () => {
    const { coordinator } = createCoordinator();

    coordinator.setBootstrapCacheEntry('bob.agentid.pub', { cachedAt: 100, devices: [{ device_id: 'old' }] });
    coordinator.setBootstrapCacheEntry('alice.agentid.pub', { cachedAt: 900, devices: [{ device_id: 'fresh' }] });

    coordinator.pruneExpiredBootstrapCache(500, 1000);

    expect(coordinator.getBootstrapCacheEntry('bob.agentid.pub')).toBeUndefined();
    expect(coordinator.getBootstrapCacheEntry('alice.agentid.pub')?.devices).toEqual([{ device_id: 'fresh' }]);

    coordinator.deleteBootstrapCacheEntry('alice.agentid.pub');
    expect(coordinator.getBootstrapCacheEntry('alice.agentid.pub')).toBeUndefined();

    coordinator.setBootstrapCacheEntry('group:g1', { cachedAt: 1000, devices: [] });
    coordinator.clearBootstrapCache();
    expect(coordinator.getBootstrapCacheEntry('group:g1')).toBeUndefined();
  });

  it('message.thought.put V2 走内部 transport raw call，并先写入 client_signature', async () => {
    const { coordinator, client } = createCoordinator();

    const result = await coordinator.putMessageThoughtEncryptedV2({
      to: 'alice.agentid.pub',
      thought_id: 'thought-1',
      timestamp: 123,
      payload: { text: 'hello' },
      context: { topic: 'ctx' },
    });

    expect(result).toEqual({ ok: true });
    expect(client._buildV2P2PEnvelope).toHaveBeenCalledWith(expect.objectContaining({
      to: 'alice.agentid.pub',
      payload: { text: 'hello' },
      messageId: 'thought-1',
      timestamp: 123,
      protectedHeaders: { trace_id: 'trace-1' },
      context: { topic: 'ctx' },
      useCache: true,
    }));
    expect(client._signClientOperation).toHaveBeenCalledWith('message.thought.put', expect.objectContaining({
      to: 'alice.agentid.pub',
      encrypted: true,
      thought_id: 'thought-1',
    }));
    expect(client._transport.call).toHaveBeenCalledWith('message.thought.put', expect.objectContaining({
      to: 'alice.agentid.pub',
      encrypted: true,
      client_signature: { signed: true },
    }));
  });

  it('message.thought.put 遇到 V2 retryable code 时清理 bootstrap cache 后重试一次', async () => {
    const { coordinator, client } = createCoordinator();
    const retryable = Object.assign(new Error('bootstrap stale'), { code: -33011 });
    client._transport.call
      .mockRejectedValueOnce(retryable)
      .mockResolvedValueOnce({ ok: true, retried: true });
    coordinator.setBootstrapCacheEntry('alice.agentid.pub', { cachedAt: Date.now(), devices: [{ device_id: 'stale' }] });

    const result = await coordinator.putMessageThoughtEncryptedV2({
      to: 'alice.agentid.pub',
      thought_id: 'thought-1',
      timestamp: 123,
      payload: { text: 'hello' },
    });

    expect(result).toEqual({ ok: true, retried: true });
    expect(coordinator.getBootstrapCacheEntry('alice.agentid.pub')).toBeUndefined();
    expect(client._buildV2P2PEnvelope.mock.calls.map((call: any[]) => call[0].useCache)).toEqual([true, false]);
    expect(client._transport.call).toHaveBeenCalledTimes(2);
  });

  it('encrypted push 解密失败时只发布 header-only undecryptable 事件', async () => {
    const { coordinator, client } = createCoordinator();
    const msg = {
      message_id: 'm-1',
      from: 'alice.agentid.pub',
      to: 'bob.agentid.pub',
      seq: 7,
      timestamp: 123,
      device_id: 'device-a',
      slot_id: 'slot-a',
      payload: {
        type: 'e2ee.p2p_encrypted',
        version: 'v2',
        suite: 'P256_HKDF_SHA256_AES_256_GCM',
        payload_type: 'text',
        protected_headers: { payload_type: 'text', trace_id: 'trace-1' },
        agent_md: { sender: { etag: 'etag-1' } },
        ciphertext: 'cipher',
      },
    };

    await expect(coordinator.publishEncryptedPushMessage(
      'message.received',
      'message.undecryptable',
      'p2p:bob.agentid.pub',
      7,
      msg,
      false,
    )).resolves.toBe(true);

    expect(client._decryptV2EnvelopeForThought).toHaveBeenCalledWith({
      envelope: msg.payload,
      fromAid: 'alice.agentid.pub',
    });
    expect(client._publishOrderedMessage).toHaveBeenCalledWith(
      'message.undecryptable',
      'p2p:bob.agentid.pub',
      7,
      expect.objectContaining({
        message_id: 'm-1',
        from: 'alice.agentid.pub',
        to: 'bob.agentid.pub',
        _decrypt_stage: 'push_envelope',
        _envelope_type: 'e2ee.p2p_encrypted',
        payload_type: 'text',
        protected_headers: { payload_type: 'text', trace_id: 'trace-1' },
        agent_md: { sender: { etag: 'etag-1' } },
      }),
    );
    expect(client._publishAppEvent).not.toHaveBeenCalled();
  });
});
