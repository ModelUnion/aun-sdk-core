/**
 * RPCTransport 单元测试
 *
 * 覆盖连接超时相关的两个 P2 修复：
 * - ISSUE-SDK-TS-005: 连接超时应使用构造函数传入的 _timeout，而非硬编码 10s
 * - ISSUE-SDK-TS-006: WebSocket open 后不应清除超时，超时应覆盖整个握手流程
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import { EventDispatcher } from '../../src/events.js';
import { RPCTransport } from '../../src/transport.js';
import { ConnectionError } from '../../src/errors.js';

// ── Mock WebSocket ────────────────────────────────────────

/**
 * 模拟 WebSocket 实例：继承 EventEmitter 以支持 on/emit，
 * 提供 send / close / terminate 空操作。
 */
class MockWebSocket extends EventEmitter {
  readyState = 1; // OPEN
  sent: string[] = [];
  close(): void { this.emit('close', 1000); }
  terminate(): void { /* noop */ }
  send(data: string, cb?: (err?: Error) => void): void {
    this.sent.push(data);
    cb?.();
  }
}

class MockConnectingWebSocket extends EventEmitter {
  readyState = 0; // CONNECTING
  terminateCalls = 0;
  errorListenerCountAtTerminate = -1;

  close(): void {
    this.terminate();
  }

  terminate(): void {
    this.terminateCalls += 1;
    this.errorListenerCountAtTerminate = this.listenerCount('error');
    process.nextTick(() => {
      this.emit('error', new Error('WebSocket was closed before the connection was established'));
      this.readyState = 3; // CLOSED
      this.emit('close', 1006);
    });
  }

  send(_data: string, cb?: (err?: Error) => void): void {
    cb?.();
  }
}

// ── 辅助函数 ────────────────────────────────────────────────

/**
 * 通过 monkey-patch _connectWithWs，绕过真实 WebSocket 构造，
 * 直接注入 MockWebSocket 实例。返回 { transport, ws, connectPromise }。
 */
function createTestTransport(opts: { timeout?: number } = {}) {
  const dispatcher = new EventDispatcher();
  const transport = new RPCTransport({
    eventDispatcher: dispatcher,
    timeout: opts.timeout ?? 10_000,
    verifySsl: false,
  });
  const ws = new MockWebSocket();

  // 劫持 connect 方法，让它调用内部 _connectWithWs 并注入 mock ws
  const connectPromise = (transport as any)._connectWithWs(ws);

  return { transport, ws, connectPromise, dispatcher };
}

// ── 测试 ────────────────────────────────────────────────────

describe('RPCTransport 连接超时', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── ISSUE-SDK-TS-005: 超时使用 _timeout 参数 ──────────────

  it('连接超时应使用构造函数传入的 timeout（非硬编码 10s）', async () => {
    // 设置一个较短的自定义超时 (3s)
    const { ws, connectPromise } = createTestTransport({ timeout: 3_000 });

    // 触发 open 但不发送 challenge（模拟服务端沉默）
    ws.emit('open');

    // 推进 3s — 自定义超时应触发
    vi.advanceTimersByTime(3_000);

    await expect(connectPromise).rejects.toThrow(ConnectionError);
    await expect(connectPromise).rejects.toThrow(/timeout/i);
  });

  it('自定义 timeout=500ms 时 500ms 后超时', async () => {
    const { ws, connectPromise } = createTestTransport({ timeout: 500 });

    ws.emit('open');

    // 499ms 不应超时
    vi.advanceTimersByTime(499);
    // Promise 应仍在 pending 状态（无法直接断言 pending，但 500ms 时应触发）

    vi.advanceTimersByTime(1);

    await expect(connectPromise).rejects.toThrow(ConnectionError);
    await expect(connectPromise).rejects.toThrow(/timeout/i);
  });

  // ── ISSUE-SDK-TS-006: open 后超时不被清除 ─────────────────

  it('WebSocket open 后如果服务端不发 challenge，应超时拒绝', async () => {
    const { ws, connectPromise } = createTestTransport({ timeout: 2_000 });

    // 仅触发 open，不发送任何消息
    ws.emit('open');

    // 推进超时时间
    vi.advanceTimersByTime(2_000);

    // 应因超时拒绝，不应永远挂起
    await expect(connectPromise).rejects.toThrow(ConnectionError);
    await expect(connectPromise).rejects.toThrow(/timeout/i);
  });

  it('WebSocket open 后收到 challenge 应正常 resolve', async () => {
    const { ws, connectPromise } = createTestTransport({ timeout: 2_000 });

    ws.emit('open');

    // 在超时前发送 challenge 消息
    const challenge = JSON.stringify({
      jsonrpc: '2.0',
      method: 'challenge',
      params: { nonce: 'test-nonce-123' },
    });
    ws.emit('message', Buffer.from(challenge));

    const result = await connectPromise;
    expect(result).toBeDefined();
    expect(result!.method).toBe('challenge');
    expect(result!.params).toEqual({ nonce: 'test-nonce-123' });
  });

  it('收到 challenge 后超时定时器不应再触发错误', async () => {
    const { ws, connectPromise } = createTestTransport({ timeout: 1_000 });

    ws.emit('open');

    // 发送 challenge
    const challenge = JSON.stringify({
      jsonrpc: '2.0',
      method: 'challenge',
      params: { nonce: 'abc' },
    });
    ws.emit('message', Buffer.from(challenge));

    const result = await connectPromise;
    expect(result).toBeDefined();

    // 推进时间超过超时值 — 不应抛出异常
    vi.advanceTimersByTime(2_000);
    // 如果定时器仍活着且未被 initialResolved 守卫，这里会报错
  });

  it('连接超时回滚 CONNECTING WebSocket 时应吸收 ws 异步 error', async () => {
    const dispatcher = new EventDispatcher();
    const transport = new RPCTransport({
      eventDispatcher: dispatcher,
      timeout: 100,
      verifySsl: false,
    });
    const ws = new MockConnectingWebSocket();

    const connectPromise = (transport as any)._connectWithWs(ws);
    vi.advanceTimersByTime(100);

    await expect(connectPromise).rejects.toThrow(/timeout/i);
    expect(ws.terminateCalls).toBe(1);
    expect(ws.errorListenerCountAtTerminate).toBeGreaterThan(0);
    await new Promise<void>((resolve) => process.nextTick(resolve));
  });
});

describe('RPCTransport 后台 RPC 调度', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function createReadyTransport(timeout = 10_000) {
    const dispatcher = new EventDispatcher();
    const transport = new RPCTransport({
      eventDispatcher: dispatcher,
      timeout,
      verifySsl: false,
    });
    const ws = new MockWebSocket();
    (transport as any)._ws = ws;
    (transport as any)._closed = false;
    return { transport, ws, dispatcher };
  }

  function createReadyTransportWithListeners(timeout = 10_000) {
    const ready = createReadyTransport(timeout);
    (ready.transport as any)._setupListeners(ready.ws);
    return ready;
  }

  function parseSent(ws: MockWebSocket): Array<{ id: string; method: string; params?: Record<string, unknown> }> {
    return ws.sent.map((raw) => JSON.parse(raw));
  }

  // 源码 _enqueueSend 把 ws.send 推迟到微任务串行执行，
  // 读取 ws.sent 前需 flush 微任务队列（真实计时器）。
  async function flushSends(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  it('后台 RPC 不能占满全部 in-flight，普通 RPC 应优先发送', async () => {
    const { transport, ws } = createReadyTransport();
    const calls = Array.from({ length: 16 }, (_, i) =>
      transport.call(`background.${i}`, { _rpc_background: true }).catch((err) => err),
    );

    await flushSends();
    expect(parseSent(ws).filter((msg) => msg.method.startsWith('background.'))).toHaveLength(8);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(8);
    expect((transport as any)._pendingBackground.size).toBe(8);

    const normalCall = transport.call('meta.ping', {}).catch((err) => err);
    await flushSends();
    const sent = parseSent(ws);
    expect(sent).toHaveLength(9);
    expect(sent[8].method).toBe('meta.ping');

    await transport.close();
    await Promise.allSettled([...calls, normalCall]);
  });

  it('后台 RPC 成功和错误响应都应释放后台计数并继续 drain', async () => {
    const { transport, ws } = createReadyTransport();
    const calls = Array.from({ length: 10 }, (_, i) =>
      transport.call(`background.${i}`, { _rpc_background: true }).catch((err) => err),
    );
    await flushSends();
    expect(ws.sent).toHaveLength(8);

    const first = parseSent(ws)[0];
    const firstMeta = (transport as any)._pendingMeta.get(first.id);
    expect(firstMeta).toMatchObject({ method: first.method, background: true });
    expect(firstMeta.pendingSince).toBeGreaterThanOrEqual(firstMeta.queuedAt);
    expect(firstMeta.deadlineAt).toBeGreaterThan(firstMeta.pendingSince);
    (transport as any)._routeMessage({ jsonrpc: '2.0', id: first.id, result: { ok: true } });
    await flushSends();
    expect(ws.sent).toHaveLength(9);
    expect((transport as any)._pendingBackground.size).toBe(8);
    expect((transport as any)._pendingMeta.has(first.id)).toBe(false);

    const second = parseSent(ws)[1];
    (transport as any)._routeMessage({
      jsonrpc: '2.0',
      id: second.id,
      error: { code: -32000, message: 'unit-error' },
    });
    await flushSends();
    expect(ws.sent).toHaveLength(10);
    expect((transport as any)._pendingBackground.size).toBe(8);

    await transport.close();
    await Promise.allSettled(calls);
  });

  it('后台 RPC 超时应释放 pending 与后台队列记账', async () => {
    vi.useFakeTimers();
    const { transport, ws } = createReadyTransport(100);
    const calls = Array.from({ length: 10 }, (_, i) =>
      transport.call(`background.${i}`, { _rpc_background: true }, 100).catch((err) => err),
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(ws.sent).toHaveLength(8);

    vi.advanceTimersByTime(100);
    await Promise.allSettled(calls);
    expect((transport as any)._pending.size).toBe(0);
    expect((transport as any)._pendingMeta.size).toBe(0);
    expect((transport as any)._pendingBackground.size).toBe(0);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(0);

    const normalCall = transport.call('meta.ping', {}, 100).catch((err) => err);
    await vi.advanceTimersByTimeAsync(0);
    expect(parseSent(ws).at(-1)?.method).toBe('meta.ping');
    await transport.close();
    await Promise.allSettled([normalCall]);
  });

  it('close 应拒绝 pending、普通队列和后台队列并清空记账', async () => {
    const { transport } = createReadyTransport();
    const calls = Array.from({ length: 18 }, (_, i) =>
      transport.call(`background.${i}`, { _rpc_background: true }).catch((err) => err),
    );
    const normalCalls = Array.from({ length: 10 }, (_, i) =>
      transport.call(`normal.${i}`, {}).catch((err) => err),
    );

    expect((transport as any)._pendingBackground.size).toBe(8);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(10);
    expect((transport as any)._rpcQueue).toHaveLength(2);

    await transport.close();
    await Promise.allSettled([...calls, ...normalCalls]);
    expect((transport as any)._pending.size).toBe(0);
    expect((transport as any)._pendingMeta.size).toBe(0);
    expect((transport as any)._pendingBackground.size).toBe(0);
    expect((transport as any)._rpcQueue).toHaveLength(0);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(0);
  });

  it('连接关闭后再次调用应在错误信息中保留 close code', async () => {
    const { transport, ws } = createReadyTransportWithListeners();

    ws.emit('close', 4013);

    await expect(transport.call('auth.connect', {})).rejects.toThrow(/4013/);
  });
});

describe('RPCTransport notify', () => {
  it('发送 JSON-RPC Notification 时不应包含 id', async () => {
    const dispatcher = new EventDispatcher();
    const transport = new RPCTransport({ eventDispatcher: dispatcher, verifySsl: false });
    const ws = new MockWebSocket();
    (transport as any)._ws = ws;
    (transport as any)._closed = false;

    await transport.notify('notification/client.activity', { state: 'idle' });

    const sent = JSON.parse(ws.sent[0]);
    expect(sent).toEqual({
      jsonrpc: '2.0',
      method: 'notification/client.activity',
      params: { state: 'idle' },
    });
    expect(sent.id).toBeUndefined();
  });

  it('event/app.* 应直接发布为应用事件', async () => {
    const dispatcher = new EventDispatcher();
    const transport = new RPCTransport({ eventDispatcher: dispatcher, verifySsl: false });
    const received: unknown[] = [];
    dispatcher.subscribe('app.typing', (payload) => { received.push(payload); });

    (transport as any)._routeMessage({
      jsonrpc: '2.0',
      method: 'event/app.typing',
      params: { thread_id: 't1' },
    });
    await Promise.resolve();

    expect(received).toEqual([{ thread_id: 't1' }]);
  });
});
