import { describe, it, expect, vi, afterEach } from 'vitest';
import { EventDispatcher } from '../../src/events.js';
import { RPCTransport } from '../../src/transport.js';

class MockWebSocket {
  sent: string[] = [];
  close(): void { /* noop */ }
  send(data: string): void { this.sent.push(data); }
}

class ClosingMockWebSocket {
  readyState = 2;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;
  private closeListeners: Array<(event: { code: number; reason: string }) => void> = [];

  close(): void { /* noop */ }
  send(_data: string): void {
    throw new Error('WebSocket is already in CLOSING or CLOSED state');
  }
  addEventListener(type: string, handler: (event: { code: number; reason: string }) => void): void {
    if (type === 'close') this.closeListeners.push(handler);
  }
  removeEventListener(type: string, handler: (event: { code: number; reason: string }) => void): void {
    if (type === 'close') this.closeListeners = this.closeListeners.filter((item) => item !== handler);
  }
  emitClose(code: number, reason: string): void {
    const event = { code, reason };
    this.onclose?.(event);
    for (const listener of [...this.closeListeners]) listener(event);
  }
}

function createReadyTransport(timeout = 10) {
  const dispatcher = new EventDispatcher();
  const transport = new RPCTransport({
    eventDispatcher: dispatcher,
    timeout,
  });
  const ws = new MockWebSocket();
  (transport as any)._ws = ws;
  (transport as any)._closed = false;
  return { transport, ws, dispatcher };
}

function parseSent(ws: MockWebSocket): Array<{ id: string; method: string; params?: Record<string, unknown> }> {
  return ws.sent.map((raw) => JSON.parse(raw));
}

// 源码 _sendText 经由 _sendChain 把 ws.send 推迟到微任务执行，
// 读取 ws.sent 前需 flush 微任务队列（真实计时器场景）。
function flushSend(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe('RPCTransport 后台 RPC 调度', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('transport 已关闭时应在错误中保留最近 WebSocket close code', async () => {
    const { transport } = createReadyTransport();

    (transport as any)._lastCloseCode = 4013;
    (transport as any)._lastCloseReason = 'short_connection_capacity_exceeded';
    (transport as any)._closed = true;

    await expect(transport.call('auth.connect', {})).rejects.toThrow(/4013/);
    await expect(transport.call('auth.connect', {})).rejects.toThrow(/short_connection_capacity_exceeded/);
  });

  it('send 与 close 竞态时应等待并保留 close code', async () => {
    const dispatcher = new EventDispatcher();
    const transport = new RPCTransport({
      eventDispatcher: dispatcher,
      timeout: 1,
    });
    const ws = new ClosingMockWebSocket();
    (transport as any)._ws = ws;
    (transport as any)._closed = false;
    ws.onclose = (event) => (transport as any)._handleClose(event);

    const call = transport.call('meta.ping', {});
    setTimeout(() => ws.emitClose(4013, 'short_connection_capacity_exceeded'), 0);

    await expect(call).rejects.toThrow(/4013/);
    await expect(call).rejects.toThrow(/short_connection_capacity_exceeded|websocket closed/);
  });

  it('后台 RPC 不能占满全部 in-flight，普通 RPC 应优先发送', async () => {
    const { transport, ws } = createReadyTransport();
    const calls = Array.from({ length: 16 }, (_, i) =>
      transport.call(`background.${i}`, { _rpc_background: true }).catch((err) => err),
    );

    await flushSend();
    expect(parseSent(ws).filter((msg) => msg.method.startsWith('background.'))).toHaveLength(8);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(8);
    expect((transport as any)._pendingBackground.size).toBe(8);

    const normalCall = transport.call('meta.ping', {}).catch((err) => err);
    await flushSend();
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
    await flushSend();
    expect(ws.sent).toHaveLength(8);

    const first = parseSent(ws)[0];
    (transport as any)._routeMessage({ jsonrpc: '2.0', id: first.id, result: { ok: true } });
    await flushSend();
    expect(ws.sent).toHaveLength(9);
    expect((transport as any)._pendingBackground.size).toBe(8);

    const second = parseSent(ws)[1];
    (transport as any)._routeMessage({
      jsonrpc: '2.0',
      id: second.id,
      error: { code: -32000, message: 'unit-error' },
    });
    await flushSend();
    expect(ws.sent).toHaveLength(10);
    expect((transport as any)._pendingBackground.size).toBe(8);

    await transport.close();
    await Promise.allSettled(calls);
  });

  it('后台 RPC 超时应释放 pending 与后台队列记账', async () => {
    vi.useFakeTimers();
    const { transport, ws } = createReadyTransport(0.1);
    const calls = Array.from({ length: 10 }, (_, i) =>
      transport.call(`background.${i}`, { _rpc_background: true }, 0.1).catch((err) => err),
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(ws.sent).toHaveLength(8);

    await vi.advanceTimersByTimeAsync(100);
    await Promise.allSettled(calls);
    expect((transport as any)._pending.size).toBe(0);
    expect((transport as any)._pendingBackground.size).toBe(0);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(0);

    const normalCall = transport.call('meta.ping', {}, 0.1).catch((err) => err);
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
    expect((transport as any)._pendingBackground.size).toBe(0);
    expect((transport as any)._rpcQueue).toHaveLength(0);
    expect((transport as any)._backgroundRpcQueue).toHaveLength(0);
  });
});

describe('RPCTransport notify', () => {
  it('发送 JSON-RPC Notification 时不应包含 id', async () => {
    const { transport, ws } = createReadyTransport();

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
    const { transport, dispatcher } = createReadyTransport();
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
