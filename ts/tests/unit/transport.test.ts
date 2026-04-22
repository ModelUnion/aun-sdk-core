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
  close(): void { this.emit('close', 1000); }
  terminate(): void { /* noop */ }
  send(_data: string): void { /* noop */ }
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
});
