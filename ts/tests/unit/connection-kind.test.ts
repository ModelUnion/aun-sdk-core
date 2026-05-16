/**
 * 长短连接共存 单元测试
 *
 * 对齐 Python SDK test_connection_kind.py 的 10 个用例。
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AUNClient } from '../../src/client.js';
import { ValidationError } from '../../src/errors.js';

describe('长短连接共存', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aun-conn-kind-'));
  });

  // 1. _NO_RECONNECT_CODES 包含 4012 / 4013
  it('_NO_RECONNECT_CODES 包含 4012 和 4013', () => {
    const codes = (AUNClient as any)._NO_RECONNECT_CODES as Set<number>;
    expect(codes.has(4012)).toBe(true);
    expect(codes.has(4013)).toBe(true);
  });

  // 2. _normalizeConnectParams 不传 connection_kind 默认 "long"
  it('_normalizeConnectParams 默认 connection_kind 为 long', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const params = (client as any)._normalizeConnectParams({
      access_token: 'tok',
      gateway: 'ws://localhost/aun',
    });
    expect(params.connection_kind).toBe('long');
  });

  // 3. _normalizeConnectParams 接受 kind="short" + short_ttl_ms
  it('_normalizeConnectParams 接受 kind=short + short_ttl_ms', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const params = (client as any)._normalizeConnectParams({
      access_token: 'tok',
      gateway: 'ws://localhost/aun',
      connection_kind: 'short',
      short_ttl_ms: 30000,
    });
    expect(params.connection_kind).toBe('short');
    expect(params.short_ttl_ms).toBe(30000);
  });

  // 4. _normalizeConnectParams 拒绝无效 kind
  it('_normalizeConnectParams 拒绝无效 connection_kind', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    expect(() =>
      (client as any)._normalizeConnectParams({
        access_token: 'tok',
        gateway: 'ws://localhost/aun',
        connection_kind: 'invalid',
      }),
    ).toThrow(ValidationError);
  });

  // 5. _initializeSession kind=short 时 payload 含 options.kind="short" + short_ttl_ms
  it('auth.connect payload kind=short 含 options', async () => {
    const client = new AUNClient({ aun_path: tmpDir });
    // 直接测试 AuthFlow._initializeSession 的行为：
    // 通过 mock transport.call 捕获 auth.connect 的 params
    const capturedCalls: Array<{ method: string; params: any }> = [];
    const mockTransport = {
      call: vi.fn(async (method: string, params: any) => {
        capturedCalls.push({ method, params });
        return { status: 'ok' };
      }),
    };
    // 访问内部 _auth 实例并调用 _initializeSession
    const auth = (client as any)._auth;
    await auth._initializeSession(mockTransport, 'nonce123', 'token123', {
      deviceId: 'dev1',
      slotId: 'slot1',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'short',
      shortTtlMs: 30000,
    });
    expect(capturedCalls.length).toBe(1);
    expect(capturedCalls[0].method).toBe('auth.connect');
    const payload = capturedCalls[0].params;
    expect(payload.options).toBeDefined();
    expect(payload.options.kind).toBe('short');
    expect(payload.options.short_ttl_ms).toBe(30000);
  });

  // 6. _initializeSession kind=long 时 payload 不含 options（向后兼容）
  it('auth.connect payload kind=long 不含 options', async () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const capturedCalls: Array<{ method: string; params: any }> = [];
    const mockTransport = {
      call: vi.fn(async (method: string, params: any) => {
        capturedCalls.push({ method, params });
        return { status: 'ok' };
      }),
    };
    const auth = (client as any)._auth;
    await auth._initializeSession(mockTransport, 'nonce123', 'token123', {
      deviceId: 'dev1',
      slotId: 'slot1',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'long',
      shortTtlMs: 0,
    });
    expect(capturedCalls.length).toBe(1);
    const payload = capturedCalls[0].params;
    expect(payload.options).toBeUndefined();
  });

  // 7. 短连接禁用心跳和 token_refresh（_startBackgroundTasks 跳过）
  it('短连接禁用后台任务', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    // 设置 _sessionOptions 为 short
    (client as any)._sessionOptions = { connection_kind: 'short' };
    const startHeartbeat = vi.spyOn(client as any, '_startHeartbeatTask');
    const startTokenRefresh = vi.spyOn(client as any, '_startTokenRefreshTask');
    (client as any)._startBackgroundTasks();
    expect(startHeartbeat).not.toHaveBeenCalled();
    expect(startTokenRefresh).not.toHaveBeenCalled();
  });

  // 8. 长连接启动心跳和 token_refresh
  it('长连接启动后台任务', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    (client as any)._sessionOptions = { connection_kind: 'long' };
    const startHeartbeat = vi.spyOn(client as any, '_startHeartbeatTask').mockImplementation(() => {});
    const startTokenRefresh = vi.spyOn(client as any, '_startTokenRefreshTask').mockImplementation(() => {});
    // 也 mock group epoch tasks 避免副作用
    vi.spyOn(client as any, '_startGroupEpochTasks').mockImplementation(() => {});
    (client as any)._startBackgroundTasks();
    expect(startHeartbeat).toHaveBeenCalled();
    expect(startTokenRefresh).toHaveBeenCalled();
  });

  // 9. 短连接默认 auto_reconnect=false
  it('短连接默认 auto_reconnect=false', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const options = (client as any)._buildSessionOptions({
      connection_kind: 'short',
    });
    expect(options.auto_reconnect).toBe(false);
  });

  // 10. 长连接保持默认 auto_reconnect=true
  it('长连接保持默认 auto_reconnect=true', () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const options = (client as any)._buildSessionOptions({
      connection_kind: 'long',
    });
    expect(options.auto_reconnect).toBe(true);
  });
});
