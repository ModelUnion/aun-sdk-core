/**
 * 错误体系单元测试
 */

import { describe, it, expect } from 'vitest';
import {
  AUNError,
  AuthError,
  PermissionError,
  NotFoundError,
  RateLimitError,
  SessionError,
  ValidationError,
  GroupNotFoundError,
  GroupStateError,
  GroupError,
  mapRemoteError,
} from '../../src/errors.js';

describe('mapRemoteError', () => {
  // ── 认证错误 ────────────────────────────────────────────
  it.each([4001, 4010, -32001, -32003])('code %d 映射为 AuthError', (code) => {
    const err = mapRemoteError({ code, message: 'auth failed' });
    expect(err).toBeInstanceOf(AuthError);
    expect(err.code).toBe(code);
    expect(err.message).toBe('auth failed');
    expect(err.retryable).toBe(false);
  });

  // ── 权限错误 ────────────────────────────────────────────
  it.each([4030, 403, -32004])('code %d 映射为 PermissionError', (code) => {
    const err = mapRemoteError({ code, message: 'forbidden' });
    expect(err).toBeInstanceOf(PermissionError);
    expect(err.retryable).toBe(false);
  });

  // ── 未找到错误 ──────────────────────────────────────────
  it.each([4040, 404])('code %d 映射为 NotFoundError', (code) => {
    const err = mapRemoteError({ code, message: 'not found' });
    expect(err).toBeInstanceOf(NotFoundError);
    expect(err.retryable).toBe(false);
  });

  // ── 频率限制错误（可重试） ──────────────────────────────
  it.each([4290, 429, -32029])('code %d 映射为 RateLimitError（retryable=true）', (code) => {
    const err = mapRemoteError({ code, message: 'rate limited' });
    expect(err).toBeInstanceOf(RateLimitError);
    expect(err.retryable).toBe(true);
  });

  // ── 会话错误 ────────────────────────────────────────────
  it.each([-32010, -32011, -32013])('code %d 映射为 SessionError', (code) => {
    const err = mapRemoteError({ code, message: 'session error' });
    expect(err).toBeInstanceOf(SessionError);
    expect(err.retryable).toBe(false);
  });

  // ── 验证错误 ────────────────────────────────────────────
  it.each([-32600, -32601, -32602, 4000])('code %d 映射为 ValidationError', (code) => {
    const err = mapRemoteError({ code, message: 'validation error' });
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.retryable).toBe(false);
  });

  // ── 群组错误 ────────────────────────────────────────────
  it('code -33001 映射为 GroupNotFoundError', () => {
    const err = mapRemoteError({ code: -33001, message: 'group not found' });
    expect(err).toBeInstanceOf(GroupNotFoundError);
  });

  it.each([-33002, -33003])('code %d 映射为 GroupStateError', (code) => {
    const err = mapRemoteError({ code, message: 'group state error' });
    expect(err).toBeInstanceOf(GroupStateError);
  });

  it.each([-33004, -33005, -33009])('code %d 映射为 GroupError', (code) => {
    const err = mapRemoteError({ code, message: 'group error' });
    expect(err).toBeInstanceOf(GroupError);
  });

  // ── 服务端可重试错误 ────────────────────────────────────
  it.each([5000, 5001, 5500, 5999])('code %d（5000-5999范围）标记为 retryable', (code) => {
    const err = mapRemoteError({ code, message: 'server error' });
    expect(err).toBeInstanceOf(AUNError);
    expect(err.retryable).toBe(true);
  });

  it('code 6000 不在 5000-5999 范围，retryable=false', () => {
    const err = mapRemoteError({ code: 6000, message: 'other error' });
    expect(err.retryable).toBe(false);
  });

  // ── traceId 提取 ────────────────────────────────────────
  it('从 data.trace_id 提取 traceId', () => {
    const err = mapRemoteError({
      code: 4001,
      message: 'auth fail',
      data: { trace_id: 'abc-123' },
    });
    expect(err.traceId).toBe('abc-123');
  });

  it('从 data.traceId（camelCase）提取 traceId', () => {
    const err = mapRemoteError({
      code: 4001,
      message: 'auth fail',
      data: { traceId: 'def-456' },
    });
    expect(err.traceId).toBe('def-456');
  });

  // ── 默认值 ──────────────────────────────────────────────
  it('缺少 code 和 message 时使用默认值', () => {
    const err = mapRemoteError({});
    expect(err.code).toBe(-32603);
    expect(err.message).toBe('remote error');
  });
});
