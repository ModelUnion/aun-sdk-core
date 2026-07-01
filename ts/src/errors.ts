/**
 * AUN SDK 错误层级体系
 *
 * 与 Python SDK 完全对齐，覆盖所有错误类型和远程错误映射逻辑。
 */

import { isJsonObject, type JsonValue, type RpcErrorObject } from './types.js';

// ── 基础错误 ──────────────────────────────────────────────────

export class AUNError extends Error {
  /** JSON-RPC 错误码（数字，用于 RPC 层） */
  readonly code: number;
  /** 业务字符串错误码（与 Python/JS SDK error_codes 对齐） */
  readonly stringCode: string;
  /** 附加数据 */
  readonly data: JsonValue | null;
  /** 是否可重试 */
  readonly retryable: boolean;
  /** 链路追踪 ID */
  readonly traceId: string | undefined;

  constructor(
    message: string,
    opts: {
      code?: number;
      stringCode?: string;
      data?: JsonValue | null;
      retryable?: boolean;
      traceId?: string;
    } = {},
  ) {
    super(message);
    this.name = 'AUNError';
    this.code = opts.code ?? -1;
    this.stringCode = opts.stringCode ?? '';
    this.data = opts.data ?? null;
    this.retryable = opts.retryable ?? false;
    this.traceId = opts.traceId;
  }
}

// ── 通用错误子类 ──────────────────────────────────────────────

export class ConnectionError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'ConnectionError';
  }
}

export class TimeoutError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'TimeoutError';
  }
}

export class AuthError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'AuthError';
  }
}

export class PermissionError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'PermissionError';
  }
}

export class ValidationError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'ValidationError';
  }
}

export class NotFoundError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'RateLimitError';
  }
}

export class StateError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'StateError';
  }
}

export class SerializationError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'SerializationError';
  }
}

export class SessionError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'SessionError';
  }
}

/** 版本冲突错误 */
export class VersionConflictError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'VersionConflictError';
  }
}

// ── 群组错误 ──────────────────────────────────────────────────

export class GroupError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'GroupError';
  }
}

export class GroupNotFoundError extends GroupError {
  constructor(message: string = 'group not found', opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'GroupNotFoundError';
  }
}

export class GroupStateError extends GroupError {
  constructor(message: string = 'group state error', opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'GroupStateError';
  }
}

// ── E2EE 错误 ─────────────────────────────────────────────────

export class E2EEError extends AUNError {
  /** 本地错误码 */
  readonly localCode: string;
  /** WebSocket 关闭原因 */
  readonly closeReason: string | undefined;

  constructor(
    message: string,
    opts: ConstructorParameters<typeof AUNError>[1] & {
      localCode?: string;
      closeReason?: string;
    } = {},
  ) {
    super(message, opts);
    this.name = 'E2EEError';
    this.localCode = opts.localCode ?? 'E2EE_ERROR';
    this.closeReason = opts.closeReason;
  }
}

export class E2EEDecryptFailedError extends E2EEError {
  constructor(message: string = 'e2ee decrypt failed', opts: ConstructorParameters<typeof E2EEError>[1] = {}) {
    super(message, {
      ...opts,
      localCode: 'E2EE_DECRYPT_FAILED',
      closeReason: 'decrypt_failed',
    });
    this.name = 'E2EEDecryptFailedError';
  }
}

/** 对端证书已被吊销 */
export class CertificateRevokedError extends AuthError {
  constructor(message: string = 'peer certificate has been revoked', opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, { ...opts, code: -32050 });
    this.name = 'CertificateRevokedError';
  }
}

/** AID 已被注册（查重命中 / TOCTOU race / 服务端拒绝重复注册） */
export class IdentityConflictError extends AuthError {
  constructor(message: string = 'AID already registered', opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, { ...opts, code: -32052 });
    this.name = 'IdentityConflictError';
  }
}

/** E2EE 降级（无前向保密） */
export class E2EEDegradedError extends E2EEError {
  constructor(message: string = 'e2ee degraded: no forward secrecy', opts: ConstructorParameters<typeof E2EEError>[1] = {}) {
    super(message, { ...opts, localCode: 'E2EE_DEGRADED' });
    this.name = 'E2EEDegradedError';
  }
}

/** 客户端操作签名验证失败 */
export class ClientSignatureError extends ValidationError {
  constructor(message: string = 'client signature verification failed', opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, { ...opts, code: -32051 });
    this.name = 'ClientSignatureError';
  }
}

// ── 远程错误映射 ──────────────────────────────────────────────

function isTransientGatewayDegradedError(message: string): boolean {
  const text = message.trim().toLowerCase();
  return text.includes('gateway service degraded')
    || text.includes('certificate not loaded');
}

/**
 * 将 JSON-RPC error 对象映射为具体的 AUNError 子类。
 * 与 Python SDK 的 map_remote_error 逻辑完全一致。
 */
export function mapRemoteError(error: RpcErrorObject): AUNError {
  const code = Number(error.code ?? -32603);
  const message = String(error.message ?? 'remote error');
  const data = error.data ?? null;

  let traceId: string | undefined;
  if (isJsonObject(data)) {
    const d = data;
    traceId = (d.trace_id ?? d.traceId) as string | undefined;
  }

  // 认证错误
  const AUTH_CODES = new Set([4001, 4010, -32001, -32003]);
  const PERMISSION_CODES = new Set([4030, 403, -32004]); // -32004 = PERMISSION_DENIED
  const NOT_FOUND_CODES = new Set([4040, 404, -32008]);
  const RATE_LIMIT_CODES = new Set([4290, 429, -32029, -32429]);
  const SESSION_CODES = new Set([-32010, -32011, -32013]);
  const VALIDATION_CODES = new Set([-32600, -32601, -32602, 4000]);

  const transientRetryable = isTransientGatewayDegradedError(message);
  const opts = { code, data, traceId, retryable: transientRetryable };

  let err: AUNError;

  if (AUTH_CODES.has(code)) {
    err = new AuthError(message, opts);
  } else if (PERMISSION_CODES.has(code)) {
    err = new PermissionError(message, opts);
  } else if (NOT_FOUND_CODES.has(code)) {
    err = new NotFoundError(message, opts);
  } else if (RATE_LIMIT_CODES.has(code)) {
    err = new RateLimitError(message, { ...opts, retryable: true });
  } else if (code === -32009) {
    err = new VersionConflictError(message, opts);
  } else if (SESSION_CODES.has(code)) {
    err = new SessionError(message, opts);
  } else if (VALIDATION_CODES.has(code)) {
    err = new ValidationError(message, opts);
  } else if (code === -33001) {
    err = new GroupNotFoundError(message, opts);
  } else if (code === -33002 || code === -33003) {
    err = new GroupStateError(message, opts);
  } else if (code >= -33009 && code <= -33004) {
    err = new GroupError(message, opts);
  } else {
    // 5000-5999 范围的服务端错误可重试
    const retryable = transientRetryable || (code >= 5000 && code < 6000);
    err = new AUNError(message, { ...opts, retryable });
  }

  return err;
}
