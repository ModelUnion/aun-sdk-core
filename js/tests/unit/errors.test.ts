// ── errors 模块单元测试 ──────────────────────────────────────
import { describe, it, expect } from 'vitest';
import {
  AUNError,
  ConnectionError,
  TimeoutError,
  AuthError,
  PermissionError,
  ValidationError,
  NotFoundError,
  RateLimitError,
  StateError,
  SerializationError,
  SessionError,
  GroupError,
  GroupNotFoundError,
  GroupStateError,
  E2EEError,
  E2EEDecryptFailedError,
  E2EEGroupSecretMissingError,
  E2EEGroupEpochMismatchError,
  E2EEGroupCommitmentInvalidError,
  E2EEGroupNotMemberError,
  E2EEGroupDecryptFailedError,
  CertificateRevokedError,
  E2EEDegradedError,
  ClientSignatureError,
  mapRemoteError,
} from '../../src/errors.js';

// ── 错误类继承关系 ──────────────────────────────────────

describe('错误类层级', () => {
  it('所有错误类均继承自 AUNError', () => {
    const classes = [
      ConnectionError, TimeoutError, AuthError, PermissionError,
      ValidationError, NotFoundError, RateLimitError, StateError,
      SerializationError, SessionError, GroupError, E2EEError,
    ];
    for (const Cls of classes) {
      const err = new Cls('test');
      expect(err).toBeInstanceOf(AUNError);
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('AUNError 默认属性正确', () => {
    const err = new AUNError('base error');
    expect(err.message).toBe('base error');
    expect(err.code).toBe(-1);
    expect(err.data).toBeNull();
    expect(err.retryable).toBe(false);
    expect(err.traceId).toBeNull();
    expect(err.name).toBe('AUNError');
  });

  it('AUNError 可设置自定义属性', () => {
    const err = new AUNError('custom', {
      code: 42,
      data: { key: 'val' },
      retryable: true,
      traceId: 'trace-123',
    });
    expect(err.code).toBe(42);
    expect(err.data).toEqual({ key: 'val' });
    expect(err.retryable).toBe(true);
    expect(err.traceId).toBe('trace-123');
  });

  it('各子类 name 属性正确', () => {
    expect(new ConnectionError('').name).toBe('ConnectionError');
    expect(new TimeoutError('').name).toBe('TimeoutError');
    expect(new AuthError('').name).toBe('AuthError');
    expect(new PermissionError('').name).toBe('PermissionError');
    expect(new ValidationError('').name).toBe('ValidationError');
    expect(new NotFoundError('').name).toBe('NotFoundError');
    expect(new RateLimitError('').name).toBe('RateLimitError');
    expect(new StateError('').name).toBe('StateError');
    expect(new SerializationError('').name).toBe('SerializationError');
    expect(new SessionError('').name).toBe('SessionError');
  });

  it('GroupError 子类继承正确', () => {
    const gnf = new GroupNotFoundError('not found');
    expect(gnf).toBeInstanceOf(GroupError);
    expect(gnf).toBeInstanceOf(AUNError);
    expect(gnf.name).toBe('GroupNotFoundError');

    const gse = new GroupStateError('bad state');
    expect(gse).toBeInstanceOf(GroupError);
    expect(gse.name).toBe('GroupStateError');
  });

  it('E2EE 错误类层级正确', () => {
    const e2ee = new E2EEError('base');
    expect(e2ee).toBeInstanceOf(AUNError);
    expect(e2ee.localCode).toBe('E2EE_ERROR');
    expect(e2ee.closeReason).toBeNull();

    const decFailed = new E2EEDecryptFailedError();
    expect(decFailed).toBeInstanceOf(E2EEError);
    expect(decFailed.localCode).toBe('E2EE_DECRYPT_FAILED');
    expect(decFailed.closeReason).toBe('decrypt_failed');

    const secretMissing = new E2EEGroupSecretMissingError();
    expect(secretMissing).toBeInstanceOf(E2EEError);
    expect(secretMissing.code).toBe(-32040);
    expect(secretMissing.localCode).toBe('E2EE_GROUP_SECRET_MISSING');

    const epochMismatch = new E2EEGroupEpochMismatchError();
    expect(epochMismatch.code).toBe(-32041);

    const commitInvalid = new E2EEGroupCommitmentInvalidError();
    expect(commitInvalid.code).toBe(-32042);

    const notMember = new E2EEGroupNotMemberError();
    expect(notMember.code).toBe(-32043);

    const decGroupFailed = new E2EEGroupDecryptFailedError();
    expect(decGroupFailed.code).toBe(-32044);
  });

  it('CertificateRevokedError 继承自 AuthError', () => {
    const err = new CertificateRevokedError();
    expect(err).toBeInstanceOf(AuthError);
    expect(err).toBeInstanceOf(AUNError);
    expect(err.code).toBe(-32050);
    expect(err.name).toBe('CertificateRevokedError');
  });

  it('E2EEDegradedError 属性正确', () => {
    const err = new E2EEDegradedError();
    expect(err).toBeInstanceOf(E2EEError);
    expect(err.localCode).toBe('E2EE_DEGRADED');
  });

  it('ClientSignatureError 继承自 ValidationError', () => {
    const err = new ClientSignatureError();
    expect(err).toBeInstanceOf(ValidationError);
    expect(err).toBeInstanceOf(AUNError);
    expect(err.code).toBe(-32051);
    expect(err.name).toBe('ClientSignatureError');
  });
});

// ── mapRemoteError 错误码映射 ──────────────────────────

describe('mapRemoteError', () => {
  it('认证错误码 → AuthError', () => {
    for (const code of [4001, 4010, -32003]) {
      const err = mapRemoteError({ code, message: 'auth fail' });
      expect(err).toBeInstanceOf(AuthError);
      expect(err.code).toBe(code);
    }
  });

  it('权限错误码 → PermissionError', () => {
    for (const code of [4030, 403]) {
      const err = mapRemoteError({ code, message: 'forbidden' });
      expect(err).toBeInstanceOf(PermissionError);
    }
  });

  it('资源不存在错误码 → NotFoundError', () => {
    for (const code of [4040, 404, -32004]) {
      const err = mapRemoteError({ code, message: 'not found' });
      expect(err).toBeInstanceOf(NotFoundError);
    }
  });

  it('限流错误码 → RateLimitError（且 retryable = true）', () => {
    for (const code of [4290, 429, -32029]) {
      const err = mapRemoteError({ code, message: 'rate limited' });
      expect(err).toBeInstanceOf(RateLimitError);
      expect(err.retryable).toBe(true);
    }
  });

  it('会话错误码 → SessionError', () => {
    for (const code of [-32010, -32011, -32013]) {
      const err = mapRemoteError({ code, message: 'session fail' });
      expect(err).toBeInstanceOf(SessionError);
    }
  });

  it('校验错误码 → ValidationError', () => {
    for (const code of [-32600, -32601, -32602, 4000]) {
      const err = mapRemoteError({ code, message: 'invalid' });
      expect(err).toBeInstanceOf(ValidationError);
    }
  });

  it('群组不存在错误码 → GroupNotFoundError', () => {
    const err = mapRemoteError({ code: -33001, message: 'group not found' });
    expect(err).toBeInstanceOf(GroupNotFoundError);
    expect(err).toBeInstanceOf(GroupError);
  });

  it('群组状态错误码 → GroupStateError', () => {
    for (const code of [-33002, -33003]) {
      const err = mapRemoteError({ code, message: 'group state' });
      expect(err).toBeInstanceOf(GroupStateError);
    }
  });

  it('群组通用错误码 → GroupError', () => {
    for (const code of [-33004, -33005, -33006, -33007, -33008, -33009]) {
      const err = mapRemoteError({ code, message: 'group error' });
      expect(err).toBeInstanceOf(GroupError);
    }
  });

  it('未知错误码 → AUNError', () => {
    const err = mapRemoteError({ code: -99999, message: 'unknown' });
    expect(err).toBeInstanceOf(AUNError);
    expect(err.constructor).toBe(AUNError);
  });

  it('应正确提取 traceId', () => {
    const err = mapRemoteError({
      code: -1,
      message: 'err',
      data: { trace_id: 'abc-123' },
    });
    expect(err.traceId).toBe('abc-123');
  });

  it('缺少字段时使用默认值', () => {
    const err = mapRemoteError({});
    expect(err.code).toBe(-32603);
    expect(err.message).toBe('remote error');
  });
});
