/**
 * Auth 模块单元测试
 *
 * 认证流程涉及 WebSocket 连接和 PKI 证书链验证，
 * 复杂的集成场景需要 Docker 环境。这里用 stub 覆盖可单元测试的部分。
 */

import { describe, it, expect } from 'vitest';
import { AuthError, StateError } from '../../src/errors.js';

describe('AuthFlow', () => {
  // 以下测试需要复杂的证书链 fixture，标记为 skip
  // 集成测试中会覆盖完整的认证流程

  it.skip('verifyPhase1Response 接受有效的证书链', () => {
    // 需要构造完整的 CA 链 + 签名 fixture
  });

  it.skip('verifyPhase1Response 拒绝无效签名', () => {
    // 需要构造错误签名的 fixture
  });

  it.skip('new_cert CN 不匹配时被拒绝', () => {
    // 需要构造 CN 不匹配的证书
  });

  it.skip('new_cert 公钥不匹配时被拒绝', () => {
    // 需要构造公钥不匹配的证书
  });

  it.skip('new_cert 过期时被拒绝', () => {
    // 需要构造过期证书
  });

  it.skip('CRL 吊销的证书被拒绝', () => {
    // 需要 Gateway CRL 端点 mock
  });

  it.skip('OCSP revoked 状态的证书被拒绝', () => {
    // 需要 Gateway OCSP 端点 mock
  });

  // 可以直接测试的错误类型
  it('AuthError 包含正确的属性', () => {
    const err = new AuthError('test auth error', { code: 4001 });
    expect(err.name).toBe('AuthError');
    expect(err.message).toBe('test auth error');
    expect(err.code).toBe(4001);
  });

  it('StateError 包含正确的属性', () => {
    const err = new StateError('no identity');
    expect(err.name).toBe('StateError');
    expect(err.message).toBe('no identity');
  });
});
