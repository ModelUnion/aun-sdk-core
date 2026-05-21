/**
 * Auth 模块单元测试
 *
 * 认证流程涉及 WebSocket 连接和 PKI 证书链验证，
 * 复杂的集成场景需要 Docker 环境。这里用 stub 覆盖可单元测试的部分。
 */

import { describe, it, expect, vi } from 'vitest';
import { AuthFlow } from '../../src/auth.js';
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

  it('默认 capabilities 仅声明 E2EE V2 能力', async () => {
    const auth = new AuthFlow({
      keystore: {} as any,
      crypto: {} as any,
      verifySsl: false,
      logger: {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      },
    });
    const mockTransport = {
      call: vi.fn().mockResolvedValue({ status: 'ok' }),
    };

    await (auth as any)._initializeSession(mockTransport, 'nonce123', 'token123', {
      deviceId: 'dev1',
      slotId: '',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'long',
      shortTtlMs: 0,
    });

    const args = mockTransport.call.mock.calls[0][1] as Record<string, unknown>;
    expect(args.capabilities).toBeDefined();
    const capabilities = args.capabilities as Record<string, unknown>;
    expect(capabilities.supported_p2p_e2ee).toEqual(['e2ee_v2']);
    expect(capabilities.supported_group_e2ee).toEqual(['group_e2ee_v2']);
    expect(capabilities.e2ee).toBe(true);
    expect(capabilities.group_e2ee).toBe(true);
  });

  it('覆盖 capabilities 也会被规范化为 V2-only', async () => {
    const auth = new AuthFlow({
      keystore: {} as any,
      crypto: {} as any,
      verifySsl: false,
      logger: {
        error: vi.fn(),
        warn: vi.fn(),
        info: vi.fn(),
        debug: vi.fn(),
      },
    });
    const mockTransport = {
      call: vi.fn().mockResolvedValue({ status: 'ok' }),
    };

    await (auth as any)._initializeSession(mockTransport, 'nonce123', 'token123', {
      deviceId: 'dev1',
      slotId: '',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'long',
      shortTtlMs: 0,
      extraInfo: {
        _capabilities: {
          e2ee: false,
          group_e2ee: false,
          supported_p2p_e2ee: ['e2ee'],
          supported_group_e2ee: ['group_e2ee'],
        },
      },
    });

    const args = mockTransport.call.mock.calls[0][1] as Record<string, unknown>;
    const capabilities = args.capabilities as Record<string, unknown>;
    expect(capabilities.supported_p2p_e2ee).toEqual(['e2ee_v2']);
    expect(capabilities.supported_group_e2ee).toEqual(['group_e2ee_v2']);
    expect(capabilities.e2ee).toBe(true);
    expect(capabilities.group_e2ee).toBe(true);
    expect((args.extra_info as Record<string, unknown> | undefined)?._capabilities).toBeUndefined();
  });

  it('OCSP DER 解析应支持 responderID byKey ([2]) 响应', () => {
    const auth = new AuthFlow({
      keystore: {} as any,
      crypto: {} as any,
      verifySsl: false,
    });
    // 来自本地 Gateway /pki/ocsp/{serial} 的真实 successful/good 响应。
    // ResponseData 无 version 字段，responderID 使用 byKey [2] (0xa2) 编码。
    const ocspB64 = 'MIIBWAoBAKCCAVEwggFNBgkrBgEFBQcwAQEEggE+MIIBOjCBwKIWBBQOakEDao+eTehZD3kHuzfc5Cgu0xgPMjAyNjA1MDgxNTI2MTVaMIGUMIGRMGkwDQYJYIZIAWUDBAIBBQAEII1IIaVHL73SrxXa7UIB0USYcFMRvzYDRqqlBX7Sf7sNBCCoqOR2Bp61FDCEvUEjq8nHZBCSWjI6wK6GRxv3979HlwIUPeGG/OKaOACVF4/6cYe50Ir/Y02AABgPMjAyNjA1MDgxNTI2MTVaoBEYDzIwMjYwNTA4MTYyNjE1WjAKBggqhkjOPQQDAwNpADBmAjEAw+wETjod6THb3+YQgh7gVbSlFg1i9Fzb/ZvW9vc+0nwkM/qvHOEmaGF38PEUORgIAjEAzq0F1C0eLiRFqvM0MpEYICWYiIn7EBv/W/hsbSfhxNC+4a/hb9mZfiiwDyx7SA3f';

    const status = (auth as any)._parseOcspResponse(Buffer.from(ocspB64, 'base64'), null, null);

    expect(status).toBe('good');
  });

  it('OCSP 非成功响应应回退到 JSON status 而不是误报结构缺失', () => {
    const auth = new AuthFlow({
      keystore: {} as any,
      crypto: {} as any,
      verifySsl: false,
    });
    const ocspB64 = 'MAMKAQY='; // unauthorized

    expect(() => (auth as any)._parseOcspResponse(Buffer.from(ocspB64, 'base64'), null, null))
      .toThrow(/unauthorized|non-successful/i);
  });

  it('OCSP DER 解析应支持 certStatus unknown 响应', () => {
    const auth = new AuthFlow({
      keystore: {} as any,
      crypto: {} as any,
      verifySsl: false,
    });
    const ocspB64 = 'MIIBNwoBAKCCATAwggEsBgkrBgEFBQcwAQEEggEdMIIBGTCBwKIWBBT+w/6sCcpmOxppLljRdNlY6aEWThgPMjAyNjA1MDkwMDQwMDlaMIGUMIGRMGkwDQYJYIZIAWUDBAIBBQAEIFDRAP0nT4Kon2gd1QNPhAGTjhif7qDiFd+SGbKjYQu7BCBpiE8i8ijmzvfYvjMVFtKdKFN6vzXMyvY4ZjjioU4rTAIUNpSEVz4WJWg3O930pb6kU0FR4NaCABgPMjAyNjA1MDkwMTAwMDBaoBEYDzIwMjYwNTA5MDEwNTAwWjAKBggqhkjOPQQDAgNIADBFAiB9qTqyI84W+y06CfHivBhAmPcqqy1VMeYvKNB+ZVvDtQIhAL5NIRkH9hDLfrzUZVmxLt0OQPCpQsgPpQdS+wN9/fSV';

    const status = (auth as any)._parseOcspResponse(Buffer.from(ocspB64, 'base64'), null, null);

    expect(status).toBe('unknown');
  });
});
