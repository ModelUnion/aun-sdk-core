/**
 * Auth 模块单元测试
 *
 * 认证流程涉及 WebSocket 连接和 PKI 证书链验证，
 * 复杂的集成场景需要 Docker 环境。这里用 stub 覆盖可单元测试的部分。
 */

import { describe, it, expect, vi } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { AuthFlow } from '../../src/auth.js';
import { RegisterFlow } from '../../src/register-flow.js';
import { AuthError, StateError, IdentityConflictError } from '../../src/errors.js';
import { CryptoProvider } from '../../src/crypto.js';
import { LocalIdentityStore } from '../../src/keystore/local-identity-store.js';
import { VERSION } from '../../src/index.js';

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
      tokenStore: {} as any,
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
    expect(args.client).toMatchObject({
      sdk_lang: 'typescript',
      sdk_version: VERSION,
    });
    const capabilities = args.capabilities as Record<string, unknown>;
    expect(capabilities.supported_p2p_e2ee).toEqual(['e2ee_v2']);
    expect(capabilities.supported_group_e2ee).toEqual(['group_e2ee_v2']);
    expect(capabilities.e2ee).toBe(true);
    expect(capabilities.group_e2ee).toBe(true);
  });

  it('覆盖 capabilities 也会被规范化为 V2-only', async () => {
    const auth = new AuthFlow({
      tokenStore: {} as any,
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

  it('空 device_id 应从 instance_state 加载实例级 token', () => {
    const keystore = {
      loadInstanceState: vi.fn().mockReturnValue({ access_token: 'tok-empty-device' }),
      saveIdentity: vi.fn(),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: '',
      verifySsl: false,
    });

    const state = (auth as any)._loadInstanceState('alice.agentid.pub');

    expect(keystore.loadInstanceState).toHaveBeenCalledWith('alice.agentid.pub', '', '');
    expect(state.access_token).toBe('tok-empty-device');
  });

  it('空 device_id 应写入 instance_state 而不是留在共享身份元数据', () => {
    const updatedStates: Record<string, unknown>[] = [];
    const keystore = {
      updateInstanceState: vi.fn((_aid: string, _deviceId: string, _slotId: string, updater: (state: Record<string, unknown>) => Record<string, unknown> | void) => {
        const current: Record<string, unknown> = {};
        updater(current);
        updatedStates.push({ ...current });
        return current;
      }),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: '',
      verifySsl: false,
    });

    (auth as any)._persistIdentity({
      aid: 'alice.agentid.pub',
      private_key_pem: 'PRIVATE',
      access_token: 'tok-empty-device',
      refresh_token: 'ref-empty-device',
    });

    expect(keystore.updateInstanceState).toHaveBeenCalledWith('alice.agentid.pub', '', '', expect.any(Function));
    expect(updatedStates[0]).toMatchObject({
      access_token: 'tok-empty-device',
      refresh_token: 'ref-empty-device',
    });
  });

  it('refresh 业务失败且要求重登时应清掉本地 token 缓存', async () => {
    const updatedStates: Record<string, unknown>[] = [];
    const keystore = {
      updateInstanceState: vi.fn((_aid: string, _deviceId: string, _slotId: string, updater: (state: Record<string, unknown>) => Record<string, unknown> | void) => {
        const current: Record<string, unknown> = {
          access_token: 'old-access',
          refresh_token: 'old-refresh',
          kite_token: 'old-kite',
          access_token_expires_at: 123456,
        };
        const updated = updater(current) ?? current;
        updatedStates.push({ ...updated });
        return updated;
      }),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: 'dev-refresh',
      slotId: 'slot-refresh',
      verifySsl: false,
    });
    const identity: Record<string, unknown> = {
      aid: 'alice.agentid.pub',
      access_token: 'old-access',
      refresh_token: 'old-refresh',
      kite_token: 'old-kite',
      access_token_expires_at: 123456,
    };
    (auth as any)._refreshAccessToken = vi.fn().mockRejectedValue(new AuthError('invalid_or_expired_refresh_token', {
      data: {
        success: false,
        error: 'invalid_or_expired_refresh_token',
        relogin_required: true,
      },
    }));

    await expect(auth.refreshCachedTokens('ws://gateway/aun', identity as any)).rejects.toThrow(AuthError);

    expect(identity.access_token).toBe('');
    expect(identity.refresh_token).toBe('');
    expect(identity.kite_token).toBe('');
    expect(identity.access_token_expires_at).toBe(0);
    expect(keystore.updateInstanceState).toHaveBeenCalledWith('alice.agentid.pub', 'dev-refresh', 'slot-refresh', expect.any(Function));
    expect(updatedStates[updatedStates.length - 1]).toMatchObject({
      access_token: '',
      refresh_token: '',
      kite_token: '',
      access_token_expires_at: 0,
    });
  });

  it('connectSession 在 refresh 失败后应继续走两步登录', async () => {
    const keystore = {
      updateInstanceState: vi.fn((_aid: string, _deviceId: string, _slotId: string, updater: (state: Record<string, unknown>) => Record<string, unknown> | void) => {
        const current: Record<string, unknown> = {};
        return updater(current) ?? current;
      }),
    };
    const auth = new AuthFlow({
      tokenStore: keystore as any,
      crypto: {} as any,
      deviceId: 'dev-refresh',
      slotId: 'slot-refresh',
      verifySsl: false,
    });
    const identity: Record<string, unknown> = {
      aid: 'alice.agentid.pub',
      access_token: 'expired-access',
      refresh_token: 'expired-refresh',
      kite_token: 'old-kite',
      access_token_expires_at: 1,
    };
    auth.loadIdentity = vi.fn().mockReturnValue(identity as any);
    auth.refreshCachedTokens = vi.fn().mockRejectedValue(new AuthError('invalid_or_expired_refresh_token', {
      data: {
        success: false,
        error: 'invalid_or_expired_refresh_token',
        relogin_required: true,
      },
    }));
    auth.authenticate = vi.fn().mockResolvedValue({ access_token: 'login-access' });
    (auth as any)._initializeSession = vi.fn().mockResolvedValue({ status: 'ok' });

    const result = await auth.connectSession(
      { call: vi.fn() } as any,
      { params: { nonce: 'nonce-1' } },
      'ws://gateway/aun',
    );

    expect(auth.authenticate).toHaveBeenCalledWith('ws://gateway/aun', { aid: 'alice.agentid.pub' });
    expect(result.token).toBe('login-access');
    expect(identity.access_token).toBe('');
    expect(identity.refresh_token).toBe('');
  });

  it('OCSP DER 解析应支持 responderID byKey ([2]) 响应', () => {
    const auth = new AuthFlow({
      tokenStore: {} as any,
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
      tokenStore: {} as any,
      crypto: {} as any,
      verifySsl: false,
    });
    const ocspB64 = 'MAMKAQY='; // unauthorized

    expect(() => (auth as any)._parseOcspResponse(Buffer.from(ocspB64, 'base64'), null, null))
      .toThrow(/unauthorized|non-successful/i);
  });

  it('OCSP DER 解析应支持 certStatus unknown 响应', () => {
    const auth = new AuthFlow({
      tokenStore: {} as any,
      crypto: {} as any,
      verifySsl: false,
    });
    const ocspB64 = 'MIIBNwoBAKCCATAwggEsBgkrBgEFBQcwAQEEggEdMIIBGTCBwKIWBBT+w/6sCcpmOxppLljRdNlY6aEWThgPMjAyNjA1MDkwMDQwMDlaMIGUMIGRMGkwDQYJYIZIAWUDBAIBBQAEIFDRAP0nT4Kon2gd1QNPhAGTjhif7qDiFd+SGbKjYQu7BCBpiE8i8ijmzvfYvjMVFtKdKFN6vzXMyvY4ZjjioU4rTAIUNpSEVz4WJWg3O930pb6kU0FR4NaCABgPMjAyNjA1MDkwMTAwMDBaoBEYDzIwMjYwNTA5MDEwNTAwWjAKBggqhkjOPQQDAgNIADBFAiB9qTqyI84W+y06CfHivBhAmPcqqy1VMeYvKNB+ZVvDtQIhAL5NIRkH9hDLfrzUZVmxLt0OQPCpQsgPpQdS+wN9/fSV';

    const status = (auth as any)._parseOcspResponse(Buffer.from(ocspB64, 'base64'), null, null);

    expect(status).toBe('unknown');
  });

  // ── registerAid 查重前置 + 落盘时机修复 ─────────────────────
  describe('registerAid: 查重前置 + 落盘时机', () => {
    function makeRegisterFlow() {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ts-test-'));
      const keystore = new LocalIdentityStore(path.join(tmpDir, 'aun'));
      const flow = new RegisterFlow({
        keystore,
        crypto: new CryptoProvider(),
        verifySsl: false,
      });
      return { flow, tmpDir, keystore };
    }

    function makeFakeServerCert(aid: string, pubKeyDer?: Buffer): { certPem: string; pubDer: Buffer } {
      const { generateKeyPairSync, createSign, X509Certificate } = crypto as any;
      // 简化：生成一对 key + 自签 cert（仅用于测试 cert 解析路径）
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const usePub = pubKeyDer ? crypto.createPublicKey({ key: pubKeyDer, format: 'der', type: 'spki' }) : publicKey;
      // 通过 nodejs 的 selfSigned 不易直接做，这里走简化策略：
      // 测试只关心 registerAid 在拿到非空字符串时的行为（视为已注册）
      return { certPem: '-----BEGIN CERTIFICATE-----\nMIIB...stub...\n-----END CERTIFICATE-----', pubDer: Buffer.alloc(0) };
    }

    it('A: AID 已注册时抛 IdentityConflictError，本地不落盘', async () => {
      const { flow, tmpDir } = makeRegisterFlow();
      const aid = 'taken.example.com';
      // mock _downloadRegisteredCert 返回非空 cert（视为已注册）
      (flow as any)._downloadRegisteredCert = vi.fn().mockResolvedValue('-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----');
      const createSpy = vi.fn();
      (flow as any)._createAid = createSpy;

      await expect(flow.registerAid('https://gw.example', aid)).rejects.toBeInstanceOf(IdentityConflictError);

      // 没调 _createAid（连 RPC 都没发）
      expect(createSpy).not.toHaveBeenCalled();
      // 本地完全没该 AID 痕迹
      const aidDir = path.join(tmpDir, 'aun', 'AIDs', aid);
      expect(fs.existsSync(aidDir)).toBe(false);
    });

    it('B: TOCTOU race（查重 404 + RPC 拒绝）时不落盘', async () => {
      const { flow, tmpDir } = makeRegisterFlow();
      const aid = 'race.example.com';
      (flow as any)._downloadRegisteredCert = vi.fn().mockResolvedValue(null);
      (flow as any)._createAid = vi.fn().mockRejectedValue(new AuthError('AID already exists'));

      await expect(flow.registerAid('https://gw.example', aid)).rejects.toThrow();

      const aidDir = path.join(tmpDir, 'aun', 'AIDs', aid);
      expect(fs.existsSync(aidDir)).toBe(false);
    });

    it('C: 网络失败时不落盘', async () => {
      const { flow, tmpDir } = makeRegisterFlow();
      const aid = 'netfail.example.com';
      (flow as any)._downloadRegisteredCert = vi.fn().mockResolvedValue(null);
      (flow as any)._createAid = vi.fn().mockRejectedValue(new Error('network down'));

      await expect(flow.registerAid('https://gw.example', aid)).rejects.toThrow();

      const aidDir = path.join(tmpDir, 'aun', 'AIDs', aid);
      expect(fs.existsSync(aidDir)).toBe(false);
    });

    it('D: 查重 HTTP 失败时保守失败，不落盘', async () => {
      const { flow, tmpDir } = makeRegisterFlow();
      const aid = 'checkfail.example.com';
      (flow as any)._downloadRegisteredCert = vi.fn().mockRejectedValue(new AuthError('failed to fetch'));
      const createSpy = vi.fn();
      (flow as any)._createAid = createSpy;

      await expect(flow.registerAid('https://gw.example', aid)).rejects.toThrow();

      expect(createSpy).not.toHaveBeenCalled();
      const aidDir = path.join(tmpDir, 'aun', 'AIDs', aid);
      expect(fs.existsSync(aidDir)).toBe(false);
    });

    it('E: 全新 AID 注册成功 → keypair + cert 一次性落盘', async () => {
      const { flow, tmpDir, keystore } = makeRegisterFlow();
      const aid = 'fresh.example.com';
      (flow as any)._downloadRegisteredCert = vi.fn().mockResolvedValue(null);
      // 服务端"返回 cert"用 stub 字符串即可（_createAid 的契约只要求拿到 cert 字段）
      const stubCert = '-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----';
      (flow as any)._createAid = vi.fn().mockResolvedValue({ cert: stubCert });
      // 测试不验证 cert 解析（stubCert 不是合法 X.509）
      (flow as any)._assertCertMatchesLocalKeypair = vi.fn();

      const result = await flow.registerAid('https://gw.example', aid);
      expect(result.aid).toBe(aid);
      expect(result.cert).toBe(stubCert);

      // 落盘了 keypair + cert
      const loaded = keystore.loadIdentity(aid);
      expect(loaded?.private_key_pem).toBeTruthy();
      expect(loaded?.public_key_der_b64).toBeTruthy();
      expect(keystore.loadCert(aid)).toBe(stubCert);
    });
  });
});
