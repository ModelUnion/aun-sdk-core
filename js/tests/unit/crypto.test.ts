// ── crypto 模块单元测试 ──────────────────────────────────────
// 注意: jsdom 环境下 SubtleCrypto 的支持依赖 Node.js 内置 crypto，
// vitest + jsdom 通常可以正常使用。若不支持则跳过。
import { describe, it, expect } from 'vitest';
import { CryptoProvider } from '../../src/crypto.js';

// 检测 SubtleCrypto 是否可用
const hasSubtleCrypto = typeof globalThis.crypto?.subtle?.generateKey === 'function';

describe('CryptoProvider', () => {
  const provider = new CryptoProvider();

  describe('generateIdentity', () => {
    it.skipIf(!hasSubtleCrypto)(
      '应返回包含 private_key_pem、public_key_der_b64、curve 的对象',
      async () => {
        const identity = await provider.generateIdentity();
        expect(identity.curve).toBe('P-256');
        expect(identity.private_key_pem).toContain('-----BEGIN PRIVATE KEY-----');
        expect(identity.private_key_pem).toContain('-----END PRIVATE KEY-----');
        // SPKI DER base64 应为非空字符串
        expect(identity.public_key_der_b64.length).toBeGreaterThan(50);
      },
    );

    it.skipIf(!hasSubtleCrypto)(
      '两次生成的密钥对应不同',
      async () => {
        const id1 = await provider.generateIdentity();
        const id2 = await provider.generateIdentity();
        expect(id1.private_key_pem).not.toBe(id2.private_key_pem);
        expect(id1.public_key_der_b64).not.toBe(id2.public_key_der_b64);
      },
    );
  });

  describe('signLoginNonce', () => {
    it.skipIf(!hasSubtleCrypto)(
      '应返回 [signatureBase64, clientTime] 元组',
      async () => {
        const identity = await provider.generateIdentity();
        const [sig, clientTime] = await provider.signLoginNonce(
          identity.private_key_pem,
          'test-nonce-12345',
        );
        // signature 应为非空 base64 字符串
        expect(sig.length).toBeGreaterThan(20);
        // clientTime 应为数字字符串
        expect(parseFloat(clientTime)).toBeGreaterThan(0);
      },
    );

    it.skipIf(!hasSubtleCrypto)(
      '不同 nonce 产生不同签名',
      async () => {
        const identity = await provider.generateIdentity();
        const time = '1000000';
        const [sig1] = await provider.signLoginNonce(identity.private_key_pem, 'nonce1', time);
        const [sig2] = await provider.signLoginNonce(identity.private_key_pem, 'nonce2', time);
        expect(sig1).not.toBe(sig2);
      },
    );

    it.skipIf(!hasSubtleCrypto)(
      '自定义 clientTime 应被原样返回',
      async () => {
        const identity = await provider.generateIdentity();
        const [, clientTime] = await provider.signLoginNonce(
          identity.private_key_pem, 'nonce', '12345.678',
        );
        expect(clientTime).toBe('12345.678');
      },
    );
  });

  describe('newClientNonce', () => {
    it('应返回 base64 编码字符串', () => {
      const nonce = provider.newClientNonce();
      // 12 字节 → base64 编码约 16 字符
      expect(nonce.length).toBe(16);
      // 不含非法 base64 字符
      expect(nonce).toMatch(/^[A-Za-z0-9+/=]+$/);
    });

    it('两次调用应返回不同值', () => {
      const n1 = provider.newClientNonce();
      const n2 = provider.newClientNonce();
      expect(n1).not.toBe(n2);
    });
  });
});
