/**
 * 密码学工具单元测试
 */

import { describe, it, expect } from 'vitest';
import { CryptoProvider } from '../../src/crypto.js';
import { createPrivateKey, createPublicKey, createVerify } from 'node:crypto';

describe('CryptoProvider', () => {
  const provider = new CryptoProvider();

  describe('generateIdentity', () => {
    it('返回有效的 ECDSA P-256 密钥对', () => {
      const identity = provider.generateIdentity();
      expect(identity.curve).toBe('P-256');
      expect(identity.private_key_pem).toContain('BEGIN PRIVATE KEY');
      expect(identity.public_key_der_b64).toBeTruthy();

      // 验证私钥可以被加载
      const pk = createPrivateKey(identity.private_key_pem);
      expect(pk.asymmetricKeyType).toBe('ec');

      // 验证公钥 DER 可以被加载
      const pubDer = Buffer.from(identity.public_key_der_b64, 'base64');
      const pubKey = createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
      expect(pubKey.asymmetricKeyType).toBe('ec');
    });

    it('每次生成不同的密钥对', () => {
      const id1 = provider.generateIdentity();
      const id2 = provider.generateIdentity();
      expect(id1.private_key_pem).not.toBe(id2.private_key_pem);
      expect(id1.public_key_der_b64).not.toBe(id2.public_key_der_b64);
    });
  });

  describe('signLoginNonce', () => {
    it('生成有效的签名', () => {
      const identity = provider.generateIdentity();
      const nonce = 'test-nonce-123';
      const [sigB64, timestamp] = provider.signLoginNonce(identity.private_key_pem, nonce);

      // 签名应为非空 base64
      expect(sigB64).toBeTruthy();
      const sigBuf = Buffer.from(sigB64, 'base64');
      expect(sigBuf.length).toBeGreaterThan(0);

      // 时间戳应为数字字符串
      expect(parseFloat(timestamp)).toBeGreaterThan(0);

      // 使用公钥验证签名
      const pubDer = Buffer.from(identity.public_key_der_b64, 'base64');
      const pubKey = createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
      const signData = `${nonce}:${timestamp}`;
      const verifier = createVerify('SHA256');
      verifier.update(signData);
      verifier.end();
      expect(verifier.verify(pubKey, sigBuf)).toBe(true);
    });

    it('可以使用自定义 clientTime', () => {
      const identity = provider.generateIdentity();
      const [, timestamp] = provider.signLoginNonce(
        identity.private_key_pem, 'nonce', '1234567890.0',
      );
      expect(timestamp).toBe('1234567890.0');
    });
  });

  describe('newClientNonce', () => {
    it('返回有效的 base64 字符串', () => {
      const nonce = provider.newClientNonce();
      expect(nonce).toBeTruthy();
      // base64 解码后应为 12 字节
      const decoded = Buffer.from(nonce, 'base64');
      expect(decoded.length).toBe(12);
    });

    it('每次生成不同的 nonce', () => {
      const n1 = provider.newClientNonce();
      const n2 = provider.newClientNonce();
      expect(n1).not.toBe(n2);
    });
  });
});
