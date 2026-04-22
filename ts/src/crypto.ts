/**
 * AUN SDK 密码学工具
 *
 * 使用 Node.js 内置 crypto 模块，与 Python SDK 的 CryptoProvider 对齐。
 */

import { generateKeyPairSync, createSign, createHash, randomBytes, X509Certificate } from 'node:crypto';

export interface IdentityKeyPair {
  /** PEM 格式私钥 */
  private_key_pem: string;
  /** DER 格式公钥的 base64 编码 */
  public_key_der_b64: string;
  /** 曲线名称 */
  curve: string;
}

/**
 * 密码学操作提供者。
 */
export class CryptoProvider {
  readonly curveName = 'P-256';

  /**
   * 生成 ECDSA P-256 密钥对。
   * 返回 PEM 私钥 + DER 公钥（base64）+ 曲线名称。
   */
  generateIdentity(): IdentityKeyPair {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });

    const privateKeyPem = privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });

    return {
      private_key_pem: privateKeyPem,
      public_key_der_b64: publicKeyDer.toString('base64'),
      curve: this.curveName,
    };
  }

  /**
   * 使用私钥签名登录 nonce。
   * 签名数据格式："nonce:timestamp"
   *
   * @returns [signature_b64, timestamp]
   */
  signLoginNonce(
    privateKeyPem: string,
    nonce: string,
    clientTime?: string,
  ): [string, string] {
    const usedTime = clientTime ?? String(Math.floor(Date.now() / 1000));
    const signData = `${nonce}:${usedTime}`;

    // Python 的 cryptography 库默认输出 DER 编码签名，
    // Node.js createSign 默认也输出 DER 编码，保持一致。
    const signer = createSign('SHA256');
    signer.update(signData);
    signer.end();
    const signature = signer.sign(privateKeyPem);

    return [signature.toString('base64'), usedTime];
  }

  /**
   * 生成客户端 nonce（12 字节随机数的 base64 编码）。
   */
  newClientNonce(): string {
    return randomBytes(12).toString('base64');
  }
}

/**
 * 统一的证书 SHA-256 指纹计算（对齐 Python certificate_sha256_fingerprint）。
 * 返回 "sha256:{hex}" 格式的指纹。
 * e2ee.ts 与 keystore/file.ts 共用此函数，避免两套实现不一致。
 */
export function certificateSha256Fingerprint(certPem: string | Buffer): string {
  const raw = Buffer.isBuffer(certPem) ? certPem : Buffer.from(certPem, 'utf-8');
  const text = raw.toString('utf-8');
  let der: Buffer;
  if (text.includes('-----BEGIN CERTIFICATE-----')) {
    // PEM → DER 解码
    const body = text
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    if (!body) return '';
    der = Buffer.from(body, 'base64');
  } else {
    // 尝试通过 X509Certificate 获取 DER
    try {
      der = new X509Certificate(raw).raw;
    } catch {
      der = raw;
    }
  }
  const hash = createHash('sha256').update(der).digest('hex');
  return `sha256:${hash}`;
}
