/**
 * AUN E2EE V2: ECDSA P-256 + SHA-256 RAW（r||s, 64B）
 *
 * 规范引用: §3.4 / §5.1 / §10
 *
 * 浏览器实现：
 * - 签名：使用 @noble/curves p256（RFC 6979 deterministic），保持与 Python /
 *   Go SDK 字节一致。WebCrypto 的 ECDSA 签名是不确定性的（每次随机 k），
 *   无法用于 golden 比对，因此签名走 noble。
 * - 验签：用 WebCrypto subtle.verify，公钥从 SPKI DER 导入。
 * - 哈希：noble p256.sign 默认 prehash=true（自带 SHA-256），与 Python /
 *   Go ECDSA-SHA256 行为一致；显式传 prehash 让意图更明确。
 */
import { p256 } from '@noble/curves/nist.js';

/**
 * ECDSA-SHA256 RAW 签名（RFC 6979 deterministic, r||s 64 字节）。
 *
 * @param privateKeyScalar 32 字节 P-256 私钥标量
 * @param message          原始消息（noble 内部 SHA-256）
 */
export async function ecdsaSignRaw(
  privateKeyScalar: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`ECDSA private key must be 32 bytes, got ${privateKeyScalar.length}`);
  }
  // noble v2: sign 直接返回 Uint8Array（默认 format='compact' 即 r||s 64B）
  // lowS=false 与 Python cryptography / Go ecdsa 行为一致
  const sig = p256.sign(message, privateKeyScalar, { lowS: false, prehash: true });
  if (!(sig instanceof Uint8Array) || sig.length !== 64) {
    throw new Error(`unexpected ECDSA signature shape: ${sig?.constructor?.name} len=${(sig as { length?: number })?.length}`);
  }
  return sig;
}

/**
 * ECDSA-SHA256 RAW 验签。
 *
 * @param publicKeyDer SPKI DER 公钥
 * @param signatureRaw 64 字节 r||s
 * @param message      原始消息（内部做 SHA-256）
 */
export async function ecdsaVerifyRaw(
  publicKeyDer: Uint8Array,
  signatureRaw: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (signatureRaw.length !== 64) return false;
  try {
    const pubKey = await crypto.subtle.importKey(
      'spki',
      publicKeyDer.slice().buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      pubKey,
      signatureRaw.slice().buffer,
      message.slice().buffer,
    );
    return Boolean(ok);
  } catch {
    return false;
  }
}
