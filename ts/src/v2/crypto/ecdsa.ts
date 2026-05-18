/**
 * AUN E2EE V2: ECDSA-SHA256 RAW（RFC 6979 deterministic）
 *
 * 规范引用：§3.1
 * - 曲线 P-256
 * - RFC 6979 deterministic nonce（必须）
 * - 输出 RAW 编码 r(32B)||s(32B)
 *
 * 实现选型：
 * - 使用 @noble/curves/nist 提供 deterministic ECDSA
 * - 公钥使用 DER SubjectPublicKeyInfo（与 Python/Go 对齐）
 *   通过 Node createPublicKey 提取未压缩点（0x04||X||Y）后传给 noble
 */

import { p256 } from '@noble/curves/nist.js';
import { createHash, createPublicKey } from 'node:crypto';

/**
 * 把 base64url 字符串解码为 32 字节大端序无前导零填充的字节数组。
 */
function b64uToFixed32(b64url: string): Buffer {
  const buf = Buffer.from(b64url, 'base64url');
  if (buf.length === 32) return buf;
  if (buf.length < 32) {
    const padded = Buffer.alloc(32);
    buf.copy(padded, 32 - buf.length);
    return padded;
  }
  const start = buf.length - 32;
  for (let i = 0; i < start; i++) {
    if (buf[i] !== 0) {
      throw new Error(`invalid EC coordinate: length=${buf.length}, leading non-zero byte`);
    }
  }
  return buf.subarray(start, buf.length);
}

/**
 * 从 DER SPKI 编码公钥提取未压缩点（0x04||X||Y），共 65 字节。
 */
function derSpkiToUncompressed(publicKeyDer: Uint8Array): Uint8Array {
  const pub = createPublicKey({
    key: Buffer.from(publicKeyDer),
    format: 'der',
    type: 'spki',
  });
  const jwk = pub.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('public key is not a P-256 EC key');
  }
  const x = b64uToFixed32(jwk.x);
  const y = b64uToFixed32(jwk.y);
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

/**
 * ECDSA-SHA256 签名（RFC 6979 deterministic），输出 RAW 编码 r||s（64 字节）。
 *
 * @param privateKeyScalar P-256 私钥标量（32 字节 big-endian）
 * @param message 待签名消息原文
 * @returns 64 字节签名
 */
export function ecdsaSignRaw(
  privateKeyScalar: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`expected 32-byte P-256 private scalar, got ${privateKeyScalar.length}`);
  }
  // 显式 prehash=true（默认值），noble 会用 SHA-256 摘要。
  // lowS=false 与 Python/Go SDK 行为对齐（不强制低 S）。
  // format='compact' 是默认值，输出 64B = r||s。
  const sig = p256.sign(message, privateKeyScalar, {
    prehash: true,
    lowS: false,
    format: 'compact',
  });
  if (sig.length !== 64) {
    throw new Error(`unexpected signature length: ${sig.length}`);
  }
  return sig;
}

/**
 * ECDSA-SHA256 验签（RAW 64 字节签名）。
 */
export function ecdsaVerifyRaw(
  publicKeyDer: Uint8Array,
  signatureRaw: Uint8Array,
  message: Uint8Array,
): boolean {
  if (signatureRaw.length !== 64) return false;
  try {
    const uncompressed = derSpkiToUncompressed(publicKeyDer);
    return p256.verify(signatureRaw, message, uncompressed, {
      prehash: true,
      lowS: false,
      format: 'compact',
    });
  } catch {
    return false;
  }
}

/**
 * 仅用于本地校验：根据 P-256 私钥派生公钥的 DER SPKI 编码。
 */
export function privateScalarToPublicDer(privateKeyScalar: Uint8Array): Uint8Array {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`expected 32-byte P-256 private scalar, got ${privateKeyScalar.length}`);
  }
  // noble 返回未压缩 65 字节
  const uncompressed = p256.getPublicKey(privateKeyScalar, false);
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new Error('failed to derive uncompressed P-256 public key');
  }
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);
  const pubKey = createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(x).toString('base64url'),
      y: Buffer.from(y).toString('base64url'),
    },
    format: 'jwk',
  });
  return new Uint8Array(pubKey.export({ format: 'der', type: 'spki' }));
}
