/**
 * ECDH P-256 — AUN E2EE V2 协议要求所有 SDK 的 ECDH 输出字节级一致。
 *
 * 共享秘密为 P-256 曲线点乘后的 X 坐标（32 字节，big-endian）。
 *
 * 实现选型：
 * - 使用 Node `crypto` 模块（非 WebCrypto，TS SDK 目标为 Node 环境）
 * - `createECDH('prime256v1')` 计算 X 坐标
 * - 公钥使用 DER SubjectPublicKeyInfo 编码（与 Python/Go SDK 对齐）
 * - 通过 JWK 中转完成 DER ↔ 未压缩点（0x04 || X || Y）的转换
 */

import { createECDH, createPublicKey } from 'node:crypto';

/**
 * 把 base64url 字符串解码为 32 字节大端序无前导零填充的字节数组。
 * 解决 JWK x/y 可能因高位为 0 而被截短的问题。
 */
function b64uToFixed32(b64url: string): Buffer {
  const buf = Buffer.from(b64url, 'base64url');
  if (buf.length === 32) return buf;
  if (buf.length < 32) {
    const padded = Buffer.alloc(32);
    buf.copy(padded, 32 - buf.length);
    return padded;
  }
  // 长度 > 32：去掉前导 0x00 填充
  const start = buf.length - 32;
  for (let i = 0; i < start; i++) {
    if (buf[i] !== 0) {
      throw new Error(`invalid EC coordinate: length=${buf.length}, leading non-zero byte`);
    }
  }
  return buf.subarray(start, buf.length);
}

/**
 * 把未压缩点（0x04 || X(32) || Y(32)）的 X/Y 坐标转换为 SPKI DER 公钥。
 */
function uncompressedPointToDer(uncompressed: Buffer): Buffer {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new Error('invalid uncompressed P-256 point');
  }
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);
  const pubKey = createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    },
    format: 'jwk',
  });
  return pubKey.export({ format: 'der', type: 'spki' });
}

/**
 * 计算 ECDH 共享秘密（P-256 X 坐标，32 字节）。
 *
 * @param privateKeyScalar 32 字节 P-256 私钥标量（big-endian）
 * @param peerPublicKeyDer DER SubjectPublicKeyInfo 编码的对端公钥
 * @returns 32 字节共享秘密（X 坐标 big-endian）
 */
export function ecdhComputeShared(
  privateKeyScalar: Uint8Array,
  peerPublicKeyDer: Uint8Array,
): Uint8Array {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`expected 32-byte P-256 private scalar, got ${privateKeyScalar.length}`);
  }

  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(privateKeyScalar));

  // 解析 DER SPKI 公钥 → 提取未压缩点（0x04 || X || Y）
  const peerPubKey = createPublicKey({
    key: Buffer.from(peerPublicKeyDer),
    format: 'der',
    type: 'spki',
  });
  const jwk = peerPubKey.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('peer public key is not a P-256 EC key');
  }
  const x = b64uToFixed32(jwk.x);
  const y = b64uToFixed32(jwk.y);
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);

  // ECDH.computeSecret 默认返回 X 坐标（32 字节大端序）
  const shared = ecdh.computeSecret(uncompressed);
  return new Uint8Array(shared);
}

/**
 * 生成 P-256 密钥对。
 *
 * @returns [privateKeyScalar 32B, publicKeyDer SPKI]
 */
export function generateP256Keypair(): [Uint8Array, Uint8Array] {
  const ecdh = createECDH('prime256v1');
  const pubUncompressed = ecdh.generateKeys();
  const priv = ecdh.getPrivateKey();

  // setPrivateKey/generateKeys 返回的 priv 可能少于 32 字节（高位为 0），左零填充
  let privPadded: Buffer;
  if (priv.length === 32) {
    privPadded = priv;
  } else if (priv.length < 32) {
    privPadded = Buffer.alloc(32);
    priv.copy(privPadded, 32 - priv.length);
  } else {
    throw new Error(`unexpected P-256 private key length: ${priv.length}`);
  }

  const pubDer = uncompressedPointToDer(pubUncompressed);
  return [new Uint8Array(privPadded), new Uint8Array(pubDer)];
}

/**
 * 从私钥标量导出公钥 DER（SPKI 编码）。
 */
export function privateToPublicDer(privateKeyScalar: Uint8Array): Uint8Array {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`expected 32-byte P-256 private scalar, got ${privateKeyScalar.length}`);
  }
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(privateKeyScalar));
  const pubUncompressed = ecdh.getPublicKey();
  const pubDer = uncompressedPointToDer(pubUncompressed);
  return new Uint8Array(pubDer);
}
