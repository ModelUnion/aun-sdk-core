/**
 * AUN E2EE V2: ECDH P-256
 *
 * 规范引用: §3.1
 * - 曲线: P-256 (secp256r1)
 * - 输出: 椭圆曲线点 X 坐标字节（32 字节，无前缀）
 *
 * 浏览器实现：使用 WebCrypto (crypto.subtle) 完成 ECDH 派生。
 * - 私钥输入是 32 字节 raw scalar，借助 @noble/curves 推算公钥点 (X, Y)，
 *   然后构造 JWK 格式导入 WebCrypto。
 * - 公钥输入是 DER SubjectPublicKeyInfo，直接走 spki 导入。
 * - deriveBits(256) 返回 32 字节 X 坐标，与 Python cryptography 库行为一致。
 */
import { p256 } from '@noble/curves/nist.js';

/** base64url（无 padding）编码，用于 JWK 字段 */
function bytesToB64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url 解码 */
function b64UrlToBytes(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = std.length % 4 === 0 ? '' : '='.repeat(4 - (std.length % 4));
  const bin = atob(std + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64UrlToFixed32(s: string): Uint8Array {
  const raw = b64UrlToBytes(s);
  if (raw.length === 32) return raw;
  if (raw.length < 32) {
    const out = new Uint8Array(32);
    out.set(raw, 32 - raw.length);
    return out;
  }
  const extra = raw.length - 32;
  for (let i = 0; i < extra; i++) {
    if (raw[i] !== 0) {
      throw new Error(`invalid P-256 private scalar length=${raw.length}`);
    }
  }
  return raw.slice(extra);
}

/** 从 raw 32B scalar 推算 P-256 公钥的未压缩 (X, Y) 字节，各 32B */
function p256PublicXY(privateKeyScalar: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  // p256.getPublicKey(secretKey, isCompressed=false) → 65 字节 0x04 || X || Y
  const pub = p256.getPublicKey(privateKeyScalar, false) as Uint8Array;
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error(`unexpected uncompressed public key encoding: len=${pub.length}`);
  }
  return { x: pub.subarray(1, 33), y: pub.subarray(33, 65) };
}

/**
 * 计算 ECDH 共享秘密（P-256 X 坐标，32 字节）。
 *
 * @param privateKeyScalar 私钥标量（32 字节 big-endian）
 * @param peerPublicKeyDer 对端公钥（DER SubjectPublicKeyInfo 编码）
 * @returns 32 字节共享秘密（椭圆曲线点 X 坐标）
 */
export async function ecdhComputeShared(
  privateKeyScalar: Uint8Array,
  peerPublicKeyDer: Uint8Array,
): Promise<Uint8Array> {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`P-256 private scalar must be 32 bytes, got ${privateKeyScalar.length}`);
  }

  // 推算公钥点用于构造 JWK（WebCrypto 不接受 raw scalar）
  const { x, y } = p256PublicXY(privateKeyScalar);

  const privJwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    d: bytesToB64Url(privateKeyScalar),
    x: bytesToB64Url(x),
    y: bytesToB64Url(y),
    ext: true,
  };

  const privKey = await crypto.subtle.importKey(
    'jwk',
    privJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );

  const pubKey = await crypto.subtle.importKey(
    'spki',
    // BufferSource：copy 到独立 ArrayBuffer，避免传入 SharedArrayBuffer/视图歧义
    peerPublicKeyDer.slice().buffer,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: pubKey },
    privKey,
    256,
  );

  const out = new Uint8Array(sharedBits);
  if (out.length !== 32) {
    throw new Error(`ECDH derive returned ${out.length} bytes, expected 32`);
  }
  return out;
}

/**
 * 生成 P-256 密钥对。
 *
 * @returns [privateKeyScalar 32B, publicKeyDer SubjectPublicKeyInfo]
 */
export async function generateP256Keypair(): Promise<[Uint8Array, Uint8Array]> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );

  const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  if (!jwk.d) {
    throw new Error('exportKey(jwk) returned no private component');
  }
  const priv = b64UrlToFixed32(jwk.d);

  const pubDerBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  return [priv, new Uint8Array(pubDerBuf)];
}

/**
 * 从私钥标量导出公钥 DER (SubjectPublicKeyInfo)。
 */
export async function privateToPublicDer(privateKeyScalar: Uint8Array): Promise<Uint8Array> {
  if (privateKeyScalar.length !== 32) {
    throw new Error(`P-256 private scalar must be 32 bytes, got ${privateKeyScalar.length}`);
  }
  const { x, y } = p256PublicXY(privateKeyScalar);

  // 仅导入公钥点，再以 spki 导出
  const pubKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: bytesToB64Url(x), y: bytesToB64Url(y), ext: true },
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
  const der = await crypto.subtle.exportKey('spki', pubKey);
  return new Uint8Array(der);
}
