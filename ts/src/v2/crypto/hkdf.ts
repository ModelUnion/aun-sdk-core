/**
 * AUN E2EE V2: HKDF-SHA256（RFC 5869）
 *
 * 规范引用：用于 1DH/3DH wrap_key 派生（info 分别为 "AUN-V2-1DH" 和 "AUN-V2-3DH"）。
 *
 * 实现选型：
 * - Node `crypto` 模块 HMAC-SHA256
 * - 空 salt 视为 32 字节零（HashLen）
 */

import { createHmac } from 'node:crypto';

const HASH_LEN = 32; // SHA-256 输出长度

/**
 * HKDF-SHA256（RFC 5869）。
 *
 * @param ikm  Input keying material
 * @param salt Salt（可为空，空时按规范用 HashLen 字节零填充）
 * @param info Optional context and application specific information
 * @param length 期望输出字节长度（不能超过 255 * HashLen）
 * @returns OKM（output keying material）
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  if (length < 0 || length > 255 * HASH_LEN) {
    throw new Error(`HKDF length out of range: ${length}`);
  }
  // RFC 5869 §2.2: salt 为空时使用 HashLen 字节零
  const realSalt = salt.length === 0 ? new Uint8Array(HASH_LEN) : salt;

  // Extract: PRK = HMAC-SHA256(salt, IKM)
  const prk = createHmac('sha256', realSalt).update(ikm).digest();

  // Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
  const out = new Uint8Array(length);
  let t = new Uint8Array(0);
  let pos = 0;
  let counter = 1;
  while (pos < length) {
    const hmac = createHmac('sha256', prk);
    hmac.update(t);
    hmac.update(info);
    hmac.update(Uint8Array.of(counter));
    t = hmac.digest();
    const remaining = length - pos;
    out.set(t.subarray(0, Math.min(remaining, t.length)), pos);
    pos += t.length;
    counter++;
  }
  return out;
}
