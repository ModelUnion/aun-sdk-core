/**
 * AUN E2EE V2: HKDF-SHA256
 *
 * 规范引用: §3.2 / §5.2 / §10
 *
 * 浏览器实现：使用 WebCrypto subtle.deriveBits 完成 HKDF。
 * - salt 长度为 0 时按 RFC 5869 规则替换为 32 字节零（与 Python sdk 行为一致）。
 * - info 必须是 BufferSource（Uint8Array 即可）。
 * - 输出长度由 `length` 控制（字节数）。
 */

/**
 * 计算 HKDF-SHA256(ikm, salt, info, length)。
 *
 * @param ikm    输入密钥材料
 * @param salt   盐（可空）
 * @param info   上下文/信息字段
 * @param length 输出字节数
 * @returns      派生密钥
 */
export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const realSalt = salt.length === 0 ? new Uint8Array(32) : salt;
  // ikm 必须是独立 ArrayBuffer，避免视图歧义
  const baseKey = await crypto.subtle.importKey(
    'raw',
    ikm.slice().buffer,
    'HKDF',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: realSalt.slice().buffer,
      info: info.slice().buffer,
    } as HkdfParams,
    baseKey,
    length * 8,
  );
  return new Uint8Array(bits);
}
