/**
 * AUN E2EE V2: AES-256-GCM AEAD
 *
 * 规范引用: §3.3 / §5.1
 * - key:   32 字节
 * - nonce: 12 字节（不可重用）
 * - tag:   16 字节
 *
 * 浏览器实现：使用 WebCrypto subtle.encrypt/decrypt('AES-GCM').
 * - WebCrypto 输出 ciphertext || tag(16B)，与 Python cryptography / Node crypto 一致。
 * - 解密时需要将 ciphertext 与 tag 拼接成单一 buffer 传入 decrypt。
 */

const TAG_LENGTH = 16;

/**
 * AES-256-GCM 加密。
 *
 * @returns { ciphertext, tag } — 分离形式
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }> {
  if (key.length !== 32) throw new Error(`AES-256-GCM key must be 32 bytes, got ${key.length}`);
  if (nonce.length !== 12) throw new Error(`AES-GCM nonce must be 12 bytes, got ${nonce.length}`);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key.slice().buffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const ctWithTag = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce.slice().buffer,
      additionalData: aad.slice().buffer,
      tagLength: TAG_LENGTH * 8,
    },
    cryptoKey,
    plaintext.slice().buffer,
  );

  const buf = new Uint8Array(ctWithTag);
  if (buf.length < TAG_LENGTH) {
    throw new Error(`AES-GCM output too short: ${buf.length}`);
  }
  // copy 出独立缓冲区，避免对外暴露 subarray 视图导致后续 slice 行为出乎意料
  const ciphertext = buf.slice(0, buf.length - TAG_LENGTH);
  const tag = buf.slice(buf.length - TAG_LENGTH);
  return { ciphertext, tag };
}

/**
 * AES-256-GCM 解密。
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32) throw new Error(`AES-256-GCM key must be 32 bytes, got ${key.length}`);
  if (nonce.length !== 12) throw new Error(`AES-GCM nonce must be 12 bytes, got ${nonce.length}`);
  if (tag.length !== TAG_LENGTH) {
    throw new Error(`AES-GCM tag must be 16 bytes, got ${tag.length}`);
  }

  const ctWithTag = new Uint8Array(ciphertext.length + tag.length);
  ctWithTag.set(ciphertext, 0);
  ctWithTag.set(tag, ciphertext.length);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key.slice().buffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce.slice().buffer,
      additionalData: aad.slice().buffer,
      tagLength: TAG_LENGTH * 8,
    },
    cryptoKey,
    ctWithTag.buffer,
  );
  return new Uint8Array(pt);
}
