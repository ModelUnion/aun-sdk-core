/**
 * AUN E2EE V2: AES-256-GCM AEAD
 *
 * 规范引用：§3.1
 * - 256-bit 密钥，96-bit nonce，128-bit tag
 * - AAD：上下文绑定（from/to/group_id 等的 canonical_json）
 */

import { createCipheriv, createDecipheriv } from 'node:crypto';

const KEY_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;

/**
 * AES-256-GCM 加密。
 *
 * @returns ciphertext 与 tag（16 字节）分离返回
 */
export function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  if (key.length !== KEY_LEN) {
    throw new Error(`AES-256-GCM key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`AES-256-GCM nonce must be ${NONCE_LEN} bytes, got ${nonce.length}`);
  }
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  if (aad.length > 0) {
    cipher.setAAD(Buffer.from(aad));
  } else {
    cipher.setAAD(Buffer.alloc(0));
  }
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext: new Uint8Array(ct), tag: new Uint8Array(tag) };
}

/**
 * AES-256-GCM 解密。tag 校验失败抛错。
 */
export function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LEN) {
    throw new Error(`AES-256-GCM key must be ${KEY_LEN} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`AES-256-GCM nonce must be ${NONCE_LEN} bytes, got ${nonce.length}`);
  }
  if (tag.length !== TAG_LEN) {
    throw new Error(`AES-256-GCM tag must be ${TAG_LEN} bytes, got ${tag.length}`);
  }
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
  if (aad.length > 0) {
    decipher.setAAD(Buffer.from(aad));
  } else {
    decipher.setAAD(Buffer.alloc(0));
  }
  decipher.setAuthTag(Buffer.from(tag));
  const pt = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
  return new Uint8Array(pt);
}
