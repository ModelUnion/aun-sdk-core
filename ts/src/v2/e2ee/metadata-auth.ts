/**
 * AUN E2EE V2: protected_headers / context HMAC 签名
 *
 * 与 Python `aun_core.v2.e2ee.encrypt_p2p._with_metadata_auth` 对齐。
 * 用 master_key 派生 HMAC key，对 metadata body 做签名，生成 `_auth` 字段。
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalJson } from '../crypto/canonical.js';

export const METADATA_KEY_DOMAIN = Buffer.from('aun-envelope-metadata-key-v1', 'utf-8');
export const PROTECTED_HEADERS_DOMAIN = Buffer.from('aun-protected-headers-v1', 'utf-8');
export const PROTECTED_CONTEXT_DOMAIN = Buffer.from('aun-protected-context-v1', 'utf-8');

/**
 * 计算 metadata HMAC 签名 tag。
 *
 * metadata_key = HMAC-SHA256(key, METADATA_KEY_DOMAIN)
 * sign_input = domain + "\0" + canonical_json(body)
 * tag = HMAC-SHA256(metadata_key, sign_input)
 */
function metadataAuthTag(key: Uint8Array, domain: Buffer, body: Record<string, unknown>): Buffer {
  const metadataKey = createHmac('sha256', key).update(METADATA_KEY_DOMAIN).digest();
  const bodyBytes = canonicalJson(body);
  return createHmac('sha256', metadataKey)
    .update(domain)
    .update(Buffer.from([0]))
    .update(Buffer.from(bodyBytes))
    .digest();
}

/**
 * 为 metadata 对象添加 HMAC 签名（_auth 字段）。
 *
 * 如果 body（去除 _auth 后）为空，返回空对象。
 */
export function withMetadataAuth(
  metadata: Record<string, unknown>,
  key: Uint8Array,
  domain: Buffer,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(metadata)) {
    if (k !== '_auth') body[k] = v;
  }
  if (Object.keys(body).length === 0) return {};
  const tag = metadataAuthTag(key, domain, body);
  return {
    ...body,
    _auth: {
      alg: 'HMAC-SHA256',
      tag: tag.toString('base64'),
    },
  };
}

export function verifyMetadataAuth(
  metadata: unknown,
  key: Uint8Array,
  domain: Buffer,
  fieldName: string,
): void {
  if (metadata == null) return;
  if (!isPlainObject(metadata)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(metadata)) {
    if (k !== '_auth') body[k] = v;
  }
  if (Object.keys(body).length === 0) return;

  const auth = metadata._auth;
  if (!isPlainObject(auth)) {
    throw new Error(`${fieldName} missing _auth`);
  }
  if (auth.alg !== 'HMAC-SHA256') {
    throw new Error(`${fieldName} unsupported _auth alg`);
  }
  if (typeof auth.tag !== 'string' || auth.tag.length === 0) {
    throw new Error(`${fieldName} missing _auth tag`);
  }

  const actual = Buffer.from(auth.tag, 'base64');
  const expected = metadataAuthTag(key, domain, body);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error(`${fieldName} _auth verification failed`);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
