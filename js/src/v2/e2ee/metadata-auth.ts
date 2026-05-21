/**
 * AUN E2EE V2: Metadata HMAC 签名（protected_headers / context）
 *
 * 算法：两级 HMAC-SHA256 key 派生
 *   metadataKey = HMAC-SHA256(masterKey, METADATA_KEY_DOMAIN)
 *   signInput   = domain + "\0" + canonicalJson(body)
 *   tag         = HMAC-SHA256(metadataKey, signInput)
 *
 * 参考实现: python/src/aun_core/v2/e2ee/encrypt_p2p.py
 */
import { canonicalJson } from '../crypto/canonical';

const encoder = new TextEncoder();

export const METADATA_KEY_DOMAIN = encoder.encode('aun-envelope-metadata-key-v1');
export const PROTECTED_HEADERS_DOMAIN = encoder.encode('aun-protected-headers-v1');
export const PROTECTED_CONTEXT_DOMAIN = encoder.encode('aun-protected-context-v1');

function bytesToBase64(b: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    key.slice().buffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', hmacKey, data.slice().buffer);
  return new Uint8Array(sig);
}

/**
 * 计算 metadata auth tag。
 */
async function metadataAuthTag(
  key: Uint8Array,
  domain: Uint8Array,
  body: Record<string, unknown>,
): Promise<Uint8Array> {
  const metadataKey = await hmacSha256(key, METADATA_KEY_DOMAIN);
  const bodyBytes = canonicalJson(body);
  const signInput = new Uint8Array(domain.length + 1 + bodyBytes.length);
  signInput.set(domain, 0);
  signInput[domain.length] = 0; // "\0" 分隔符
  signInput.set(bodyBytes, domain.length + 1);
  return hmacSha256(metadataKey, signInput);
}

/**
 * 对 metadata 对象签名，返回带 _auth 字段的新对象。
 * 如果 metadata 去掉 _auth 后为空，返回空对象。
 */
export async function withMetadataAuth(
  metadata: Record<string, unknown>,
  key: Uint8Array,
  domain: Uint8Array,
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(metadata)) {
    if (k !== '_auth') body[k] = v;
  }
  if (Object.keys(body).length === 0) return {};
  const tag = await metadataAuthTag(key, domain, body);
  return {
    ...body,
    _auth: {
      alg: 'HMAC-SHA256',
      tag: bytesToBase64(tag),
    },
  };
}
