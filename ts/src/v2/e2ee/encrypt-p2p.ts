/**
 * AUN E2EE V2: P2P 加密引擎
 *
 * 构造完整的 `e2ee.p2p_encrypted` envelope。纯计算，无 IO。
 *
 * 与 Python `aun_core.v2.e2ee.encrypt_p2p.encrypt_p2p_message` 对齐。
 *
 * 步骤：
 *  1. 生成 master_key + msg_nonce
 *  2. 构造 message_id / timestamp
 *  3. 推导 peer_aid 与 wrap_protocol_str
 *  4. 构造 AAD 并加密 payload
 *  5. 生成 sender_session keypair
 *  6. 计算 wrap_salt
 *  7. 为每个 target wrap master_key
 *  8. 排序 recipients + 计算 digest
 *  9. 计算 sender_signature
 * 10. 计算 sender_cert_fingerprint
 * 11. 组装 envelope
 */

import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { canonicalJson, canonicalStringify } from '../crypto/canonical.js';
import { ecdsaSignRaw } from '../crypto/ecdsa.js';
import { aesGcmEncrypt } from '../crypto/aead.js';
import { generateP256Keypair } from '../crypto/ecdh.js';
import { compute3DHWrap, compute1DHWrap } from '../crypto/dh-path.js';
import { sortRecipients, computeRecipientsDigest } from '../crypto/recipients.js';
import { ProtectedHeaders, type ProtectedHeadersInput } from '../../protected-headers.js';
import {
  Sender,
  Target,
  TargetSet,
  EncryptOptions,
  SUITE_NAME,
} from './types.js';
import { withMetadataAuth, PROTECTED_HEADERS_DOMAIN, PROTECTED_CONTEXT_DOMAIN } from './metadata-auth.js';

const TEXT = new TextEncoder();
const E2EE_SDK_LANG = 'typescript';
const E2EE_SDK_VERSION = '0.3.4';

/**
 * 构造完整的 V2 P2P 加密 envelope。
 */
export function encryptP2PMessage(
  sender: Sender,
  targetSet: TargetSet,
  payload: Record<string, unknown>,
  opts: EncryptOptions = {},
): Record<string, unknown> {
  // 1. master_key + msg_nonce
  const masterKey = new Uint8Array(randomBytes(32));
  const msgNonce = new Uint8Array(randomBytes(12));

  // 2. message_id + timestamp
  const messageId = opts.messageId ?? `m-${randomUUID().replace(/-/g, '')}`;
  const timestamp = opts.timestamp ?? Date.now();

  // 3. peer_aid（首个非 audit 的 target.aid；与 Python 一致）
  let peerAid = '';
  for (const t of targetSet.targets) {
    if (t.role !== 'audit') {
      peerAid = t.aid;
      break;
    }
  }

  // 4. wrap_protocol_str
  const allTargets: Target[] = [
    ...targetSet.targets,
    ...(targetSet.auditRecipients ?? []),
  ];
  const protocolSet = new Set<string>();
  for (const t of allTargets) {
    protocolSet.add(usesSPKWrap(t) ? '3DH' : '1DH');
  }
  const wrapProtocolStr =
    protocolSet.size === 0 ? '1DH' : [...protocolSet].sort().join('+');

  // 5. AAD（顺序在 canonical_json 时由键名排序统一，这里只是构造对象）
  const aad: Record<string, unknown> = {
    from: sender.aid,
    from_device: sender.deviceId,
    to: peerAid,
    message_id: messageId,
    timestamp,
    suite: SUITE_NAME,
    wrap_protocol: wrapProtocolStr,
  };

  // 6. encrypt body
  const plaintextBytes = canonicalJson(payload);
  const aadBytes = canonicalJson(aad);
  const { ciphertext, tag } = aesGcmEncrypt(masterKey, msgNonce, plaintextBytes, aadBytes);

  // 7. sender_session keypair
  const [senderSessionPriv, senderSessionPubDer] = generateP256Keypair();

  // 8. wrap_salt = SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
  const wrapSalt = computeWrapSalt(aadBytes, senderSessionPubDer);

  // 9. wrap recipients
  const recipientsRows: string[][] = [];
  for (const target of allTargets) {
    recipientsRows.push(
      wrapForRecipient(target, masterKey, senderSessionPriv, sender.ikPriv, wrapSalt),
    );
  }

  // 10. sort + digest
  const sortedRows = sortRecipients(recipientsRows);
  const digestHex = computeRecipientsDigest(sortedRows);

  // 11. sender_signature
  const digestBytes = Buffer.from(digestHex, 'hex');
  const signInput = Buffer.concat([
    Buffer.from(ciphertext),
    Buffer.from(tag),
    Buffer.from(aadBytes),
    digestBytes,
  ]);
  const senderSig = ecdsaSignRaw(sender.ikPriv, new Uint8Array(signInput));

  // 12. cert_fingerprint
  const certFpHash = createHash('sha256').update(Buffer.from(sender.ikPubDer)).digest('hex');
  const certFp = `sha256:${certFpHash.substring(0, 16)}`;

  const envelope: Record<string, unknown> = {
    type: 'e2ee.p2p_encrypted',
    version: 'v2',
    suite: SUITE_NAME,
    msg_type: 'original',
    t_send: timestamp,
    t_supplement: null,
    t_server: null,
    nonce: Buffer.from(msgNonce).toString('base64'),
    ciphertext: Buffer.from(ciphertext).toString('base64'),
    tag: Buffer.from(tag).toString('base64'),
    sender_signature: Buffer.from(senderSig).toString('base64'),
    sender_cert_fingerprint: certFp,
    sender_session_pk: Buffer.from(senderSessionPubDer).toString('base64'),
    recipients_digest: digestHex,
    recipients: sortedRows,
    aad,
  };
  const payloadType = payload?.type == null ? '' : String(payload.type);
  if (payloadType) {
    envelope.payload_type = payloadType;
  }

  // protected_headers / context：HMAC 签名，不进 AAD。
  // payload_type 自动注入 + value 转 string（与 Python _normalize_headers 对齐）
  const normalizedHeaders = normalizeProtectedHeaders(opts.protectedHeaders, payload);
  if (Object.keys(normalizedHeaders).length > 0) {
    envelope.protected_headers = withMetadataAuth(normalizedHeaders, masterKey, PROTECTED_HEADERS_DOMAIN);
  }
  if (isPlainObject(opts.context) && Object.keys(opts.context).length > 0) {
    // context 过滤 _auth 字段（withMetadataAuth 内部已处理）
    envelope.context = withMetadataAuth(opts.context, masterKey, PROTECTED_CONTEXT_DOMAIN);
  }

  return envelope;
}

/**
 * 规范化 protected_headers：value 转 string + 自动注入 payload_type。
 * 与 Python `_normalize_headers` 对齐。
 */
export function normalizeProtectedHeaders(
  headers: ProtectedHeadersInput,
  payload: Record<string, unknown>,
): Record<string, string> {
  const normalized: Record<string, string> = {};
  if (headers instanceof ProtectedHeaders) {
    Object.assign(normalized, headers.toObject());
  } else if (isPlainObject(headers)) {
    for (const [key, value] of Object.entries(headers)) {
      normalized[normalizeProtectedHeaderKey(key)] = normalizeProtectedHeaderValue(value);
    }
  }
  // payload_type 自动注入（与 Python 对齐：即使未显式传 protected_headers 也会注入）
  const payloadType = typeof payload?.type === 'string' ? payload.type : '';
  if (payloadType && !('payload_type' in normalized)) {
    normalized['payload_type'] = payloadType;
  }
  normalized.sdk_lang = E2EE_SDK_LANG;
  delete normalized.sdk_vesion;
  normalized.sdk_version = E2EE_SDK_VERSION;
  return normalized;
}

function normalizeProtectedHeaderKey(key: unknown): string {
  const value = String(key ?? '').trim().toLowerCase();
  if (!value || !/^[a-z0-9_-]+$/.test(value)) {
    throw new Error('protected header key must match [a-z0-9_-]+');
  }
  if (value === '_auth') {
    throw new Error('protected header key is reserved');
  }
  return value;
}

function normalizeProtectedHeaderValue(value: unknown): string {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  return canonicalStringify(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function computeWrapSalt(aadBytes: Uint8Array, senderSessionPubDer: Uint8Array): Uint8Array {
  const suiteBytes = TEXT.encode(SUITE_NAME);
  const h = createHash('sha256');
  h.update(Buffer.from(aadBytes));
  h.update(Buffer.from(senderSessionPubDer));
  h.update(Buffer.from(suiteBytes));
  return new Uint8Array(h.digest()).subarray(0, 16);
}

function wrapForRecipient(
  target: Target,
  masterKey: Uint8Array,
  senderSessionPriv: Uint8Array,
  senderMasterPriv: Uint8Array,
  wrapSalt: Uint8Array,
): string[] {
  const fpHash = createHash('sha256').update(Buffer.from(target.ikPkDer)).digest('hex');
  const fp = `sha256:${fpHash.substring(0, 16)}`;

  const wrapNonce = new Uint8Array(randomBytes(12));
  const use3DH = usesSPKWrap(target);
  const rowKeySource = use3DH ? target.keySource : 'aid_master';
  const rowSpkId = use3DH ? (target.spkId ?? '') : '';

  let wrapKey: Uint8Array;
  if (use3DH) {
    wrapKey = compute3DHWrap(
      senderSessionPriv,
      senderMasterPriv,
      target.ikPkDer,
      target.spkPkDer,
      wrapSalt,
    );
  } else {
    wrapKey = compute1DHWrap(senderSessionPriv, target.ikPkDer, wrapSalt);
  }

  // AES-GCM wrap master_key（无 AAD）
  const { ciphertext: wrappedCt, tag: wrappedTag } = aesGcmEncrypt(
    wrapKey,
    wrapNonce,
    masterKey,
    new Uint8Array(0),
  );
  const wrappedKey = Buffer.concat([Buffer.from(wrappedCt), Buffer.from(wrappedTag)]);

  return [
    target.aid,
    target.deviceId,
    target.role,
    rowKeySource,
    fp,
    rowSpkId,
    Buffer.from(wrapNonce).toString('base64'),
    wrappedKey.toString('base64'),
  ];
}

function usesSPKWrap(
  target: Target,
): target is Target & {
  spkId: string;
  spkPkDer: Uint8Array;
  keySource: 'peer_device_prekey' | 'group_device_prekey';
} {
  return Boolean(
    target.spkId &&
      target.spkPkDer &&
      (target.keySource === 'peer_device_prekey' || target.keySource === 'group_device_prekey'),
  );
}
