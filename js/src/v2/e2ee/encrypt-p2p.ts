/**
 * AUN E2EE V2: P2P 加密引擎（浏览器版，async）
 *
 * 构造完整的 e2ee.p2p_encrypted envelope。纯计算，无 IO。
 *
 * 规范引用: §4 / §5
 *
 * 参考实现: python/src/aun_core/v2/e2ee/encrypt_p2p.py
 */
import { canonicalJson } from '../crypto/canonical';
import { ecdsaSignRaw } from '../crypto/ecdsa';
import { aesGcmEncrypt } from '../crypto/aead';
import { generateP256Keypair } from '../crypto/ecdh';
import { compute3DHWrap, compute1DHWrap } from '../crypto/dh-path';
import { sortRecipients, computeRecipientsDigest } from '../crypto/recipients';
import {
  type Sender,
  type Target,
  type TargetSet,
  type EncryptOptions,
  SUITE_NAME,
} from './types';
import {
  withMetadataAuth,
  PROTECTED_HEADERS_DOMAIN,
  PROTECTED_CONTEXT_DOMAIN,
} from './metadata-auth';

const encoder = new TextEncoder();

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data.slice().buffer);
  return new Uint8Array(buf);
}

function bytesToBase64(b: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
  return btoa(bin);
}

function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('hex length must be even');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = parseInt(s.charAt(i * 2), 16);
    const lo = parseInt(s.charAt(i * 2 + 1), 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) throw new Error('invalid hex char');
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function uuid4Hex(): string {
  // crypto.randomUUID() 在浏览器和 Node 18+ 都可用，去掉 dash 与 Python uuid4().hex 对齐
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  // 降级：用 16B 随机字节构造 v4 hex
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant
  return bytesToHex(b);
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/**
 * 构造完整的 V2 P2P 加密 envelope。
 *
 * 与 Python `encrypt_p2p_message` 字节级对齐（除了随机字段：master_key/msg_nonce/
 * sender_session keypair/wrap_nonce/message_id/timestamp，以及由此影响的 ciphertext/
 * tag/recipients_digest/sender_signature）。
 */
export async function encryptP2PMessage(
  sender: Sender,
  targetSet: TargetSet,
  payload: Record<string, unknown>,
  opts: EncryptOptions = {},
): Promise<Record<string, unknown>> {
  // 1. master_key + msg_nonce
  const masterKey = randomBytes(32);
  const msgNonce = randomBytes(12);

  // 2. 构造 AAD
  const messageId = opts.messageId ?? `m-${uuid4Hex()}`;
  const timestamp = opts.timestamp ?? Date.now();

  // 确定 to（第一个非 audit 的 aid）
  let peerAid = '';
  for (const t of targetSet.targets) {
    if (t.role !== 'audit') {
      peerAid = t.aid;
      break;
    }
  }

  // wrap_protocol_set（防服务端篡改 key_source 引导接收方走 1DH）
  const allTargetsForProto: Target[] = [
    ...targetSet.targets,
    ...(targetSet.auditRecipients ?? []),
  ];
  const protocolSet = new Set<string>();
  for (const t of allTargetsForProto) {
    if (
      t.spkPkDer
      && (t.keySource === 'peer_device_prekey' || t.keySource === 'group_device_prekey')
    ) {
      protocolSet.add('3DH');
    } else {
      protocolSet.add('1DH');
    }
  }
  const wrapProtocolStr = protocolSet.size > 0 ? [...protocolSet].sort().join('+') : '1DH';

  const aad: Record<string, unknown> = {
    from: sender.aid,
    from_device: sender.deviceId,
    to: peerAid,
    message_id: messageId,
    timestamp,
    suite: SUITE_NAME,
    wrap_protocol: wrapProtocolStr,
  };

  // 3. 加密正文
  const plaintextBytes = canonicalJson(payload);
  const aadBytes = canonicalJson(aad);
  const { ciphertext, tag } = await aesGcmEncrypt(
    masterKey,
    msgNonce,
    plaintextBytes,
    aadBytes,
  );

  // 4. sender_session keypair
  const [senderSessionPriv, senderSessionPubDer] = await generateP256Keypair();

  // wrap_salt = SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
  const suiteBytes = encoder.encode(SUITE_NAME);
  const saltInput = new Uint8Array(
    aadBytes.length + senderSessionPubDer.length + suiteBytes.length,
  );
  saltInput.set(aadBytes, 0);
  saltInput.set(senderSessionPubDer, aadBytes.length);
  saltInput.set(suiteBytes, aadBytes.length + senderSessionPubDer.length);
  const wrapSalt = (await sha256(saltInput)).subarray(0, 16);

  // 5. 为每个 recipient wrap master_key
  const allTargets: Target[] = [
    ...targetSet.targets,
    ...(targetSet.auditRecipients ?? []),
  ];
  const recipientsRows: string[][] = [];
  for (const target of allTargets) {
    recipientsRows.push(
      await wrapForRecipient(
        target,
        masterKey,
        senderSessionPriv,
        sender.ikPriv,
        wrapSalt,
        'peer',
      ),
    );
  }

  // 6. sort + 7. digest
  const sortedRows = sortRecipients(recipientsRows);
  const digestHex = await computeRecipientsDigest(sortedRows);

  // 8. sender_signature = ECDSA(ik_priv, ct || tag || aad || digest_bytes)
  const digestBytes = hexToBytes(digestHex);
  const signInput = new Uint8Array(
    ciphertext.length + tag.length + aadBytes.length + digestBytes.length,
  );
  let pos = 0;
  signInput.set(ciphertext, pos);
  pos += ciphertext.length;
  signInput.set(tag, pos);
  pos += tag.length;
  signInput.set(aadBytes, pos);
  pos += aadBytes.length;
  signInput.set(digestBytes, pos);
  const senderSig = await ecdsaSignRaw(sender.ikPriv, signInput);

  // 9. cert fingerprint = "sha256:" + sha256(ik_pub_der).hex()[:16]
  const certFpHash = bytesToHex(await sha256(sender.ikPubDer));
  const certFp = `sha256:${certFpHash.substring(0, 16)}`;

  // 10. 组装 envelope
  const envelope: Record<string, unknown> = {
    type: 'e2ee.p2p_encrypted',
    version: 'v2',
    suite: SUITE_NAME,
    msg_type: 'original',
    t_send: timestamp,
    t_supplement: null,
    t_server: null,
    nonce: bytesToBase64(msgNonce),
    ciphertext: bytesToBase64(ciphertext),
    tag: bytesToBase64(tag),
    sender_signature: bytesToBase64(senderSig),
    sender_cert_fingerprint: certFp,
    sender_session_pk: bytesToBase64(senderSessionPubDer),
    recipients_digest: digestHex,
    recipients: sortedRows,
    aad,
  };

  // 11. protected_headers / context：HMAC 签名（与 V1 对齐），不进 AAD
  // payload_type 自动注入 + value 转 string（与 Python _normalize_headers 对齐）
  const normalizedHeaders = normalizeProtectedHeaders(opts.protectedHeaders, payload);
  if (Object.keys(normalizedHeaders).length > 0) {
    envelope.protected_headers = await withMetadataAuth(normalizedHeaders, masterKey, PROTECTED_HEADERS_DOMAIN);
  }
  const { context } = opts;
  if (context && typeof context === 'object' && Object.keys(context).length > 0) {
    envelope.context = await withMetadataAuth(context, masterKey, PROTECTED_CONTEXT_DOMAIN);
  }

  return envelope;
}

/**
 * 规范化 protected_headers：value 转 string + 自动注入 payload_type。
 * 与 Python `_normalize_headers` 对齐。
 */
export function normalizeProtectedHeaders(
  headers: Record<string, unknown> | undefined | null,
  payload: Record<string, unknown>,
): Record<string, string> {
  const normalized: Record<string, string> = {};
  if (headers && typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      if (k === '_auth') continue;
      const sv = v != null ? String(v) : '';
      if (sv) normalized[k] = sv;
    }
  }
  // payload_type 自动注入（与 Python 对齐：payload.get("type") → protected_headers["payload_type"]）
  const payloadType = typeof payload?.type === 'string' ? payload.type : '';
  if (payloadType && !('payload_type' in normalized)) {
    normalized['payload_type'] = payloadType;
  }
  return normalized;
}

/**
 * 为单个 recipient 生成 wrap 行（[aid, device_id, role, key_source, fp,
 * spk_id, wrap_nonce_b64, wrapped_key_b64]）。
 */
async function wrapForRecipient(
  target: Target,
  masterKey: Uint8Array,
  senderSessionPriv: Uint8Array,
  senderMasterPriv: Uint8Array,
  wrapSalt: Uint8Array,
  defaultRole: 'peer' | 'member',
): Promise<string[]> {
  const role = target.role ?? defaultRole;
  const keySource = target.keySource ?? 'aid_master';

  // fp = "sha256:" + sha256(ik_pk_der).hex()[:16]
  const fpHash = bytesToHex(await sha256(target.ikPkDer));
  const fp = `sha256:${fpHash.substring(0, 16)}`;

  const wrapNonce = randomBytes(12);

  let wrapKey: Uint8Array;
  if (
    target.spkPkDer
    && (keySource === 'peer_device_prekey' || keySource === 'group_device_prekey')
  ) {
    wrapKey = await compute3DHWrap(
      senderSessionPriv,
      senderMasterPriv,
      target.ikPkDer,
      target.spkPkDer,
      wrapSalt,
    );
  } else {
    wrapKey = await compute1DHWrap(senderSessionPriv, target.ikPkDer, wrapSalt);
  }

  // wrapped_key = ciphertext (32B) + tag (16B) = 48B
  const { ciphertext: wrappedCt, tag: wrappedTag } = await aesGcmEncrypt(
    wrapKey,
    wrapNonce,
    masterKey,
    new Uint8Array(0),
  );
  const wrappedKey = new Uint8Array(wrappedCt.length + wrappedTag.length);
  wrappedKey.set(wrappedCt, 0);
  wrappedKey.set(wrappedTag, wrappedCt.length);

  return [
    target.aid,
    target.deviceId,
    role,
    keySource,
    fp,
    target.spkId ?? '',
    bytesToBase64(wrapNonce),
    bytesToBase64(wrappedKey),
  ];
}
