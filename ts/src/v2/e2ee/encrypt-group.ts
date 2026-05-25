/**
 * AUN E2EE V2: Group 加密引擎
 *
 * 构造完整的 `e2ee.group_encrypted` envelope。纯计算，无 IO。
 *
 * 与 Python `aun_core.v2.e2ee.encrypt_group.encrypt_group_message` 对齐。
 *
 * 与 P2P 同构，AAD 多 group_id / epoch / state_commitment；envelope 顶层多
 * group_id / epoch，无 to / t_supplement。
 */

import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { canonicalJson } from '../crypto/canonical.js';
import { ecdsaSignRaw } from '../crypto/ecdsa.js';
import { aesGcmEncrypt } from '../crypto/aead.js';
import { generateP256Keypair } from '../crypto/ecdh.js';
import { compute3DHWrap, compute1DHWrap } from '../crypto/dh-path.js';
import { sortRecipients, computeRecipientsDigest } from '../crypto/recipients.js';
import {
  Sender,
  Target,
  EncryptOptions,
  StateCommitmentAAD,
  SUITE_NAME,
} from './types.js';
import { withMetadataAuth, PROTECTED_HEADERS_DOMAIN, PROTECTED_CONTEXT_DOMAIN } from './metadata-auth.js';
import { normalizeProtectedHeaders } from './encrypt-p2p.js';

const TEXT = new TextEncoder();

/**
 * 构造完整的 V2 Group 加密 envelope。
 *
 * @param stateCommitment 可选；缺省时写入占位（state_version=0）以兼容未启用 state 的群。
 */
export function encryptGroupMessage(
  sender: Sender,
  groupId: string,
  epoch: number,
  targets: Target[],
  payload: Record<string, unknown>,
  opts: EncryptOptions = {},
  stateCommitment?: StateCommitmentAAD | null,
): Record<string, unknown> {
  const masterKey = new Uint8Array(randomBytes(32));
  const msgNonce = new Uint8Array(randomBytes(12));

  const messageId = opts.messageId ?? `m-${randomUUID().replace(/-/g, '')}`;
  const timestamp = opts.timestamp ?? Date.now();

  // wrap_protocol_str
  const protocolSet = new Set<string>();
  for (const t of targets) {
    protocolSet.add(usesSPKWrap(t) ? '3DH' : '1DH');
  }
  const wrapProtocolStr =
    protocolSet.size === 0 ? '1DH' : [...protocolSet].sort().join('+');

  // state_commitment（缺省占位）
  const sc = stateCommitment ?? {};
  const stateCommitmentAAD = {
    state_version: Number((sc as { state_version?: number }).state_version ?? 0) || 0,
    state_hash: String((sc as { state_hash?: string }).state_hash ?? ''),
    state_chain: String((sc as { state_chain?: string }).state_chain ?? ''),
  };

  const aad: Record<string, unknown> = {
    from: sender.aid,
    from_device: sender.deviceId,
    group_id: groupId,
    epoch,
    message_id: messageId,
    timestamp,
    suite: SUITE_NAME,
    wrap_protocol: wrapProtocolStr,
    state_commitment: stateCommitmentAAD,
  };

  const plaintextBytes = canonicalJson(payload);
  const aadBytes = canonicalJson(aad);
  const { ciphertext, tag } = aesGcmEncrypt(masterKey, msgNonce, plaintextBytes, aadBytes);

  const [senderSessionPriv, senderSessionPubDer] = generateP256Keypair();

  // wrap_salt = SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
  const wrapSalt = computeWrapSalt(aadBytes, senderSessionPubDer);

  const recipientsRows: string[][] = [];
  for (const target of targets) {
    recipientsRows.push(
      wrapForRecipient(target, masterKey, senderSessionPriv, sender.ikPriv, wrapSalt),
    );
  }

  const sortedRows = sortRecipients(recipientsRows);
  const digestHex = computeRecipientsDigest(sortedRows);

  const digestBytes = Buffer.from(digestHex, 'hex');
  const signInput = Buffer.concat([
    Buffer.from(ciphertext),
    Buffer.from(tag),
    Buffer.from(aadBytes),
    digestBytes,
  ]);
  const senderSig = ecdsaSignRaw(sender.ikPriv, new Uint8Array(signInput));

  const certFpHash = createHash('sha256').update(Buffer.from(sender.ikPubDer)).digest('hex');
  const certFp = `sha256:${certFpHash.substring(0, 16)}`;

  const envelope: Record<string, unknown> = {
    type: 'e2ee.group_encrypted',
    version: 'v2',
    suite: SUITE_NAME,
    msg_type: 'original',
    group_id: groupId,
    epoch,
    t_send: timestamp,
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
  if (opts.context && typeof opts.context === 'object' && !Array.isArray(opts.context) && Object.keys(opts.context).length > 0) {
    envelope.context = withMetadataAuth(opts.context, masterKey, PROTECTED_CONTEXT_DOMAIN);
  }

  return envelope;
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
