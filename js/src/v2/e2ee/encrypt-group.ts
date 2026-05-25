/**
 * AUN E2EE V2: Group 加密引擎（浏览器版，async）
 *
 * 构造完整的 e2ee.group_encrypted envelope。纯计算，无 IO。
 * 与 P2P 引擎同构，差异在 AAD（含 group_id/epoch/state_commitment）。
 *
 * 参考实现: python/src/aun_core/v2/e2ee/encrypt_group.py
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
  type EncryptOptions,
  type StateCommitmentAAD,
  SUITE_NAME,
} from './types';
import {
  withMetadataAuth,
  PROTECTED_HEADERS_DOMAIN,
  PROTECTED_CONTEXT_DOMAIN,
} from './metadata-auth';
import { normalizeProtectedHeaders } from './encrypt-p2p';

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
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return bytesToHex(b);
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/**
 * 构造完整的 V2 Group 加密 envelope。
 *
 * @param sender           发送方身份
 * @param groupId          群 ID
 * @param epoch            当前加密 epoch
 * @param targets          所有接收设备列表
 * @param payload          业务 payload（将被加密）
 * @param opts             可选参数（messageId / timestamp）
 * @param stateCommitment  绑定到 AAD 的 state 信息；缺省 → sv=0 占位
 */
export async function encryptGroupMessage(
  sender: Sender,
  groupId: string,
  epoch: number,
  targets: Target[],
  payload: Record<string, unknown>,
  opts: EncryptOptions = {},
  stateCommitment?: Partial<StateCommitmentAAD>,
): Promise<Record<string, unknown>> {
  const masterKey = randomBytes(32);
  const msgNonce = randomBytes(12);

  const messageId = opts.messageId ?? `m-${uuid4Hex()}`;
  const timestamp = opts.timestamp ?? Date.now();

  const protocolSet = new Set<string>();
  for (const t of targets) {
    if (usesSPKWrap(t)) {
      protocolSet.add('3DH');
    } else {
      protocolSet.add('1DH');
    }
  }
  const wrapProtocolStr = protocolSet.size > 0 ? [...protocolSet].sort().join('+') : '1DH';

  const sc = stateCommitment ?? {};
  const stateCommitmentAad: StateCommitmentAAD = {
    state_version: Math.trunc(Number(sc.state_version ?? 0)) || 0,
    state_hash: String(sc.state_hash ?? ''),
    state_chain: String(sc.state_chain ?? ''),
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
    state_commitment: stateCommitmentAad,
  };

  const plaintextBytes = canonicalJson(payload);
  const aadBytes = canonicalJson(aad);
  const { ciphertext, tag } = await aesGcmEncrypt(masterKey, msgNonce, plaintextBytes, aadBytes);

  const [senderSessionPriv, senderSessionPubDer] = await generateP256Keypair();

  const suiteBytes = encoder.encode(SUITE_NAME);
  const saltInput = new Uint8Array(
    aadBytes.length + senderSessionPubDer.length + suiteBytes.length,
  );
  saltInput.set(aadBytes, 0);
  saltInput.set(senderSessionPubDer, aadBytes.length);
  saltInput.set(suiteBytes, aadBytes.length + senderSessionPubDer.length);
  const wrapSalt = (await sha256(saltInput)).subarray(0, 16);

  const recipientsRows: string[][] = [];
  for (const target of targets) {
    recipientsRows.push(
      await wrapForRecipient(target, masterKey, senderSessionPriv, sender.ikPriv, wrapSalt),
    );
  }

  const sortedRows = sortRecipients(recipientsRows);
  const digestHex = await computeRecipientsDigest(sortedRows);

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

  const certFpHash = bytesToHex(await sha256(sender.ikPubDer));
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
  const payloadType = payload?.type == null ? '' : String(payload.type);
  if (payloadType) {
    envelope.payload_type = payloadType;
  }

  // protected_headers / context：HMAC 签名（与 V1 对齐），不进 AAD
  // payload_type 自动注入 + value 转 string（与 Python _normalize_headers 对齐）
  const { context } = opts;
  const normalizedHeaders = normalizeProtectedHeaders(opts.protectedHeaders, payload);
  if (Object.keys(normalizedHeaders).length > 0) {
    envelope.protected_headers = await withMetadataAuth(normalizedHeaders, masterKey, PROTECTED_HEADERS_DOMAIN);
  }
  if (context && typeof context === 'object' && Object.keys(context).length > 0) {
    envelope.context = await withMetadataAuth(context, masterKey, PROTECTED_CONTEXT_DOMAIN);
  }

  return envelope;
}

async function wrapForRecipient(
  target: Target,
  masterKey: Uint8Array,
  senderSessionPriv: Uint8Array,
  senderMasterPriv: Uint8Array,
  wrapSalt: Uint8Array,
): Promise<string[]> {
  const role = target.role ?? 'member';
  const keySource = target.keySource ?? 'aid_master';

  const fpHash = bytesToHex(await sha256(target.ikPkDer));
  const fp = `sha256:${fpHash.substring(0, 16)}`;

  const wrapNonce = randomBytes(12);
  const use3DH = usesSPKWrap(target);
  const rowKeySource = use3DH ? keySource : 'aid_master';
  const rowSpkId = use3DH ? (target.spkId ?? '') : '';

  let wrapKey: Uint8Array;
  if (use3DH) {
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
    rowKeySource,
    fp,
    rowSpkId,
    bytesToBase64(wrapNonce),
    bytesToBase64(wrappedKey),
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
