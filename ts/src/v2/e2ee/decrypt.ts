/**
 * AUN E2EE V2: 统一解密引擎
 *
 * 支持 P2P 和 Group 消息解密（按 envelope.type / 字段结构分流）。
 * 纯计算，无 IO。
 *
 * 与 Python `aun_core.v2.e2ee.decrypt.decrypt_message` 对齐。
 *
 * 流程：
 *  1. 验 sender_signature
 *  2. 找自己的 row（recipients 数组或 per-device recipient + 可选 merkle_proof）
 *  3. 计算 wrap_salt
 *  4. 派生 wrap_key（3DH 或 1DH）
 *  5. 解 master_key
 *  6. 解 body
 *  7. 解析 JSON payload
 */

import { createHash } from 'node:crypto';
import { canonicalJson } from '../crypto/canonical.js';
import { ecdsaVerifyRaw } from '../crypto/ecdsa.js';
import { ecdhComputeShared } from '../crypto/ecdh.js';
import { hkdfSha256 } from '../crypto/hkdf.js';
import { aesGcmDecrypt } from '../crypto/aead.js';
import {
  computeLeafHash,
  computeRecipientsDigest,
  verifyMerkleProof,
  ProofStep,
} from '../crypto/recipients.js';
import { SUITE_NAME } from './types.js';
import {
  verifyMetadataAuth,
  PROTECTED_HEADERS_DOMAIN,
  PROTECTED_CONTEXT_DOMAIN,
} from './metadata-auth.js';

const TEXT = new TextEncoder();
const INFO_3DH = TEXT.encode('AUN-V2-3DH');
const INFO_1DH = TEXT.encode('AUN-V2-1DH');

/**
 * 解密 V2 加密消息（P2P 或 Group）。
 *
 * @param envelope 完整 envelope（已 JSON.parse 的对象）
 * @param selfAid 接收方 AID
 * @param selfDeviceId 接收方 device_id
 * @param selfIkPriv 接收方 IK 私钥（32B scalar）
 * @param selfSpkPriv 接收方 SPK 私钥（32B scalar）；undefined/null 表示无 SPK（1DH）
 * @param senderPubDer 发送方 AID 主公钥（DER），用于验签 + 3DH 接收侧 DH2
 * @returns 解密后的 payload；null 表示在 recipients 中找不到自己的 row
 */
export function decryptMessage(
  envelope: Record<string, unknown>,
  selfAid: string,
  selfDeviceId: string,
  selfIkPriv: Uint8Array,
  selfSpkPriv: Uint8Array | undefined,
  senderPubDer: Uint8Array,
): Record<string, unknown> | null {
  // 1. 验签
  if (!verifySenderSignature(envelope, senderPubDer)) {
    throw new Error('sender_signature verification failed');
  }

  // 2. 找自己的 row
  let row: string[] | null = null;
  if (Array.isArray(envelope.recipients)) {
    const rows = envelope.recipients as string[][];
    const expectedDigest = String(envelope.recipients_digest ?? '');
    if (computeRecipientsDigest(rows) !== expectedDigest) {
      throw new Error('recipients_digest mismatch');
    }
    row = findMyRow(rows, selfAid, selfDeviceId);
    if (!row) return null;
  } else if (envelope.recipient && typeof envelope.recipient === 'object') {
    const r = envelope.recipient as Record<string, unknown>;
    row = [
      String(r.aid ?? ''),
      String(r.device_id ?? ''),
      String(r.role ?? ''),
      String(r.key_source ?? ''),
      String(r.fp ?? ''),
      String(r.spk_id ?? ''),
      String(r.wrap_nonce ?? ''),
      String(r.wrapped_key ?? ''),
    ];
    // per-device 形态可能携带 merkle_proof
    const proof = envelope.merkle_proof as ProofStep[] | undefined;
    const expectedRoot = String(envelope.recipients_digest ?? '');
    if (proof && expectedRoot) {
      const leaf = computeLeafHash(row);
      if (!verifyMerkleProof(leaf, proof, expectedRoot)) {
        // 服务端篡改/替换 wrap，拒绝
        return null;
      }
    }
  } else {
    return null;
  }

  // 3. wrap_salt
  const senderSessionPkDer = new Uint8Array(
    Buffer.from(String(envelope.sender_session_pk ?? ''), 'base64'),
  );
  const aad = envelope.aad as Record<string, unknown>;
  const aadBytes = canonicalJson(aad);
  const suiteStr = String(envelope.suite ?? SUITE_NAME);
  const wrapSalt = computeWrapSalt(aadBytes, senderSessionPkDer, suiteStr);

  // 4. wrap_key
  const wrapKey = computeWrapKey(
    row,
    selfIkPriv,
    selfSpkPriv,
    senderSessionPkDer,
    senderPubDer,
    wrapSalt,
  );

  // 5. decrypt master_key
  const wrapNonce = new Uint8Array(Buffer.from(row[6], 'base64'));
  const wrappedKey = new Uint8Array(Buffer.from(row[7], 'base64'));
  if (wrappedKey.length < 16) {
    throw new Error('wrapped_key too short');
  }
  const wrappedCt = wrappedKey.subarray(0, wrappedKey.length - 16);
  const wrappedTag = wrappedKey.subarray(wrappedKey.length - 16);
  let masterKey: Uint8Array;
  try {
    masterKey = aesGcmDecrypt(wrapKey, wrapNonce, wrappedCt, wrappedTag, new Uint8Array(0));
  } catch (exc) {
    throw new Error(
      `wrap_key_decrypt_failed: ${rowContext(row)}; ` +
      'master_key unwrap AEAD authentication failed; ' +
      'likely wrong local SPK/IK, stale sender bootstrap, or tampered recipient wrap; ' +
      `cause=${formatCaught(exc)}`,
    );
  }
  verifyMetadataAuth(envelope.protected_headers, masterKey, PROTECTED_HEADERS_DOMAIN, 'protected_headers');
  verifyMetadataAuth(envelope.context, masterKey, PROTECTED_CONTEXT_DOMAIN, 'context');

  // 6. decrypt body
  const msgNonce = new Uint8Array(Buffer.from(String(envelope.nonce ?? ''), 'base64'));
  const ct = new Uint8Array(Buffer.from(String(envelope.ciphertext ?? ''), 'base64'));
  const tag = new Uint8Array(Buffer.from(String(envelope.tag ?? ''), 'base64'));
  let plaintext: Uint8Array;
  try {
    plaintext = aesGcmDecrypt(masterKey, msgNonce, ct, tag, aadBytes);
  } catch (exc) {
    throw new Error(
      `body_decrypt_failed: ${envelopeContext(envelope, row)}; ` +
      'message body AEAD authentication failed after master_key unwrap; ' +
      'likely AAD/ciphertext/tag mismatch or envelope body corruption; ' +
      `cause=${formatCaught(exc)}`,
    );
  }

  // 7. parse JSON
  return JSON.parse(Buffer.from(plaintext).toString('utf-8')) as Record<string, unknown>;
}

function computeWrapSalt(
  aadBytes: Uint8Array,
  senderSessionPkDer: Uint8Array,
  suiteStr: string,
): Uint8Array {
  const suiteBytes = TEXT.encode(suiteStr);
  const h = createHash('sha256');
  h.update(Buffer.from(aadBytes));
  h.update(Buffer.from(senderSessionPkDer));
  h.update(Buffer.from(suiteBytes));
  return new Uint8Array(h.digest()).subarray(0, 16);
}

function computeWrapKey(
  row: string[],
  selfIkPriv: Uint8Array,
  selfSpkPriv: Uint8Array | undefined,
  senderSessionPkDer: Uint8Array,
  senderMasterPkDer: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const spkId = row[5];
  if (spkId && !selfSpkPriv) {
    throw new Error(`spk_missing: spk_id=${spkId}`);
  }
  if (spkId && selfSpkPriv) {
    // 3DH 接收方：DH1=ECDH(self_ik, sender_session)；DH2=ECDH(self_spk, sender_master)；DH3=ECDH(self_spk, sender_session)
    const dh1 = ecdhComputeShared(selfIkPriv, senderSessionPkDer);
    const dh2 = ecdhComputeShared(selfSpkPriv, senderMasterPkDer);
    const dh3 = ecdhComputeShared(selfSpkPriv, senderSessionPkDer);
    const ikm = new Uint8Array(96);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    return hkdfSha256(ikm, salt, INFO_3DH, 32);
  }
  // 1DH 接收方
  const dh1 = ecdhComputeShared(selfIkPriv, senderSessionPkDer);
  return hkdfSha256(dh1, salt, INFO_1DH, 32);
}

function findMyRow(rows: string[][], aid: string, deviceId: string): string[] | null {
  for (const r of rows) {
    if (r[0] === aid && (r[1] === deviceId || r[1] === '')) return r;
  }
  return null;
}

function formatCaught(exc: unknown): string {
  if (exc instanceof Error) {
    return exc.message ? `${exc.name}: ${exc.message}` : exc.name;
  }
  return String(exc);
}

function rowContext(row: string[]): string {
  return [
    `recipient=${String(row[0] ?? '')}/${String(row[1] ?? '')}`,
    `role=${String(row[2] ?? '')}`,
    `key_source=${String(row[3] ?? '')}`,
    `spk_id=${String(row[5] ?? '') || '<empty>'}`,
  ].join('; ');
}

function envelopeContext(envelope: Record<string, unknown>, row: string[]): string {
  const aad = envelope.aad && typeof envelope.aad === 'object' && !Array.isArray(envelope.aad)
    ? envelope.aad as Record<string, unknown>
    : {};
  const messageId = String(aad.message_id ?? envelope.message_id ?? '');
  const groupId = String(aad.group_id ?? envelope.group_id ?? '') || '<p2p>';
  const from = String(aad.from ?? '');
  const fromDevice = String(aad.from_device ?? '');
  return [
    `message_id=${messageId}`,
    `group_id=${groupId}`,
    `from=${from}`,
    `from_device=${fromDevice}`,
    rowContext(row),
  ].join('; ');
}

function verifySenderSignature(
  envelope: Record<string, unknown>,
  senderPubDer: Uint8Array,
): boolean {
  const sigStr = envelope.sender_signature;
  const ctStr = envelope.ciphertext;
  const tagStr = envelope.tag;
  const digestHex = envelope.recipients_digest;
  if (
    typeof sigStr !== 'string' ||
    typeof ctStr !== 'string' ||
    typeof tagStr !== 'string' ||
    typeof digestHex !== 'string'
  ) {
    return false;
  }
  const sig = new Uint8Array(Buffer.from(sigStr, 'base64'));
  const ct = Buffer.from(ctStr, 'base64');
  const tag = Buffer.from(tagStr, 'base64');
  const aadBytes = canonicalJson(envelope.aad);
  const digestBytes = Buffer.from(digestHex, 'hex');
  const signInput = new Uint8Array(
    Buffer.concat([ct, tag, Buffer.from(aadBytes), digestBytes]),
  );
  return ecdsaVerifyRaw(senderPubDer, sig, signInput);
}
