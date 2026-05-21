/**
 * AUN E2EE V2: 统一解密引擎（浏览器版，async）
 *
 * 支持 P2P 和 Group 消息解密（按 envelope.type 分流）。纯计算，无 IO。
 *
 * 规范引用: §4.6 / §5.5
 *
 * 参考实现: python/src/aun_core/v2/e2ee/decrypt.py
 */
import { canonicalJson } from '../crypto/canonical';
import { ecdsaVerifyRaw } from '../crypto/ecdsa';
import { ecdhComputeShared } from '../crypto/ecdh';
import { hkdfSha256 } from '../crypto/hkdf';
import { aesGcmDecrypt } from '../crypto/aead';
import {
  computeLeafHash,
  computeMerkleRoot,
  verifyMerkleProof,
  type ProofStep,
} from '../crypto/recipients';
import { SUITE_NAME } from './types';

const encoder = new TextEncoder();
const INFO_3DH = encoder.encode('AUN-V2-3DH');
const INFO_1DH = encoder.encode('AUN-V2-1DH');

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data.slice().buffer);
  return new Uint8Array(buf);
}

function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
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

interface RecipientShape {
  aid?: string;
  device_id?: string;
  role?: string;
  key_source?: string;
  fp?: string;
  spk_id?: string;
  wrap_nonce?: string;
  wrapped_key?: string;
}

interface EnvelopeShape {
  aad: Record<string, unknown>;
  suite?: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  sender_signature: string;
  sender_session_pk: string;
  recipients_digest: string;
  recipients?: string[][];
  recipient?: RecipientShape;
  merkle_proof?: ProofStep[];
}

/**
 * 解密 V2 加密消息（P2P 或 Group）。
 *
 * @param envelope         完整 envelope dict
 * @param selfAid          接收方 AID
 * @param selfDeviceId     接收方 device_id
 * @param selfIkPriv       接收方 IK 私钥（32B scalar）
 * @param selfSpkPriv      接收方 SPK 私钥（32B scalar）；undefined 表示无 SPK（1DH）
 * @param senderPubDer     发送方 AID 主公钥（DER），用于验签
 * @returns                解密后的 payload；null 表示找不到自己的 recipient 行
 */
export async function decryptMessage(
  envelope: Record<string, unknown>,
  selfAid: string,
  selfDeviceId: string,
  selfIkPriv: Uint8Array,
  selfSpkPriv: Uint8Array | undefined,
  senderPubDer: Uint8Array,
): Promise<Record<string, unknown> | null> {
  const env = envelope as unknown as EnvelopeShape;

  // 1. 验 sender_signature
  if (!(await verifySenderSignature(env, senderPubDer))) {
    throw new Error('sender_signature verification failed');
  }

  // 2. 找自己的 row（完整 recipients 数组 / 单个 recipient + merkle_proof）
  let row: string[] | null = null;
  if (Array.isArray(env.recipients)) {
    const rows = env.recipients;
    const expected = await computeMerkleRoot(rows);
    if (expected !== env.recipients_digest) {
      throw new Error('recipients_digest mismatch');
    }
    row = findMyRow(rows, selfAid, selfDeviceId);
    if (!row) return null;
  } else if (env.recipient && typeof env.recipient === 'object') {
    const r = env.recipient;
    row = [
      r.aid ?? '',
      r.device_id ?? '',
      r.role ?? '',
      r.key_source ?? '',
      r.fp ?? '',
      r.spk_id ?? '',
      r.wrap_nonce ?? '',
      r.wrapped_key ?? '',
    ];
    // 服务端拆分后存储：用 Merkle proof 验证 wrap 在签名集中
    const proof = env.merkle_proof;
    const expectedRoot = env.recipients_digest;
    if (proof != null && expectedRoot) {
      const leaf = await computeLeafHash(row);
      const ok = await verifyMerkleProof(leaf, proof, expectedRoot);
      if (!ok) {
        // 服务端篡改/替换 wrap，拒绝
        return null;
      }
    }
  } else {
    return null;
  }

  // 3. wrap_salt = SHA256(canonical_aad || sender_session_pk_der || suite)[:16]
  const senderSessionPkDer = base64ToBytes(env.sender_session_pk);
  const aadBytes = canonicalJson(env.aad);
  const suiteStr = env.suite ?? SUITE_NAME;
  const suiteBytes = encoder.encode(suiteStr);
  const saltInput = new Uint8Array(
    aadBytes.length + senderSessionPkDer.length + suiteBytes.length,
  );
  saltInput.set(aadBytes, 0);
  saltInput.set(senderSessionPkDer, aadBytes.length);
  saltInput.set(suiteBytes, aadBytes.length + senderSessionPkDer.length);
  const wrapSalt = (await sha256(saltInput)).subarray(0, 16);

  // 4. compute wrap_key
  const wrapKey = await computeWrapKey(
    row,
    selfIkPriv,
    selfSpkPriv,
    senderSessionPkDer,
    senderPubDer,
    wrapSalt,
  );

  // 5. decrypt master_key（wrapped_key = ciphertext(32B) + tag(16B) = 48B）
  const wrapNonce = base64ToBytes(row[6]);
  const wrappedKey = base64ToBytes(row[7]);
  if (wrappedKey.length < 16) {
    throw new Error(`wrapped_key too short: ${wrappedKey.length}`);
  }
  const wrappedCt = wrappedKey.subarray(0, wrappedKey.length - 16);
  const wrappedTag = wrappedKey.subarray(wrappedKey.length - 16);
  const masterKey = await aesGcmDecrypt(
    wrapKey,
    wrapNonce,
    wrappedCt,
    wrappedTag,
    new Uint8Array(0),
  );

  // 6. decrypt body
  const msgNonce = base64ToBytes(env.nonce);
  const ct = base64ToBytes(env.ciphertext);
  const tag = base64ToBytes(env.tag);
  const plaintext = await aesGcmDecrypt(masterKey, msgNonce, ct, tag, aadBytes);

  // 7. 解析 payload
  return JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
}

async function verifySenderSignature(
  env: EnvelopeShape,
  senderPubDer: Uint8Array,
): Promise<boolean> {
  const sig = base64ToBytes(env.sender_signature);
  const ct = base64ToBytes(env.ciphertext);
  const tag = base64ToBytes(env.tag);
  const aadBytes = canonicalJson(env.aad);
  const digestBytes = hexToBytes(env.recipients_digest);

  const signInput = new Uint8Array(
    ct.length + tag.length + aadBytes.length + digestBytes.length,
  );
  let pos = 0;
  signInput.set(ct, pos);
  pos += ct.length;
  signInput.set(tag, pos);
  pos += tag.length;
  signInput.set(aadBytes, pos);
  pos += aadBytes.length;
  signInput.set(digestBytes, pos);

  return ecdsaVerifyRaw(senderPubDer, sig, signInput);
}

function findMyRow(
  recipients: string[][],
  selfAid: string,
  selfDeviceId: string,
): string[] | null {
  for (const row of recipients) {
    if (row[0] === selfAid && row[1] === selfDeviceId) return row;
  }
  return null;
}

async function computeWrapKey(
  row: string[],
  selfIkPriv: Uint8Array,
  selfSpkPriv: Uint8Array | undefined,
  senderSessionPkDer: Uint8Array,
  senderMasterPkDer: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const spkId = row[5];
  if (spkId && selfSpkPriv) {
    // 3DH 接收方路径
    // dh1 = ECDH(self_ik_priv, sender_session_pk)
    // dh2 = ECDH(self_spk_priv, sender_master_pk)
    // dh3 = ECDH(self_spk_priv, sender_session_pk)
    const dh1 = await ecdhComputeShared(selfIkPriv, senderSessionPkDer);
    const dh2 = await ecdhComputeShared(selfSpkPriv, senderMasterPkDer);
    const dh3 = await ecdhComputeShared(selfSpkPriv, senderSessionPkDer);
    if (dh1.length !== 32 || dh2.length !== 32 || dh3.length !== 32) {
      throw new Error(
        `3DH expected 32B shares, got dh1=${dh1.length} dh2=${dh2.length} dh3=${dh3.length}`,
      );
    }
    const ikm = new Uint8Array(96);
    ikm.set(dh1, 0);
    ikm.set(dh2, 32);
    ikm.set(dh3, 64);
    return hkdfSha256(ikm, salt, INFO_3DH, 32);
  }
  // 1DH 接收方路径
  const dh1 = await ecdhComputeShared(selfIkPriv, senderSessionPkDer);
  return hkdfSha256(dh1, salt, INFO_1DH, 32);
}
