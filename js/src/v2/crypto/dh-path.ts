/**
 * AUN E2EE V2: DH 派生路径
 *
 * 规范引用: §3.1 / §5.2
 * - 1DH: ECDH(sender_session_priv, recv_ik_pub) → HKDF
 * - 3DH: 三个 ECDH 拼接 → HKDF
 *
 * 浏览器实现：组合 ecdh.ts + hkdf.ts。
 */
import { ecdhComputeShared } from './ecdh';
import { hkdfSha256 } from './hkdf';

export const INFO_3DH = new TextEncoder().encode('AUN-V2-3DH');
export const INFO_1DH = new TextEncoder().encode('AUN-V2-1DH');
export const WRAP_KEY_LENGTH = 32;

/**
 * 计算 3DH wrap_key。
 *
 * - DH1 = ECDH(sender_session_priv, recv_ik_pub)
 * - DH2 = ECDH(sender_master_priv,  recv_spk_pub)
 * - DH3 = ECDH(sender_session_priv, recv_spk_pub)
 * - ikm = DH1 || DH2 || DH3 (96B)
 * - wrap_key = HKDF-SHA256(ikm, salt, "AUN-V2-3DH", 32)
 */
export async function compute3DHWrap(
  senderSessionPriv: Uint8Array,
  senderMasterPriv: Uint8Array,
  recvIKPub: Uint8Array,
  recvSPKPub: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const dh1 = await ecdhComputeShared(senderSessionPriv, recvIKPub);
  const dh2 = await ecdhComputeShared(senderMasterPriv, recvSPKPub);
  const dh3 = await ecdhComputeShared(senderSessionPriv, recvSPKPub);
  if (dh1.length !== 32 || dh2.length !== 32 || dh3.length !== 32) {
    throw new Error(
      `3DH expected 32B shares, got dh1=${dh1.length} dh2=${dh2.length} dh3=${dh3.length}`,
    );
  }
  const ikm = new Uint8Array(96);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);
  return hkdfSha256(ikm, salt, INFO_3DH, WRAP_KEY_LENGTH);
}

/**
 * 计算 1DH wrap_key。
 *
 * - DH1 = ECDH(sender_session_priv, recv_ik_pub)
 * - wrap_key = HKDF-SHA256(DH1, salt, "AUN-V2-1DH", 32)
 */
export async function compute1DHWrap(
  senderSessionPriv: Uint8Array,
  recvIKPub: Uint8Array,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const dh1 = await ecdhComputeShared(senderSessionPriv, recvIKPub);
  if (dh1.length !== 32) {
    throw new Error(`1DH expected 32B share, got ${dh1.length}`);
  }
  return hkdfSha256(dh1, salt, INFO_1DH, WRAP_KEY_LENGTH);
}
