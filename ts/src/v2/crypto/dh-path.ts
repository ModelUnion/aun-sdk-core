/**
 * AUN E2EE V2: 1DH / 3DH wrap_key 派生
 *
 * 规范引用：§4.x
 *
 * 3DH（活跃会话）:
 *   DH1 = ECDH(senderSessionPriv, recvIKPub)
 *   DH2 = ECDH(senderMasterPriv,  recvSPKPub)
 *   DH3 = ECDH(senderSessionPriv, recvSPKPub)
 *   ikm = DH1 || DH2 || DH3
 *   wrap_key = HKDF-SHA256(ikm, salt, info="AUN-V2-3DH", 32)
 *
 * 1DH（无 SPK 的回退路径）:
 *   DH  = ECDH(senderSessionPriv, recvIKPub)
 *   wrap_key = HKDF-SHA256(DH, salt, info="AUN-V2-1DH", 32)
 */

import { ecdhComputeShared } from './ecdh.js';
import { hkdfSha256 } from './hkdf.js';

const TEXT = new TextEncoder();
export const INFO_3DH: Uint8Array = TEXT.encode('AUN-V2-3DH');
export const INFO_1DH: Uint8Array = TEXT.encode('AUN-V2-1DH');
export const WRAP_KEY_LENGTH = 32;

/**
 * 计算 3DH wrap_key。
 *
 * @param senderSessionPriv 发送方会话私钥（32B 标量）
 * @param senderMasterPriv  发送方 AID 长期主私钥（32B 标量）
 * @param recvIKPub         接收方身份公钥 IK（DER SPKI）
 * @param recvSPKPub        接收方 Signed PreKey 公钥 SPK（DER SPKI）
 * @param salt              HKDF salt
 * @returns 32 字节 wrap_key
 */
export function compute3DHWrap(
  senderSessionPriv: Uint8Array,
  senderMasterPriv: Uint8Array,
  recvIKPub: Uint8Array,
  recvSPKPub: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const dh1 = ecdhComputeShared(senderSessionPriv, recvIKPub);
  const dh2 = ecdhComputeShared(senderMasterPriv, recvSPKPub);
  const dh3 = ecdhComputeShared(senderSessionPriv, recvSPKPub);
  const ikm = new Uint8Array(96);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);
  return hkdfSha256(ikm, salt, INFO_3DH, WRAP_KEY_LENGTH);
}

/**
 * 计算 1DH wrap_key（fallback）。
 *
 * @param senderSessionPriv 发送方会话私钥（32B 标量）
 * @param recvIKPub         接收方身份公钥 IK（DER SPKI）
 * @param salt              HKDF salt
 * @returns 32 字节 wrap_key
 */
export function compute1DHWrap(
  senderSessionPriv: Uint8Array,
  recvIKPub: Uint8Array,
  salt: Uint8Array,
): Uint8Array {
  const dh = ecdhComputeShared(senderSessionPriv, recvIKPub);
  return hkdfSha256(dh, salt, INFO_1DH, WRAP_KEY_LENGTH);
}
