/**
 * AUN E2EE V2: state_commitment 计算
 *
 * 规范引用：§6.2
 *
 * state_commitment = SHA256(
 *   "AUN-V2-SC-v1" ||
 *   group_aid ||
 *   uint32(epoch, big-endian) ||
 *   canonical_json({
 *     "members": [...sorted by aid, devices sorted by device_id...],
 *     "audit_aids": [...sorted...],
 *     "join_policy_hash": "64hex" | null,
 *     "admin_set": {"admin_aids": [...sorted...], "threshold": N},
 *     "recovery_quorum": {...} | null,
 *     "history_policy": "none" | "recent_N_days" | "full",
 *     "wrap_protocol": "3DH" | "1DH"
 *   })
 * )
 *
 * 排序在内部完成，调用方无需预排序。
 */

import { createHash } from 'node:crypto';
import { normalizeGroupId } from '../../group-id.js';
import { canonicalJson } from '../crypto/canonical.js';

export const STATE_PREFIX: Uint8Array = new TextEncoder().encode('AUN-V2-SC-v1');

export interface MemberDevice {
  device_id?: string;
  fp?: string;
  [k: string]: unknown;
}
export interface Member {
  aid?: string;
  devices?: MemberDevice[];
  [k: string]: unknown;
}
export interface AdminSet {
  admin_aids?: string[];
  threshold?: number;
  [k: string]: unknown;
}
export interface RecoveryQuorum {
  trigger?: string;
  quorum_aids?: string[];
  threshold?: number;
  [k: string]: unknown;
}
export interface StatePayload {
  members?: Member[];
  audit_aids?: string[];
  join_policy_hash?: string | null;
  admin_set?: AdminSet;
  recovery_quorum?: RecoveryQuorum | null;
  history_policy?: string;
  wrap_protocol?: string;
  [k: string]: unknown;
}

/** in-place 规范化排序。 */
function sortPayload(payload: StatePayload): void {
  if (Array.isArray(payload.members)) {
    payload.members.sort((a, b) => {
      const ka = a.aid ?? '';
      const kb = b.aid ?? '';
      if (ka === kb) return 0;
      return ka < kb ? -1 : 1;
    });
    for (const m of payload.members) {
      if (Array.isArray(m.devices)) {
        m.devices.sort((a, b) => {
          const ka = a.device_id ?? '';
          const kb = b.device_id ?? '';
          if (ka === kb) return 0;
          return ka < kb ? -1 : 1;
        });
      }
    }
  }
  if (Array.isArray(payload.audit_aids)) {
    payload.audit_aids.sort();
  }
  if (payload.admin_set && Array.isArray(payload.admin_set.admin_aids)) {
    payload.admin_set.admin_aids.sort();
  }
  if (payload.recovery_quorum && Array.isArray(payload.recovery_quorum.quorum_aids)) {
    payload.recovery_quorum.quorum_aids.sort();
  }
}

/** 大端 uint32 编码。 */
function uint32BE(value: number): Uint8Array {
  if (value < 0 || value > 0xffffffff || !Number.isInteger(value)) {
    throw new Error(`epoch out of uint32 range: ${value}`);
  }
  const out = new Uint8Array(4);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, value, false);
  return out;
}

/**
 * 计算 state_commitment（hex）。
 */
export function computeStateCommitment(
  groupId: string,
  epoch: number,
  statePayload: StatePayload,
): string {
  // 深拷贝避免修改调用方数据
  const payload: StatePayload = JSON.parse(JSON.stringify(statePayload));
  sortPayload(payload);

  const groupKey = normalizeGroupId(groupId) || String(groupId ?? '').trim();
  const groupBytes = new TextEncoder().encode(groupKey);
  const epochBytes = uint32BE(epoch);
  const payloadBytes = canonicalJson(payload);

  const h = createHash('sha256');
  h.update(STATE_PREFIX);
  h.update(groupBytes);
  h.update(epochBytes);
  h.update(payloadBytes);
  return h.digest('hex');
}
