/**
 * AUN E2EE V2: State Commitment 计算
 *
 * 规范引用: §6.2
 *
 * state_commitment = SHA256(
 *   "AUN-V2-SC-v1" || group_id || uint32(epoch) || canonical_json(sorted_payload)
 * )
 *
 * sorted_payload 规则：
 *  - members 按 aid 排序，每个 member 的 devices 按 device_id 排序
 *  - audit_aids 排序
 *  - admin_set.admin_aids 排序
 *  - recovery_quorum.quorum_aids 排序
 *
 * 浏览器实现：使用 WebCrypto subtle.digest('SHA-256')，async。
 */
import { canonicalJson } from '../crypto/canonical';

export const STATE_PREFIX = new TextEncoder().encode('AUN-V2-SC-v1');

interface DeviceLike {
  device_id?: string;
}

interface MemberLike {
  aid?: string;
  devices?: DeviceLike[];
}

interface StatePayload {
  members?: MemberLike[];
  audit_aids?: string[];
  admin_set?: { admin_aids?: string[]; threshold?: number };
  recovery_quorum?: { quorum_aids?: string[]; [k: string]: unknown };
  [k: string]: unknown;
}

/** 深拷贝（state_payload 仅含 JSON 兼容值） */
function deepClone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x));
}

function sortPayload(payload: StatePayload): void {
  if (Array.isArray(payload.members)) {
    payload.members.sort((a, b) => {
      const ka = a.aid ?? '';
      const kb = b.aid ?? '';
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    for (const m of payload.members) {
      if (Array.isArray(m.devices)) {
        m.devices.sort((a, b) => {
          const ka = a.device_id ?? '';
          const kb = b.device_id ?? '';
          return ka < kb ? -1 : ka > kb ? 1 : 0;
        });
      }
    }
  }
  if (Array.isArray(payload.audit_aids)) payload.audit_aids.sort();
  if (
    payload.admin_set
    && typeof payload.admin_set === 'object'
    && Array.isArray(payload.admin_set.admin_aids)
  ) {
    payload.admin_set.admin_aids.sort();
  }
  if (
    payload.recovery_quorum
    && typeof payload.recovery_quorum === 'object'
    && Array.isArray(payload.recovery_quorum.quorum_aids)
  ) {
    payload.recovery_quorum.quorum_aids.sort();
  }
}

/**
 * 计算 state_commitment（64 hex）。
 *
 * @param groupId      群 ID
 * @param epoch        当前 epoch（uint32 big-endian 编入）
 * @param statePayload 状态负载（members / audit_aids / admin_set / ...）
 */
export async function computeStateCommitment(
  groupId: string,
  epoch: number,
  statePayload: unknown,
): Promise<string> {
  const sorted = deepClone(statePayload as StatePayload);
  sortPayload(sorted);

  const groupBytes = new TextEncoder().encode(groupId);
  const epochBytes = new Uint8Array(4);
  // big-endian uint32
  new DataView(epochBytes.buffer).setUint32(0, epoch >>> 0, false);

  const payloadBytes = canonicalJson(sorted);

  const total = STATE_PREFIX.length + groupBytes.length + 4 + payloadBytes.length;
  const data = new Uint8Array(total);
  let pos = 0;
  data.set(STATE_PREFIX, pos);
  pos += STATE_PREFIX.length;
  data.set(groupBytes, pos);
  pos += groupBytes.length;
  data.set(epochBytes, pos);
  pos += 4;
  data.set(payloadBytes, pos);

  const hashBuf = await crypto.subtle.digest('SHA-256', data.slice().buffer);
  const hash = new Uint8Array(hashBuf);
  let hex = '';
  for (let i = 0; i < hash.length; i++) hex += hash[i].toString(16).padStart(2, '0');
  return hex;
}
