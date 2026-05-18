"""
AUN E2EE V2: State Commitment 计算

规范引用: §6.2
state_commitment = SHA256(
  "AUN-V2-SC-v1" ||
  group_id ||
  uint32(epoch) ||
  canonical_json({
    "members": [...sorted by aid, devices sorted by device_id...],
    "audit_aids": [...sorted...],
    "join_policy_hash": "64hex" | null,
    "admin_set": {"admin_aids": [...sorted...], "threshold": N},
    "recovery_quorum": {...} | null,
    "history_policy": "none" | "recent_N_days" | "full",
    "wrap_protocol": "3DH" | "1DH"
  })
)
"""
from __future__ import annotations

import hashlib
import struct
import copy

from ..crypto.canonical import canonical_json


PREFIX = b"AUN-V2-SC-v1"


def compute_state_commitment(group_id: str, epoch: int, state_payload: dict) -> str:
    """计算 state_commitment。

    内部会对 state_payload 做排序（members by aid, devices by device_id,
    audit_aids sorted, admin_aids sorted），调用方不需要预排序。

    Args:
        group_id: 群 ID
        epoch: 当前 epoch（uint32）
        state_payload: 状态负载字典，含 members / audit_aids / join_policy_hash /
                       admin_set / recovery_quorum / history_policy / wrap_protocol

    Returns:
        64 hex 字符的 SHA-256 摘要
    """
    # 深拷贝避免修改调用方数据
    payload = copy.deepcopy(state_payload)

    # 内部排序
    _sort_payload(payload)

    # 拼接
    group_bytes = group_id.encode("utf-8")
    epoch_bytes = struct.pack(">I", epoch)  # uint32 big-endian
    payload_bytes = canonical_json(payload)

    data = PREFIX + group_bytes + epoch_bytes + payload_bytes
    return hashlib.sha256(data).hexdigest()


def _sort_payload(payload: dict):
    """对 state_payload 内部字段做规范化排序（in-place）。"""
    # members 按 aid 排序
    if "members" in payload and isinstance(payload["members"], list):
        payload["members"].sort(key=lambda m: m.get("aid", ""))
        # 每个 member 的 devices 按 device_id 排序
        for member in payload["members"]:
            if "devices" in member and isinstance(member["devices"], list):
                member["devices"].sort(key=lambda d: d.get("device_id", ""))

    # audit_aids 排序
    if "audit_aids" in payload and isinstance(payload["audit_aids"], list):
        payload["audit_aids"].sort()

    # admin_set.admin_aids 排序
    if "admin_set" in payload and isinstance(payload["admin_set"], dict):
        admin_set = payload["admin_set"]
        if "admin_aids" in admin_set and isinstance(admin_set["admin_aids"], list):
            admin_set["admin_aids"].sort()

    # recovery_quorum.quorum_aids 排序
    if "recovery_quorum" in payload and isinstance(payload["recovery_quorum"], dict):
        quorum = payload["recovery_quorum"]
        if "quorum_aids" in quorum and isinstance(quorum["quorum_aids"], list):
            quorum["quorum_aids"].sort()
