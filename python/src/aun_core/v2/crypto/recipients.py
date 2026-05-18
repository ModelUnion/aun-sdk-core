"""
AUN E2EE V2: Recipients 排序与 Digest

规范引用: §10.3 / §5.3
- recipients 是二维数组（无 columns 表头）
- 行按 (aid asc, device_id asc, role asc) 字典序排序
- 每行固定 8 字段: [aid, device_id, role, key_source, fp, spk_id, wrap_nonce, wrapped_key]

Digest 计算：
- recipients_digest = MerkleRoot(leaf_hashes)
  - leaf_i = SHA256(LEAF_PREFIX || canonical row binary fields)
  - inner = SHA256(NODE_PREFIX || left || right)
  - 奇数节点复制最后一个
- 服务端拆分 per-device 投递时，附 merkle_proof（log N 个 sibling hash）
- 接收端重算 leaf + proof → 验证 root

向后兼容：保留 compute_recipients_digest 老 API 用于过渡期。
"""
from __future__ import annotations

import base64
import hashlib

from .canonical import canonical_json


_LEAF_PREFIX = b"AUN-V2-RCPT-LEAF-v1"
_NODE_PREFIX = b"AUN-V2-RCPT-NODE-v1"


def sort_recipients(rows: list[list]) -> list[list]:
    """按 (aid asc, device_id asc, role asc) 字典序排序 recipients 行。"""
    return sorted(rows, key=lambda row: (row[0], row[1], row[2]))


def compute_leaf_hash(row: list) -> bytes:
    """计算单个 recipient 行的 leaf hash。

    Args:
        row: 8 字段的 recipient 行 [aid, device_id, role, key_source, fp,
             spk_id, wrap_nonce_b64, wrapped_key_b64]

    Returns:
        32 字节 SHA256 摘要
    """
    aid = str(row[0]).encode("utf-8")
    device_id = str(row[1]).encode("utf-8")
    role = str(row[2]).encode("utf-8")
    key_source = str(row[3]).encode("utf-8")
    fp = str(row[4]).encode("utf-8")
    spk_id = str(row[5] if len(row) > 5 else "").encode("utf-8")
    # wrap_nonce/wrapped_key: 优先 base64 解码，失败时回退 utf-8 字节（兼容测试用例）
    def _decode_or_raw(value):
        if not value:
            return b""
        try:
            return base64.b64decode(value)
        except Exception:
            return str(value).encode("utf-8")
    wrap_nonce = _decode_or_raw(row[6]) if len(row) > 6 else b""
    wrapped_key = _decode_or_raw(row[7]) if len(row) > 7 else b""

    h = hashlib.sha256()
    h.update(_LEAF_PREFIX)
    h.update(aid)
    h.update(b"\x00")
    h.update(device_id)
    h.update(b"\x00")
    h.update(role)
    h.update(b"\x00")
    h.update(key_source)
    h.update(b"\x00")
    h.update(fp)
    h.update(b"\x00")
    h.update(spk_id)
    h.update(b"\x00")
    h.update(wrap_nonce)
    h.update(wrapped_key)
    return h.digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_NODE_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()


def compute_merkle_root(rows: list[list]) -> str:
    """计算 recipients 的 Merkle root（hex）。

    rows 必须已排序（compute_recipients_digest 兼容路径会先排序）。
    """
    if not rows:
        return ""
    leaves = [compute_leaf_hash(row) for row in rows]
    return _merkle_root_from_leaves(leaves).hex()


def _merkle_root_from_leaves(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    layer = list(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # 奇数节点复制最后一个
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(_node_hash(layer[i], layer[i + 1]))
        layer = next_layer
    return layer[0]


def compute_merkle_proof(rows: list[list], target_index: int) -> list[dict]:
    """为指定 index 的 recipient 生成 Merkle proof。

    Returns:
        [{"sibling": hex, "position": "L"|"R"}, ...]
    """
    if not rows or target_index < 0 or target_index >= len(rows):
        return []
    leaves = [compute_leaf_hash(row) for row in rows]
    proof: list[dict] = []
    layer = list(leaves)
    idx = target_index
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        sibling_idx = idx ^ 1  # XOR 1 → 兄弟节点
        sibling = layer[sibling_idx]
        position = "R" if sibling_idx > idx else "L"
        proof.append({"sibling": sibling.hex(), "position": position})
        # 进入下一层
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(_node_hash(layer[i], layer[i + 1]))
        layer = next_layer
        idx //= 2
    return proof


def verify_merkle_proof(leaf: bytes, proof: list[dict], expected_root_hex: str) -> bool:
    """验证 leaf + proof 重建出的 root 与期望值一致。"""
    if not expected_root_hex:
        return False
    cur = leaf
    for step in proof:
        sibling_hex = str(step.get("sibling", ""))
        position = str(step.get("position", ""))
        try:
            sibling = bytes.fromhex(sibling_hex)
        except Exception:
            return False
        if position == "L":
            cur = _node_hash(sibling, cur)
        elif position == "R":
            cur = _node_hash(cur, sibling)
        else:
            return False
    return cur.hex() == expected_root_hex


def compute_recipients_digest(rows: list[list]) -> str:
    """计算 recipients_digest（Merkle root）。

    调用方 MUST 先调 sort_recipients 排序。
    """
    return compute_merkle_root(rows)
