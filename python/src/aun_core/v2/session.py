"""V2 E2EE Session Manager。

管理本设备的 IK/SPK 生命周期、服务端注册、加解密密钥获取。
"""
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, TYPE_CHECKING

from .crypto.ecdh import generate_p256_keypair
from .crypto.ecdsa import ecdsa_sign_raw, ecdsa_verify_raw
from .keystore import V2KeyStore

if TYPE_CHECKING:
    from ..keystore.sqlite_db import AIDDatabase


# 对端公钥缓存 TTL（秒）
_PEER_KEY_CACHE_TTL = 3600


class V2Session:
    """单个设备的 V2 E2EE 会话。

    职责：
    - 管理本设备 IK + SPK 密钥对
    - 注册到服务端
    - 提供加密所需的 sender identity
    - 提供解密所需的私钥
    - 缓存对端 IK 公钥
    """

    def __init__(self, db: "AIDDatabase", device_id: str, aid: str,
                 aid_priv_der: bytes | None = None, aid_pub_der: bytes | None = None):
        """
        Args:
            aid_priv_der: AID 长期私钥（DER 格式 PKCS8 raw scalar）
            aid_pub_der: AID 长期公钥（DER 格式 SubjectPublicKeyInfo）
        """
        self._store = V2KeyStore(db)
        self._device_id = device_id
        self._aid = aid
        self._aid_priv_der = aid_priv_der
        self._aid_pub_der = aid_pub_der
        self._ik_priv: bytes | None = aid_priv_der  # IK = AID 私钥（多设备共享 AID 身份）
        self._ik_pub_der: bytes | None = aid_pub_der  # IK 公钥 = AID 证书公钥
        self._spk_id: str | None = None
        self._spk_priv: bytes | None = None
        self._spk_pub_der: bytes | None = None
        self._registered = False
        # 对端 IK 公钥缓存：{(peer_aid, device_id): (ik_pub_der, cached_at)}
        self._peer_ik_cache: dict[str, tuple[bytes, float]] = {}
        # 已验证的 SPK 签名缓存：{(peer_aid, device_id, spk_id)}
        self._verified_spks: set[tuple[str, str, str]] = set()

    def _load_or_generate_ik(self) -> None:
        """IK = AID 长期密钥（多设备共享 AID 身份），不再独立生成。"""
        if self._aid_priv_der is None or self._aid_pub_der is None:
            raise RuntimeError("V2Session requires AID priv/pub keys (IK = AID identity)")
        self._ik_priv = self._aid_priv_der
        self._ik_pub_der = self._aid_pub_der

    def _load_or_generate_spk(self) -> None:
        result = self._store.load_current_spk(self._device_id)
        if result:
            self._spk_id, self._spk_priv, self._spk_pub_der = result
        else:
            spk_priv, spk_pub_der = generate_p256_keypair()
            spk_id = "sha256:" + hashlib.sha256(spk_pub_der).hexdigest()[:16]
            self._store.save_spk(self._device_id, spk_id, spk_priv, spk_pub_der)
            self._spk_id = spk_id
            self._spk_priv = spk_priv
            self._spk_pub_der = spk_pub_der

    def ensure_keys(self) -> None:
        """确保 IK 和 SPK 已加载或生成。"""
        if self._ik_priv is None:
            self._load_or_generate_ik()
        if self._spk_priv is None:
            self._load_or_generate_spk()

    async def ensure_registered(self, call_fn) -> None:
        """注册本设备 SPK 到服务端。IK = AID 长期密钥（无需注册，从 CA 拉取）。"""
        if self._registered:
            return
        self.ensure_keys()

        # SPK 由 AID 私钥（IK）签名背书
        spk_timestamp = int(time.time())
        sign_data = self._spk_pub_der + self._spk_id.encode() + str(spk_timestamp).encode()
        spk_signature = ecdsa_sign_raw(self._ik_priv, sign_data)

        await call_fn("message.v2.put_peer_pk", {
            "peer_aid": self._aid,
            "key_source": "peer_device_prekey",
            "spk_id": self._spk_id,
            "spk_pk": base64.b64encode(self._spk_pub_der).decode(),
            "spk_signature": base64.b64encode(spk_signature).decode(),
            "spk_timestamp": spk_timestamp,
        })
        self._registered = True

    def get_sender_identity(self) -> dict[str, Any]:
        """返回加密所需的 sender 结构。"""
        self.ensure_keys()
        return {
            "aid": self._aid,
            "device_id": self._device_id,
            "ik_priv": self._ik_priv,
            "ik_pub_der": self._ik_pub_der,
        }

    def get_decrypt_keys(self, spk_id: str | None) -> tuple[bytes, bytes | None]:
        """返回解密所需的私钥。

        Returns:
            (ik_priv, spk_priv | None)
        """
        self.ensure_keys()
        if not spk_id:
            return (self._ik_priv, None)
        if spk_id == self._spk_id:
            return (self._ik_priv, self._spk_priv)
        old_spk = self._store.load_spk(self._device_id, spk_id)
        return (self._ik_priv, old_spk)

    def is_current_spk(self, spk_id: str | None) -> bool:
        """判断 spk_id 是否命中当前活跃 SPK。"""
        return bool(spk_id) and spk_id == self._spk_id

    def track_old_spk_max_seq(self, spk_id: str, seq: int) -> None:
        """跟踪每个旧 SPK 引用的最大 seq（用于销毁判定）。"""
        if not spk_id or spk_id == self._spk_id:
            return
        if not hasattr(self, "_old_spk_max_seq"):
            self._old_spk_max_seq: dict[str, tuple[int, float]] = {}
        cur = self._old_spk_max_seq.get(spk_id)
        cur_seq = cur[0] if cur else 0
        if seq > cur_seq:
            self._old_spk_max_seq[spk_id] = (seq, time.time())

    def maybe_destroy_old_spks(self, contig_seq: int) -> list[str]:
        """contig_seq >= 旧 SPK 的最大 seq、超过 7h 安全窗口、且不在最近 7 代保留窗口内时销毁。

        销毁条件（全部满足才销毁）：
        - contig_seq >= 该 SPK 引用的最大 seq（接收方已消费完所有引用此 SPK 的消息）
        - 自最后一次见到该 spk_id 引用 >= 7 小时（给发送方刷新缓存的冗余窗口）
        - 不在最近 7 代 SPK 保留窗口内（对齐 V1 七 SPK 策略，给低频群额外兜底）

        7h + 7 代双兜底：低频群即便 contig_seq 已覆盖也至少留 7 代或 7h，避免发送方陈旧
        bootstrap 缓存导致新消息加密失败。

        返回销毁的 spk_id 列表。
        """
        destroyed = []
        if not hasattr(self, "_old_spk_max_seq"):
            return destroyed
        now = time.time()
        DESTROY_DELAY_SECONDS = 7 * 3600  # 7 小时缓冲
        RECENT_GENERATIONS = 7  # 最近 N 代保留窗口
        try:
            recent_keep = set(self._store.list_recent_spk_ids(self._device_id, RECENT_GENERATIONS))
        except Exception:
            recent_keep = set()
        for spk_id in list(self._old_spk_max_seq.keys()):
            max_seq, last_seen_at = self._old_spk_max_seq[spk_id]
            if spk_id == self._spk_id:
                continue
            if contig_seq < max_seq:
                continue
            if now - last_seen_at < DESTROY_DELAY_SECONDS:
                continue
            if spk_id in recent_keep:
                continue  # 在最近 7 代保留窗口内，跳过
            try:
                self._store.delete_spk(self._device_id, spk_id)
            except Exception:
                pass
            self._old_spk_max_seq.pop(spk_id, None)
            destroyed.append(spk_id)

        # 180 天硬上限：无论是否被引用，超龄 SPK 强制销毁
        HARD_LIMIT_SECONDS = 180 * 24 * 3600
        try:
            expired = self._store.list_expired_spk_ids(self._device_id, HARD_LIMIT_SECONDS)
            for spk_id in expired:
                if spk_id == self._spk_id:
                    continue
                try:
                    self._store.delete_spk(self._device_id, spk_id)
                except Exception:
                    pass
                self._old_spk_max_seq.pop(spk_id, None)
                if spk_id not in destroyed:
                    destroyed.append(spk_id)
        except Exception:
            pass

        return destroyed

    async def rotate_spk(self, call_fn) -> None:
        """轮换 SPK：生成新 SPK 并注册到服务端。旧 SPK 保留本地用于解密。"""
        spk_priv, spk_pub_der = generate_p256_keypair()
        spk_id = "sha256:" + hashlib.sha256(spk_pub_der).hexdigest()[:16]
        self._store.save_spk(self._device_id, spk_id, spk_priv, spk_pub_der)
        self._spk_id = spk_id
        self._spk_priv = spk_priv
        self._spk_pub_der = spk_pub_der

        spk_timestamp = int(time.time())
        sign_data = spk_pub_der + spk_id.encode() + str(spk_timestamp).encode()
        spk_signature = ecdsa_sign_raw(self._ik_priv, sign_data)

        await call_fn("message.v2.put_peer_pk", {
            "peer_aid": self._aid,
            "key_source": "peer_device_prekey",
            "spk_id": self._spk_id,
            "spk_pk": base64.b64encode(self._spk_pub_der).decode(),
            "spk_signature": base64.b64encode(spk_signature).decode(),
            "spk_timestamp": spk_timestamp,
        })

    def cache_peer_ik(self, peer_aid: str, device_id: str, ik_pub_der: bytes) -> None:
        """缓存对端 IK 公钥（带 TTL）。"""
        self._peer_ik_cache[f"{peer_aid}#{device_id}"] = (ik_pub_der, time.time())

    def get_peer_ik(self, peer_aid: str, device_id: str) -> bytes | None:
        """获取对端 IK 公钥，过期返回 None。"""
        entry = self._peer_ik_cache.get(f"{peer_aid}#{device_id}")
        if entry is None:
            return None
        ik_pub_der, cached_at = entry
        if (time.time() - cached_at) >= _PEER_KEY_CACHE_TTL:
            self._peer_ik_cache.pop(f"{peer_aid}#{device_id}", None)
            return None
        return ik_pub_der

    def is_peer_spk_verified(self, peer_aid: str, device_id: str, spk_id: str) -> bool:
        """检查对端 SPK 是否已验证过。"""
        return (peer_aid, device_id, spk_id) in self._verified_spks

    def mark_peer_spk_verified(self, peer_aid: str, device_id: str, spk_id: str) -> None:
        """标记对端 SPK 已验证。"""
        self._verified_spks.add((peer_aid, device_id, spk_id))

    @property
    def ik_pub_der(self) -> bytes:
        self.ensure_keys()
        return self._ik_pub_der

    @property
    def device_id(self) -> str:
        return self._device_id
