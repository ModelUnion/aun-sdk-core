"""
AUN E2EE V2: SPK 生命周期管理

规范引用: §2.3.3
- 事件驱动轮换（群成员变更 / P2P 被消费 / 同 AID 设备变更 / 手动 / 可选时间触发）
- 事实销毁（service 通知 spk_drainable 时销毁）
- 180 天硬上限兜底
- 节流：同一 (scope, device) 内 1 小时最小间隔

纯逻辑层，无 IO。keystore 操作通过抽象接口注入。
"""
from __future__ import annotations

import time
from typing import Any, Callable

from ..crypto.ecdh import generate_p256_keypair
from ..crypto.ecdsa import ecdsa_sign_raw


# 常量
ROTATION_THROTTLE_SECONDS = 3600  # 1 小时最小轮换间隔
HARD_DESTROY_AFTER_SECONDS = 180 * 24 * 3600  # 180 天硬上限


class SpkEntry:
    """单个 SPK 条目"""
    def __init__(self, spk_id: str, spk_priv: bytes, spk_pub_der: bytes, created_at: float, status: str = "active"):
        self.spk_id = spk_id
        self.spk_priv = spk_priv
        self.spk_pub_der = spk_pub_der
        self.created_at = created_at
        self.status = status  # "active" / "pending_drain" / "destroyed"


class SpkLifecycleManager:
    """SPK 生命周期管理器。

    职责：
    1. 事件触发轮换（节流）
    2. 生成新 SPK + IK 签名背书
    3. 标记旧 SPK 为 pending_drain
    4. 收到 spk_drainable 通知后销毁
    5. 180 天硬上限兜底销毁
    """

    def __init__(
        self,
        *,
        scope: str,
        device_id: str,
        ik_priv: bytes,
        on_spk_publish: Callable[[str, str, bytes, bytes], Any] | None = None,
    ):
        """
        Args:
            scope: 作用域标识（如 "peer:bob.aid" 或 "group:g-xxx"）
            device_id: 本设备 ID
            ik_priv: AID 主私钥（用于签名 SPK）
            on_spk_publish: 回调，新 SPK 生成后调用（scope, spk_id, spk_pub_der, signature）
        """
        self._scope = scope
        self._device_id = device_id
        self._ik_priv = ik_priv
        self._on_spk_publish = on_spk_publish

        # SPK 库：spk_id → SpkEntry
        self._spk_store: dict[str, SpkEntry] = {}
        self._current_spk_id: str | None = None
        self._last_rotation_time: float = 0

    @property
    def current_spk_id(self) -> str | None:
        return self._current_spk_id

    @property
    def current_spk(self) -> SpkEntry | None:
        if self._current_spk_id is None:
            return None
        return self._spk_store.get(self._current_spk_id)

    def get_spk_priv(self, spk_id: str) -> bytes | None:
        """获取指定 spk_id 的私钥（解密时用）。"""
        entry = self._spk_store.get(spk_id)
        if entry is None or entry.status == "destroyed":
            return None
        return entry.spk_priv

    def generate_initial_spk(self) -> SpkEntry:
        """生成初始 SPK（首次入组 / 首次 P2P 时调用）。"""
        return self._do_rotation(force=True)

    def try_rotate(self, trigger: str = "event") -> SpkEntry | None:
        """尝试轮换 SPK（受节流控制）。

        Args:
            trigger: 触发原因（"members_changed" / "p2p_consumed" / "device_changed" / "manual" / "periodic"）

        Returns:
            新 SpkEntry 如果轮换成功；None 如果被节流
        """
        now = time.time()
        if now - self._last_rotation_time < ROTATION_THROTTLE_SECONDS:
            return None  # 节流
        return self._do_rotation()

    def on_spk_drainable(self, spk_id: str):
        """收到 service 的 spk_drainable 通知 → 销毁该 SPK 私钥。"""
        entry = self._spk_store.get(spk_id)
        if entry is None:
            return
        if entry.status == "destroyed":
            return
        entry.status = "destroyed"
        entry.spk_priv = b""  # 清零

    def check_hard_limit(self):
        """检查 180 天硬上限，强制销毁过期 SPK。"""
        now = time.time()
        for spk_id, entry in list(self._spk_store.items()):
            if entry.status == "destroyed":
                continue
            if now - entry.created_at > HARD_DESTROY_AFTER_SECONDS:
                entry.status = "destroyed"
                entry.spk_priv = b""

    def list_pending_drain(self) -> list[str]:
        """列出所有 pending_drain 状态的 spk_id。"""
        return [
            spk_id for spk_id, entry in self._spk_store.items()
            if entry.status == "pending_drain"
        ]

    def _do_rotation(self, force: bool = False) -> SpkEntry:
        """执行轮换。"""
        import hashlib

        # 生成新 SPK
        spk_priv, spk_pub_der = generate_p256_keypair()
        spk_id = "sha256:" + hashlib.sha256(spk_pub_der).hexdigest()[:16]
        now = time.time()

        # 签名背书：sign(spk_pub || scope || device_id || created_at)
        sign_data = spk_pub_der + self._scope.encode() + self._device_id.encode() + str(int(now)).encode()
        signature = ecdsa_sign_raw(self._ik_priv, sign_data)

        # 存入新 SPK
        entry = SpkEntry(
            spk_id=spk_id,
            spk_priv=spk_priv,
            spk_pub_der=spk_pub_der,
            created_at=now,
            status="active",
        )
        self._spk_store[spk_id] = entry

        # 先上传新 SPK，成功后再标记旧 SPK 为 pending_drain
        if self._on_spk_publish:
            self._on_spk_publish(self._scope, spk_id, spk_pub_der, signature)

        # 上传成功后才标记旧 SPK 为 pending_drain
        if self._current_spk_id and self._current_spk_id in self._spk_store:
            old_entry = self._spk_store[self._current_spk_id]
            if old_entry.status == "active":
                old_entry.status = "pending_drain"

        self._current_spk_id = spk_id
        self._last_rotation_time = now

        return entry
