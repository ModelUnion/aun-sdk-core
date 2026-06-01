"""
AUN-RPC-SDK 示例共享基础设施
============================

提供连接、认证、关闭的 boilerplate，让每个示例聚焦业务逻辑。

前置条件：
  1. pip install fastaun

环境变量（可选）：
  AUN_DATA_ROOT  — 数据存储根目录，默认 ~/.aun
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Windows 终端默认编码可能是 cp936，强制 UTF-8 避免中文乱码
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from aun_core import AIDStore, AUNClient, get_device_id

_DATA_ROOT = Path(os.environ.get("AUN_DATA_ROOT", "") or str(Path.home() / ".aun"))

# 设备 ID：同一台机器上固定不变，用于构造稳定的 AID
DEVICE_ID = get_device_id(_DATA_ROOT)
# 取前 8 位作为短标识，便于 AID 命名
DEVICE_SHORT = DEVICE_ID[:8]


def make_client(label: str | None = None) -> AUNClient:
    """创建一个无身份 AUNClient，并绑定示例用 AIDStore。

    label 用于区分同一台机器上的不同角色（如 sender/receiver）。
    不传 label 时使用默认 aun_path（~/.aun）。
    """
    storage = _DATA_ROOT / label if label else _DATA_ROOT
    storage.mkdir(parents=True, exist_ok=True)
    store = AIDStore(aun_path=str(storage), encryption_seed="")
    client = AUNClient()
    setattr(client, "_example_store", store)
    return client


async def ensure_connected(client: AUNClient, aid: str) -> str:
    """检查本地 identity，按需注册，然后加载身份并连接。返回 AID。

    先通过 AIDStore.load() 检查本地身份；不存在时 register()；
    成功加载 AID 后交给 AUNClient.connect() 自动认证并连接。
    """
    store = getattr(client, "_example_store", None)
    if store is None:
        raise RuntimeError("client was not created by make_client()")

    loaded = store.load(aid)
    if not loaded.ok:
        registered = await store.register(aid)
        if not registered.ok:
            message = registered.error.message if registered.error else "register failed"
            raise RuntimeError(message)
        loaded = store.load(aid)

    if not loaded.ok or loaded.data is None:
        message = loaded.error.message if loaded.error else "load identity failed"
        raise RuntimeError(message)

    if not client.has_identity:
        client.load_identity(loaded.data["aid"])

    await client.connect({"auto_reconnect": True})
    return aid


async def close_clients(*clients: AUNClient) -> None:
    """安全关闭多个客户端。"""
    for c in clients:
        try:
            await c.close()
        except Exception:
            pass
