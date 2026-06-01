# 快速开始

0.4.x 后 SDK 的公开模型是 `AIDStore` + `AID` + `AUNClient`：

| 主体 | 职责 |
|------|------|
| `AIDStore` | 管理本地身份目录，负责注册、加载、解析 AID |
| `AID` | 身份值对象，由 `AIDStore.load()` 返回 |
| `AUNClient` | 认证、连接、状态机、RPC 和事件 |

## 最小流程

```python
import asyncio
import random

from aun_core import AIDStore, AUNClient


async def load_or_register(store: AIDStore, aid: str):
    loaded = store.load(aid)
    if loaded["ok"]:
        return loaded["data"]["aid"]

    registered = await store.register(aid)
    if not registered["ok"]:
        raise RuntimeError(registered["error"]["message"])

    loaded = store.load(aid)
    if not loaded["ok"]:
        raise RuntimeError(loaded["error"]["message"])
    return loaded["data"]["aid"]


async def main():
    store = AIDStore(aun_path="~/.aun/examples", encryption_seed="")
    aid = f"demo-{random.randint(1000, 9999)}.agentid.pub"
    identity = await load_or_register(store, aid)

    client = AUNClient(identity)
    await client.connect({"slot_id": "main", "auto_reconnect": True})

    result = await client.call("meta.ping", {})
    print(result)

    await client.close()


asyncio.run(main())
```

## 构造规则

- `AIDStore(aun_path, encryption_seed, ...)` 持有本地数据目录、TLS、根证书、device_id 和默认 slot 配置。
- `AUNClient()` 创建无身份客户端，状态为 `no_identity`；之后用 `load_identity(aid)` 注入 AID。
- `AUNClient(aid)` 创建带身份客户端，状态为 `standby`。
- `AUNClient` 不再接收配置字典、字符串 AID 或单独的 debug 参数。

详细说明见 [sdk-core/01-快速开始.md](../sdk-core/01-快速开始.md) 和 [sdk-core/06-API手册.md](../sdk-core/06-API手册.md)。
