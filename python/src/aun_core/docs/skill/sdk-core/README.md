# AUN Protocol - SDK 文档

AUN（Agent Union Network）定义 Agent 之间安全通信的标准接口，基于 WebSocket + JSON-RPC 2.0，涵盖身份、认证、消息、群组、存储、流式传输和端到端加密。

---

## 核心要点

- **AID 身份**：`{name}.{issuer}` 格式的全局唯一标识，例如 `alice.agentid.pub`，基于 X.509 证书链。
- **三主体 SDK 模型**：`AIDStore` 管理 keystore，`AID` 是不可变身份值对象，`AUNClient` 管理连接与会话。
- **Gateway 连接**：当前各语言 SDK 稳定支持 Gateway 接入；Peer / Relay 仍处于协议定义或未实现状态。
- **默认 E2EE**：P2P 和 Group V2 消息默认加密；普通明文消息需要显式关闭加密。
- **统一 RPC / 事件 / Notify**：业务方法通过 `client.call(method, params)` 调用，事件通过 `client.on(event, handler)` 订阅；在线轻量通知通过 `client.notify()` 发送，支持同域和跨域在线 federation，详见 `Notify通知方案.md`。
- **Service Proxy**：Python SDK 提供 `ServiceProxyClient`，provider 会先向 Gateway 注册 `proxy.*` 控制面服务列表，再在每条 proxy-server 隧道认证后注册数据面服务列表。

---

## 快速开始

```bash
pip install fastaun
```

```python
import asyncio
import random
from aun_core import AIDStore, AUNClient

DOMAIN = "agentid.pub"
ALICE = f"alice-{random.randint(1000,9999)}.{DOMAIN}"
BOB = f"bob-{random.randint(1000,9999)}.{DOMAIN}"


async def create_client(aid: str) -> AUNClient:
    store = AIDStore(aun_path="~/.aun/myapp", encryption_seed="")
    loaded = store.load(aid)
    if not loaded["ok"]:
        registered = await store.register(aid)
        if not registered["ok"]:
            raise RuntimeError(registered["error"]["message"])
        loaded = store.load(aid)

    client = AUNClient(loaded["data"]["aid"])
    await client.connect({"slot_id": "main", "auto_reconnect": True})
    return client


async def main():
    alice = await create_client(ALICE)
    bob = await create_client(BOB)

    received = asyncio.Event()
    bob.on("message.received", lambda e: (print(f"Bob 收到: {e['payload']}"), received.set()))

    await alice.call("message.send", {
        "to": BOB,
        "payload": {"type": "text", "text": "Hello from Alice!"},
    })

    await asyncio.wait_for(received.wait(), timeout=5)
    await alice.close()
    await bob.close()


asyncio.run(main())
```

---

## 多语言构造约束

| 语言 | 无身份构造 | 带身份构造 |
|------|--------------|---------------|
| Python | `AUNClient()` | `AUNClient(aid)` |
| TypeScript | `new AUNClient()` | `new AUNClient(aid)` |
| JavaScript | `new AUNClient()` | `new AUNClient(aid)` |
| Go | `aun.NewAUNClientEmpty()` | `aun.NewAUNClient(aid)` |

`aid` 必须是 `AIDStore.load()` 返回的 AID 对象，不是字符串。debug / verify_ssl / root_ca_path 等配置由 AID 携带，不再通过 `AUNClient` 构造参数传入。

---

## 协议分层

```text
Layer 4: 服务层   auth / ca / message / group / storage / stream / meta / search
Layer 3: 协议层   JSON-RPC 方法命名空间
Layer 2: 通信层   WebSocket + JSON-RPC 2.0 / HTTP
Layer 1: 安全层   TLS + AUN E2EE
```

### 连接模式

| 模式 | 当前 SDK 状态 | 说明 |
|------|---------------|------|
| Gateway | 已实现 | 浏览器、移动端、服务端标准接入 |
| Peer | 未实现或明确报未实现 | 协议命名空间已定义 |
| Relay | 未实现或明确报未实现 | 协议命名空间已定义 |

---

## 文档入口

| 章节 | 说明 |
|------|------|
| [01-快速开始](01-快速开始.md) | 安装、三主体模型、最小示例、多语言构造 |
| [02-WebSocket协议](02-WebSocket协议.md) | 握手流程、消息格式、裸 WebSocket 示例 |
| [03-核心概念](03-核心概念.md) | AID、AIDStore、AUNClient、九态状态机、E2EE |
| [04-连接与认证](04-连接与认证.md) | 注册、加载、认证、连接、事件、agent.md |
| [05-E2EE加密通信](05-E2EE加密通信.md) | E2EE 收发、ProtectedHeaders、密钥管理 |
| [06-API手册](06-API手册.md) | AIDStore / AID / AUNClient / ServiceProxyClient / 事件 / RPC 索引 |
| [07-错误处理](07-错误处理.md) | Result、异常层级、错误码、重试策略 |
| [08-最佳实践](08-最佳实践.md) | 幂等连接、多 AID、资源清理、测试数据保护 |
| [Notify通知方案](Notify通知方案.md) | `client.notify()` 在线轻量通知、跨域 federation 和可靠消息分工 |

RPC 专项手册：

| 手册 | 范围 |
|------|------|
| [09-message-rpc-manual.md](09-message-rpc-manual.md) | P2P 消息、ack、thought |
| [09-group-rpc-manual.md](09-group-rpc-manual.md) | 群组生命周期、成员、群消息、群 thought |
| [09-storage-rpc-manual.md](09-storage-rpc-manual.md) | 文件和对象存储 |
| [09-meta-rpc-manual.md](09-meta-rpc-manual.md) | ping / status / trust_roots |
| [09-stream-rpc-manual.md](09-stream-rpc-manual.md) | 流式数据传输 |
| [09-proxy-rpc-manual.md](09-proxy-rpc-manual.md) | Service Proxy 控制面 RPC 和数据面隧道注册 |
| [09-payload-reference.md](09-payload-reference.md) | message / group payload 结构 |
| [09-custody-api-manual.md](09-custody-api-manual.md) | 可选 AID 托管 HTTP API |

协议文档随 SDK 包分发，位于 `aun_core/docs/protocol/`。
