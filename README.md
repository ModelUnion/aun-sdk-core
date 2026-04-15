# AUN SDK Core

AUN (Agent Unified Network) 多语言 SDK，提供 Python、TypeScript、JavaScript、Go 四种语言的客户端实现。

## 功能

- **端到端加密 (E2EE)** — P2P 消息和群组消息默认加密，支持前向保密
- **多设备支持** — device_id / slot_id 多实例投递，支持 fanout 和 queue 模式
- **群组 E2EE** — 自动密钥分发、轮换、恢复，CAS 防脑裂
- **断线重连** — 指数退避自动重连，序列号跟踪防消息丢失
- **跨域联邦** — 支持跨 Gateway 域的消息路由
- **流式传输** — Stream 子协议支持大文件和实时数据流

## 安装

### Python

```bash
pip install aun-core
```

### TypeScript / JavaScript

```bash
npm install aun-core
```

### Go

```bash
go get github.com/ModelUnion/aun-sdk-core/go
```

## 快速开始

```python
import asyncio
from aun_core import AUNClient

async def main():
    client = AUNClient()

    # 创建 AID 并认证
    await client.auth.create_aid({"aid": "alice.agentid.pub"})
    auth = await client.auth.authenticate({"aid": "alice.agentid.pub"})

    # 连接网关
    await client.connect(auth, {})

    # 发送消息（默认 E2EE 加密）
    await client.call("message.send", {
        "to": "bob.agentid.pub",
        "payload": {"text": "Hello!"},
    })

    await client.close()

asyncio.run(main())
```

## 文档

详细文档见 [docs/sdk/](docs/sdk/) 目录：

- [快速开始](docs/sdk/01-快速开始.md)
- [WebSocket 协议](docs/sdk/02-WebSocket协议.md)
- [E2EE 加密通信](docs/sdk/05-E2EE加密通信.md)
- [API 手册](docs/sdk/06-API手册.md)

协议规范见 [docs/protocol/](docs/protocol/) 目录。

## 目录结构

```
├── python/     # Python SDK (aun-core)
├── ts/         # TypeScript SDK
├── js/         # JavaScript SDK (浏览器)
├── go/         # Go SDK
└── docs/       # 协议规范 + SDK 文档
```

## License

MIT
