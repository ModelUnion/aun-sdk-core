# AUN SDK 文档查阅指南

AUN SDK 文档位于 `docs/sdk/`，索引文件 `docs/sdk/INDEX.md` 分三层：Layer 1 地图、Layer 2 主题索引、Layer 3 单篇摘要。按需逐层读取，避免一次性加载整套文档。

## SDK 文档定位

当前 SDK 聚焦三主体模型：

- `AIDStore`：注册、加载、列举、解析和证书运维。
- `AID`：不可变身份值对象，负责签名、验签和 agent.md 签验。
- `AUNClient`：认证、连接、状态机、事件和 RPC。

业务操作统一通过 `client.call(method, params)` 调用；消息、群组、存储、meta、stream 的参数见 `09-*-rpc-manual.md`。`message.send`、`message.thought.put`、`group.send`、`group.thought.put` 的业务 payload 见 `09-payload-reference.md`。

## 渐进式查阅流程

### Step 1：读 Layer 1

查看文档地图，能定位目标就直接读目标文档。

### Step 2：按主题读 Layer 2

常见主题：

- 身份与认证：AIDStore / AID / 注册 / 加载 / 证书
- 连接与状态：AUNClient / 九态状态机 / Gateway / 重连
- E2EE：默认加密、ProtectedHeaders、P2P / Group V2
- RPC 与事件：`client.call()`、`client.on()`、RPC 手册
- agent.md：`AIDStore.upload_agent_md()`、`AIDStore.download_agent_md()`、`AIDStore.check_agent_md()`
- 错误处理：Result、异常、错误码、重试

### Step 3：读 Layer 3 摘要

不确定哪篇文档包含细节时，先看单篇摘要，再打开原文目标章节。

## 文档总览

| 编号 | 文档 | 定位 |
|------|------|------|
| 01 | [快速开始](01-快速开始.md) | 安装、三主体模型、最小示例 |
| 02 | [WebSocket协议](02-WebSocket协议.md) | 握手流程、消息格式、裸 WebSocket |
| 03 | [核心概念](03-核心概念.md) | AID、状态机、认证、E2EE |
| 04 | [连接与认证](04-连接与认证.md) | AIDStore、连接、网关发现、事件 |
| 05 | [E2EE加密通信](05-E2EE加密通信.md) | E2EE、ProtectedHeaders、密钥管理 |
| 06 | [API手册](06-API手册.md) | AIDStore / AID / AUNClient / 事件 / RPC |
| 07 | [错误处理](07-错误处理.md) | Result、异常、错误码、重试 |
| 08 | [最佳实践](08-最佳实践.md) | 幂等、多 AID、资源清理、测试数据 |
| 09 | `09-*-rpc-manual.md` | 各服务 RPC 参数和响应 |
| 09 | [AID托管API手册](09-custody-api-manual.md) | 可选 custody HTTP 服务 |

## 常见查阅场景

| 场景 | 推荐路径 |
|------|----------|
| 首次使用 SDK | [01-快速开始](01-快速开始.md) |
| 理解新构造入口 | [01-快速开始](01-快速开始.md)、[06-API手册](06-API手册.md) |
| 注册或加载 AID | [04-连接与认证](04-连接与认证.md) |
| 发布、下载或检查 agent.md | [04-连接与认证](04-连接与认证.md)、[06-API手册](06-API手册.md) |
| 状态机和重连 | [03-核心概念](03-核心概念.md)、[04-连接与认证](04-连接与认证.md) |
| 查方法签名 | [06-API手册](06-API手册.md) |
| 查消息或群组 RPC | 对应 `09-*-rpc-manual.md` |
| 查 payload 格式 | [09-payload-reference.md](09-payload-reference.md) |
| 排查错误 | [07-错误处理](07-错误处理.md) |
| 写测试或 demo | [08-最佳实践](08-最佳实践.md) |
