# AUN SDK 文档索引

> 三层索引：Layer 1 文档地图，Layer 2 主题交叉索引，Layer 3 单篇摘要。

---

## Layer 1：文档地图

| 文档 | 说明 |
|------|------|
| [01-快速开始](01-快速开始.md) | 安装 · 三主体模型 · 最小示例 · 多语言构造 |
| [02-WebSocket协议](02-WebSocket协议.md) | 握手流程 · JSON-RPC 消息格式 · 裸 WebSocket 示例 |
| [03-核心概念](03-核心概念.md) | AID · AIDStore · AUNClient · 九态状态机 · E2EE |
| [04-连接与认证](04-连接与认证.md) | 注册加载 · 认证连接 · 网关发现 · 事件 · agent.md |
| [05-E2EE加密通信](05-E2EE加密通信.md) | E2EE 消息 · ProtectedHeaders · 密钥管理 · 高级存储 |
| [E2EE_V2消息通信时序图](E2EE_V2消息通信时序图.md) | V2 P2P/GROUP 明文与加密主链路 |
| [06-API手册](06-API手册.md) | AIDStore · AID · AUNClient · 事件 · E2EE 高级 API · RPC 索引 |
| [07-错误处理](07-错误处理.md) | Result · 错误类层级 · 错误码 · 重试 |
| [08-最佳实践](08-最佳实践.md) | 幂等连接 · 多 AID · 资源清理 · 测试数据保护 |
| [09-payload-reference](09-payload-reference.md) | message / group / thought payload 格式 |
| [09-message-rpc-manual](09-message-rpc-manual.md) | P2P 消息 RPC |
| [09-group-rpc-manual](09-group-rpc-manual.md) | 群组 RPC |
| [09-storage-rpc-manual](09-storage-rpc-manual.md) | 存储 RPC |
| [AUN Storage架构设计](<AUN Storage架构设计.md>) | Storage SDK VFS、控制面/数据面分离、服务端分层、类 Linux 权限、mount/symlink 与关键时序 |
| [09-meta-rpc-manual](09-meta-rpc-manual.md) | meta RPC 和信任根 |
| [09-stream-rpc-manual](09-stream-rpc-manual.md) | stream RPC |
| [09-proxy-rpc-manual](09-proxy-rpc-manual.md) | Service Proxy 控制面 RPC 和数据面隧道注册 |
| [09-custody-api-manual](09-custody-api-manual.md) | 可选 AID 托管 HTTP API |
| [Notify通知方案](Notify通知方案.md) | `client.notify()` 在线轻量通知、跨域 federation 和可靠消息分工 |

---

## Layer 2：概念交叉索引

### 身份与认证

- AID 格式、证书、不可变值对象 → [03-核心概念](03-核心概念.md)
- `AIDStore.register()` / `load()` / `exists()` / `resolve()` → [04-连接与认证](04-连接与认证.md)、[06-API手册](06-API手册.md)
- AID 构造约束与多语言入口 → [01-快速开始](01-快速开始.md)、[06-API手册](06-API手册.md)
- 认证链路和 token → [03-核心概念](03-核心概念.md)、[04-连接与认证](04-连接与认证.md)
- AID 托管恢复 / 跨设备复制 → [09-custody-api-manual](09-custody-api-manual.md)

### 连接与状态

- 九态状态机、device_id / slot_id 隔离键 → [03-核心概念](03-核心概念.md)
- `connect()` 选项、长短连接、网关发现 → [04-连接与认证](04-连接与认证.md)
- capability getter、事件、生命周期 API → [06-API手册](06-API手册.md)
- 裸 WebSocket 握手 → [02-WebSocket协议](02-WebSocket协议.md)

### E2EE

- E2EE 原理和默认行为 → [03-核心概念](03-核心概念.md)
- ProtectedHeaders、prekey、replay guard → [05-E2EE加密通信](05-E2EE加密通信.md)
- V2 P2P/GROUP 时序 → [E2EE_V2消息通信时序图](E2EE_V2消息通信时序图.md)
- 高级 E2EE API → [06-API手册](06-API手册.md)
- 解密失败排查 → [07-错误处理](07-错误处理.md)

### RPC 与事件

- `client.call()` / `client.on()` → [04-连接与认证](04-连接与认证.md)、[06-API手册](06-API手册.md)
- `client.notify()` 在线轻量通知、跨域 federation、在线/离线边界 → [Notify通知方案](Notify通知方案.md)
- Message RPC → [09-message-rpc-manual](09-message-rpc-manual.md)
- Group RPC → [09-group-rpc-manual](09-group-rpc-manual.md)
- Storage 架构、SDK VFS、控制面/数据面分离、类 Linux 权限和 mount/symlink → [AUN Storage架构设计](<AUN Storage架构设计.md>)
- Storage RPC → [09-storage-rpc-manual](09-storage-rpc-manual.md)
- Meta RPC → [09-meta-rpc-manual](09-meta-rpc-manual.md)
- Stream RPC → [09-stream-rpc-manual](09-stream-rpc-manual.md)
- Service Proxy RPC 和隧道注册 → [09-proxy-rpc-manual](09-proxy-rpc-manual.md)
- Payload 格式 → [09-payload-reference](09-payload-reference.md)

### 错误与测试

- Result 与异常层级 → [07-错误处理](07-错误处理.md)
- 重试策略 → [07-错误处理](07-错误处理.md)
- 幂等连接、多 AID、资源清理 → [08-最佳实践](08-最佳实践.md)
- 集成 / E2E 运行顺序 → [../aun测试运行指南.md](../aun测试运行指南.md)

---

## Layer 3：文档摘要

### 01-快速开始

说明安装、三主体模型、Python 最小消息收发示例、`AIDStore` / `AID` / `AUNClient` 的职责和 TS/JS/Go 构造约束。

### 02-WebSocket协议

说明 Gateway WebSocket 握手、JSON-RPC 请求/响应/通知格式，以及裸 WebSocket 客户端如何借助 SDK 完成 token 获取。

### 03-核心概念

解释 AID 身份、三主体职责、device_id / slot_id 隔离键、九态状态机、认证挑战-响应、默认 E2EE 行为和 RPC/事件模型。

### 04-连接与认证

描述 `AIDStore` 注册加载、`AUNClient` 身份加载、显式认证、连接选项、长短连接共存、网关发现、agent.md 和 RPC 调用。

### 05-E2EE加密通信

覆盖默认加密发送、接收自动解密、ProtectedHeaders、prekey、群 E2EE、replay guard 和高级存储扩展边界。

### 06-API手册

列出 AIDStore、AID、AUNClient、事件、ServiceProxyClient、E2EE 高级 API 和 RPC 手册索引，包含 Python / TS / JS / Go 的主要命名差异。

### 07-错误处理

说明 Result 字典、AUNError 异常层级、错误码映射、重试策略和常见错误场景。

### 08-最佳实践

给出幂等加载身份、连接、关闭、多 AID 管理、protected_headers、Flow Control 和测试数据保护建议。

### 09-*-rpc-manual

各业务服务的 RPC 参数、响应和错误语义。除 Storage VFS、Service Proxy 等明确提供高层门面的能力外，应用通常通过 `client.call()` 调用业务 RPC。

### AUN Storage架构设计

定义 AUN Storage 的 SDK VFS、low-level storage client、Storage Service、Storage Core、Metadata Engine 和 Blob Backend 分层。文档明确主数据流量直连 backend、控制面走 `storage.*` RPC，底层 session/ticket/complete RPC 继续保留，但普通应用通过 SDK VFS 获得类 POSIX 文件操作语义；同时定义类 Linux mode/ACL、目录 `x` 位、mount/unmount、symlink/readlink/lstat、share link 与 direct backend ticket 的授权边界，并给出上传、下载、rename/move、delete/GC、路径解析和鉴权的 Mermaid 时序图。

### 09-proxy-rpc-manual

定义 Service Proxy 的 Gateway 控制面 `proxy.register_services` / `proxy.unregister_services` / `proxy.list_services`，以及 proxy-server 数据面 `register_services` 隧道消息、双注册顺序、服务列表一致性和 wakeup 路由语义。

### Notify通知方案

定义 `client.notify()` 的在线轻量通知语义、服务端/AID/群路由方式、跨域 federation 在线转发、无离线存储边界、安全约束，以及与 `message.send` / `group.send` 可靠应用事件的分工。
