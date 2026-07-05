# AUN SDK 文档查阅指南

AUN SDK 文档位于 `docs/sdk/`，索引文件 `docs/sdk/INDEX.md` 分三层：Layer 1 地图、Layer 2 主题索引、Layer 3 单篇摘要。按需逐层读取，避免一次性加载整套文档。

## SDK 文档定位

当前 SDK 聚焦三主体模型：

- `AIDStore`：注册、加载、列举、解析和证书运维。
- `AID`：不可变身份值对象，负责签名、验签和 agent.md 签验。
- `AUNClient`：认证、连接、状态机、事件和 RPC。
- `ServiceProxyClient`：Python SDK 的 Service Proxy provider 侧客户端，负责 Gateway 控制面注册和 proxy-server 数据面隧道注册。

业务 RPC 的底层参数见 `09-*-rpc-manual.md`，可通过 `client.call(method, params)` 调用；Storage、Collab、Group FS、Service Proxy 等具备高层门面的能力以对应专项文档为准。`message.send`、`message.thought.put`、`group.send`、`group.thought.put` 的业务 payload 见 `09-payload-reference.md`。群组标识以 `group_aid` 为主，`group_id` 只作为兼容参数名，详见 `09-group-rpc-manual.md`。在线轻量通知和跨域 federation notify 方案见 `Notify通知方案.md`。

Storage 的 SDK VFS、控制面/数据面分离、direct backend 上传下载、类 Linux 权限、mount/symlink 和服务端分层见 `AUN Storage架构设计.md`。
Group FS 的 `group.fs.*` RPC、`client.group.fs.*` 门面、`aun group fs` CLI、`cp/mv` 语义、群自有区角色 ACL 授权/撤销/查询与 `group_aid` 签名、`parents` 语义、JS string 差异和 memberdata 服务端映射见 `09-group-rpc-manual.md`。Collab 的 `gc`、`reflog`、`revert`、`clone` 及版本化文档/标签语义见 `09-collab-rpc-manual.md`。

## 渐进式查阅流程

### Step 1：读 Layer 1

查看文档地图，能定位目标就直接读目标文档。

### Step 2：按主题读 Layer 2

常见主题：

- 身份与认证：AIDStore / AID / 注册 / 加载 / 证书
- 连接与状态：AUNClient / 九态状态机 / Gateway / 重连
- E2EE：默认加密、ProtectedHeaders、P2P / Group V2
- RPC 与事件：`client.call()`、`client.on()`、`client.notify()`、RPC 手册
- Storage：SDK VFS、direct backend 数据面、`storage.*` low-level RPC、类 Linux 权限、mount/symlink、Storage Service 分层
- 群文件系统：`group.fs.*`、`client.group.fs.*`、`aun group fs`、`cp/mv` 上传下载、群自有区角色 ACL 与 `group_aid` 签名、`parents`、JS string 差异和 memberdata 服务端映射（见 `09-group-rpc-manual.md`）
- 协作（collab）：`collab.*` 版本化文档、乐观锁 CAS commit、三方合并、标签、GC、reflog、revert（见 `09-collab-rpc-manual.md`）
- Service Proxy：`ServiceProxyClient`、`proxy.register_services`、proxy-server `register_services`
- agent.md：`AIDStore.upload_agent_md()`、`AIDStore.download_agent_md()`、`AIDStore.check_agent_md()`、Gateway `_meta.agent_md_etags` 被动观察、`requester` / `peer` / `group` 角色
- 错误处理：Result、异常、错误码、重试

### Step 3：读 Layer 3 摘要

不确定哪篇文档包含细节时，先看单篇摘要，再打开原文目标章节。

## 文档总览

| 编号 | 文档 | 定位 |
|------|------|------|
| 01 | [快速开始](01-快速开始.md) | 安装、三主体模型、最小示例 |
| 02 | [WebSocket协议](02-WebSocket协议.md) | 握手流程、消息格式、裸 WebSocket |
| 03 | [核心概念](03-核心概念.md) | AID、状态机、认证、E2EE |
| 04 | [连接与认证](04-连接与认证.md) | AIDStore、连接、网关发现、事件、agent.md 自动观察 |
| 05 | [E2EE加密通信](05-E2EE加密通信.md) | E2EE V2、ProtectedHeaders、agent.md 版本提示、recipient wrap |
| 06 | [API手册](06-API手册.md) | AIDStore / AID / AUNClient / agent.md / ServiceProxyClient / 事件 / RPC |
| 07 | [错误处理](07-错误处理.md) | Result、异常、错误码、重试 |
| 08 | [最佳实践](08-最佳实践.md) | 幂等、多 AID、资源清理、测试数据 |
| - | [AUN Storage架构设计](<AUN Storage架构设计.md>) | Storage SDK VFS、控制面/数据面分离、类 Linux 权限、mount/symlink、服务端分层 |
| 09 | `09-*-rpc-manual.md` | 各服务 RPC 参数和响应 |
| 09 | [Service Proxy RPC手册](09-proxy-rpc-manual.md) | `proxy.*` 控制面和 proxy-server 数据面注册 |
| 09 | [AID托管API手册](09-custody-api-manual.md) | 可选 custody HTTP 服务 |

## 常见查阅场景

| 场景 | 推荐路径 |
|------|----------|
| 首次使用 SDK | [01-快速开始](01-快速开始.md) |
| 理解新构造入口 | [01-快速开始](01-快速开始.md)、[06-API手册](06-API手册.md) |
| 注册或加载 AID | [04-连接与认证](04-连接与认证.md) |
| 发布、下载、检查或排查 agent.md 远端 ETag | [04-连接与认证](04-连接与认证.md)、[06-API手册](06-API手册.md)、[../agent.md/远程agent.md缓存与etag透传方案.md](../agent.md/远程agent.md缓存与etag透传方案.md) |
| 状态机和重连 | [03-核心概念](03-核心概念.md)、[04-连接与认证](04-连接与认证.md) |
| 查方法签名 | [06-API手册](06-API手册.md) |
| 查消息或群组 RPC | 对应 `09-*-rpc-manual.md` |
| 查群组标识 `group_aid` / `group_id` 兼容规范 | [09-group-rpc-manual.md](09-group-rpc-manual.md) |
| 查群文件系统 RPC / SDK / CLI 入口、群自有区角色 ACL 授权/撤销/查询、`parents` 和 JS string 差异 | [09-group-rpc-manual.md](09-group-rpc-manual.md)、[06-API手册](06-API手册.md) |
| 查 Storage 架构、SDK VFS、权限模型、mount/symlink 和上传下载链路 | [AUN Storage架构设计.md](<AUN Storage架构设计.md>) |
| 查 Storage RPC 参数 | [09-storage-rpc-manual.md](09-storage-rpc-manual.md) |
| 查协作（版本化文档/乐观锁/标签/GC/reflog/revert）RPC | [09-collab-rpc-manual.md](09-collab-rpc-manual.md) |
| 查 notify 在线轻量通知 / 跨域 federation | [Notify通知方案.md](Notify通知方案.md) |
| 查 Service Proxy 服务注册和路由 | [06-API手册](06-API手册.md)、[09-proxy-rpc-manual.md](09-proxy-rpc-manual.md) |
| 查 payload 格式 | [09-payload-reference.md](09-payload-reference.md) |
| 排查错误 | [07-错误处理](07-错误处理.md) |
| 写测试或 demo | [08-最佳实践](08-最佳实践.md) |


