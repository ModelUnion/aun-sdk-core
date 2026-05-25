# AUN SDK Python 文档查阅指南

AUN SDK 文档在 `docs/sdk/` 下，索引文件 `docs/sdk/INDEX.md` 分三层，**严格按需逐层加载，禁止一次性读取整个索引**。

行区间格式：`L43-49` 表示用 Read 工具读取时读取第 43 行到 49 行。

## SDK 文档定位

SDK 文档聚焦核心封装：**认证（`client.auth`）**、**元信息与信任根（`client.meta`）** 和 **E2EE（`client.e2ee`）**。AID 托管是可选 HTTP 服务，查 `10-custody-api-manual.md`。

其他业务操作（消息、群组、存储等）通过 `client.call(method, params)` 调用 RPC 方法，参数和响应格式见 `docs/sdk/09-*-rpc-manual.md`；`message.send` / `message.thought.put` / `group.send` / `group.thought.put` 的业务 payload 共用格式见 `docs/sdk/09-payload-reference.md`。

## 渐进式查阅流程

### Step 1：只读 Layer 1（L7-34）

列出所有文档名和章节行区间。能直接定位目标 → 跳 Step 4。

### Step 2：按需读 Layer 2 对应小节

仅当 Step 1 不够时，按关键词读：

身份与认证 L40-45 · 连接与状态 L47-52 · E2EE L54-63 · RPC与事件 L65-77 · 配置与存储 L79-85 · 错误处理 L87-90 · AID托管 L45

### Step 3：按需读 Layer 3 单篇摘要

仅当需要某篇详情但不确定读哪个章节时：

快速开始 L96-97 · WebSocket协议 L99-100 · 核心概念 L102-103 · 连接与认证 L105-106 · E2EE加密通信 L108-109 · E2EE_V2消息通信时序图 L111-112 · GROUP-E2EE轮换竞态清单 L114-115 · GROUP-E2EE现状对比与改进建议 L117-118 · API参考 L120-121 · 错误处理 L123-124 · 最佳实践 L126-127 · AID托管 L129-130 · 消息Payload L132-133 · 多语言SDK对齐审查 L135-136

大多数问题在摘要层就能解答。

### Step 4：读原文目标章节

根据前面获得的文档路径和行区间，精确读取对应章节。**只有需要完整分析时才读整篇原文。**

## 文档总览

| 编号 | 文档 | 定位 |
|------|------|------|
| 01 | [快速开始](01-快速开始.md) | 安装、配置、最小示例 |
| 02 | [WebSocket协议](02-WebSocket协议.md) | 握手流程、消息格式、裸 WebSocket 示例 |
| 03 | [核心概念](03-核心概念.md) | AID、状态机、认证、E2EE |
| 04 | [连接与认证](04-连接与认证.md) | 认证封装、call()、on()、连接 |
| 05 | [E2EE加密通信](05-E2EE加密通信.md) | E2EE封装、ProtectedHeaders、自定义存储 |
| - | [E2EE_V2消息通信时序图](E2EE_V2消息通信时序图.md) | V2-only 明文/加密 P2P/GROUP 消息主链路 Mermaid 时序图 |
| - | [GROUP-E2EE轮换竞态清单](GROUP-E2EE轮换竞态清单.md) | GROUP epoch key 轮换状态、竞态条件、补测清单 |
| - | [GROUP-E2EE现状对比与改进建议](GROUP-E2EE现状对比与改进建议.md) | 当前 GROUP E2EE 实现定位、成熟方案对比、风险边界、分阶段改进建议 |
| 06 | [API手册](06-API手册.md) | AUNClient / AuthNamespace / MetaNamespace（信任根列表与 issuer root 更新） / E2EEManager |
| 07 | [错误处理](07-错误处理.md) | 错误类层级、错误码、重试 |
| 08 | [最佳实践](08-最佳实践.md) | 幂等、隔离、资源清理 |
| 10 | [AID托管API手册](10-custody-api-manual.md) | 手机号验证码、证书与加密私钥备份恢复、跨设备复制 |
| - | [09-payload-reference](09-payload-reference.md) | `message.send` / `message.thought.put` / `group.send` / `group.thought.put` 共用业务负载格式、类型总览、思考内容、交互卡片/action_card_reply、任务事件、附件引用 |
| - | [多语言SDK使用场景与调用链路对齐审查清单](多语言SDK使用场景与调用链路对齐审查清单.md) | 多语言场景、调用链路、字段对齐、竞态和服务端风险总表 |

## 常见查阅场景

| 场景 | 推荐路径 |
|------|----------|
| 首次使用 SDK | 01-快速开始 全文 |
| 裸 WebSocket 或其他语言实现 | 02-WebSocket协议 |
| 理解 AID / E2EE 原理 | 03-核心概念 对应章节 |
| 认证 + 连接 + call/on 用法 | 04-连接与认证 |
| 需要加密通信 | 05-E2EE加密通信 |
| 需要查看 E2EE V2 消息主链路时序 | [E2EE_V2消息通信时序图](E2EE_V2消息通信时序图.md) |
| GROUP E2EE 轮换竞态/测试设计 | [GROUP-E2EE轮换竞态清单](GROUP-E2EE轮换竞态清单.md) |
| GROUP E2EE 架构评估/演进路线 | [GROUP-E2EE现状对比与改进建议](GROUP-E2EE现状对比与改进建议.md) |
| 查消息或思考内容 payload 类型和格式 | [09-payload-reference](09-payload-reference.md) |
| 查某个方法的签名 | 06-API手册 |
| 遇到报错需排查 | 07-错误处理 |
| 部署前检查 | 08-最佳实践 |
| AID 证书和加密私钥托管恢复/跨设备复制 | 10-custody-api-manual |
| 查 RPC 方法参数 | `docs/sdk/*-rpc-manual.md` |
| 多语言 SDK 功能 gap / 字段和事件对齐 / 失败分支审查 | [多语言SDK使用场景与调用链路对齐审查清单](多语言SDK使用场景与调用链路对齐审查清单.md) |
