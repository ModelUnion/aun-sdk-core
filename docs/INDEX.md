# AUN SDK Core 文档索引

> 根级文档索引采用三层结构。Layer 1 用于快速定位，Layer 2 按主题交叉查找，Layer 3 给出重点文档摘要。SDK API 细节继续查看 `docs/sdk/INDEX.md`。

---

## Layer 1：文档地图

| 文档 | 定位 |
| --- | --- |
| [aun测试运行指南](aun测试运行指南.md) | 当前 Docker 单域、双域、多语言 SDK 测试运行命令 |
| [跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md) | 多语言 SDK 同网同服、test-runner 控制面的跨语言 E2E 方案 |
| [AUN RPC Trace 增强设计](design/2026-05-22-aun-rpc-trace-enhancement.md) | RPC trace 诊断字段与 enter/exit span 设计 |
| [远程 agent.md 缓存与 ETag 透传方案](agent.md/远程agent.md缓存与etag透传方案.md) | 远程 agent.md per-AID 缓存、SQLite 表、消息信封与 RPC 响应 ETag 透传方案 |
| [SDK 文档索引](sdk/INDEX.md) | SDK 使用手册、RPC 手册、E2EE 手册的子索引 |
| [SDK 查阅指南](sdk/AUN_DOCS_GUIDE.md) | SDK 文档按行区间渐进式查阅方法 |
| [协议文档目录](protocol/) | AUN 协议相关文档 |
| [审查与路线图目录](audit/) | 历史审查、修复路线图、测试补充清单 |
| [superpowers 目录](superpowers/) | AUN SDK 规范类补充文档 |

---

## Layer 2：主题交叉索引

### 测试与 E2E

- 现有测试命令、容器名、单域/双域运行入口 → [aun测试运行指南](aun测试运行指南.md)
- Python / TypeScript / Go / C++ 跨语言容器 E2E、test-runner、test-control API、用例矩阵 → [aun测试运行指南](aun测试运行指南.md)、[跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md)
- 多语言 SDK 测试缺口与补测清单 → [审查与路线图目录](audit/)

### SDK 使用与协议

- Python / TS / Go / JS SDK 使用手册、RPC 参数、E2EE 机制 → [SDK 文档索引](sdk/INDEX.md)
- 按主题和行区间查 SDK 文档 → [SDK 查阅指南](sdk/AUN_DOCS_GUIDE.md)
- 协议细节、子协议和消息格式 → [协议文档目录](protocol/)
- agent.md 远程缓存、`remote_etag` / `local_etag`、消息信封 ETag 透传 → [远程 agent.md 缓存与 ETag 透传方案](agent.md/远程agent.md缓存与etag透传方案.md)

### 诊断与可观测性

- RPC trace span、跨模块诊断字段、安全字段白名单 → [AUN RPC Trace 增强设计](design/2026-05-22-aun-rpc-trace-enhancement.md)
- 测试日志路径、测试输出、容器日志查看 → [aun测试运行指南](aun测试运行指南.md)
- 跨语言 E2E trace 字段、日志产物、失败分类 → [跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md)

### E2EE 与跨语言一致性

- SDK E2EE API、会话管理、ProtectedHeaders → [SDK 文档索引](sdk/INDEX.md)
- 共享测试向量、transcript 回放、Python / TS / Go / C++ E2EE 互通 → [aun测试运行指南](aun测试运行指南.md)、[跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md)

---

## Layer 3：重点文档摘要

### aun测试运行指南

记录当前 AUN 服务与 SDK 在 Docker 单域、双域环境中的实际测试入口。包含 Python、TypeScript、Go、JavaScript、C++ 五语言测试矩阵，Python / TypeScript / Go / C++ 跨语言容器 E2E 的 69 用例矩阵，覆盖 P2P 明文/E2EE、群聊 pairwise 明文/E2EE，以及四语言 agent 同群的明文/E2EE 矩阵，另包含固定身份目录、容器名、典型命令、浏览器 E2E、C++ Docker 测试、双域 federation 测试和数据保护规则。

### 跨语言容器E2E测试方案

定义多语言 SDK 同时作为真实客户端运行的目标测试体系。核心模型是每个语言一个客户端容器，全连接同一 AUN server / gateway；业务消息走 AUN，test-runner 通过每个客户端暴露的 test-control HTTP API 编排动作和断言结果。当前单域落地覆盖 Python / TypeScript / Go / C++，浏览器 JavaScript 仍按宿主机 Playwright 运行。

### AUN RPC Trace 增强设计

设计 RPC trace 的 enter/exit span 结构，补充方法、AID、route、错误码、业务结果等诊断字段，并定义安全字段白名单。目标是在跨模块 RPC 失败时能定位到具体业务原因，而不是只看到模块路径和耗时。

### 远程 agent.md 缓存与 ETag 透传方案

定义每个远程 AID 在 SDK 内存和 SQLite 中维护一条 `remote_agent_md_cache` 记录，字段包含 `remote_etag`、`local_etag`、`content`、`last_modified`、`fetched_at`、`observed_at` 等。方案同时规定 `message.send` 响应向发送端透传 `to` 的 agent.md ETag，消息信封向接收端透传 `from` 的 agent.md ETag，并给出按需下载、304 处理、竞态和跨 SDK 一致性规则。

### SDK 文档索引

`docs/sdk/INDEX.md` 是 SDK 手册的三层子索引，覆盖快速开始、WebSocket 协议、核心概念、连接认证、E2EE、API 手册、错误处理、最佳实践、payload 和各类 RPC 手册。

### SDK 查阅指南

`docs/sdk/AUN_DOCS_GUIDE.md` 说明如何按行区间渐进式读取 SDK 文档，避免一次性加载过多文档内容。