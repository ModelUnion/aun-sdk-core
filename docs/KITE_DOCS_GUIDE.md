# Kite / AUN SDK Core 文档查阅指南

AUN SDK Core 文档在 `docs/` 下。根级索引为 `docs/INDEX.md`，SDK API 子索引为 `docs/sdk/INDEX.md`。

行区间格式：`L7-18` 表示读取第 7 行到第 18 行。需要查 SDK 细节时，优先进入 `docs/sdk/AUN_DOCS_GUIDE.md`，不要一次性读取整套 SDK 手册。

## 渐进式查阅流程

### Step 1：先读根级 Layer 1

- `docs/INDEX.md` L7-20：根级文档地图。

### Step 2：按主题读根级 Layer 2

- 测试与 E2E：`docs/INDEX.md` L25-29。
- SDK 使用与协议：`docs/INDEX.md` L31-36。
- 诊断与可观测性：`docs/INDEX.md` L38-42。
- E2EE 与跨语言一致性：`docs/INDEX.md` L45-49。

### Step 3：需要判断文档价值时读 Layer 3 摘要

- `docs/INDEX.md` L53-81：重点文档摘要。

### Step 4：再读目标文档章节

只读取目标章节，不要默认读取全文。常用入口如下。

## 常见查阅场景

| 场景 | 推荐读取 |
| --- | --- |
| 当前 Docker 单域/双域测试怎么跑 | `docs/aun测试运行指南.md` L5-46、L65-80 |
| 测试环境数据保护规则 | `docs/aun测试运行指南.md` L48-63 |
| 单域 Docker 测试容器和命令 | `docs/aun测试运行指南.md` L113-533 |
| 跨语言容器 E2E 执行方式 | `docs/aun测试运行指南.md` L146-263 |
| 双域 federation 测试容器和命令 | `docs/aun测试运行指南.md` L534-714 |
| 何时 rebuild / restart | `docs/aun测试运行指南.md` L715-762 |
| 测试故障排查 | `docs/aun测试运行指南.md` L763-782 |
| 跨语言容器 E2E 背景与目标 | `docs/design/跨语言容器E2E测试方案.md` L5-35 |
| E2EE V2 1DH/per-AID wrap 方案 | `docs/design/E2EE_V2简化为1DH加Per-AID_Wrap方案.md` |
| 跨语言 Docker 拓扑 | `docs/design/跨语言容器E2E测试方案.md` L37-76 |
| 共享测试向量、CLI transcript、单域/双域分层 | `docs/design/跨语言容器E2E测试方案.md` L78-147 |
| test-runner 如何控制不同语言 client | `docs/design/跨语言容器E2E测试方案.md` L149-158 |
| test-control HTTP API | `docs/design/跨语言容器E2E测试方案.md` L160-305 |
| 客户端容器要求和 Compose 建议 | `docs/design/跨语言容器E2E测试方案.md` L307-411 |
| test-runner 标准用例流程 | `docs/design/跨语言容器E2E测试方案.md` L413-440 |
| Python / TypeScript / Go / C++ 跨 SDK 测试矩阵 | `docs/aun测试运行指南.md` L210-228 |
| 跨语言日志、trace、身份隔离、CLI 定位 | `docs/design/跨语言容器E2E测试方案.md` L514-576 |
| 失败分类与落地阶段 | `docs/design/跨语言容器E2E测试方案.md` L579-625 |
| 与现有测试环境的关系和验收标准 | `docs/design/跨语言容器E2E测试方案.md` L627-665 |
| agent.md 远程缓存目标与字段 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L5-86 |
| agent.md ETag 透传时序图 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L88-185 |
| agent.md 服务端与 SDK 实现流程 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L187-268 |
| agent.md SQLite 表结构、竞态和测试点 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L270-328 |
| SDK API、RPC、E2EE 使用细节 | `docs/sdk/AUN_DOCS_GUIDE.md` |
