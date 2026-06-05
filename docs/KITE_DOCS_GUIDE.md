# Kite / AUN SDK Core 文档查阅指南

AUN SDK Core 文档在 `docs/` 下。根级索引为 `docs/INDEX.md`，SDK API 子索引为 `docs/sdk/INDEX.md`。

行区间格式：`L7-18` 表示读取第 7 行到第 18 行。需要查 SDK 细节时，优先进入 `docs/sdk/AUN_DOCS_GUIDE.md`，不要一次性读取整套 SDK 手册。

## 渐进式查阅流程

### Step 1：先读根级 Layer 1

- `docs/INDEX.md` L7-28：根级文档地图。

### Step 2：按主题读根级 Layer 2

- 测试与 E2E：`docs/INDEX.md` L32-39。
- SDK 使用与协议：`docs/INDEX.md` L43-49。
- Service Proxy 与服务暴露：`docs/INDEX.md` L51-56。
- 诊断与可观测性：`docs/INDEX.md` L58-64。
- E2EE 与跨语言一致性：`docs/INDEX.md` L66-70。

### Step 3：需要判断文档价值时读 Layer 3 摘要

- `docs/INDEX.md` L74-134：重点文档摘要。

### Step 4：再读目标文档章节

只读取目标章节，不要默认读取全文。常用入口如下。

## 常见查阅场景

| 场景 | 推荐读取 |
| --- | --- |
| 当前 Docker 单域/双域测试怎么跑 | `docs/aun测试运行指南.md` L5-43、L62-70 |
| 本轮 SDK 重构修改清单 | `docs/AUN_SDK_重构修改清单.md` |
| AUNClient 巨类拆分重构执行方案 | `docs/design/AUNClient拆分重构执行方案.md` L3-252、L253-698、L699-803 |
| AUNClient 完全门面化与 Runtime 状态迁移细化方案 | `docs/design/AUNClient门面化与Runtime状态迁移细化方案.md` |
| 测试环境数据保护规则 | `docs/aun测试运行指南.md` L45-60 |
| 单域 Docker 测试容器和命令 | `docs/aun测试运行指南.md` L105-463 |
| 跨语言容器 E2E 执行方式 | `docs/aun测试运行指南.md` L139-250 |
| 双域 federation 测试容器和命令 | `docs/aun测试运行指南.md` L464-630 |
| 何时 rebuild / restart | `docs/aun测试运行指南.md` L631-675 |
| 测试故障排查 | `docs/aun测试运行指南.md` L677-704 |
| 跨语言容器 E2E 背景与目标 | `docs/design/跨语言容器E2E测试方案.md` L5-35 |
| E2EE V2 1DH/per-AID wrap 方案 | `docs/design/E2EE_V2简化为1DH加Per-AID_Wrap方案.md` |
| 服务端消息通信诊断总体方案 | `docs/design/AUN服务端消息通信诊断面板方案.md` L3-47 |
| 服务端消息通信 P0 诊断面板 | `docs/design/服务端消息通信诊断面板P0方案.md` L3-73 |
| AUN Service Proxy 总体架构、参考项目与边界 | `docs/design/AUN反向代理服务方案与TDD实施计划.md` L3-127 |
| AUN Service Proxy URL、注册、隧道协议和 Web 边界 | `docs/design/AUN反向代理服务方案与TDD实施计划.md` L129-384 |
| AUN Service Proxy 服务列表注册、双注册和 wakeup 路由 | `docs/sdk/09-proxy-rpc-manual.md` L1-226、`docs/protocol/06-服务协议.md` L43-204 |
| AUN Service Proxy 不影响现有接口的约束 | `docs/design/AUN反向代理服务方案与TDD实施计划.md` L385-422 |
| AUN Service Proxy TDD 分阶段实施计划 | `docs/design/AUN反向代理服务方案与TDD实施计划.md` L424-906 |
| 跨语言 Docker 拓扑 | `docs/design/跨语言容器E2E测试方案.md` L37-76 |
| 共享测试向量、CLI transcript、单域/双域分层 | `docs/design/跨语言容器E2E测试方案.md` L78-147 |
| test-runner 如何控制不同语言 client | `docs/design/跨语言容器E2E测试方案.md` L149-158 |
| test-control HTTP API | `docs/design/跨语言容器E2E测试方案.md` L160-305 |
| 客户端容器要求和 Compose 建议 | `docs/design/跨语言容器E2E测试方案.md` L307-411 |
| test-runner 标准用例流程 | `docs/design/跨语言容器E2E测试方案.md` L413-440 |
| Python / TypeScript / Go 跨 SDK 测试矩阵 | `docs/aun测试运行指南.md` L200-218 |
| 跨语言日志、trace、身份隔离、CLI 定位 | `docs/design/跨语言容器E2E测试方案.md` L514-576 |
| 失败分类与落地阶段 | `docs/design/跨语言容器E2E测试方案.md` L579-625 |
| 与现有测试环境的关系和验收标准 | `docs/design/跨语言容器E2E测试方案.md` L627-665 |
| agent.md 远程缓存目标与字段 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L5-86 |
| agent.md ETag 透传时序图 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L88-185 |
| agent.md 服务端与 SDK 实现流程 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L187-268 |
| agent.md 本地持久化、竞态和测试点 | `docs/agent.md/远程agent.md缓存与etag透传方案.md` L269-317 |
| SDK API、RPC、E2EE 使用细节 | `docs/sdk/AUN_DOCS_GUIDE.md` |
| Notify 在线轻量通知 / 跨域 federation 方案 | `docs/sdk/Notify通知方案.md` |
