# AUN SDK Core 文档索引

> 根级文档索引采用三层结构。Layer 1 用于快速定位，Layer 2 按主题交叉查找，Layer 3 给出重点文档摘要。SDK API 细节继续查看 `docs/sdk/INDEX.md`。

---

## Layer 1：文档地图

| 文档 | 定位 |
| --- | --- |
| [aun测试运行指南](aun测试运行指南.md) | 当前 Docker 单域、双域、多语言 SDK 与 Service Proxy E2E 测试运行命令 |
| [AUN SDK 重构修改清单](AUN_SDK_重构修改清单.md) | 本轮 SDK 重构的实际修改点、测试结果和遗留事项 |
| [AUNClient 拆分重构执行方案](design/AUNClient拆分重构执行方案.md) | Python / Go / TS / JS SDK AUNClient 内部拆分边界、执行步骤和验收矩阵 |
| [AUNClient 门面化与 Runtime 状态迁移细化方案](design/AUNClient门面化与Runtime状态迁移细化方案.md) | AUNClient 完全门面化、ClientRuntime 单一状态源和四端分批迁移步骤 |
| [跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md) | 多语言 SDK 同网同服、test-runner 控制面的跨语言 E2E 方案 |
| [E2EE V2 简化为 1DH + Per-AID Wrap 方案](design/E2EE_V2简化为1DH加Per-AID_Wrap方案.md) | SDK bootstrap 能力声明 + 服务端 policy 控制 1DH/per-AID wrap 的兼容方案 |
| [AUN RPC Trace 增强设计](design/2026-05-22-aun-rpc-trace-enhancement.md) | RPC trace 诊断字段与 enter/exit span 设计 |
| [AUN 服务端消息通信诊断面板方案](design/AUN服务端消息通信诊断面板方案.md) | aun-console 消息通信页的服务端可观察诊断面板总体方案 |
| [服务端消息通信诊断面板 P0 方案](design/服务端消息通信诊断面板P0方案.md) | aun-console 消息通信页的服务端可观察 P0 诊断面板 |
| [AUN 反向代理服务方案与 TDD 实施计划](design/AUN反向代理服务方案与TDD实施计划.md) | AUN Service Proxy、service_proxy 服务模块、SDK service-proxy-client、URL 路由、隧道协议、Web 边界和分阶段 TDD 落地计划 |
| [远程 agent.md 缓存与 ETag 透传方案](agent.md/远程agent.md缓存与etag透传方案.md) | 远程 agent.md per-AID 本地文件/IndexedDB 缓存、消息信封与 RPC 响应 ETag 透传方案 |
| [SDK 文档索引](sdk/INDEX.md) | SDK 使用手册、RPC 手册、E2EE、Storage VFS、Group resources pending_ops 和 Collab 的子索引 |
| [SDK 查阅指南](sdk/AUN_DOCS_GUIDE.md) | SDK 文档按行区间渐进式查阅方法 |
| [AUN Storage 架构设计](<aun-fs/AUN Storage架构设计.md>) | Storage SDK VFS、控制面/数据面分离、类 Linux 权限、mount/symlink、服务端分层和 direct backend 上传下载 |
| [AUN Storage SDK 存储分层设计](<aun-fs/SDK存储分层设计.md>) | Python SDK StorageVFS / StorageLowLevel 接口契约、返回类型、错误映射和跨语言对齐要求 |
| [AUN Storage CLI-fs 命令设计](<aun-fs/CLI-fs命令设计.md>) | `aun fs` 命令语义、寻址规则、输出格式、CLI 工程改造和端到端场景 |
| [AUN Storage 分阶段实施计划](<aun-fs/分阶段实施计划.md>) | AUN Storage VFS + CLI 的 6 阶段 TDD 实施计划、P1-P6 实际执行记录和验收口径 |
| [群存储 group.resources.* 重构设计](<aun-fs/group-storage/2026-06-10-group-storage-重构设计.md>) | `group.resources.*` 从旧 `storage_ref` 引用树迁移到 group_aid storage 命名空间、成员 `memberdata` 挂载和 group-storage 门面编排的终态设计 |
| [群存储 group-storage 重构实施计划](<aun-fs/group-storage/2026-06-10-group-storage-重构实施计划.md>) | group-storage 0-10 阶段 TDD 实施计划、阶段 IPO/测试矩阵、实际执行记录、四语言 SDK/CLI/服务端验收与 Docker 单域/双域 E2E 通过记录 |
| [collab 协作层服务端编排设计](<aun-fs/collab/2026-06-10-collab层服务端编排详细设计.md>) | collab 服务端编排、台账、diff3、snapshot、export/adopt、群协作注册表和四语言薄 SDK 设计 |
| [collab 协作层 Plan 1 服务端基础](<aun-fs/collab/2026-06-10-collab服务端编排-plan1.md>) | storage 进程内 collab 编排的 TDD 任务拆分、repository 事务原语、RPC 注册和群协作发现计划 |
| [collab 协作层 Plan 2 Python SDK/CLI](<aun-fs/collab/2026-06-12-collab协作层-plan2.md>) | Python SDK collab 薄封装、CLI 命令、单域 Docker E2E 和文档同步计划 |
| [collab 协作层 Plan 3 四语言互操作](<aun-fs/collab/2026-06-12-collab协作层-plan3.md>) | Go / TypeScript / JavaScript SDK collab 薄封装、跨语言 E2E 和双域边界验证计划 |
| [Notify 通知方案](sdk/Notify通知方案.md) | `client.notify()` 在线轻量通知、跨域 federation 和可靠消息分工 |
| [Service Proxy RPC 手册](sdk/09-proxy-rpc-manual.md) | `proxy.*` 控制面、proxy-server 数据面注册、服务列表一致性和 wakeup 路由语义 |
| [协议文档目录](protocol/) | AUN 协议相关文档 |
| [审查与路线图目录](audit/) | 历史审查、修复路线图、测试补充清单 |
| [superpowers 目录](superpowers/) | AUN SDK 规范类补充文档 |

---

## Layer 2：主题交叉索引

### 测试与 E2E

- 现有测试命令、容器名、单域/双域运行入口 → [aun测试运行指南](aun测试运行指南.md)
- 本轮 SDK 重构阶段进度、修改点和测试结果 → [AUN SDK 重构修改清单](AUN_SDK_重构修改清单.md)
- AUNClient 巨类拆分、内部组件边界、逐步迁移和验收矩阵 → [AUNClient 拆分重构执行方案](design/AUNClient拆分重构执行方案.md)
- AUNClient 完全门面化、Runtime 状态归属、状态写入收口和四端分批实施 → [AUNClient 门面化与 Runtime 状态迁移细化方案](design/AUNClient门面化与Runtime状态迁移细化方案.md)
- Python / TypeScript / Go / JavaScript 跨语言容器 E2E、test-runner、test-control API、用例矩阵 → [aun测试运行指南](aun测试运行指南.md)、[跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md)
- 多语言 SDK 测试缺口与补测清单 → [审查与路线图目录](audit/)

### SDK 使用与协议

- Python / TS / Go / JS SDK 使用手册、RPC 参数、E2EE 机制、Storage VFS、Group resources pending_ops、Collab GC/reflog/reset → [SDK 文档索引](sdk/INDEX.md)
- 按主题和行区间查 SDK 文档 → [SDK 查阅指南](sdk/AUN_DOCS_GUIDE.md)
- Storage SDK VFS、控制面/数据面分离、类 Linux 权限、mount/symlink、direct backend 上传下载和服务端分层 → [AUN Storage 架构设计](<aun-fs/AUN Storage架构设计.md>)
- StorageVFS / StorageLowLevel 接口契约、NodeView/ObjectView、错误映射和跨语言对齐 → [AUN Storage SDK 存储分层设计](<aun-fs/SDK存储分层设计.md>)
- `aun fs` 命令语义、AID 路径解析、输出格式和 CLI 到 SDK 的调用边界 → [AUN Storage CLI-fs 命令设计](<aun-fs/CLI-fs命令设计.md>)
- AUN Storage 6 阶段 TDD 计划、P1/P2/P3/P4/P5/P6 实际执行记录、阶段实施前详细计划和 Docker 验证纪律 → [AUN Storage 分阶段实施计划](<aun-fs/分阶段实施计划.md>)
- `group.resources.*` 替代旧 `storage_ref` 引用树、group_aid 命名空间、群自有区、`memberdata` 成员挂载区、签名者切换和下载 ticket → [群存储 group.resources.* 重构设计](<aun-fs/group-storage/2026-06-10-group-storage-重构设计.md>)
- group-storage 0-10 阶段 TDD 推进记录、CLI 收口、四语言 SDK pending-op signer、服务端回归和 Docker 单域/双域 E2E 通过记录 → [群存储 group-storage 重构实施计划](<aun-fs/group-storage/2026-06-10-group-storage-重构实施计划.md>)
- collab 协作层服务端编排、`collab.*` RPC、版本台账、snapshot、群协作注册表和后续四语言 SDK/CLI/E2E 计划 → [collab 协作层服务端编排设计](<aun-fs/collab/2026-06-10-collab层服务端编排详细设计.md>)、[Plan 1](<aun-fs/collab/2026-06-10-collab服务端编排-plan1.md>)、[Plan 2](<aun-fs/collab/2026-06-12-collab协作层-plan2.md>)、[Plan 3](<aun-fs/collab/2026-06-12-collab协作层-plan3.md>)
- `client.notify()` 在线轻量通知、AID/群路由、跨域 federation 和不离线存储边界 → [Notify 通知方案](sdk/Notify通知方案.md)
- 协议细节、子协议和消息格式 → [协议文档目录](protocol/)
- agent.md 远程缓存、`remote_etag` / `local_etag`、消息信封 ETag 透传 → [远程 agent.md 缓存与 ETag 透传方案](agent.md/远程agent.md缓存与etag透传方案.md)

### Service Proxy 与服务暴露

- AUN Service Proxy、service_proxy 服务模块、SDK service-proxy-client、embedded registry、URL 路由、隧道协议和 Docker E2E 入口 → [AUN 反向代理服务方案与 TDD 实施计划](design/AUN反向代理服务方案与TDD实施计划.md)
- Service Proxy `proxy.*` 控制面、proxy-server `register_services` 数据面注册、服务列表一致性和 wakeup 路由语义 → [Service Proxy RPC 手册](sdk/09-proxy-rpc-manual.md)、[服务协议](protocol/06-服务协议.md)
- ACP Proxy 可借鉴点、GlobalRegistry/RSA 不照搬项、目录式 Web 边界 → [AUN 反向代理服务方案与 TDD 实施计划](design/AUN反向代理服务方案与TDD实施计划.md)
- 不影响现有 Gateway、NameService、SDK 接口的 TDD 分阶段计划 → [AUN 反向代理服务方案与 TDD 实施计划](design/AUN反向代理服务方案与TDD实施计划.md)

### 诊断与可观测性

- RPC trace span、跨模块诊断字段、安全字段白名单 → [AUN RPC Trace 增强设计](design/2026-05-22-aun-rpc-trace-enhancement.md)
- aun-console 消息通信服务端可观察总体面板、事实/推断边界 → [AUN 服务端消息通信诊断面板方案](design/AUN服务端消息通信诊断面板方案.md)
- 服务端可观察的消息通信 P0 面板、过滤语义、数据来源 → [服务端消息通信诊断面板 P0 方案](design/服务端消息通信诊断面板P0方案.md)
- 测试日志路径、测试输出、容器日志查看 → [aun测试运行指南](aun测试运行指南.md)
- 跨语言 E2E trace 字段、日志产物、失败分类 → [跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md)

### E2EE 与跨语言一致性

- SDK E2EE API、会话管理、ProtectedHeaders → [SDK 文档索引](sdk/INDEX.md)
- E2EE V2 1DH/per-AID wrap、bootstrap 能力声明、服务端 fanout → [E2EE V2 简化为 1DH + Per-AID Wrap 方案](design/E2EE_V2简化为1DH加Per-AID_Wrap方案.md)
- 共享测试向量、transcript 回放、Python / TS / Go / JS 互通 → [aun测试运行指南](aun测试运行指南.md)、[跨语言容器E2E测试方案](design/跨语言容器E2E测试方案.md)

---

## Layer 3：重点文档摘要

### aun测试运行指南

记录当前 AUN 服务与 SDK 在 Docker 单域、双域环境中的实际测试入口。包含 Python、TypeScript、Go、JavaScript 四语言测试矩阵，Python / TypeScript / Go / JavaScript 跨语言容器 E2E 的 43 用例矩阵，覆盖 P2P 明文/E2EE、群聊 pairwise 明文/E2EE、三语言 agent 同群的明文/E2EE 矩阵，以及 `group_storage_matrix_python_ts_go_js` 四语言 group-storage 互操作，另包含固定身份目录、容器名、典型命令、浏览器 E2E、双域 federation 测试、Service Proxy 单域/双域 E2E 入口和数据保护规则。

### AUN SDK 重构修改清单

记录本轮 AUN SDK 重构执行中的阶段进度、实际修改点、测试命令、测试结果和遗留事项。它是实施过程中的工作清单，最终以 SDK 文档和 skill 同步结果为准。

### AUNClient 拆分重构执行方案

定义在不改变公开 API、协议字段、事件名和默认行为的前提下，如何把 Python / Go / TypeScript / JavaScript SDK 的 `AUNClient` 拆为内部门面、运行时上下文、生命周期控制、RPC 流水线、消息投递、V2 E2EE、群状态和 peer 目录等组件。文档给出 19 个执行步骤、跨 SDK 迁移顺序、风险点和验收矩阵，并记录当前进度：Python 已形成组件化参考实现，TS/JS/Go 已完成 runtime、identity、peers、lifecycle 和 `RpcPipeline` preflight/签名/pull gate/raw call 接入。

### AUNClient 门面化与 Runtime 状态迁移细化方案

在既有 AUNClient 拆分方案基础上，进一步定义“完全门面化、状态全部迁入 runtime”的完成标准和分步执行方法。文档给出状态归属表，将身份与配置、基础依赖、生命周期、RPC、消息投递、V2 E2EE、群状态和 peer 状态分别归入 runtime 与对应 coordinator，并按 Step 0 到 Step 10 说明基线建立、ClientRuntime 状态分区、identity/lifecycle/RPC/delivery/V2/group state 迁移、runtime 写入接口收口、shim 清理、四端 parity 验证和回滚策略。

### 跨语言容器E2E测试方案

定义多语言 SDK 同时作为真实客户端运行的目标测试体系。核心模型是每个语言一个客户端容器，全连接同一 AUN server / gateway；业务消息走 AUN，test-runner 通过每个客户端暴露的 test-control HTTP API 编排动作和断言结果。当前单域落地覆盖 Python / TypeScript / Go / JavaScript 容器互操作；浏览器 JavaScript 网络 E2E 仍按宿主机 Playwright 运行。

### E2EE V2 简化为 1DH + Per-AID Wrap 方案

定义新 SDK 通过 bootstrap 入参声明 `e2ee_wrap_capabilities`，服务端再返回实际 `e2ee_wrap_policy`；旧 SDK 未声明时保留 legacy `3DH/device`。policy 不进入 envelope 或 AAD。方案规定 per-AID row 使用现有 8 字段结构并以 `device_id=""` 标识，服务端按真实 device fanout 但保存 `recipient_row_json` 原始 row，pull 时用原始 row 重建 recipient，确保 Merkle proof 和历史消息兼容。

### AUN RPC Trace 增强设计

设计 RPC trace 的 enter/exit span 结构，补充方法、AID、route、错误码、业务结果等诊断字段，并定义安全字段白名单。目标是在跨模块 RPC 失败时能定位到具体业务原因，而不是只看到模块路径和耗时。

### AUN 服务端消息通信诊断面板方案

记录 aun-console“消息通信”页面的服务端可观察诊断总体方案。方案明确只展示 Gateway、Message/Group、Federation、Service Plane 和模块业务指标可观察事实，不依赖 SDK 诊断模式，不读取 SDK 本地状态，并定义发送端、接收端、消息 ID、Group ID、关键词和任意方向过滤语义。服务端自主 Trace 默认关闭，只能通过面板临时开启。

### 服务端消息通信诊断面板 P0 方案

定义 aun-console 消息通信页的 P0 服务端诊断面板。范围限定为 Gateway、Message/Group、Federation 和 Service Plane 可观察事实，不采集 SDK 本地状态。文档给出发送端、接收端、消息 ID、Group ID 和任意方向过滤语义，并定义服务端 Trace、投递路径、Pull/ACK/GAP、E2EE、Federation、Service Plane 六个子标签，其中服务端自主 Trace 是默认关闭的运行时开关，`message.ack` 需区分 RPC 与同名事件的设备字段语义。

### AUN 反向代理服务方案与 TDD 实施计划

定义 AUN Service Proxy / AUN 服务代理的整体方案：服务侧新增 `service_proxy` 模块，`service-proxy-server` 负责公网 HTTP/HTTPS 入口、WSS 隧道、在线连接索引和协议桥接；SDK 侧 `service-proxy-client` 负责 provider 侧 embedded registry、本地 endpoint 调用和服务摘要上报。方案明确去掉 ACP GlobalRegistry/RSA 同步，URL 以 `https://proxy.{issuer}/{user_name}/{svc_name}/...` 为 canonical，`https://{user_name}.{issuer}/proxy/{svc_name}/...` 由 NameService 跳转；Web 服务推荐 host-root 模式，目录式 path-prefix 只做受限转发。文档还按 Phase 0 到 Phase 11 给出 TDD 实施步骤，记录 Phase 10 已新增宿主机进程内 7 类 HTTP/SSE/WS/NameService/Web/ACL/双域边界 E2E，以及单域和双域 Docker E2E 脚本入口；真实 Docker 执行仍需先满足模块启用、镜像包含新模块和 `/ws/client` AUN 身份 resolver 前置条件。

### 远程 agent.md 缓存与 ETag 透传方案

定义每个远程 AID 在 SDK 内存和本地持久化记录中维护一条 agent.md 状态：Python / TypeScript / Go 使用 `{aun_path}/AIDs/{aid}/agent.md` 与 `agentmd.json`，浏览器 JavaScript 使用 IndexedDB logical key。方案同时规定 `message.send` 响应向发送端透传 `to` 的 agent.md ETag，消息信封向接收端透传 `from` 的 agent.md ETag，并给出按需下载、无条件 GET、304 兼容、竞态和跨 SDK 一致性规则。

### SDK 文档索引

`docs/sdk/INDEX.md` 是 SDK 手册的三层子索引，覆盖快速开始、WebSocket 协议、核心概念、连接认证、E2EE、API 手册、错误处理、最佳实践、payload、Service Proxy、Storage VFS、Group resources pending_ops 执行模型、Collab GC/reflog/reset 和各类 RPC 手册。

### Service Proxy RPC 手册

定义 `proxy.register_services` / `proxy.unregister_services` / `proxy.list_services` 的 Gateway 控制面语义，以及 proxy-server `register_services` 数据面隧道消息、服务列表与连接绑定、一致性约束和 wakeup 路由策略。

### SDK 查阅指南

`docs/sdk/AUN_DOCS_GUIDE.md` 说明如何按行区间渐进式读取 SDK 文档，避免一次性加载过多文档内容。

### AUN Storage 架构设计

定义 AUN Storage 的 SDK VFS、low-level storage client、Storage Service、Storage Core、Metadata Engine 和 Blob Backend 分层。文档明确大文件主数据流量直连 localfs/OSS/S3/COS backend，控制面通过 `storage.*` RPC 管理权限、配额、session/ticket、元数据提交和事件；普通应用通过 SDK VFS 使用类 POSIX 文件操作，底层 session/ticket/complete RPC 保留给 SDK 和高级客户端。文档还定义类 Linux mode/ACL、目录 `x` 位、mount/unmount、symlink/readlink/lstat、share link 与 direct backend ticket 的授权边界。

### AUN Storage SDK 存储分层设计

定义 Python SDK 中 `StorageVFS` 与 `StorageLowLevel` 的分层职责。文档给出应用默认入口、low-level RPC 一对一封装、`NodeView/ObjectView/QuotaView` 返回类型、上传下载编排、路径规范化、P1 list 兼容实现、服务端 code 到 SDK 异常的映射，以及后续 TS/Go/JS 对齐要求。

### AUN Storage CLI-fs 命令设计

定义 `aun fs` 命令组的用户语义和工程落地方式。文档覆盖 `ls/stat/cat/cp/mv/rm/mkdir/ln/df` 等命令、`<AID>:<path>` 寻址规则、操作者身份来源、Typer 命令组注册、路径解析工具、现有 `storage_core.py` 迁移、端到端场景和输出格式规范。

### AUN Storage 分阶段实施计划

把 AUN Storage 架构、SDK 分层和 CLI 设计落地为 6 个 TDD 阶段。文档记录 P1 VFS 基础读写层、P2 symlink 原语、P3 `storage.fs.*` 统一 RPC、P4 ACL/token、P5 四语言 SDK/CLI 对齐和 P6 mount/umount 的实际修改范围、执行顺序、单元/集成/E2E 覆盖内容、Docker 内 Python/TS/Go 实测结果、JS 浏览器 Playwright Storage VFS P6 E2E 补跑结果、公网验证口径修正，以及 P6 退群自动失效和完整虚拟卷生命周期等遗留边界；并在每阶段开始前展开服务端表/RPC 变更、任务依赖图、可并行工作包、TDD 执行步骤和 Docker 验证纪律。

### 群存储 group.resources.* 重构设计

定义 `group.resources.*` 从旧的独立群资源树与 `storage_ref` 引用模型切换为 group_aid storage 命名空间封装层。文档明确 group 服务不持群私钥、不代签，群自有区由群主以 group_aid 身份签名直调 storage，成员 `memberdata/<aid>/` 区由成员自助挂载，storage 通过 CA `aid_type=group` 与 `group.check_membership` 实时校验成员身份。文档还给出目录基线、身份生成与匿名群 bind、群主转让 rekey、鉴权矩阵、pending ops、`group.resources.*` 门面重映射、列表/下载/df/生命周期和服务端改造边界。

### 群存储 group-storage 重构实施计划

把 group-storage 重构拆为 0-10 个 TDD 阶段，覆盖契约脚手架、命名群身份、匿名群 bind、命名空间初始化、自有区写、ACL 映射、读路径、成员挂载、生命周期/df、群主转让 rekey、四语言 SDK 对齐、CLI/E2E/文档收口。文档记录每阶段 IPO、阶段计划、测试矩阵、实际执行记录和命令结果；当前阶段 0-10 的代码与文档收口已完成，Python/TS/JS/Go 单元、服务端 group/CA/storage 回归、Docker 镜像重建、单域 `named_group_storage_full_flow` 与双域 `cross_domain_memberdata_mount_read` E2E 均已通过。

### collab 协作层服务端编排与实施计划

定义 collab 是锚定在 storage 上的自包含版本化目录，服务端负责 `collab.*` 编排、`collab_ledger` 台账、乐观锁、行级 diff3、snapshot、export/adopt、prune 和群协作注册表。Plan 1 拆解 storage 进程内服务端基础实现和测试；Plan 2 扩展 Python SDK/CLI 与单域 Docker E2E；Plan 3 扩展 Go / TypeScript / JavaScript SDK、跨语言互操作和双域边界验证。

### Notify 通知方案

定义 `client.notify()` 的 JSON-RPC Notification 发送语义。方案规定 notify 只投递在线长连接设备，不做离线存储、不分配 seq、不进入 pull/ack；同时说明服务端通知、AID 在线转发、群在线转发、跨域 federation 转发的路由模型，以及和 `message.send` / `group.send` 可靠应用事件的分工。
