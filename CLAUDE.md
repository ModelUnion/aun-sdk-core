# Kite

Kite 框架设计文档查阅方法见 `docs/KITE_DOCS_GUIDE.md`。

**Logs 模块 API 使用说明**见 `docs/logs-api-guide.md`。

## 启动方法

在 Kite 工程目录执行：

```bash
python main.py
```

## 工作规则

### Git 操作安全规则（最高优先级）

**严格禁止在没有用户明确要求的情况下执行以下破坏性 Git 操作：**

- ❌ `git reset --hard` - 会丢失未提交的修改
- ❌ `git checkout -- <file>` - 会覆盖工作区文件
- ❌ `git clean -fd` - 会删除未跟踪的文件
- ❌ `git rebase` - 会重写提交历史
- ❌ `git push --force` - 会覆盖远程仓库

**必须先询问用户才能执行的操作：**
- ⚠️ 任何会修改 Git 历史的操作
- ⚠️ 任何会覆盖工作区文件的操作
- ⚠️ 任何会删除未提交数据的操作

**安全的 Git 操作（可以自主执行）：**
- ✅ `git status` - 查看状态
- ✅ `git log` - 查看历史
- ✅ `git diff` - 查看差异
- ✅ `git add` - 暂存文件
- ✅ `git commit` - 提交更改
- ✅ `git stash` - 暂存工作区（可恢复）

**原则：宁可多问一句，也不要擅自执行破坏性操作。**

## 核心原则

### 零共享代码依赖（最高优先级）

**模块间不可有任何代码级依赖。** 这是 Kite 框架的最高设计原则，确保跨平台、跨语言、跨进程完全兼容。

**严格禁止：**
- ❌ 模块 import 共享库（如 `from core.xxx import yyy`）
- ❌ 模块调用共享函数或类
- ❌ 模块依赖共享配置文件（除环境变量外）
- ❌ 任何形式的代码复用机制（继承、mixin、trait 等）

**唯一允许的共享方式：**
- ✅ 环境变量（`KITE_*`）
- ✅ 文件路径约定（如 `{KITE_MODULE_DATA}/log/`）
- ✅ 文件格式约定（如 JSONL、Markdown）
- ✅ 网络协议（WebSocket JSON-RPC 2.0、stdin JSON）
- ✅ 事件协议（Kernel 事件格式）

**`core/kite_log.py` 的特殊地位：**
- 这是 **Python 模块的便利库**，不是强制依赖
- Node.js/Binary 模块必须独立实现等效功能
- 所有模块必须能在**不依赖任何共享代码**的情况下独立运行
- 如果 `core/kite_log.py` 被删除，所有模块仍应正常工作（自行实现日志规范）

**设计理念：**
- 每个模块是**独立的微服务**，可以用任何语言重写
- 规范定义**接口**（路径、格式、协议），不定义**实现**
- 模块间通过**约定**协作，不通过**代码**耦合

### 跨平台兼容（Windows / Linux / macOS）

- 所有功能必须在三个平台上可用，不可依赖单一平台特有的 API 或工具
- 涉及进程管理、文件系统、信号处理等 OS 相关操作时，必须提供各平台的实现或降级方案
- 外部命令调用（如 `tasklist`、`ps`、`wmic`）必须有多策略降级兜底，不可单点依赖

### 跨语言兼容（Python / Node.js / Binary）

- 模块间通信仅使用语言无关协议：stdin JSON（boot_info）、WebSocket JSON-RPC 2.0
- 不可在框架层引入任何语言特定的 IPC 机制（如 Python multiprocessing、Node IPC channel）
- 进程管理（启动、停止、健康检查、遗留清理）必须对所有 runtime 类型一视同仁

## 参考项目

以下两个项目是 Kite 框架设计的主要参考和比较对象，用于在机制、模式、可扩展性、安全性等层面对标改进：

- **龙虾（clawdbot）** — `C:/Users/agentcp/AppData/Roaming/evol/default/workspace/clawdbot`
  TypeScript/Node.js 个人 AI 助手框架。Gateway WebSocket 控制面 + 插件系统（8 种注册类型）+ Zod schema 配置验证 + 多通道路由 + 设备配对安全模型。架构成熟度高，插件生态完善。
- **CoPaw** — `C:/Users/agentcp/AppData/Roaming/evol/default/workspace/CoPaw-main`
  Python AI 助手框架。FastAPI + AgentScope + 注册表模式（Channel/Skill/Provider）+ Pydantic 配置验证 + 配置热重载 + MCP 客户端管理。单进程异步架构，扩展性好。

以下三个项目是AUN协议的主要参考和比较对象，用于在机制、模式、可扩展性、安全性等层面对标改进：
- **A2A** — `C:/Users/agentcp/AppData/Roaming/evol/default/workspace/a2a`  Agent2Agent (A2A) Protocol
   An open protocol enabling communication and interoperability between opaque agentic applications.

   The Agent2Agent (A2A) protocol addresses a critical challenge in the AI landscape: enabling gen AI agents, built on diverse frameworks by different companies running on separate servers, to communicate and collaborate effectively - as agents, not just as tools. A2A aims to provide a common language for agents, fostering a more interconnected, powerful, and innovative AI ecosystem.

   With A2A, agents can:

   Discover each other's capabilities.
   Negotiate interaction modalities (text, forms, media).
   Securely collaborate on long-running tasks.
   Operate without exposing their internal state, memory, or tools.

- **ACP** — `C:/Users/agentcp/AppData/Roaming/evol/default/workspace/acp-sdk` Agent Connect Protocol The "Agent Connect Protocol SDK" is an open-source library designed to facilitate the adoption of the Agent Connect Protocol. It offers tools for both client and server implementations, enabling seamless integration and communication between multi-agent systems.
- **ANP** — `C:/Users/agentcp/AppData/Roaming/evol/default/workspace/anp` Agent Network Protocol AgentConnect is an open-source SDK implementation of the Agent Network Protocol (ANP).

The goal of Agent Network Protocol (ANP) is to become the HTTP of the Intelligent Agent Internet Era, building an open, secure, and efficient collaborative network for billions of intelligent agents.

### 语言要求

- **所有回复和总结必须使用中文**，包括代码注释中的说明性文字

### 文档命名规范

- **文档文件名使用中文命名**（如 `握手认证方案.md`、`模块开发指南.md`）
- 英文缩写/专有名词可保留原文（如 `WebSocket连接韧性方案.md`、`CLI开发计划.md`）

### 文档写作原则

- **未经用户明确要求，禁止创建任何文档**
- **未经用户明确要求保存文件时，不要生成总结文档、修复文档、对比文档等任何形式的文档**
- 用户的注意力和 token 带宽极其宝贵，不要用廉价的输出浪费
- 用户的输入 token 比你的输出 token 更贵
- **规范文档（如模块开发指南）侧重定义、机制、流程和规范要求**，不堆砌大段代码
- 必要时只附简短代码片段说明关键概念，详细实现引导读者查看实际模块代码
- 非要附代码时，加上参考模块的索引路径即可（如 `extensions/services/watchdog/entry.py`）

### 代码展示规范

- **禁止大段代码罗列**，用户没有时间阅读冗长的代码块
- **只讲清楚机制和细节注意点**，不要展示完整实现
- 如需说明实现细节，使用简短的伪代码或关键代码片段（不超过 10 行）
- 引导用户查看具体文件路径，而不是复制粘贴整个函数
- 例外：当用户明确要求查看完整代码时才展示

## Evol 前端测试框架

Evol 控制台的"模块管理"页面提供了完整的测试中心，支持模块测试、集成测试和完整测试。

### 测试分类

- **模块测试**：测试各个模块（Kernel、Launcher、Watchdog、Web、Backup）的 RPC 方法、事件订阅、API 接口和 Hook
- **集成测试**：测试跨模块流程（注册中心核心、Ping-Pong 机制、认证机制、完整流程）
- **完整测试**：运行所有测试项，生成完整报告和错误报告

### 测试日志

测试输出实时显示在前端页面，测试完成后自动上传到后端保存。

**日志目录**：`C:/Users/agentcp/.kite/workspace/Kite/evol/log/`

**日志文件命名规则**：
- 模块测试：`module_test_{module_name}.log`（如 `module_test_kernel.log`）
- 集成测试：`integration_test_{test_name}.log`（如 `integration_test_pingpong.log`）
- 完整测试：`full_test.log`

**查看所有测试日志**：
```bash
ls -lh C:/Users/agentcp/.kite/workspace/Kite/evol/log/*test*.log 2>/dev/null | grep -v latest
```

**完整路径示例**：
```
C:/Users/agentcp/.kite/workspace/Kite/evol/log/module_test_kernel.log
C:/Users/agentcp/.kite/workspace/Kite/evol/log/integration_test_pingpong.log
C:/Users/agentcp/.kite/workspace/Kite/evol/log/full_test.log
```

每次测试会覆盖同名日志文件。完整测试还可在前端下载两个报告：
- `kite-test-full-{timestamp}.log`：完整日志（所有测试项）
- `kite-test-errors-{timestamp}.log`：错误日志（仅失败项）

### 测试代码结构

```
extensions/services/evol/static/js/tests/
├── test-runner.js          # 测试运行器核心（含日志上传）
├── index.js                # 测试入口和调度
├── modules/                # 模块测试（RPC + 事件 + API + Hook）
│   ├── kernel.js
│   ├── launcher.js
│   ├── watchdog.js
│   ├── web.js
│   └── backup.js
└── integration/            # 集成测试（跨模块流程）
    ├── registry-core.js
    ├── pingpong.js
    ├── auth.js
    └── full-workflow.js
```

详细说明见 `extensions/services/evol/static/js/tests/README.md`。

## 行动规范

### 核心模块修改限制（最高优先级）

**严格禁止未经用户同意的修改：**

1. **禁止擅自启动Kite测试**
   - 不得直接运行 `python main.py` 或任何启动命令
   - 如需测试，必须提示用户手动启动

2. **核心模块代码修改需用户同意**
   - **Kernel**（`kernel/`）— 内核模块
   - **Launcher**（`launcher/`）— 启动器模块
   - **Watchdog**（`extensions/services/watchdog/`）— 监控模块
   - 任何对这三个模块的代码修改必须先征得用户同意

3. **框架机制变更需用户同意**
   - 给任何模块新增 RPC 方法
   - 给任何模块新增事件类型
   - 调整 Kite 框架的核心机制或行为
   - 修改模块间通信协议
   - 变更事件订阅/发布机制

**违反以上规则的后果：**
- 可能破坏系统稳定性
- 可能引入难以追踪的bug
- 可能违背架构设计原则

### 接口变更纪律

- **未经用户确认，不得新增、删除或修改任何模块的对外接口**（HTTP endpoint、WS 消息类型、stdin 协议等）
- 接口是架构契约，变更必须先提出方案、说明理由，获得确认后再动手

### 调试日志

每个模块都有独立的日志目录，路径统一为 `{KITE_INSTANCE_DIR}/{module_name}/log/`。

**查看启动日志**（未特指模块时，默认查看启动器）：

`C:/Users/agentcp/.kite/workspace/Kite/launcher/log/latest.log`

**查看指定模块日志**：

`C:/Users/agentcp/.kite/workspace/Kite/{module_name}/log/latest.log`

其中 `{module_name}` 可以是：`kernel`、`watchdog`、`web`、`backup`、`model_service` 等。

**查看崩溃日志**：

`C:/Users/agentcp/.kite/workspace/Kite/{module_name}/log/crashes.jsonl`

**查看注册中心测试日志**：

`C:/Users/agentcp/.kite/workspace/Kite/web/log/registry_test.log`

**查看退出日志**：

`C:/Users/agentcp/.kite/workspace/Kite/launcher/log/shutdown.log`

所有 `latest.log` 和 `crashes.jsonl` 每次启动时清空，只包含本次运行的内容。历史日志按天保存在同目录下的 `{YYYY-MM}/{YYYY-MM-DD}.log` 和 `crashes/{YYYY-MM}/{YYYY-MM-DD}.jsonl`。

`registry_test.log` 每次测试时覆盖写入，不保留历史记录。

**注册中心测试失败时的调试流程**：

当 `registry_test.log` 显示某个模块的测试失败时，应该：
1. 查看失败测试的时间戳（格式：`[YYYY-MM-DD HH:MM:SS.mmm]`）
2. 根据时间戳查看对应模块的归档日志：`C:/Users/agentcp/.kite/workspace/Kite/{module_name}/log/{YYYY-MM}/{YYYY-MM-DD}.log`
3. 在归档日志中搜索时间戳附近的错误信息，定位问题根源

**多实例共存**：同目录启动多个 Launcher 时，第 1 个实例使用无后缀文件名（完全向后兼容），第 N 个实例使用 `~N` 后缀（如 `latest~2.log`、`crashes~2.jsonl`、`processes~2.json`、`lifecycle~2.jsonl`）。查看日志时默认读无后缀文件；多实例场景可搜索带 `~` 后缀的文件。

详细规范见 `docs/日志与异常处理规范.md`。

### 文档索引同步

当新增文档或大幅更新文档后，必须主动同步更新两个索引文件：

- `docs/INDEX.md` — 三层索引（Layer 1 地图 + Layer 2 交叉索引 + Layer 3 详细摘要）
- `docs/KITE_DOCS_GUIDE.md` — 查阅指南中的行区间引用

### 流程机制调试规范

当涉及框架流程机制的问题（如事件传递、RPC 调用、模块状态变更等）需要调试时：

**调试流程：**

1. **梳理流程** — 先通过阅读代码梳理完整的调用链路和数据流
2. **提出调试方案** — 如果梳理后仍找不到问题，向用户说明需要在哪些关键节点添加临时调试日志，等待用户同意
3. **添加调试日志** — 获得用户同意后，在关键节点添加临时调试日志
   - 在流程的入口、出口、分支点添加 `print()` 日志
   - 日志必须标记 `DEBUG:` 前缀便于后续清理
4. **提示用户测试** — 添加日志后，提示用户重启 Kite 进行测试
5. **分析日志** — 用户重启后，读取相关模块的 `latest.log` 分析问题
6. **清理日志** — 问题解决并经用户确认后，清理所有临时调试日志

**注意事项：**
- 添加调试日志前必须征得用户同意（属于代码修改）
- 调试日志必须标记 `DEBUG:` 前缀
- 不要在生产代码中保留调试日志
- 清理时搜索 `DEBUG:` 关键词确保全部移除

### 兼容性自动审查

当新增或修改了以下类型的功能时，必须主动进行跨平台 + 跨语言兼容性审查并给出改进建议：

- 进程创建、销毁、信号发送
- 文件路径拼接、临时文件、锁文件
- 外部命令调用（shell 命令、系统工具）
- 网络端口绑定、服务发现
- 环境变量、编码处理
- 

### 相关项目及文档位置

1. aun服务模块: ../extensions/services
2. docker发布环境 ../docker-deploy, 跑集成测试和E2E测试时如果aun服务模块的代码有修改，需要重新build和重启docker镜像
3. 测试脚本目录 ../tests
4. aun协议文档目录 ../docs/aun文档/aun协议
5. aun skill目录 ../../aun-skill/.claude/skills/aun-sdk
6. aun sdk文档目录 ./python/docs
7. ./python/src/aun-core/docs 这下面的文档不用直接编辑，发布前可通过./python/sync_docs.py同步过去
