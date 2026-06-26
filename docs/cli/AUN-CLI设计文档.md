# AUN CLI 设计文档

## 1. 定位

AUN CLI 是 Python SDK 随包提供的命令行入口，用于在不编写业务代码的情况下完成身份管理、消息收发、群组操作、Storage / Group FS 文件操作、Collab 协作层操作、agent.md 管理、诊断和压测。

当前实现位于：

- 源码目录：`D:\modelunion\kite\aun-sdk-core\python\src\aun_cli`
- 包内入口：`python/src/aun_cli/main.py`
- 模块入口：`python -m aun_cli`
- 安装后命令：`aun`
- 脚本注册：`python/pyproject.toml` 中的 `[project.scripts] aun = "aun_cli.main:app"`

CLI 是 SDK 的薄封装和调试入口，不直接实现协议状态机、E2EE、Gateway 发现或业务 RPC 语义；这些能力由 `aun_core` 提供。

## 2. 当前架构

```text
aun CLI
  ├─ main.py                 # Typer 根应用、全局选项、命令组注册
  ├─ config.py               # cli.toml、profile、终端标签页状态
  ├─ adapter.py              # AUNClient / AIDStore 生命周期桥接
  ├─ output.py               # human / table / JSON 输出
  ├─ storage_core.py         # storage object 上传下载数据面复用逻辑
  ├─ fs_utils.py             # AID:path 远程路径解析
  └─ commands/
      ├─ identity.py         # identity list/check；根命令 register/login/whoami 复用这里
      ├─ message.py          # send/pull/ack
      ├─ listen.py           # listen 长连接监听
      ├─ group.py            # group.* 与 group fs
      ├─ fs.py               # storage VFS POSIX 风格 fs 命令
      ├─ storage.py          # object storage 兼容命令
      ├─ collab.py           # collab 与 collab tag
      ├─ agentmd.py          # agent.md 上传、下载、检查
      ├─ keys.py             # 本地密钥与 seed 迁移
      ├─ diag.py             # status/ping/doctor/logs
      ├─ config.py           # config/profile
      └─ bench.py            # message/group 发送压测
```

核心调用链：

```text
Typer command
  -> resolve_profile_config(ctx)
  -> CLISession(ctx)
  -> AIDStore.load(aid)
  -> AUNClient.authenticate()
  -> AUNClient.connect()
  -> client.call(...) / client.storage.* / client.group.fs.* / client.collab.*
  -> output_json / output_table / output_dict
```

## 3. 关键设计决策

| 主题 | 当前实现 |
|------|----------|
| 命令框架 | 使用 Typer，根应用在 `main.py` 中注册 |
| SDK 桥接 | `adapter.run_async()` 用 `asyncio.run()` 执行 SDK 异步调用 |
| 会话生命周期 | 每个短命令创建一个 `CLISession`，完成后关闭 `AUNClient` 和 `AIDStore` |
| Gateway | CLI 不提供 `--gateway` 覆盖；Gateway 发现交给 SDK |
| Profile | 默认读取 `~/.aun/cli.toml`，支持终端标签页级 profile 状态 |
| 输出 | 默认人类可读；`--json` 输出结构化 JSON |
| RPC 统计 | 非 JSON 模式下输出本次 CLI 调用的 RPC / phase summary |
| 长连接 | `aun listen` 使用 `background_sync=True`，监听 P2P 与群消息事件 |
| 数据面 | Storage / Group FS 的上传下载由 SDK 高层或 `storage_core.py` 编排 |

## 4. 全局选项

当前根命令支持：

```text
aun [全局选项] <command> [参数]

--profile, -p TEXT   仅本次命令使用指定 profile
--json               JSON 格式输出
--debug              启用 debug 日志
--no-color           禁用彩色输出
--timeout, -t INT    操作超时秒数，默认 30
--version, -V        显示 CLI 版本
--install-completion 安装当前 shell 的补全脚本，Typer 自动提供
--show-completion    输出补全脚本，Typer 自动提供
--help               显示帮助
```

注意：旧设计稿中的 `--gateway`、`-g` 不存在。当前 Gateway 路由由 SDK discovery 处理。

## 5. 配置与 Profile

配置文件默认路径为 `~/.aun/cli.toml`，可用 `AUN_CLI_CONFIG` 覆盖。配置结构：

```toml
[default]
profile = "default"
output = "table"
color = true
timeout = 30

[profiles.default]
aid = "alice.agentid.pub"
aun_path = "~/.aun/profiles/default"
active_group = "group.agentid.pub/10042"
```

有效 profile 解析顺序：

```text
--profile > AUN_PROFILE > 当前终端标签页状态 > [default].profile
```

`aun profile switch` 会写入当前终端标签页状态，同时更新新标签页默认 profile。终端标签页状态目录默认在 `~/.aun/cli-sessions/`，可用 `AUN_CLI_STATE_DIR` 覆盖。

常用环境变量：

| 变量 | 用途 |
|------|------|
| `AUN_CLI_CONFIG` | 覆盖 CLI 配置文件路径 |
| `AUN_PROFILE` | 覆盖本次命令 profile |
| `AUN_CLI_SESSION_ID` | 显式指定终端标签页状态 ID |
| `AUN_CLI_STATE_DIR` | 覆盖标签页状态目录 |
| `AUN_DATA_ROOT` | 覆盖当前 profile 的 `aun_path` |
| `AUN_DEBUG` | 开启 debug |
| `AUN_ENCRYPTION_SEED` / `AUN_SEED_PASSWORD` | 本地身份材料加密 seed |

## 6. 命令注册面

根命令在 `main.py` 中注册：

| 命令 | 来源模块 | 说明 |
|------|----------|------|
| `register` / `login` / `whoami` | `commands.identity` | 根级身份快捷命令 |
| `identity` | `commands.identity` | 身份列表和诊断 |
| `send` / `pull` / `ack` | `commands.message` | P2P 消息 |
| `listen` | `commands.listen` | P2P + 群消息实时监听 |
| `group` | `commands.group` | 群组管理和 `group fs` |
| `status` / `ping` / `doctor` / `logs` | `commands.diag` | 诊断 |
| `config` / `profile` | `commands.config` | 配置和 profile 管理；`profile` 也挂在 `config profile` 下 |
| `storage` | `commands.storage` | 对象存储兼容命令 |
| `fs` | `commands.fs` | Storage VFS / POSIX 风格命令 |
| `collab` | `commands.collab` | 版本化协作层 |
| `agentmd` | `commands.agentmd` | agent.md 管理 |
| `keys` | `commands.keys` | 本地密钥与 seed 管理 |
| `bench` | `commands.bench` | 消息发送压测 |

## 7. 命令组职责

### 7.1 身份与连接

- `aun register <aid>`：注册 AID，并写入当前 profile 的 `aid` / `aun_path`。
- `aun login [aid]`：加载本地身份、认证并连接一次，成功后更新当前 profile 的 AID。
- `aun whoami`：显示当前 profile、AID 和数据目录。
- `aun identity list`：列出本地身份。
- `aun identity check <aid>`：检查本地身份材料和远端注册状态。

### 7.2 消息

- `aun send <target-aid> <message|-> [--no-encrypt]`：发送 P2P 消息，`-` 表示从 stdin 读取。
- `aun pull [--from <aid>] [--limit N] [--after-seq N]`：拉取离线消息。
- `aun ack <sender-aid> --seq N`：推进消息 ack。
- `aun listen [--from <aid>] [--group <group-id>]`：监听 P2P 和群消息，Ctrl+C 退出。

### 7.3 群组

- `aun group create <name> [--members a,b] [--group-name name]`
- `aun group use <group-id>` / `aun group current`
- `aun group send [group-id] <message> [--no-encrypt]`
- `aun group list` / `aun group info [group-id]` / `aun group members [group-id]`
- `aun group invite [group-id] <aid...>`
- `aun group add-member [group-id] <aid> [--role member|admin] [--member-type human|ai]`
- `aun group kick [group-id] <aid>`
- `aun group leave [group-id]`
- `aun group dissolve [group-id]`
- `aun group bind [group-id] [--group-name name]`
- `aun group transfer [group-id] <new-owner>`
- `aun group complete-transfer [group-id]`

公开兼容别名包括 `aun group bind-aid` 和 `aun group add_member`。

多数群命令省略 `group-id` 时使用当前 profile 的 `active_group`。`aun group create` 成功后会自动把新群设为 active group。

### 7.4 群文件系统

`aun group fs` 面向 `group.fs.*` 和 SDK `client.group.fs`。裸路径会绑定当前 active group；完整 group path 可直接传入。

主要命令：

- `ls` / `find` / `stat` / `lstat`
- `mkdir` / `rm`
- `cp` / `mv`
- `df`
- `setfacl` / `getfacl`
- `mount` / `umount`

群自有区写入需要按服务端要求使用 `group_aid` 身份签名，CLI 通过 `--as` 传入操作者 AID。角色 ACL 命令只管理 `role:admin`：`setfacl -m role:admin:rwx` 授权，`setfacl -x role:admin` 撤销，`getfacl` 查询。

### 7.5 Storage VFS

`aun fs` 面向 SDK Storage VFS，路径格式为 `<AID>:/path`。裸路径会补当前 profile AID。

主要命令：

- 读侧：`ls`、`stat`、`cat`、`find`、`df`、`quota`、`du`
- 写侧：`cp`、`mv`、`rm`、`mkdir`、`touch`、`ln -s`
- 权限：`chmod`、`setfacl`、`getfacl`
- 挂载：`mount`、`approve`、`reject`、`umount`
- token：`token issue`、`token revoke`、`token ls`

### 7.6 对象存储兼容命令

`aun storage` 保留对象级快捷入口：

- `aun storage ls [prefix]`
- `aun storage info <object-key>`
- `aun storage upload <local-path> [--name key] [--public] [--force]`
- `aun storage download <object-key> [-o path] [--force]`
- `aun storage delete <object-key>`

新应用优先使用 `aun fs`；对象命令主要用于兼容对象存储心智和低层调试。

### 7.7 Collab

`aun collab` 面向版本化协作目录：

- 文档：`ls-files`、`create`、`show`、`commit`、`merge`、`log`、`diff`、`revert`
- 运维：`clone`、`prune`、`gc`、`reflog`
- 群发现：`ls-remote`、`unregister`
- 标签：`tag create/list/show/diff/restore/rm/prune`

`create` / `commit` / `merge` 的 `source` 支持 AID 远程路径、本地文件、base64 或普通文本。

### 7.8 agent.md、keys、诊断与压测

- `aun agentmd upload/download/check`
- `aun keys list/rotate/change-seed`
- `aun status` / `aun ping` / `aun doctor` / `aun logs`
- `aun bench send` / `aun bench group-send` / `aun bench group send`

公开兼容别名包括 `aun agentmd upload_agent_md/download_agent_md/check_agent_md` 和 `aun bench group_send`。

当前没有 `keys export/import`、`group listen`、`config init`、`profile delete` 这些命令；需要新增时应先更新实现和本文档。

## 8. 错误处理与退出码

错误映射在 `adapter.handle_error()` 中：

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 通用错误 |
| 2 | 参数错误 |
| 3 | 认证失败 |
| 4 | 连接失败 |
| 5 | 超时 |
| 6 | 权限不足 |
| 7 | 目标不存在 |

JSON 模式下错误仍通过统一错误输出函数输出，便于脚本判断。

## 9. 当前实现边界

- CLI 不直接接受外部 Gateway URL，避免绕过 SDK discovery。
- CLI 不维护独立协议实现；业务行为以 SDK 和服务端为准。
- 默认短命令不启用长连接重连；`listen` 使用后台同步和自动重连。
- `--json` 会关闭 banner 和 RPC summary，适合脚本管道。
- `aun group fs` 是 Group FS 入口；`aun fs` 是普通 Storage VFS 入口，两者路径模型不同。
