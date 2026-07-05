# AUN CLI 手册

## 位置与入口

AUN CLI 是 Python SDK 的命令行工具，源码位于：

```text
D:\modelunion\kite\aun-sdk-core\python\src\aun_cli
```

仓库内相对路径为 `python/src/aun_cli`。安装入口在 `python/pyproject.toml`：

```toml
[project.scripts]
aun = "aun_cli.main:app"
```

开发环境可直接运行：

```powershell
cd D:\modelunion\kite\aun-sdk-core\python
pip install -e .
aun --help
```

也可以不安装包，直接指定 `PYTHONPATH`：

```powershell
$env:PYTHONPATH="D:\modelunion\kite\aun-sdk-core\python\src"
python -m aun_cli --help
```

## 全局用法

```text
aun [全局选项] <command> [参数]
```

全局选项：

| 选项 | 说明 |
|------|------|
| `--profile, -p` | 仅本次命令使用指定 profile |
| `--json` | 输出 JSON，适合脚本 |
| `--debug` | 启用 debug 日志 |
| `--no-color` | 禁用彩色输出 |
| `--timeout, -t` | 操作超时秒数，默认 30 |
| `--version, -V` | 显示版本 |
| `--install-completion` | 安装当前 shell 的补全脚本，Typer 自动提供 |
| `--show-completion` | 输出补全脚本，Typer 自动提供 |
| `--help` | 显示帮助 |

CLI 不提供 `--gateway` 选项；Gateway 发现由 SDK 处理。

非 JSON 模式会先打印当前 `profile`、`aid`、`active_group` 和 `trace`，命令结束时可能输出 RPC summary。脚本里建议使用 `--json`。

## 配置与 Profile

默认配置文件为 `~/.aun/cli.toml`。常用命令：

```powershell
aun profile create dev --aid alice.agentid.pub
aun profile switch dev
aun profile current
aun profile list

aun config set timeout 60
aun config get timeout
aun config list
```

`profile` 也挂在 `config` 下，`aun config profile list/current/create/switch` 与根级 `aun profile ...` 使用同一套实现。

当前 profile 的核心字段：

| 字段 | 说明 |
|------|------|
| `aid` | 默认操作身份 |
| `aun_path` | 本地身份、密钥、日志等数据目录 |
| `active_group` | 默认群组；值使用目标态 `group_aid`，省略 `group_id` 兼容参数时使用 |
| `debug` / `trace` / `timeout` | 调试、trace 和超时配置 |

有效 profile 选择顺序：

```text
--profile > AUN_PROFILE > 当前终端标签页状态 > default.profile
```

## 身份命令

| 命令 | 用法 |
|------|------|
| `aun register <aid>` | 注册新 AID，并写入当前 profile |
| `aun login [aid]` | 加载本地身份、认证并连接一次 |
| `aun whoami` | 查看当前 profile / AID / 数据目录 |
| `aun identity list` | 列出本地身份 |
| `aun identity check <aid>` | 检查本地身份材料和远端注册状态 |

示例：

```powershell
aun register alice.agentid.pub
aun login alice.agentid.pub
aun whoami
aun identity check alice.agentid.pub
```

## P2P 消息命令

| 命令 | 用法 |
|------|------|
| `aun send <target-aid> <message>` | 发送 P2P 消息，默认加密 |
| `aun send <target-aid> -` | 从 stdin 读取消息 |
| `aun pull [--from aid] [--limit N] [--after-seq N]` | 拉取离线消息 |
| `aun ack <sender-aid> --seq N` | 确认消息 seq |
| `aun listen [--from aid] [--group group_id]` | 实时监听 P2P 和群消息；`group_id` 是兼容参数名，值使用 `group_aid` |

示例：

```powershell
aun send bob.agentid.pub "hello"
Get-Content .\msg.txt | aun send bob.agentid.pub -
aun pull --limit 20
aun listen --from bob.agentid.pub
```

## 群组命令

| 命令 | 用法 |
|------|------|
| `aun group create <name> [--members a,b] [--group-name name]` | 创建群；成功后自动设为 active group |
| `aun group use <group-id>` | 设置当前 active group |
| `aun group current` | 查看当前 active group |
| `aun group send [group-id] <message>` | 发送群消息；省略 group-id 时使用 active group |
| `aun group list` | 列出已加入群 |
| `aun group info [group-id]` | 查看群详情 |
| `aun group members [group-id]` | 查看成员 |
| `aun group invite [group-id] <aid...>` | 邀请成员 |
| `aun group add-member [group-id] <aid> [--role member|admin]` | 直接添加成员 |
| `aun group kick [group-id] <aid>` | 移除成员 |
| `aun group leave [group-id]` | 退出群 |
| `aun group dissolve [group-id]` | 解散群 |
| `aun group bind [group-id] [--group-name name]` | 为匿名群补齐 group_aid；`bind-aid` 是公开别名 |
| `aun group transfer [group-id] <new-owner>` | 转移群主 |
| `aun group complete-transfer [group-id]` | 完成转让后的 group.fs rekey |

`aun group add_member` 是 `aun group add-member` 的公开兼容别名。

示例：

```powershell
aun group create "项目讨论组" --members bob.agentid.pub,carol.agentid.pub
aun group current
aun group send "大家好"
aun group members
aun group add-member dave.agentid.pub --role member
```

## 群文件系统命令

`aun group fs` 对应 `group.fs.*` 和 SDK `client.group.fs`。裸路径使用当前 active group；完整 group path 也可直接传入。

| 命令 | 用法 |
|------|------|
| `aun group fs ls [path] [-l]` | 列出目录 |
| `aun group fs find [path] [--name "*.md"] [--type f]` | 查找节点 |
| `aun group fs stat <path>` | 查看节点 |
| `aun group fs lstat <path>` | 查看链接本身 |
| `aun group fs mkdir <path> [-p]` | 创建目录 |
| `aun group fs rm <path> [-r] [--force]` | 删除节点 |
| `aun group fs cp <src> <dst> [-r] [--force]` | 上传、下载或远程复制 |
| `aun group fs mv <src> <dst> [--force]` | 远程移动 |
| `aun group fs df [path]` | 查看用量 |
| `aun group fs setfacl <path> -m role:admin:<perms>` | 群主授予群自有区 admin 角色 ACL |
| `aun group fs setfacl <path> -x role:admin` | 群主撤销群自有区 admin 角色 ACL |
| `aun group fs getfacl <path>` | 查看群自有区角色 ACL |
| `aun group fs mount <path> [--readonly/--readwrite]` | 挂载成员数据区 |
| `aun group fs umount <path>` | 卸载成员数据区 |

示例：

```powershell
aun group fs mkdir /docs -p
aun group fs cp .\README.md /docs/README.md
aun group fs ls /docs -l
aun group fs setfacl /docs -m role:admin:rwx
aun group fs getfacl /docs
aun group fs cp /docs/README.md .\downloaded.md
```

群自有区写入需要使用当前 `group_identity` 对应的 `group_aid` 身份签名时，可通过 `--as <group-aid>` 指定操作者。`setfacl/getfacl` 只允许当前 group owner 调用；当前只支持 `role:admin` 角色 ACL，权限位对外显示为 POSIX 视图 `rwx`。

## Storage VFS 命令

`aun fs` 是普通 Storage VFS 入口，路径格式为 `<AID>:/path`。裸路径自动使用当前 profile AID。

| 命令 | 用法 |
|------|------|
| `aun fs ls <path> [-l]` | 列目录 |
| `aun fs stat <path> [-L]` | 查看节点，`-L` 跟随链接 |
| `aun fs cat <path>` | 输出文件内容 |
| `aun fs cp <src> <dst>` | 本地/远程上传下载或远程复制 |
| `aun fs mv <src> <dst>` | 同 AID 内原子移动 |
| `aun fs rm <path> [-r]` | 删除 |
| `aun fs ln -s <target> <link-path>` | 创建软链 |
| `aun fs mkdir <path> [-p]` | 创建目录 |
| `aun fs touch <path> [-p] [--no-create] [--mtime TS]` | 创建空文件或更新时间戳 |
| `aun fs df <aid:>` | 查看用量 |
| `aun fs quota [aid:]` | 查看配额 |
| `aun fs du <path> [-h] [--max-depth N]` | 汇总路径占用 |
| `aun fs find <path> [--name PATTERN] [--type f|d|l]` | 查找 |
| `aun fs chmod +r <path>` / `aun fs chmod o-r <path>` | 设置 public/private |
| `aun fs setfacl <path> -m aid:<AID>:<perms>` / `-x aid:<AID>` | 设置或移除 ACL |
| `aun fs getfacl <path>` | 查看 ACL |
| `aun fs mount/approve/reject/umount ...` | 挂载生命周期 |
| `aun fs token issue/revoke/ls ...` | 访问 token 管理 |

示例：

```powershell
aun fs mkdir alice.agentid.pub:/docs -p
aun fs touch alice.agentid.pub:/docs/empty.txt --mtime 1700000000
aun fs cp .\a.txt alice.agentid.pub:/docs/a.txt
aun fs cat alice.agentid.pub:/docs/a.txt
aun fs token issue alice.agentid.pub:/docs/a.txt
```

## 对象存储兼容命令

`aun storage` 是对象级快捷入口，适合低层调试和兼容旧用法：

```powershell
aun storage ls docs/
aun storage info docs/a.txt
aun storage upload .\a.txt --name docs/a.txt --force
aun storage download docs/a.txt -o .\a.txt --force
aun storage delete docs/a.txt
```

新应用优先使用 `aun fs`。

## Collab 命令

`aun collab` 操作版本化协作目录：

| 命令 | 用法 |
|------|------|
| `aun collab ls-files <collab-root>` | 列出文档 |
| `aun collab create <root> <doc> <source>` | 创建文档 |
| `aun collab show <root> <doc> [--rev N] [-o file]` | 查看版本 |
| `aun collab commit <root> <doc> <source> --onto N` | 提交版本 |
| `aun collab merge <root> <doc> <source> --onto N` | 三方合并 |
| `aun collab log <root> <doc>` | 历史 |
| `aun collab diff <root> <doc> --from A --to B` | 差异 |
| `aun collab revert <root> <doc> --rev N` | 回退 |
| `aun collab clone <src> <dest> [--reroot]` | 克隆 |
| `aun collab prune/gc/reflog ...` | 清理和审计 |
| `aun collab ls-remote <group-aid>` | 列群内协作目录 |
| `aun collab unregister <group-aid> <root>` | 取消群注册 |
| `aun collab tag create/list/show/diff/restore/rm/prune ...` | 目录级标签 |

示例：

```powershell
aun collab create alice.agentid.pub:/repo notes.md .\notes.md
aun collab show alice.agentid.pub:/repo notes.md -o .\notes.md
aun collab commit alice.agentid.pub:/repo notes.md .\notes.md --onto 1 --message "update"
```

## agent.md、密钥、诊断和压测

agent.md：

```powershell
aun agentmd upload
aun agentmd download bob.agentid.pub
aun agentmd check bob.agentid.pub --max-unsynced-days 1
```

`upload_agent_md`、`download_agent_md`、`check_agent_md` 是 `upload`、`download`、`check` 的公开兼容别名。

密钥：

```powershell
aun keys list
aun keys rotate --type spk
aun keys change-seed --old-seed .seed --new-seed "new-seed"
```

诊断：

```powershell
aun status
aun ping bob.agentid.pub --count 3
aun doctor
aun logs --tail 100
aun logs --follow
```

压测：

```powershell
aun bench send bob.agentid.pub --count 100 --concurrency 4
aun bench group-send 10042.agentid.pub --count 100 --concurrency 4
aun bench group send --count 100
```

`aun bench group_send` 是 `aun bench group-send` 的公开兼容别名。

## 退出码

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

## 相关实现文件

| 文件 | 说明 |
|------|------|
| `python/src/aun_cli/main.py` | 根应用和命令注册 |
| `python/src/aun_cli/config.py` | CLI 配置、profile、标签页状态 |
| `python/src/aun_cli/adapter.py` | SDK 会话桥接、错误映射、RPC summary |
| `python/src/aun_cli/output.py` | 输出格式 |
| `python/src/aun_cli/commands/*.py` | 各命令组实现 |
