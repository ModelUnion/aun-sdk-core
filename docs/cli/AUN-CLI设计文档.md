# AUN CLI 设计文档

## 1. 定位

AUN CLI 是面向开发者和运维的命令行工具，提供与 AUN 网络交互的完整能力：身份管理、消息收发、群组操作、加密状态检查、故障诊断。

核心价值：不写代码即可完成 AUN 协议的全部操作，同时作为 SDK 功能的验证工具和调试入口。

## 2. 架构

```
┌─────────────────────────────────────────────┐
│                  aun CLI                     │
│  ┌─────────┐ ┌─────────┐ ┌──────────────┐  │
│  │ typer   │ │ config  │ │ output fmt   │  │
│  │ routing │ │ manager │ │ (table/json) │  │
│  └────┬────┘ └────┬────┘ └──────┬───────┘  │
│       │            │             │           │
│  ┌────▼────────────▼─────────────▼────────┐ │
│  │           SDK Adapter Layer             │ │
│  │  (async → sync bridge, session mgmt)   │ │
│  └────────────────┬───────────────────────┘ │
└───────────────────┼─────────────────────────┘
                    │
┌───────────────────▼───────────────────────┐
│              aun_core (SDK)                │
│  AUNClient / AuthFlow / E2EE / Groups     │
└───────────────────────────────────────────┘
```

### 2.1 关键设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| 命令框架 | typer | 类型注解驱动，自动生成 help，比 click 更简洁 |
| 异步桥接 | asyncio.run() 包装 | SDK 全异步，CLI 需要同步入口 |
| 配置格式 | TOML | Python 生态标准，人类可读 |
| 输出格式 | 默认 human-readable，`--json` 切换 | 兼顾交互和脚本管道 |
| 状态持久化 | 复用 SDK 的 aun_path 目录 | 零额外存储概念 |
| 分发方式 | pip + PyInstaller 独立二进制 | 覆盖开发者和终端用户 |

### 2.2 目录结构

```
aun-sdk-core/python/
├── src/
│   ├── aun_core/              # 现有 SDK（不动）
│   └── aun_cli/               # CLI 工具
│       ├── __init__.py
│       ├── __main__.py        # python -m aun_cli 入口
│       ├── main.py            # typer app 定义 + 全局选项
│       ├── adapter.py         # SDK 异步桥接 + 会话管理
│       ├── config.py          # profile/配置 CRUD
│       ├── output.py          # 输出格式化（table/json/plain）
│       └── commands/
│           ├── __init__.py
│           ├── identity.py    # register / login / whoami / list
│           ├── message.py     # send / pull / listen / ack
│           ├── group.py       # create / send / invite / kick / ...
│           ├── storage.py     # upload / download / delete
│           ├── keys.py        # list / rotate / export / import
│           └── diag.py        # doctor / status / ping / trace / logs
└── pyproject.toml             # 新增 [project.scripts] aun = "aun_cli.main:app"
```

## 3. 全局选项

```
aun [全局选项] <command> [子选项] [参数]

全局选项：
  --profile, -p TEXT     使用指定 profile（默认 "default"）
  --gateway, -g URL      覆盖网关地址
  --json                 JSON 格式输出
  --debug                启用 debug 日志
  --no-color             禁用彩色输出
  --timeout, -t INT      操作超时秒数（默认 30）
  --version, -V          显示版本
  --help, -h             显示帮助
```

## 4. 命令详细设计

### 4.1 身份管理 (identity)

#### `aun register`

注册新 AID 并保存到本地 profile。

```
aun register <aid> --gateway <url> [--password <seed-password>]

示例：
  aun register alice@aid.com --gateway wss://gw.aid.com/ws
  aun register bob@example.com -g wss://gw.example.com/ws -p work
```

流程：
1. 生成 P-256 密钥对
2. 连接网关，调用 `auth.create_aid()`
3. 保存身份材料到 `~/.aun/profiles/{profile}/AIDs/{aid}/`
4. 输出注册结果（AID、证书指纹、有效期）

#### `aun login`

登录已有 AID（验证本地密钥可用，刷新 token）。

```
aun login [aid]

示例：
  aun login                    # 登录当前 profile 的默认 AID
  aun login alice@aid.com      # 指定 AID
```

#### `aun whoami`

显示当前身份信息。

```
aun whoami

输出：
  AID:        alice@aid.com
  Profile:    default
  Gateway:    wss://gw.aid.com/ws
  Cert:       SHA256:a1b2c3... (expires 2027-01-15)
  State:      authenticated
  Device ID:  d8f2...
```

#### `aun identity list`

列出本地所有身份。

```
aun identity list

输出：
  PROFILE   AID                GATEWAY              STATUS
  default   alice@aid.com      wss://gw.aid.com     active
  work      bot@corp.com       wss://gw.corp.com    expired
```

### 4.2 消息 (message)

#### `aun send`

发送 P2P 消息。

```
aun send <target-aid> <message> [--no-encrypt] [--persist]

示例：
  aun send bob@aid.com "hello"
  aun send bob@aid.com --no-encrypt "plaintext msg"
  echo "piped content" | aun send bob@aid.com -
```

- 默认 E2EE 加密
- 支持 stdin 管道输入（`-` 表示从 stdin 读取）
- `--persist` 标志控制消息持久化

#### `aun pull`

拉取离线消息。

```
aun pull [--from <aid>] [--limit N] [--after-seq N]

示例：
  aun pull                         # 拉取所有未读
  aun pull --from bob@aid.com      # 只拉某人的
  aun pull --limit 10              # 最多 10 条
```

#### `aun listen`

实时监听消息（长连接，类似 tail -f）。

```
aun listen [--from <aid>] [--include-group]

示例：
  aun listen                       # 监听所有 P2P 消息
  aun listen --include-group       # 同时监听群消息
  aun listen --from bob@aid.com    # 只监听某人

输出（逐行）：
  [2026-05-21 14:32:01] bob@aid.com → you: hello
  [2026-05-21 14:32:05] group:abc123 carol@aid.com: meeting at 3pm
```

Ctrl+C 退出。

#### `aun ack`

确认消息。

```
aun ack <sender-aid> --seq <N>
aun ack --all
```

### 4.3 群组 (group)

#### `aun group create`

```
aun group create <name> [--members <aid1,aid2,...>]

示例：
  aun group create "Project Alpha"
  aun group create "Team" --members bob@aid.com,carol@aid.com
```

#### `aun group list`

```
aun group list

输出：
  GROUP ID     NAME            MEMBERS  ROLE    EPOCH
  g:abc123     Project Alpha   5        owner   3
  g:def456     Team Chat       3        member  1
```

#### `aun group send`

```
aun group send <group-id> <message> [--no-encrypt]

示例：
  aun group send g:abc123 "hello team"
```

#### `aun group invite`

```
aun group invite <group-id> <aid> [<aid2> ...]

示例：
  aun group invite g:abc123 dave@aid.com eve@aid.com
```

#### `aun group kick`

```
aun group kick <group-id> <aid>
```

#### `aun group leave`

```
aun group leave <group-id>
```

#### `aun group dissolve`

```
aun group dissolve <group-id>
```

#### `aun group members`

```
aun group members <group-id>

输出：
  AID                ROLE     JOINED
  alice@aid.com      owner    2026-05-01
  bob@aid.com        admin    2026-05-02
  carol@aid.com      member   2026-05-10
```

#### `aun group info`

```
aun group info <group-id>

输出：
  Name:         Project Alpha
  ID:           g:abc123
  Owner:        alice@aid.com
  Members:      5
  Epoch:        3
  E2EE:         enabled (V2)
  Created:      2026-05-01
```

#### `aun group listen`

```
aun group listen <group-id>

输出（逐行）：
  [14:32:01] bob@aid.com: let's sync
  [14:32:05] carol@aid.com: sounds good
```

### 4.4 存储 (storage)

#### `aun storage upload`

```
aun storage upload <local-path> [--name <remote-name>]

示例：
  aun storage upload ./report.pdf
  aun storage upload ./img.png --name avatar.png
```

#### `aun storage download`

```
aun storage download <object-id> [--output <path>]
```

#### `aun storage delete`

```
aun storage delete <object-id>
```

### 4.5 密钥管理 (keys)

#### `aun keys list`

```
aun keys list

输出：
  TYPE    ID/FINGERPRINT          CREATED      EXPIRES      STATUS
  IK      SHA256:a1b2c3...        2026-05-01   2027-05-01   active
  SPK     SHA256:d4e5f6...        2026-05-20   2026-06-20   active
  SPK     SHA256:789abc...        2026-04-20   2026-05-20   expired
```

#### `aun keys rotate`

```
aun keys rotate [--type spk|ik]

示例：
  aun keys rotate              # 轮换 SPK
  aun keys rotate --type ik    # 轮换 IK（需确认）
```

#### `aun keys export`

导出身份（加密打包）。

```
aun keys export [aid] --output <path> --password <password>

示例：
  aun keys export alice@aid.com --output ./alice-backup.aun
```

#### `aun keys import`

导入身份。

```
aun keys import <path> --password <password> [--profile <name>]
```

### 4.6 诊断 (diag)

#### `aun doctor`

一键健康检查。

```
aun doctor

输出：
  ✓ Profile "default" exists
  ✓ Identity alice@aid.com found
  ✓ Private key intact (P-256)
  ✓ Certificate valid (expires 2027-01-15)
  ✓ Gateway wss://gw.aid.com reachable (latency: 45ms)
  ✓ Authentication successful
  ✓ SPK valid (expires 2026-06-20)
  ✗ Trust root CA not configured (optional)

  7/8 checks passed
```

#### `aun status`

连接状态概览。

```
aun status

输出：
  Gateway:     wss://gw.aid.com/ws
  Protocol:    AUN/1.0
  Connection:  connected
  Latency:     42ms
  Session:     active (expires in 23h)
```

#### `aun ping`

验证目标 AID 可达性。

```
aun ping <target-aid> [--count N]

示例：
  aun ping bob@aid.com
  aun ping bob@aid.com --count 5

输出：
  bob@aid.com is reachable (latency: 67ms)
```

#### `aun logs`

查看本地 SDK 日志。

```
aun logs [--tail N] [--follow]

示例：
  aun logs --tail 50
  aun logs --follow          # 实时跟踪
```

## 5. 配置系统

### 5.1 配置文件

```toml
# ~/.aun/cli.toml

[default]
profile = "default"          # 默认 profile
output = "table"             # 默认输出格式: table | json | plain
color = true                 # 彩色输出
timeout = 30                 # 默认超时（秒）

[profiles.default]
aid = "alice@aid.com"
gateway = "wss://gw.aid.com/ws"
aun_path = "~/.aun/profiles/default"

[profiles.work]
aid = "bot@corp.com"
gateway = "wss://gw.corp.com/ws"
aun_path = "~/.aun/profiles/work"
```

### 5.2 Profile 管理命令

```
aun config init                          # 初始化配置
aun config set <key> <value>             # 设置配置项
aun config get <key>                     # 读取配置项
aun config profile create <name>         # 创建 profile
aun config profile delete <name>         # 删除 profile
aun config profile switch <name>         # 切换默认 profile
```

### 5.3 配置优先级

```
命令行参数 > 环境变量 > cli.toml > 内置默认值
```

环境变量映射：
- `AUN_PROFILE` → `--profile`
- `AUN_GATEWAY` → `--gateway`
- `AUN_DEBUG` → `--debug`
- `AUN_DATA_ROOT` → 覆盖 aun_path

## 6. 会话管理

### 6.1 短命令模式（默认）

每次命令执行：连接 → 认证 → 操作 → 断开。

为避免每次都做完整握手，引入 session cache：

```
~/.aun/profiles/{profile}/.session.json
{
  "gateway": "wss://gw.aid.com/ws",
  "token": "...",
  "expires_at": "2026-05-22T14:00:00Z",
  "device_id": "d8f2..."
}
```

- token 未过期：跳过认证，直接用 token 连接
- token 过期：重新挑战-响应认证，更新 cache

### 6.2 长连接模式（listen）

`aun listen` 和 `aun group listen` 保持 WebSocket 长连接：
- 前台运行，Ctrl+C 优雅退出
- 自动重连（SDK 内置机制）
- 断线时输出提示，重连后继续

## 7. 输出格式

### 7.1 Human-readable（默认）

```
aun group list

  GROUP ID     NAME            MEMBERS  ROLE
  g:abc123     Project Alpha   5        owner
  g:def456     Team Chat       3        member
```

### 7.2 JSON（`--json`）

```json
[
  {"group_id": "g:abc123", "name": "Project Alpha", "members": 5, "role": "owner"},
  {"group_id": "g:def456", "name": "Team Chat", "members": 3, "role": "member"}
]
```

JSON 模式适合脚本管道：`aun group list --json | jq '.[0].group_id'`

## 8. 错误处理

### 8.1 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 通用错误 |
| 2 | 参数错误 |
| 3 | 认证失败 |
| 4 | 连接失败（网关不可达） |
| 5 | 超时 |
| 6 | 权限不足 |
| 7 | 目标不存在（AID/群组） |

### 8.2 错误输出

```
# 默认模式
Error: Gateway wss://gw.aid.com unreachable (connection refused)
Hint: Check network connectivity or verify gateway URL with `aun config get profiles.default.gateway`

# JSON 模式
{"error": "connection_failed", "message": "Gateway unreachable", "code": 4}
```

## 9. SDK Adapter Layer

CLI 与 SDK 之间的桥接层，解决以下问题：

### 9.1 异步桥接

```python
# adapter.py 核心模式
import asyncio
from aun_core import AUNClient

def run_async(coro):
    """CLI 同步入口调用 SDK 异步方法"""
    return asyncio.run(coro)

class CLISession:
    """管理 SDK client 生命周期"""

    def __init__(self, profile: str, gateway: str = None, timeout: int = 30):
        self.profile = profile
        self.gateway = gateway
        self.timeout = timeout

    async def __aenter__(self):
        # 加载配置 → 创建 client → 连接/认证
        ...
        return self.client

    async def __aexit__(self, *exc):
        await self.client.close()
```

### 9.2 命令实现模式

```python
# commands/message.py 示例模式
@app.command()
def send(target: str, message: str, no_encrypt: bool = False):
    async def _send():
        async with CLISession(profile) as client:
            result = await client.call("message.send", {
                "to": target,
                "content": {"text": message},
                "encrypt": not no_encrypt,
            })
            return result
    result = run_async(_send())
    output(result)
```

## 10. 分发策略

### 10.1 开发阶段

```bash
# 直接运行
python -m aun_cli send bob@aid.com "hello"

# 或 editable install
pip install -e ".[cli]"
aun send bob@aid.com "hello"
```

### 10.2 正式发布

**pip 包**（面向 Python 开发者）：
```bash
pip install fastaun[cli]
```

**独立二进制**（面向终端用户）：
```bash
# 构建
pyinstaller --onefile src/aun_cli/main.py -n aun --hidden-import aun_core

# 产出
dist/aun        (Linux/Mac)
dist/aun.exe    (Windows)
```

### 10.3 pyproject.toml 变更

```toml
[project.optional-dependencies]
cli = ["typer>=0.9", "rich>=13.0"]

[project.scripts]
aun = "aun_cli.main:app"
```

## 11. 实现优先级

### Phase 1：核心可用（MVP）

- [ ] 项目骨架（typer app + 全局选项 + 配置加载）
- [ ] `aun register` / `aun login` / `aun whoami`
- [ ] `aun send` / `aun pull`
- [ ] `aun status` / `aun ping`
- [ ] 基本输出格式化（table + json）

### Phase 2：完整通信

- [ ] `aun listen`（长连接）
- [ ] `aun group create/send/list/members/invite/kick/leave`
- [ ] `aun group listen`
- [ ] `aun ack`

### Phase 3：管理与诊断

- [ ] `aun keys list/rotate/export/import`
- [ ] `aun doctor`
- [ ] `aun logs`
- [ ] `aun storage upload/download/delete`
- [ ] `aun config` 子命令

### Phase 4：体验优化

- [ ] Shell 自动补全（typer 内置支持）
- [ ] PyInstaller 打包流程
- [ ] 交互式模式（`aun interactive` — REPL 风格）
- [ ] `aun trace <message-id>` 消息追踪

## 12. 与现有工具的关系

| 工具 | 定位 | 用户 |
|------|------|------|
| **certool** | 服务端 CA 证书管理 | 运维 |
| **aun CLI** | 客户端身份 + 通信 | 开发者/Agent |
| **SDK** | 编程接口 | 应用开发者 |

三者互补：certool 管服务端证书链，CLI 管客户端身份和消息，SDK 供应用集成。
