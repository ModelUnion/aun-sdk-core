# 跨语言容器 E2E 测试方案

本文档定义 AUN 多语言 SDK 在 Docker 环境中进行跨语言集成 / E2E 测试的目标拓扑、控制协议、测试矩阵和落地顺序。重点覆盖 Python SDK 与 TypeScript SDK 的互通测试，并为 Go、C++、浏览器 JavaScript 后续接入预留一致模型。

## 背景

当前各语言 SDK 已有各自的单元测试、集成测试和部分 E2E 测试，但“各自通过”不能证明跨语言真实互通稳定。尤其是 E2EE、消息 envelope、canonical JSON、设备密钥、群组 epoch、ack cursor、跨域 routing 等能力，容易出现某个 SDK 自测通过、组合运行失败的问题。

问题的根源通常不是某个 SDK 单点逻辑，而是多语言实现之间存在细微协议差异：

- 同一字段是否参与签名、加密 AAD 或 digest 计算。
- JSON canonical 序列化、字段排序、空值处理、base64 padding 是否一致。
- E2EE key id、recipient、device id、slot id、message id 是否一致。
- 服务端返回错误码、部分成功语义、ack 推进语义是否被各语言一致处理。
- 跨域时 issuer、domain、gateway discovery、federation envelope 绑定是否一致。

因此需要建立一套独立于任意单一 SDK 的跨语言测试体系，让多个语言客户端在同一个 Docker 网络内真实连接 AUN 服务端，并由统一 test-runner 编排用例、收集日志、判断结果。

## 目标

- 优先覆盖 Python <-> TypeScript 的单域互通。
- 在同一 Docker network 中同时启动不同语言 SDK 客户端实例。
- 所有客户端连接同一 AUN server / gateway，通过 AUN 服务端路由业务消息。
- test-runner 只负责编排和断言，不 import 任意语言 SDK。
- 各语言客户端暴露一致的测试控制面，便于 test-runner 跨语言控制。
- 每个失败用例都能定位到协议一致性、客户端运行时、服务端路由或跨域 federation 层。
- 浏览器 JavaScript E2E 与 Node/TS 容器 E2E 分层，不把浏览器环境问题混入第一优先级的跨语言主路径。

## 非目标

- 不把测试控制协议设计成正式业务 API。
- 不要求所有语言 SDK 共用任何代码、配置文件或本地数据库。
- 不把 test-runner 变成某个 SDK 的上层封装。
- 不在首阶段覆盖完整产品级 CLI 功能。
- 不在容器 test-runner 中挂载 Docker socket 后使用 `docker exec` 控制其他容器。

## 总体拓扑

单域跨语言 E2E 的目标拓扑：

```text
docker network: kite-net
├── aun-server / gateway
├── python-client
│   ├── Python SDK agent 长连接
│   └── test-control HTTP
├── ts-client
│   ├── TypeScript SDK agent 长连接
│   └── test-control HTTP
└── test-runner
    └── 通过 HTTP 控制各语言 client
```

业务消息面：

```text
python-client -> AUN gateway -> ts-client
ts-client -> AUN gateway -> python-client
```

测试控制面：

```text
test-runner -> python-client:test-control
test-runner -> ts-client:test-control
```

日志与产物面：

```text
python-client -> /artifacts/logs/python
ts-client -> /artifacts/logs/ts
test-runner -> /artifacts/results
```

关键原则：客户端之间不通过测试 HTTP 接口传业务消息。测试 HTTP 只用于“让某个客户端执行动作”和“查询某个客户端观察到的结果”。真实消息必须走 AUN server / gateway。

## 分层测试模型

跨语言测试按四层推进，避免所有问题都落到难调的大 E2E。

### 第一层：共享测试向量

每个 SDK 读取同一批 JSON / JSONL fixture，验证 E2EE 原语、canonical bytes、签名、加密 envelope 和非法包拒绝行为。fixture 是共享数据，不是共享代码。

覆盖内容：

- 固定 identity key、prekey、recipient、nonce、salt、message id。
- canonical JSON bytes hash。
- AAD hash。
- ciphertext hash。
- signature hash。
- 成功解密结果。
- 篡改密文、篡改 tag、错误 recipient、错误 signer、重放消息等反例。

失败定位：

- 这一层失败，优先查密码学原语、序列化、字段排序、base64、签名输入、AAD 输入。

### 第二层：CLI / transcript 互通

Python CLI 和 TS 测试 CLI 读取同一 transcript 或 fixture 文件，互相生成和验证 envelope。此层可以通过共享 volume 交换文件，不要求启动长连接 agent。

示例流程：

```text
python-cli 生成 encrypted envelope -> /work/py-to-ts.json
ts-cli 读取并解密 /work/py-to-ts.json
ts-cli 生成 encrypted envelope -> /work/ts-to-py.json
python-cli 读取并解密 /work/ts-to-py.json
```

失败定位：

- 这一层失败，优先查 SDK 本地实现和 CLI JSON 输入输出，不查服务端。

### 第三层：单域真实客户端 E2E

每个语言客户端以长连接方式登录到同一 AUN gateway，test-runner 通过测试控制面触发发送、轮询收件箱、断言解密结果。

示例流程：

```text
test-runner -> python-client /send(to=ts-agent, e2ee=true)
python-client -> AUN gateway -> ts-client
test-runner -> ts-client /inbox(trace_id=case-001)
test-runner 断言 received=true, decrypted=true, text=expected
```

失败定位：

- 第一、二层通过但这一层失败，优先查连接状态、gateway discovery、消息 RPC、push/pull、ack、SDK 后台任务、日志 trace。

### 第四层：双域 federation E2E

在 `docker-deploy/federation-test` 中启动两个 issuer 域，分别运行不同语言客户端，验证跨域消息和 E2EE。

示例流程：

```text
python-client-aid.com -> kite-a -> federation -> kite-b -> ts-client-aid.net
ts-client-aid.net -> kite-b -> federation -> kite-a -> python-client-aid.com
```

失败定位：

- 前三层通过但这一层失败，优先查 issuer 绑定、well-known gateway discovery、federation envelope、远端证书链、跨域路由和跨域 AAD 字段。

## test-runner 控制方式

test-runner 不直接执行某个语言 SDK，也不通过 Docker socket 控制容器。它只调用每个客户端容器暴露的统一测试控制面。

推荐每个语言 client 容器启动两个逻辑组件：

- SDK agent：使用本语言 SDK 连接 AUN gateway，负责真实收发消息。
- test-control：仅测试环境启用的 HTTP 服务，负责接收 test-runner 命令并查询 agent 状态。

test-control 与 SDK agent 可以在同一进程内实现，也可以是同容器内的两个进程。首阶段建议同进程实现，降低生命周期协调成本。

## 测试控制面 API

所有语言客户端实现同一套最小 HTTP API。端口建议统一为 `9001`，容器内监听 `0.0.0.0:9001`。

### `GET /health`

返回客户端测试控制面和 SDK agent 是否就绪。

响应字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `ok` | bool | test-control 是否可用 |
| `agent_ready` | bool | SDK agent 是否已完成认证和连接 |
| `aid` | string | 当前客户端 AID |
| `language` | string | `python` / `ts` / `go` / `cpp` |
| `sdk_version` | string | SDK 版本 |
| `gateway_url` | string | 实际连接的 gateway |

### `POST /reset`

清理本轮测试的内存收件箱、trace 缓存和临时状态。默认不删除 AID 身份材料、本地密钥、数据库和持久化状态。

请求字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `scope` | string | `case` / `session`，默认 `case` |
| `trace_id` | string | 可选，仅清理某条 trace |

### `GET /identity`

返回当前客户端身份和设备信息。

响应字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `aid` | string | 当前 AID |
| `device_id` | string | 当前设备 ID |
| `slot_id` | string | 当前 slot ID |
| `issuer` | string | issuer 域 |
| `public_key_fingerprint` | string | 公钥指纹，不返回私钥 |

### `POST /send`

触发本客户端通过 AUN 发送消息。

请求字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `to` | string | 目标 AID 或 agent id |
| `text` | string | 测试文本 |
| `e2ee` | bool | 是否启用 E2EE |
| `trace_id` | string | 用例 trace id |
| `message_id` | string | 可选，外部指定消息 ID |
| `timeout_ms` | number | 单次发送超时 |

响应字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `ok` | bool | 发送动作是否完成 |
| `trace_id` | string | trace id |
| `message_id` | string | 实际消息 ID |
| `seq` | number | 如服务端返回 seq，则记录 |
| `encrypted` | bool | 是否按 E2EE 发送 |
| `error_code` | string | 失败时返回 |
| `error_message` | string | 失败时返回 |

### `GET /inbox`

查询本客户端已观察到的消息。test-runner 应按 `trace_id` 轮询，直到命中或超时。

查询参数：

| 参数 | 说明 |
| --- | --- |
| `trace_id` | 按 trace 过滤 |
| `from` | 可选，按发送方过滤 |
| `limit` | 返回数量，默认 20 |

响应字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `items` | array | 消息列表 |
| `received` | bool | 是否有匹配消息 |

消息项字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `trace_id` | string | trace id |
| `message_id` | string | message id |
| `from` | string | 发送方 |
| `to` | string | 接收方 |
| `text` | string | 解密后的测试文本；仅测试消息可返回 |
| `decrypted` | bool | 是否成功解密 |
| `encrypted` | bool | 原消息是否加密 |
| `seq` | number | 消息 seq |
| `ack_seq` | number | 当前 ack seq |
| `error_code` | string | 解密或处理失败时返回 |

### `GET /traces/{trace_id}`

返回本客户端与该 trace 相关的安全诊断字段。

允许字段：

- `trace_id`
- `session_id`
- `message_id`
- `key_id`
- `sender`
- `recipient`
- `device_id`
- `slot_id`
- `aad_sha256`
- `canonical_sha256`
- `ciphertext_sha256`
- `public_key_fingerprint`
- `nonce`
- `stage`
- `error_code`

禁止字段：

- 私钥
- 明文会话密钥
- 原始明文
- token
- 完整证书私密材料
- 可复用认证凭证

### `GET /logs`

返回测试相关日志的元信息或尾部片段。正式日志仍以 volume 产物为准。

响应字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `log_files` | array | 日志文件路径列表 |
| `tail` | array | 可选尾部日志行 |

## 客户端容器要求

每个语言客户端容器必须满足以下要求：

- 使用独立 `AUN_DATA_ROOT` / `aun_path`，避免不同语言共用 SQLite、SQLCipher 或本地密钥数据库。
- 使用固定或可预期的 AID，便于 test-runner 建立发送矩阵。
- 启动后自动完成身份准备、认证、连接 gateway、订阅消息事件。
- 通过 test-control 暴露 readiness，而不是只依赖容器启动成功。
- 日志输出同时进入控制台和挂载目录，便于 CI 收集。
- 所有测试控制响应使用 JSON，失败时返回稳定 `error_code`。
- 退出码只用于进程级失败，不用于单条测试断言。

Python 当前已有 CLI 入口 `aun`，可优先补 `test-agent` 或独立测试控制进程。TypeScript 当前主要是 SDK + Vitest 测试，建议新增最小测试 CLI / test-agent，用于容器内长连接和 HTTP 控制面。

建议 TS 测试 CLI 先实现测试能力，不追求产品级完整 CLI：

```text
aun-ts test-agent --aid <aid> --gateway <url> --control-port 9001
aun-ts e2ee encrypt --fixture <file> --json
aun-ts e2ee decrypt --fixture <file> --json
aun-ts trace replay <transcript.jsonl> --json
```

## Docker Compose 设计

### 单域建议结构

在现有 `docker-deploy` 单域环境中，可新增一组跨语言 client 与 test-runner 服务。现有服务名包括：

- `kite` / `kite-app`：AUN 服务端。
- `sdk-tester` / `kite-sdk-tester`：Python 测试容器。
- `ts-tester` / `kite-ts-tester`：TypeScript 测试容器。
- `go-tester` / `kite-go-tester`：Go 测试容器。

跨语言 E2E 不建议直接复用“sleep infinity + docker exec”的模式作为最终形态，而是新增专门服务：

```yaml
services:
  cross-python-client:
    image: aun-sdk-tester:latest
    command: aun-test-agent-python --control-port 9001
    environment:
      AUN_DATA_ROOT: /data/aun
      AUN_TEST_AID: py-agent.agentid.pub
      AUN_GATEWAY_URL: wss://gateway.agentid.pub:20001/aun
    volumes:
      - ./data/cross-sdk/python:/data/aun
      - ./data/cross-sdk/logs/python:/root/.aun/logs
    networks:
      - kite-net

  cross-ts-client:
    image: node:22-bookworm
    command: bash -lc "cd /workspace/ts && npm run test-agent -- --control-port 9001"
    environment:
      AUN_DATA_ROOT: /data/aun
      AUN_TEST_AID: ts-agent.agentid.pub
      AUN_GATEWAY_URL: wss://gateway.agentid.pub:20001/aun
    volumes:
      - ../aun-sdk-core/ts:/workspace/ts
      - cross-ts-node-modules:/workspace/ts/node_modules
      - ./data/cross-sdk/ts:/data/aun
      - ./data/cross-sdk/logs/ts:/root/.aun/logs
    networks:
      - kite-net

  cross-sdk-runner:
    image: aun-sdk-tester:latest
    command: python /runner/run_cross_sdk_e2e.py
    environment:
      PY_CLIENT_URL: http://cross-python-client:9001
      TS_CLIENT_URL: http://cross-ts-client:9001
      ARTIFACT_DIR: /artifacts
    volumes:
      - ../aun-sdk-core/tests/cross-sdk:/runner:ro
      - ./data/cross-sdk/artifacts:/artifacts
    networks:
      - kite-net
```

这只是目标结构示例，实际落地时可以拆成 `docker-compose.cross-sdk.yml`，避免影响现有常规测试环境。

### 双域建议结构

在 `docker-deploy/federation-test` 中保持两个服务端域：

- `kite-a`：issuer `aid.com`
- `kite-b`：issuer `aid.net`

新增跨语言客户端：

```text
cross-python-client-a -> aid.com
cross-ts-client-b -> aid.net
cross-sdk-federation-runner
```

测试流：

```text
python(aid.com) -> kite-a -> federation -> kite-b -> ts(aid.net)
ts(aid.net) -> kite-b -> federation -> kite-a -> python(aid.com)
```

跨域客户端仍使用同一套 test-control API。test-runner 只需要切换目标 client URL 和目标 AID。

## test-runner 用例流程

单条 P2P E2EE 用例的标准流程：

```text
1. 等待 python-client /health: agent_ready=true
2. 等待 ts-client /health: agent_ready=true
3. 调两个 client /reset
4. 读取两个 client /identity
5. 生成 trace_id 和 message_id
6. 调 python-client /send(to=ts-aid, e2ee=true)
7. 轮询 ts-client /inbox?trace_id=...
8. 断言 received=true, decrypted=true, text=expected
9. 查询双方 /traces/{trace_id}
10. 记录测试结果与日志索引
```

反向用例只交换发送方和接收方。

失败时 test-runner 必须收集：

- 用例名、trace id、发送方、接收方、语言组合。
- `/health` 最终结果。
- `/identity` 结果。
- `/send` 响应。
- `/inbox` 最终响应。
- `/traces/{trace_id}`。
- 相关日志文件尾部。

## 优先测试矩阵

### P0：Python <-> TypeScript 单域

| 用例 | 方向 | 目标 |
| --- | --- | --- |
| health_ready | 双方 | 客户端完成认证和连接 |
| p2p_plain_smoke | Python -> TS, TS -> Python | 明文消息基础互通 |
| p2p_e2ee_smoke | Python -> TS, TS -> Python | E2EE 单条消息互通 |
| p2p_e2ee_sequence | 双向 | 连续多条消息不丢、不乱、ack 正常 |
| p2p_e2ee_large | 双向 | 大 payload 加解密与传输 |
| p2p_e2ee_concurrent | 双向 | 并发发送不串 session / message id |
| invalid_recipient | 双向 | 错误 recipient 必须失败 |
| tampered_ciphertext | 双向 | 篡改密文必须拒绝 |
| replay_message | 双向 | 重放消息必须拒绝或幂等处理 |
| reconnect_after_send | 双向 | 断线重连后消息状态一致 |

### P1：Python <-> TypeScript 双域

| 用例 | 方向 | 目标 |
| --- | --- | --- |
| federation_plain_smoke | aid.com -> aid.net, aid.net -> aid.com | 跨域明文消息 |
| federation_e2ee_smoke | aid.com -> aid.net, aid.net -> aid.com | 跨域 E2EE |
| federation_e2ee_sequence | 双向 | 跨域连续消息、ack、pull |
| federation_wrong_issuer | 双向 | issuer 绑定错误必须拒绝 |
| federation_reconnect | 双向 | 远端域重启后恢复 |

### P2：扩展语言

在 Python <-> TS 稳定后，再接入：

- Python <-> Go
- TS <-> Go
- Python <-> C++
- TS <-> C++

每接入一种语言，先完成共享测试向量和 test-control API，再进入真实 E2E。

### 浏览器 JavaScript

浏览器 SDK 不作为第一阶段 Docker 跨语言主路径。它应通过 Playwright 专项测试覆盖：

- WebCrypto 行为。
- CORS / HTTPS / 证书。
- bundle 加载。
- 浏览器 storage。
- 页面生命周期。

浏览器测试可以连接同一 Docker AUN 服务端，但 test-runner 应是 Playwright runner，而不是容器内 HTTP test-control 主路径。

## 产物目录

建议统一产物目录：

```text
docker-deploy/data/cross-sdk/
├── python/
│   └── AUN_DATA_ROOT
├── ts/
│   └── AUN_DATA_ROOT
├── logs/
│   ├── python/
│   └── ts/
└── artifacts/
    ├── results.json
    ├── results.jsonl
    ├── traces/
    └── logs/
```

`results.jsonl` 每行记录一个用例结果，便于 CI 直接解析。`traces/` 保存按 trace id 聚合后的安全诊断信息。

## 日志与 trace 要求

所有跨语言 E2E 必须在日志中携带以下字段：

- `trace_id`
- `case_id`
- `language`
- `aid`
- `peer_aid`
- `message_id`
- `session_id`
- `key_id`
- `device_id`
- `slot_id`
- `stage`
- `error_code`

E2EE 诊断只记录 hash 或指纹：

- `canonical_sha256`
- `aad_sha256`
- `ciphertext_sha256`
- `public_key_fingerprint`

不得记录：

- 私钥。
- 明文会话密钥。
- 原始敏感明文。
- token / refresh token。
- 可用于重放认证的完整 challenge 或签名材料。

## 身份与数据隔离

跨语言同时运行时，必须避免共享同一个 SDK 本地数据库或密钥目录。原因：

- Python 使用 SQLCipher 数据库。
- TS/Node 可能使用不同 SQLite 或文件存储。
- Go/C++ 也可能有独立存储格式。
- 多进程共写同一身份目录容易产生锁冲突和密钥材料竞争写入。

推荐策略：

- 每个语言 client 使用独立数据目录。
- 每个语言 client 使用独立 AID。
- 如果必须使用固定 AID，固定身份由该语言自己的初始化流程创建和维护。
- test-runner 只读取 `/identity` 结果，不直接读写身份材料。

## CLI 的必要性

TS 侧有必要提供一个最小测试 CLI，但定位是测试入口和调试入口，不是首阶段产品 CLI。原因：

- Docker 中启动 Node CLI 稳定、可观察、可由 Compose 管理。
- 可以直接用于共享测试向量和 transcript 回放。
- 可与 Python CLI 做一致的 JSON 输入输出和退出码。
- 失败时能在不启动完整 agent 的情况下复现协议问题。

建议统一 CLI 规范：

- `--json` 输出机器可读 JSON。
- stdin 支持 JSON 输入。
- exit code `0` 表示动作成功，`1` 表示运行时失败，`2` 表示参数错误，`3` 表示断言失败。
- 错误响应包含 `error_code`、`error_message`、`stage`、`trace_id`。
- CLI 和 test-control 复用同一套结果 JSON schema。

## 失败分类

test-runner 应按层分类失败，避免调试方向混乱。

| 分类 | 判定 | 优先排查 |
| --- | --- | --- |
| fixture 失败 | 共享向量不一致 | 序列化、base64、签名输入、AAD、加密原语 |
| transcript 失败 | 文件回放不一致 | envelope 字段、状态机、非法包拒绝 |
| readiness 失败 | `/health` 不 ready | 身份准备、认证、gateway discovery、连接 |
| send 失败 | `/send` 返回失败 | RPC 参数、服务端错误、客户端发送逻辑 |
| delivery 失败 | 接收方 inbox 超时 | 服务端路由、push/pull、订阅、ack |
| decrypt 失败 | 收到但 `decrypted=false` | E2EE session、prekey、recipient、AAD |
| federation 失败 | 单域通过、双域失败 | issuer、well-known、federation envelope、证书链 |

## 落地阶段

### 阶段 1：规范与最小 test-agent

- 定义 test-control API schema。
- Python 增加测试 agent 入口，复用现有 SDK 和 CLI 能力。
- TS 增加最小测试 CLI / test-agent。
- test-runner 先支持 Python <-> TS 单条明文和单条 E2EE。

### 阶段 2：单域 P0 矩阵

- 补 Python -> TS、TS -> Python 的 P2P E2EE smoke。
- 补连续、多条、大消息、并发、非法包。
- 输出 `results.jsonl` 和 trace 产物。

### 阶段 3：双域 P1 矩阵

- 在 `federation-test` 增加 Python/TS 跨域客户端。
- 复用同一 test-runner 用例，只替换 client URL 与 AID。
- 增加 issuer 错误、远端域重启、跨域 reconnect。

### 阶段 4：扩展语言

- Go/C++ 先接入共享测试向量。
- 再实现最小 test-control API。
- 最后加入跨语言真实 E2E 矩阵。

### 阶段 5：浏览器专项

- Playwright 启真实浏览器。
- 页面加载 browser SDK。
- 连接同一 Docker AUN 服务端。
- 覆盖 browser SDK 与 Python/TS 后端客户端互通。

## 与现有测试环境的关系

现有 `docs/aun测试运行指南.md` 记录了当前单域和双域 Docker 测试命令，仍作为运行指南使用。本文档定位为跨语言容器 E2E 的设计方案。

当前现状：

- 单域已有 `kite-sdk-tester`、`kite-ts-tester`、`kite-go-tester`、`kite-cpp-tester`。
- 双域已有 `client-a`、`client-b`、`ts-tester`、`go-tester`、`cpp-client-a`、`cpp-client-b`。
- 这些容器当前主要是“测试执行容器”，常见模式是 `sleep infinity` 后用 `docker exec` 手动跑测试。
- 跨语言 E2E 的目标形态是“常驻语言客户端 + test-control + test-runner”，减少宿主机脚本和人工 docker exec 编排。

推荐新增独立 Compose override 文件，而不是直接改动现有常规测试服务：

```text
docker-compose.cross-sdk.yml
federation-test/docker-compose.cross-sdk.yml
```

这样现有测试命令不受影响，跨语言测试可以按需启用。

## 验收标准

首阶段完成后，应满足：

- 一条命令启动单域 AUN 服务端、Python client、TS client、test-runner。
- test-runner 能自动等待两个 client ready。
- Python -> TS E2EE 单条消息通过。
- TS -> Python E2EE 单条消息通过。
- 任一方向失败时能输出 trace id、双方 identity、send 响应、inbox 响应、trace 诊断和日志路径。
- 不需要 test-runner import Python SDK 或 TS SDK。
- 不需要在 test-runner 容器中使用 Docker socket。
- 不共享跨语言本地身份数据库。

后续完成双域阶段后，应满足：

- aid.com Python -> aid.net TS 跨域 E2EE 通过。
- aid.net TS -> aid.com Python 跨域 E2EE 通过。
- issuer 错误和篡改 envelope 类用例能稳定失败并给出可定位错误码。

