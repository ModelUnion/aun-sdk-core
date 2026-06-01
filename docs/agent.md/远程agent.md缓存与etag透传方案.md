# 远程 agent.md 缓存与 ETag 透传方案

状态：方案草案

## 目标

让 SDK 在给对端发送消息、收到对端消息时，都能观察到对端云端 `agent.md` 的最新 ETag，并据此维护本机远程 `agent.md` 缓存状态。

核心目标：

- 每个远程 AID 在 SDK 本地维护一条 `agent.md` 记录，包含 `remote_etag`、`local_etag`、`content`、`last_modified` 等字段。
- Python / TypeScript / Go 将正文和元数据持久化到 `{aun_path}/AIDs/{aid}/agent.md` 与 `agentmd.json`；浏览器 JavaScript 使用 IndexedDB 等价 key，存储不可用时退化为内存缓存。
- `message.send` 的 RPC 响应携带接收方 `agent.md` ETag，让发送方更新 `to` 的云端版本。
- 接收端收到消息信封时携带发送方 `agent.md` ETag，让接收方更新 `from` 的云端版本。
- ETag 只作为版本提示，不替代 `agent.md` 内容下载和验签。

## 可行性结论

方案可行。服务端已有 `agent.md` HEAD/ETag 能力，Gateway 当前也已经在 RPC response `_meta.agent_md_etag` 中注入“请求者自己”的服务端 ETag。需要扩展两条路径：

1. `message.send` / V2 P2P send：把 `from` 的 `agent.md` ETag 注入消息信封，随消息到达接收端。
2. `message.send` RPC response：把 `to` 的 `agent.md` ETag 注入响应 `_meta`，返回发送端。

注意：服务端注入的 ETag 只能代表云端版本。SDK 本地必须区分“观察到的远端云端 ETag”和“当前本地内容对应的 ETag”。字段命名固定为 `remote_etag` 和 `local_etag`，其中 `remote_etag` 表示远端云端版本，`local_etag` 表示本地 `content` 对应版本。下载必须始终使用无条件 GET，不能把 `remote_etag` 或 `local_etag` 放进 `If-None-Match` / `If-Modified-Since`，否则会把版本提示误用成 HTTP 缓存状态。

## 字段建议

消息信封新增字段：

```json
{
  "agent_md": {
    "sender": {
      "aid": "alice.agentid.pub",
      "etag": "\"sha256...\""
    }
  }
}
```

`message.send` RPC response 的 `_meta` 新增字段：

```json
{
  "_meta": {
    "agent_md_etag": "\"sender-self-etag\"",
    "agent_md_etags": {
      "to": {
        "aid": "bob.agentid.pub",
        "etag": "\"sha256...\""
      }
    }
  }
}
```

兼容说明：

- `_meta.agent_md_etag` 保持现有语义，仍表示请求者自己在服务端的 `agent.md` ETag。
- `_meta.agent_md_etags.to` 表示本次消息接收方的 `agent.md` ETag。
- `envelope.agent_md.sender` 表示本条消息发送方的 `agent.md` ETag。
- 字段缺失、ETag 为空、HEAD 失败均不影响消息收发。

## SDK 缓存模型

每个远程 AID 在内存和本地持久化记录中都维护一条 agent.md 状态。Python / TypeScript / Go 的持久化记录是 `{aun_path}/AIDs/{aid}/agentmd.json`；浏览器 JavaScript 是 IndexedDB 中的 `{aid}/agentmd.json` logical key。SDK 启动或内存 miss 时按需加载该记录。

| 字段 | 含义 |
| --- | --- |
| `aid` | 远程 AID |
| `content` | 本地缓存的完整 `agent.md` 内容，可为空 |
| `local_etag` | 当前 `content` 对应的 ETag，由成功 GET 200 内容确认；304 复用本地内容时沿用原值 |
| `remote_etag` | 从消息信封或 RPC `_meta` 观察到的远端云端 ETag |
| `last_modified` | GET 响应的 `Last-Modified` |
| `fetched_at` | 最近一次成功确认内容的本机时间 |
| `checked_at` | 最近一次 HEAD / GET 确认远端状态的本机时间 |
| `observed_at` | 最近一次观察到远端 ETag 的本机时间 |
| `remote_status` | `found` / `missing` / `error` |
| `verify_status` | 最近一次 agent.md 验签结果：`ok` / `unsigned` / `invalid` 等 |
| `verify_error` | 最近一次验签失败原因 |
| `last_error` | 最近一次网络或 HTTP 错误 |

状态规则：

- 收到远端 ETag 时，只更新 `remote_etag` 和 `observed_at`。
- 只有下载到内容并完成验签后，才能更新 `content`、`local_etag`、`last_modified`、`fetched_at`。
- `remote_etag == local_etag` 时视为同步。
- `remote_etag != local_etag` 或 `content` 为空时视为需要更新；该状态可由字段推导，不要求单独存储 `stale` 字段。
- `verify_status=invalid` 时内容可以缓存但应用层应能看到无效状态；是否拒绝展示由上层策略决定。

## 时序图

### 发送消息时，发送端获得 to 的 agent.md ETag

```mermaid
sequenceDiagram
    participant A as Sender SDK
    participant GW as Gateway
    participant MSG as Message Service
    participant NS as NameService
    participant DB as Message DB

    A->>GW: RPC message.send(to=B, payload=v2 envelope)
    GW->>MSG: 转发 send，附带 _auth.aid=A
    MSG->>NS: HEAD https://A/agent.md<br/>取 sender ETag（缓存命中则不请求）
    NS-->>MSG: ETag(A)
    MSG->>MSG: 注入 envelope.agent_md.sender={aid:A, etag}
    MSG->>DB: 持久化 envelope / wraps
    MSG-->>GW: send result
    GW->>NS: HEAD https://B/agent.md<br/>取 to ETag（缓存命中则不请求）
    NS-->>GW: ETag(B)
    GW-->>A: RPC response + _meta.agent_md_etags.to
    A->>A: observeRemoteAgentMdEtag(B, etag)<br/>更新内存 + agentmd.json/IndexedDB remote_etag
```

### 接收消息时，接收端获得 from 的 agent.md ETag

```mermaid
sequenceDiagram
    participant MSG as Message Service
    participant B as Receiver SDK
    participant Cache as SDK AgentMdCache
    participant NS as NameService

    MSG-->>B: peer.v2.message_received(seq, from=A)
    B->>MSG: message.v2.pull(after_seq)
    MSG-->>B: messages[].envelope_json<br/>包含 agent_md.sender={aid:A, etag}
    B->>Cache: observeRemoteAgentMdEtag(A, etag)

    alt 本地 local_etag == remote_etag
        Cache-->>B: 只刷新 observed_at，不下载
    else 本地无内容或 ETag 不一致
        Cache->>Cache: 标记需要更新，按需或后台拉取
        B->>NS: GET https://A/agent.md<br/>不带条件请求头
        NS-->>B: 200 content + ETag，或异常 304/404/error
        B->>B: verify_agent_md(content, aid=A)
        B->>Cache: 写内存 + agentmd.json/IndexedDB
    end
```

### SDK 本地缓存按需加载

```mermaid
sequenceDiagram
    participant App
    participant SDK
    participant Mem as Memory Cache
    participant Store as agentmd.json / IndexedDB
    participant NS as NameService

    App->>SDK: downloadAgentMd(A)
    SDK->>Mem: 查 A
    alt 内存有可用 content
        Mem-->>SDK: content, local_etag
    else 内存缺失
        SDK->>Store: load {aid}/agentmd.json
        Store-->>SDK: content/remote_etag/local_etag/last_modified
        SDK->>Mem: 回填内存
    end

    alt 内容缺失或 remote_etag != local_etag
        SDK->>NS: GET /agent.md<br/>不带条件请求头
        NS-->>SDK: 200/304/404/error
        SDK->>SDK: 200 时验签；304 时有本地 content 则复用，无 content 则再无条件 GET 一次
        SDK->>Mem: upsert
        SDK->>Store: upsert agent.md + agentmd.json
    end

    SDK-->>App: agent.md content + signature + sync 状态
```

### agent.md 上传后的服务端缓存失效

```mermaid
sequenceDiagram
    participant A as A SDK
    participant NS as NameService
    participant GW as Gateway
    participant MSG as Message Service

    A->>NS: PUT /agent.md
    NS->>NS: 保存 content，生成新 ETag
    NS-->>A: upload result + ETag
    NS-->>GW: event nameservice.agent_md_updated(aid=A)
    GW->>GW: invalidate agent_md_etag_cache[A]
    NS-->>MSG: 可选同事件
    MSG->>MSG: invalidate message-side agent_md_etag_cache[A]
```

## 服务端流程细化

### Gateway

现有行为：

- `deliver_response_to_client` 会在 RPC response `_meta.agent_md_etag` 中注入请求者自己的 `agent.md` ETag。
- ETag 获取采用本地 TTL 缓存，miss 时异步 HEAD 预热，不阻塞响应热路径。
- `nameservice.agent_md_updated` 事件会失效对应 AID 的 Gateway ETag 缓存。

新增行为：

- 对 `message.send` 和未来真实启用的 `message.v2.send`，根据请求参数提取 `to`。
- 在响应 `_meta.agent_md_etags.to` 中注入 `to` 的 ETag。
- 注入逻辑应使用同一套 ETag 缓存和 HEAD fetcher。
- 如果缓存 miss，第一轮响应可以不带 `to` ETag；后台预热后下一次消息或 RPC 再带上。
- 如果产品希望“发送后立即拿到 to ETag”，可对 message send 做同步 HEAD，但应设置短超时并保证失败不影响发送。

### Message Service

现有 V2 路径：

- SDK 加密 P2P 消息当前实际调用 `message.send`。
- 服务端通过 payload `type=e2ee.p2p_encrypted` 且 `version=v2` 进入 `_rpc_send_v2_p2p`。
- `_rpc_send_v2_p2p` 持久化 `protected_headers`、`context`，并在 `message.v2.pull` 时重建 `envelope_json`。

新增行为：

- 在 `_rpc_send_v2_p2p` 写入共享体前，为 `from_aid` 查询 `agent.md` ETag。
- 将结果注入 envelope 顶层 `agent_md.sender`。
- `agent_md` 应随 envelope 持久化并在 `_rebuild_v2_envelope_json` 中恢复。
- 在线 push 事件可以只带 seq，不强制带完整 ETag；接收端通过 pull 取得完整信封即可。
- V1 明文/旧 `message.send` 如需同样能力，可在传统 message envelope 中透传同等 `agent_md.sender` 字段。

### NameService

现有能力足够支撑：

- `GET /agent.md` 与 `HEAD /agent.md` 返回 `ETag` 和 `Last-Modified`。
- `PUT /agent.md` 上传后生成新 ETag。
- 上传后发布 `nameservice.agent_md_updated` 事件，Gateway 已订阅并失效缓存。

建议补齐：

- 如果 Message Service 也维护自己的 ETag 缓存，应订阅同一事件或复用 Gateway 的注入结果。
- HEAD 失败、404、超时返回空 ETag，不影响消息主链路。

## SDK 流程细化

### 观察远端 ETag

SDK 增加统一入口：

```text
observe_remote_agent_md_etag(aid, etag, source)
```

触发来源：

- RPC response `_meta.agent_md_etags.to`：发送消息后观察 `to`。
- 消息信封 `agent_md.sender`：收到消息后观察 `from`。
- 现有 `_meta.agent_md_etag`：仍用于当前客户端自己的云端 ETag。

处理规则：

- aid 或 etag 为空时忽略。
- etag 与当前 `remote_etag` 相同：只刷新 `observed_at`。
- etag 变化：更新 `remote_etag`、`observed_at`，并根据 `local_etag` 推导是否需要更新。
- 变更需要同时写入内存和 agentmd.json / IndexedDB。

### 按需下载

当应用调用 `downloadAgentMd(aid)` 或 SDK 需要展示远程 agent 信息时：

- 可先查内存，miss 时查 agentmd.json / IndexedDB，用于展示本地已有状态。
- `downloadAgentMd(aid)` 的远端下载请求一律发起无条件 GET，不用本地 ETag 决定请求头。
- GET 请求不得发送 `If-None-Match` / `If-Modified-Since`。
- 200：验签，更新内容和 `local_etag`。
- 304：本地已有 content 时复用该 content；本地没有 content 时再发起一次无条件 GET。第二次仍非 2xx 时按错误返回。
- 404：标记远端未发布 `agent.md`，不要删除已有内容，除非产品要求严格同步。
- 网络错误：保留旧内容，记录 `fetch_error` 或更新失败时间。

### 本地文件 / 浏览器持久化

agent.md 不写入 SQLite。当前 SDK 使用以下持久化位置：

| SDK | 正文 | 元数据 |
| --- | --- | --- |
| Python | `{aun_path}/AIDs/{aid}/agent.md` | `{aun_path}/AIDs/{aid}/agentmd.json` |
| TypeScript / Node | `{aun_path}/AIDs/{aid}/agent.md` | `{aun_path}/AIDs/{aid}/agentmd.json` |
| Go | `{aun_path}/AIDs/{aid}/agent.md` | `{aun_path}/AIDs/{aid}/agentmd.json` |
| JavaScript / 浏览器 | IndexedDB logical key `{root}/{aid}/agent.md` | IndexedDB logical key `{root}/{aid}/agentmd.json` |

`agentmd.json` 至少承载以下语义字段：

| 字段 | 说明 |
| --- | --- |
| `aid` | AID |
| `content` | 正文副本；文件系统 SDK 也会单独写 `agent.md` |
| `local_etag` / `remote_etag` | 本地内容版本 / 远端观察版本 |
| `last_modified` | 远端 Last-Modified |
| `fetched_at` / `checked_at` / `observed_at` / `updated_at` | 本机时间戳 |
| `remote_status` | `found` / `missing` / `error` |
| `verify_status` / `verify_error` | 最近一次验签状态 |
| `last_error` | 最近一次错误 |

四个已实现 SDK 应保持字段语义一致。旧 `agent_md_cache` / `remote_agent_md_cache` SQLite 表不再作为 agent.md 缓存来源；迁移逻辑可清理旧表，但不得把新 agent.md 写回 SQLite。

## 异常与竞态处理

- 多个消息同时观察同一 AID 的新 ETag：按 ETag 值幂等 upsert。
- 多个协程同时触发同一 AID 下载：需要 per-AID in-flight 去重。
- 观察到 ETag A 后开始下载，期间又观察到 ETag B：下载完成时只更新 `local_etag=A`，随后仍可由 `remote_etag != local_etag` 推导为需要更新，下一轮继续拉 B。
- 304 但本地 content 缺失：不能返回空内容，必须再无条件 GET 一次。
- 信封里的 ETag 不参与 AAD，不作为安全声明；安全性仍依赖 `agent.md` 签名和证书校验。
- HEAD/GET 超时不影响 message send 和 message pull。
- 跨域场景中，目标域 Message Service 注入 sender ETag 时可能需要跨域 HEAD；失败时允许缺字段。

## 测试要点

- 发送方收到 `message.send` 响应后，能把 `to` 的 ETag 写入本地缓存 `remote_etag`。
- 接收方 `message.v2.pull` 后，能从 `envelope.agent_md.sender` 写入 `from` 的 `remote_etag`。
- ETag 变化但内容未下载时，可由 `remote_etag != local_etag` 推导为需要更新。
- 本地文件 / IndexedDB 有缓存、内存为空时，SDK 能按需加载。
- 304 且本地有内容时复用内容；304 但本地无内容时再无条件 GET 一次。
- `agent.md` 上传后，Gateway 缓存失效，后续消息能看到新 ETag。
- HEAD/GET 404、超时、网络错误不影响消息收发主链路。
- Python / TS / JS / Go 四个 SDK 对 `remote_etag`、`local_etag`、`content`、`remote_status`、`verify_status` 语义一致。
