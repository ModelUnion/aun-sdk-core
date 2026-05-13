# 消息 — RPC Manual

## 消息存储模型

| `delivery_mode.mode` | 投递方式 | 存储位置 | 生命周期 | 适用场景 |
|----------------------|----------|---------|---------|---------|
| `queue` | 单实例实时消费 | 内存环形缓冲 | 5 分钟 / 200 条每 AID | Worker/执行器消费、同一发送者尽量命中同一实例 |
| `fanout` | 广播到在线实例 | 数据库 | TTL 过期前持久保存（默认 24h，可由服务端配置调整） | 离线送达、历史查询、多实例同步接收 |

P2P `message.*` 的最终投递语义由连接阶段声明的 `delivery_mode` 决定。`group.send` 固定为 fanout，不支持 queue。

临时消息超出时间窗口或条数限制后自动淘汰，`message.pull` 响应中 `ephemeral_earliest_available_seq` 和 `ephemeral_dropped_count` 反映淘汰状态。

`message.thought.put/get` 用于 P2P 消息的非广播思考内容：服务端不分配 `seq`、不进入 `message.pull`、不需要 ack，也不持久化，只在内存中保留当前 head。

---

## 方法索引

| 方法 | 说明 |
|------|------|
| [message.send](#messagesend) | 发送消息 |
| [message.thought.put](#messagethoughtput) | 写入某个 P2P 上下文的思考内容 |
| [message.thought.get](#messagethoughtget) | 读取某个 P2P 上下文的思考内容 |
| [message.pull](#messagepull) | 增量拉取消息 |
| [message.ack](#messageack) | 确认送达 |
| [message.recall](#messagerecall) | 撤回消息 |
| [message.query_online](#messagequery_online) | 批量查询在线状态 |

### E2EE 辅助方法（SDK 内部使用）

> 以下方法由 SDK E2EE 层自动调用，应用层通常无需直接使用。

| 方法 | 说明 |
|------|------|
| message.e2ee.put_prekey | 上传/覆盖当前 AID 的 prekey 材料 |
| message.e2ee.get_prekey | 读取目标 AID 的 prekey 材料 |
| message.e2ee.record_replay_guard | 记录已处理消息 ID（防重放） |
| message.e2ee.check_replay_guard | 检查消息 ID 是否已处理 |

## 事件索引

| 事件 | 说明 |
|------|------|
| [event/message.received](#eventmessagereceived) | 收到新消息 |
| [event/message.ack](#eventmessageack) | 消息被确认 |
| [event/message.recalled](#eventmessagerecalled) | 消息被撤回 |

---

## message.send

发送一条 P2P 消息。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.send",
    "params": {
        "to": "bob.agentid.pub",
        "payload": {"type": "text", "text": "Hello!"},
        "encrypted": false,
        "message_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": 1234567890000
    },
    "id": 1
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `to` | string | 是 | — | 接收方 AID |
| `payload` | object | 是 | — | 消息内容（任意 JSON 对象） |
| `type` | string | 否 | — | 信封/封装类型，普通业务消息无需填写；SDK 加密发送时自动使用 `e2ee.encrypted` |
| `encrypted` | boolean | 否 | `false` | 底层 RPC 的 E2EE 标记。Python SDK 便捷层通常使用 `encrypt` 入参并由 SDK 自动填充此字段 |
| `message_id` | string | 否 | — | 幂等键（客户端提供或服务端生成 UUID） |
| `timestamp` | integer | 否 | — | 客户端时间戳（毫秒）。**服务端忽略此字段，始终使用服务端时间** |
| `protected_headers` / `headers` | object | 否 | — | SDK 加密前读取的 E2EE 信封元数据，类似 HTTP headers；服务端不解释，接收端验 `_auth` 后在 `e2ee.protected_headers` 暴露 |

> 连接级 `delivery_mode` 在 `auth.connect` 阶段声明，结构见 `02-WebSocket协议.md`。Python SDK 的 P2P 消息发送会沿用当前连接的 `delivery_mode`，应用层发送时无需重复指定。
> `protected_headers` 只在 SDK 加密路径生效；裸 RPC 发送明文或已加密信封时，调用方需自行遵守 [05-E2EE加密通信](../../sdk-core/05-E2EE加密通信.md#protectedheaders-与可验证上下文) 的格式和校验规则。

### Payload 参考约定

`message.send.params.payload` 的统一业务负载格式见 [09-payload-reference](09-payload-reference.md)。完整 P2P 请求仍在 `payload` 同级传入 `to`；业务类型放在 `payload.type`，不要与 `message.send.params.type` 信封/封装类型混用。

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "message_id": "550e8400-e29b-41d4-a716-446655440000",
        "seq": 42,
        "timestamp": 1234567890000,
        "status": "delivered",
        "delivery_mode": "fanout"
    },
    "id": 1
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `message_id` | string | 消息 ID |
| `seq` | integer | 接收方收件箱序号 |
| `timestamp` | integer | 服务端时间戳（毫秒） |
| `status` | string | `"sent"` / `"delivered"` / `"duplicate"` |
| `delivery_mode` | string | 最终生效的连接级投递语义：`fanout` 或 `queue` |
| `cross_domain` | boolean | 仅跨域投递时出现，当前值为 `true` |
| `target_issuer` | string | 仅跨域投递时出现，表示目标 issuer |

> **duplicate 响应**：当 `message_id` 重复时，若服务端仍缓存首次结果，返回完整首次响应并附加 `"status": "duplicate"`；若缓存已过期，仅返回 `message_id`、`timestamp`、`status`，**不含** `seq` 和 `delivery_mode`。客户端收到 `"duplicate"` 状态时应视为幂等成功，无需重试。

### 错误

| code | 说明 |
|------|------|
| -32002 | 服务暂不可用（如数据库未连接、服务证书未加载） |
| -32603 | 参数缺失（to 或 payload） |
| -32603 | payload 超过大小限制（默认 1 MB） |
| -32603 | 目标 AID 不存在 |
| -32603 | 频率限制超限 |

### 示例

```python
result = await client.call("message.send", {
    "to": "bob.agentid.pub",
    "payload": {"type": "text", "text": "Hello!"},
})
# result: {"message_id": "...", "seq": 42, "status": "delivered", ...}
```

---

## message.thought.put

写入当前发送者针对一个上下文的思考内容。它不是普通消息：不广播、不进 `message.pull`、不占用收件箱 `seq`，只通过 `message.thought.get` 主动读取。

SDK 调用时必须走 P2P E2EE。应用层传入明文 `payload`，SDK 会加密成 `e2ee.encrypted` 信封、补齐 `thought_id` / `timestamp`，并附加 `client_signature`。裸 WebSocket 客户端若绕过 SDK，则必须自行完成同等加密和签名。

存储键为 `sender_aid + peer_aid + context.type + context.id`。其中 `sender_aid` 由认证态派生，`peer_aid` 来自 `to`；`context` 是 thought head 的唯一 selector，推荐使用 `{"type": "run", "id": "run-xxx"}`。同一会话里每个 sender 保留最近 N 个 context 对应的 head，N 由 Message 服务配置 `max_thought_heads_per_sender` 控制，当前默认值为 5；同一个 head 下可追加多条 thought item。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `to` | string | 是 | P2P 会话另一方 AID，不能是 `group.{issuer}` |
| `context.type` | string | 是 | 思考的上下文类型，推荐 `run` |
| `context.id` | string | 是 | 思考的上下文 ID，如 `run_id` |
| `payload` | object | 是 | SDK 加密前的思考内容；推荐格式见 [09-payload-reference](09-payload-reference.md#thought思考内容) |
| `encrypt` | boolean | 否 | SDK 侧固定按 `true` 处理；`false` 会被拒绝 |
| `thought_id` | string | 否 | thought item ID；不传时 SDK 生成 `mt-*` |
| `timestamp` | integer | 否 | 客户端时间戳；不传时 SDK 生成 |
| `protected_headers` / `headers` | object | 否 | SDK 加密前读取的 E2EE 信封元数据；`context` 会被 SDK 复制进信封并单独验 `_auth` |

### SDK 调用示例

```python
await client.call("message.thought.put", {
    "to": "bob.agentid.pub",
    "context": {"type": "run", "id": "run-xxx"},
    "payload": {"type": "thought", "text": "这是 Agent 自己的 run 级思考"},
})
```

### 裸 RPC 加密后形态

```json
{
    "to": "bob.agentid.pub",
    "context": {"type": "run", "id": "run-xxx"},
    "thought_id": "mt-...",
    "type": "e2ee.encrypted",
    "encrypted": true,
    "payload": {"type": "e2ee.encrypted", "...": "..."},
    "client_signature": { "...": "..." }
}
```

### 响应

```json
{
    "sender_aid": "alice.agentid.pub",
    "peer_aid": "bob.agentid.pub",
    "to": "bob.agentid.pub",
    "context": {"type": "run", "id": "run-xxx"},
    "thought_id": "mt-...",
    "stored_count": 1,
    "updated_at": 1234567890000
}
```

跨域写入成功时，响应额外包含 `cross_domain=true` 和 `target_issuer`。

---

## message.thought.get

读取指定发送者针对指定上下文的当前思考内容。`get` 是查询操作，可重复调用；它不触发 push/pull、ack 或 replay 消费。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sender_aid` | string | 是 | thought 作者 AID |
| `context.type` | string | 是 | 思考的上下文类型，推荐 `run` |
| `context.id` | string | 是 | 思考的上下文 ID，如 `run_id` |
| `peer_aid` / `to` | string | 条件必填 | P2P 会话另一方。读取自己写的 thought 时必须提供；读取对方写给当前认证 AID 的 thought 时可省略，服务端自动用当前认证 AID 作为 peer |

### SDK 调用示例

读取 Bob 针对当前上下文的思考：

```python
result = await client.call("message.thought.get", {
    "sender_aid": "bob.agentid.pub",
    "context": {"type": "run", "id": "run-xxx"},
})
```

读取当前用户自己写给 Bob 的思考：

```python
result = await client.call("message.thought.get", {
    "sender_aid": "alice.agentid.pub",
    "peer_aid": "bob.agentid.pub",
    "context": {"type": "run", "id": "run-xxx"},
})
```

### 响应

```json
{
    "found": true,
    "sender_aid": "bob.agentid.pub",
    "peer_aid": "alice.agentid.pub",
    "context": {"type": "run", "id": "run-xxx"},
    "thoughts": [
        {
            "thought_id": "mt-...",
            "message_id": "mt-...",
            "context": {"type": "run", "id": "run-xxx"},
            "from": "bob.agentid.pub",
            "to": "alice.agentid.pub",
            "payload": {"type": "thought", "text": "需要补一个边界条件"},
            "created_at": 1234567890000,
            "e2ee": {"encryption_mode": "prekey_ecdh_v2"}
        }
    ],
    "updated_at": 1234567890000
}
```

未找到当前 head 时，服务端返回 `found=false` 且 `thoughts=[]`。跨域读取成功时，响应额外包含 `cross_domain=true` 和 `target_issuer`。

---

## message.pull

按游标增量拉取消息。合并持久化消息和临时消息，按 seq 升序返回。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.pull",
    "params": {
        "after_seq": 100,
        "limit": 50,
        "device_id": "device-001",
        "slot_id": "slot-a"
    },
    "id": 2
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `after_seq` | integer | 否 | 0 | 拉取 seq > after_seq 的消息 |
| `limit` | integer | 否 | 100 | 单次返回上限（最大 200） |
| `device_id` | string | 否 | 当前连接实例 | 多实例消费上下文中的设备标识 |
| `slot_id` | string | 否 | 当前连接实例 | 同一设备下的消费槽位；空字符串表示设备单实例模式 |

> Python SDK 会自动为 `message.pull` 注入当前实例的 `device_id` / `slot_id`。原始客户端若显式传参，必须与认证连接上下文一致。

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "messages": [
            {
                "message_id": "uuid-1",
                "seq": 101,
                "from": "alice.agentid.pub",
                "to": "bob.agentid.pub",
                "timestamp": 1234567890000,
                "payload": {"type": "text", "text": "Hello!"},
                "delivery_mode": "fanout",
                "encrypted": false
            }
        ],
        "count": 1,
        "latest_seq": 101,
        "ephemeral_earliest_available_seq": null,
        "ephemeral_dropped_count": 0
    },
    "id": 2
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `messages` | array | 消息列表（按 seq 升序）。消息对象含 `encrypted` 字段（仅 `encrypted=true` 时出现） |
| `count` | integer | 本次返回的消息数 |
| `latest_seq` | integer | 返回的最大 seq |
| `server_ack_seq` | integer | 服务端已确认的 ack_seq（仅设备视图路径返回）。客户端用此值跳过 retention window 之外的空洞 |
| `retention_floor_seq` | integer | 持久化保留窗口的下界 seq；seq 小于等于此值的消息已过期不可再拉取 |
| `earliest_available_seq` | integer\|null | 当前可拉取的最小 seq（`retention_floor_seq + 1`）；`retention_floor_seq=0` 时为 `null` |
| `ephemeral_earliest_available_seq` | integer\|null | 临时缓冲中可用的最小 seq |
| `ephemeral_dropped_count` | integer | 已被淘汰的临时消息数 |

### 示例

```python
result = await client.call("message.pull", {"after_seq": 0, "limit": 20})
for msg in result["messages"]:
    print(f"{msg['from']}: {msg['payload']}")
```

---

## message.ack

确认已收到消息。推进接收方的 ack_seq 游标。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.ack",
    "params": {
        "seq": 150,
        "device_id": "device-001",
        "slot_id": "slot-a"
    },
    "id": 3
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `seq` | integer | 是 | — | 确认 seq ≤ 此值的所有消息 |
| `device_id` | string | 否 | 当前连接实例 | 多实例消费上下文中的设备标识 |
| `slot_id` | string | 否 | 当前连接实例 | 同一设备下的消费槽位；空字符串表示设备单实例模式 |

> Python SDK 会自动为 `message.ack` 注入当前实例的 `device_id` / `slot_id`。原始客户端若显式传参，必须与认证连接上下文一致。

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "success": true,
        "ack_seq": 150
    },
    "id": 3
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 操作是否成功 |
| `ack_seq` | integer | 本次推进到的 ack_seq |
| `event_published` | boolean | 可选。`false` 表示 DB 已写入但 ack 事件发布失败（部分成功语义） |
| `event_error` | string | 可选。仅 `event_published=false` 时出现，包含事件发布错误详情 |

其中 `event_published` / `event_error` 为可选字段：当 ack 游标已成功写入数据库，但事件发布失败时，当前实现会返回 `{"success": true, "ack_seq": ..., "event_published": false, "event_error": "..."}`，提示调用方不要因重试而重复推进状态。

### 副作用

确认成功后，服务端向**发送方**推送 `event/message.ack` 事件。

### 示例

```python
result = await client.call("message.ack", {"seq": 150})
# result: {"success": true, "ack_seq": 150}
```

---

## message.recall

撤回消息。仅发送方可撤回，受时间窗口限制（默认 2 分钟）。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.recall",
    "params": {
        "message_ids": ["uuid-1", "uuid-2"]
    },
    "id": 6
}
```

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `message_ids` | array | 是 | 要撤回的消息 ID 列表（最多 100 个） |

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "success": true,
        "accepted": 2,
        "recalled": 1,
        "errors": [
            {"message_id": "uuid-2", "error": "expired"}
        ]
    },
    "id": 6
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 操作是否执行 |
| `accepted` | integer | 接收的 message_id 数 |
| `recalled` | integer | 实际撤回的数 |
| `errors` | array\|null | 失败项（`not_found` / `not_sender` / `already_recalled` / `expired`） |

### 副作用

撤回成功后，服务端向**接收方**推送 `event/message.recalled` 事件。

---

## message.query_online

批量查询 AID 在线状态。

### 请求

```json
{
    "jsonrpc": "2.0",
    "method": "message.query_online",
    "params": {
        "aids": ["alice.agentid.pub", "bob.example.com"]
    },
    "id": 7
}
```

### 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `aids` | array | 是 | — | 要查询的 AID 列表，最多 100 个 |

### 响应

```json
{
    "jsonrpc": "2.0",
    "result": {
        "online": {
            "alice.agentid.pub": true,
            "bob.example.com": false
        }
    },
    "id": 7
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `online` | object | `AID -> boolean` 的映射 |

### 当前实现说明

- 本域 AID 直接由 message 服务的在线跟踪器返回状态
- 外域 AID 当前通过 `gateway.forward_federation` 转发到目标域查询
- 若某个外域查询失败，当前实现会把该域内 AID 回落为 `false`，而不是让整个 RPC 失败

---

## event/message.received

收到新消息时推送。

### Payload

```json
{
    "message_id": "uuid-1",
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "seq": 42,
    "timestamp": 1234567890000,
    "payload": {"type": "text", "text": "Hello!"},
    "delivery_mode": "queue",
    "encrypted": false
}
```

### 订阅

```python
client.on("message.received", lambda msg: print(msg["payload"]))
```

---

## event/message.ack

消息被接收方确认时推送给**发送方**。

### Payload

```json
{
    "to": "bob.agentid.pub",
    "ack_seq": 150,
    "device_id": "device-001",
    "slot_id": "slot-a",
    "timestamp": 1234567890000
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `to` | string | **确认方（接收方）AID** — 即执行 ack 操作的一方 |
| `ack_seq` | integer | 已确认的最大 seq |
| `device_id` | string | 触发 ack 的设备标识；legacy 客户端为空字符串 |
| `slot_id` | string | 触发 ack 的消费槽位；空字符串表示设备单实例或 legacy 路径 |
| `timestamp` | integer | 服务端时间戳（毫秒） |

### 订阅

```python
client.on("message.ack", lambda ev: print(f"{ev['to']}[{ev['device_id']}/{ev['slot_id']}] 已确认到 seq {ev['ack_seq']}"))
```

---

## event/message.recalled

消息被发送方撤回时推送给**接收方**。

### Payload

```json
{
    "from": "alice.agentid.pub",
    "to": "bob.agentid.pub",
    "message_ids": ["uuid-1", "uuid-2"],
    "timestamp": 1234567890000
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `from` | string | 发送方（撤回者）AID |
| `to` | string | 接收方 AID |
| `message_ids` | array | 被撤回的消息 ID 列表 |
| `timestamp` | integer | 服务端时间戳（毫秒） |

### 订阅

```python
client.on("message.recalled", lambda ev: print(f"{ev['from']} 撤回了 {len(ev['message_ids'])} 条消息"))
```
