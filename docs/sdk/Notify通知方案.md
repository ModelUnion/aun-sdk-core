# Notify 通知方案

> 状态：已实现。本文定义 SDK 公开 `notify()` API 的语义边界、路由方式、跨域行为，以及与可靠消息通道的分工。

## 目标

`notify()` 用于发送 JSON-RPC 2.0 Notification：无 `id`、不等待业务响应、只面向在线长连接的轻量通知。

它补齐 SDK 发送侧能力：SDK 已通过 `client.on(event, handler)` 接收 `event/...`，`notify()` 则提供对称的发送端能力。可靠应用事件仍走 `message.send` / `group.send`，在 payload 中使用 `type="event"` 或 `type="status"`。

## 非目标

- 不做离线存储。
- 不分配 `seq`。
- 不进入 `message.pull` / `group.pull`。
- 不需要 ack。
- 不提供送达保证。
- 不承载敏感内容，除非应用自行加密。
- 不替代 `message.send` / `group.send`。

## API 形态

公共方法命名为 `notify()`，不用 `emit()`。

原因：

- `notify` 对齐 JSON-RPC Notification 术语。
- `emit` 容易被理解为触发本地事件 handler，和 `client.on()` 组合时有歧义。
- `notify` 更清楚表达单向、轻量、无业务响应。

四端 SDK 公开形态：

| 语言 | API |
|------|-----|
| Python | `await client.notify(method, params=None, *, to=None, group_id=None, device_id=None, slot_id=None, ttl_ms=None)` |
| TypeScript / JavaScript | `await client.notify(method, params?, { to?, groupId?/group_id?, deviceId?/device_id?, slotId?/slot_id?, ttlMs?/ttl_ms? })` |
| Go | `client.Notify(ctx, method, params, NotifyOptions{To, GroupID, DeviceID, SlotID, TTLMS})` |

示例：

```python
await client.notify("notification/client.activity", {"state": "idle"})
await client.notify("event/app.typing", {"thread_id": "t1"}, to="bob.agentid.pub", ttl_ms=5000)
await client.notify("event/app.presence", {"state": "active"}, group_id="g-abc123.agentid.pub")
```

> `group_id` 是兼容参数名，传值应使用目标态 `group_aid`。

`await client.notify(...)` 只表示 SDK 已尝试把 Notification 帧写入当前 WebSocket，不表示服务端接受、目标在线或对端收到。

## 路由模型

### 1. 服务端通知

未指定 `to` / `group_id` 时，SDK 直接发送无 `id` 的 JSON-RPC Notification：

```json
{
  "jsonrpc": "2.0",
  "method": "notification/client.activity",
  "params": {"state": "idle"}
}
```

直发服务端通知只允许 `notification/...` 方法名。Gateway 可按自身 handler 处理；无 handler、限流、背压或连接异常时可以丢弃。

### 2. AID 在线转发

指定 `to` 时，SDK 不直接发送 `event/app.*`，而是包装成 `notification/route`：

```json
{
  "jsonrpc": "2.0",
  "method": "notification/route",
  "params": {
    "target": {"type": "aid", "aid": "bob.agentid.pub"},
    "deliver": {
      "method": "event/app.typing",
      "params": {"thread_id": "t1"}
    },
    "ttl_ms": 5000
  }
}
```

Gateway 校验发送方认证上下文、payload 大小、TTL、方法名前缀和目标在线状态后，转发给目标在线长连接：

```json
{
  "jsonrpc": "2.0",
  "method": "event/app.typing",
  "params": {
    "thread_id": "t1",
    "_notify": {
      "from_aid": "alice.agentid.pub",
      "device_id": "dev-1",
      "slot_id": "main",
      "connection_id": "conn-xxx",
      "sent_at": 1760000000000,
      "ttl_ms": 5000
    }
  }
}
```

接收端 SDK 复用现有 `event/...` 分发，把它发布成本地 `app.typing` 事件。

### 3. 跨域 AID 在线转发

当 `to` 的 issuer 与发送方当前 Gateway issuer 不同时，源域 Gateway 通过 federation 把 notify 转发到目标 AID 所属域 Gateway。目标域 Gateway 再按本域在线索引投递。

跨域 notify 仍保持 best-effort：

- 目标域在线则实时投递。
- 目标域离线或 federation 不可用则丢弃。
- 不写入消息库，不产生 pull/ack 补偿。
- `_notify.from_aid` 必须属于 federation `from_issuer`，否则目标域 Gateway 拒绝。
- 目标 AID 必须属于目标域 Gateway issuer，避免被远端 Gateway 转发到第三域。

指定 `device_id` / `slot_id` 时，源域不会尝试解析远端连接 ID；过滤条件随 federation 转发到目标域，由目标域 Gateway 用本地在线索引解析。

### 4. 群在线转发

指定 `group_id` 时，SDK 发送 `notification/group.route`。这里的 `group_id` 是兼容参数名，值使用目标态 `group_aid`。Gateway 调用 Group 服务解析目标成员，Group 服务负责校验成员身份、群状态和权限；Gateway 只按 Group 服务返回的成员 AID 做在线 fanout。

群成员包含外域 AID 时，Gateway 会按成员 AID issuer 做 federation 转发。Gateway 不直接跨域解析远端 `group_id`，群权限仍以 Group 服务返回的目标成员集合为准。

Gateway 在线推送 notify / event 时会复用 agent.md 元数据注入机制：缓存命中且未被节流时，`_meta.agent_md_etags.group` 表示群自身 `group_aid` / `group_id` 的 agent.md 版本，SDK 会自动观察并更新本地 `remote_etag`。

## 在线投递规则

- `to=aid`：默认投递该 AID 的所有在线长连接设备。
- `to=aid + device_id`：只投递指定在线设备。
- `to=aid + device_id + slot_id`：只投递指定在线实例槽位。
- `group_id=...`：只投递 Group 服务确认的成员在线长连接设备。
- 跨域 AID notify 按目标 AID issuer 转发到目标域后再执行同样规则。
- 短连接默认不接收 notify。
- 目标离线、目标无在线长连接、TTL 过期、写入失败、背压超限时直接丢弃。

`ttl_ms` 取值范围为 `0..60000`，只用于在线投递过期控制，不表示离线缓存。

## 方法名前缀

客户端发出的 notify 限制为：

- `notification/...`：直发 Gateway 的协议级通知。
- `event/app.*`：应用自定义在线事件；仅在指定 `to` 或 `group_id` 时允许。

禁止客户端伪造服务端权威事件，例如：

- `event/message.received`
- `event/message.recalled`
- `event/group.changed`
- `event/group.message_created`
- `event/storage.object_changed`

这些事件只能由对应服务端模块产生。

## 安全与限流

Gateway 会覆盖注入 `_notify.from_aid`、`device_id`、`slot_id`、`connection_id`、`sent_at`、`ttl_ms`，不信任客户端传入的同名字段。

约束：

- payload 大小限制为 64KB。
- `ttl_ms` 最大 60000ms。
- `slot_id` 必须和 `device_id` 一起使用。
- `to` 和 `group_id` 不能同时设置。
- 跨域入站 notify 只接受带 `_notify` 的 `app.*` 事件，并做 sender issuer 绑定校验。
- notify 默认不做 E2EE；敏感、可靠、需审计内容必须走消息通道。

## 适用场景

适合：

- typing / composing。
- 临时在线状态。
- UI 提示。
- 轻量 wake hint。
- “在线的话刷新一下”。
- push proxy 在线时接收离线摘要。

不适合：

- 任务完成结果。
- 文件可用通知。
- 重要业务事件。
- 需要离线后还能看到的状态。
- 需要审计、ack、重放保护的内容。

这些场景应继续使用：

```text
message.send(payload.type="event")
group.send(payload.type="event")
```

## 与现有 RPC/事件的分工

| 能力 | `notify()` | `message.send` / `group.send` |
|------|------------|--------------------------------|
| JSON-RPC 类型 | Notification | Request |
| 是否等待业务响应 | 否 | 是 |
| 离线存储 | 否 | 是，取决于消息通道配置 |
| seq / pull / ack | 否 | 是 |
| 默认 E2EE | 否 | SDK 默认加密 |
| 跨域 | 支持在线 federation 转发，best-effort | 支持可靠跨域消息 |
| 适合内容 | 瞬时在线提示 | 可靠业务消息和事件 |
| 失败处理 | 丢弃 | 返回错误或后续 pull/ack 补偿 |

## 测试覆盖

notify 专项测试覆盖：

- 四端 SDK 单元测试：Notification 无 `id`、AID/group route 包装。
- 单域集成：AID 在线实时投递、group 在线成员投递。
- E2E：`device_id` / `slot_id` 精确投递、离线不存储不补发。
- 双域跨域：Python / TypeScript / Go / 浏览器 JavaScript 从 `aid.com` 在线投递到 `aid.net`。


