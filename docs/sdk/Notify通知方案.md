# Notify 通知方案

> 状态：设计方案。本文定义 SDK 公开 `notify()` API 的语义边界、路由方式和与可靠消息通道的分工。

## 目标

`notify()` 用于发送 JSON-RPC 2.0 Notification：无 `id`、不等待业务响应、只面向在线连接的轻量通知。

它补齐 SDK 发送侧能力：现有 SDK 已通过 `client.on(event, handler)` 接收 `event/...`，但应用层没有对称的发送端 Notification API。可靠应用事件仍走 `message.send` / `group.send`，在 payload 中使用 `type="event"` 或 `type="status"`。

## 非目标

- 不做离线存储。
- 不分配 `seq`。
- 不进入 `message.pull` / `group.pull`。
- 不需要 ack。
- 不提供送达保证。
- 不承载敏感内容，除非应用自行加密。
- 不替代 `message.send` / `group.send`。

## API 形态

建议公共方法命名为 `notify()`，不用 `emit()`。

原因：

- `notify` 对齐 JSON-RPC Notification 术语。
- `emit` 容易被理解为触发本地事件 handler，和 `client.on()` 组合时有歧义。
- `notify` 更清楚表达单向、轻量、无业务响应。

推荐调用形态：

```python
await client.notify("notification/client.activity", {"state": "idle"})

await client.notify(
    "event/app.typing",
    {"thread_id": "t1"},
    to="bob.agentid.pub",
    ttl_ms=5000,
)

await client.notify(
    "event/app.typing",
    {"thread_id": "t1"},
    group_id="g-xxx.agentid.pub",
    ttl_ms=5000,
)
```

`await client.notify(...)` 只表示 SDK 已尝试把帧写入当前 WebSocket，不表示服务端接受、目标在线或对端收到。

## 路由模型

### 1. 服务端通知

目标是当前连接的 Gateway 或服务模块时，SDK 直接发送无 `id` 的 JSON-RPC Notification：

```json
{
  "jsonrpc": "2.0",
  "method": "notification/client.activity",
  "params": {"state": "idle"}
}
```

Gateway 按 `notification/{namespace}` 路由到自身或服务模块。无 handler、限流、背压或连接异常时可以丢弃，不返回 JSON-RPC error。

### 2. AID 在线转发

目标是另一个客户端时，SDK 不直接向 Gateway 发送 `event/app.*`。应包装成路由通知：

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

Gateway 校验发送方认证上下文、限流、TTL 和目标在线状态后，转发给目标在线长连接：

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
      "sent_at": 1760000000000,
      "ttl_ms": 5000
    }
  }
}
```

接收端 SDK 复用现有 `event/...` 路由，把它发布成本地 `app.typing` 事件。

### 3. 群在线转发

目标是群时，SDK 仍暴露 `client.notify(..., group_id=...)`，底层发送 `notification/group.route`。Gateway 应转给 Group 服务，由 Group 服务校验成员身份、群状态和权限后，只 fanout 给群内在线长连接。

不建议 Gateway 绕过 Group 服务直接按 `group_id` fanout，除非 Gateway 拥有可靠且实时的群权限缓存。

## 在线投递规则

- `to=aid`：默认投递该 AID 的所有在线长连接设备。
- `to=aid + device_id`：只投递指定在线设备。
- `to=aid + device_id + slot_id`：只投递指定在线实例槽位。
- `group_id=...`：只投递群内有权限成员的在线长连接设备。
- 短连接默认不接收 notify。
- 目标离线、目标无在线长连接、TTL 过期、写入失败、背压超限时直接丢弃。

`ttl_ms` 只用于在线投递过期控制，不表示离线缓存。

## 方法名前缀

客户端发出的 notify 应限制为：

- `notification/...`：服务端或路由控制通知。
- `event/app.*`：应用自定义在线事件。

禁止客户端伪造服务端权威事件，例如：

- `event/message.received`
- `event/message.recalled`
- `event/group.changed`
- `event/group.message_created`
- `event/storage.object_changed`

这些事件只能由对应服务端模块产生。

## 安全与限流

Gateway 或服务端必须覆盖注入 `_notify.from_aid`、`device_id`、`slot_id`、`sent_at`，不能信任客户端传入的同名字段。

建议约束：

- payload 大小限制，例如 16KB 或 64KB。
- per-AID / per-connection 速率限制。
- 只允许白名单前缀和目标类型。
- 跨域 notify 默认可先不支持；如支持，应保持 best-effort，不做离线补偿。
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
| 适合内容 | 瞬时在线提示 | 可靠业务消息和事件 |
| 失败处理 | 丢弃 | 返回错误或后续 pull/ack 补偿 |

## 实施建议

1. 四端 SDK 增加 `client.notify(method, params=None, *, to=None, group_id=None, device_id=None, slot_id=None, ttl_ms=None)`。
2. Transport 增加发送无 `id` JSON-RPC Notification 的底层方法。
3. Gateway 增加 `notification/route` 在线 AID 转发。
4. Gateway / Group 服务增加 `notification/group.route` 群在线转发。
5. 接收端复用现有 `event/...` 分发，不新增本地事件系统。
6. 文档明确 `notify()` 不可靠、不离线、不替代消息通道。
