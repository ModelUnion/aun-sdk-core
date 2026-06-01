# 连接管理

当前稳定实现为 Gateway 模式。Peer / Relay 是协议能力定义，SDK 连接层会明确返回未实现。

## connect() 参数

```python
await client.connect({
    "slot_id": "main",
    "connection_kind": "long",
    "short_ttl_ms": 30000,
    "delivery_mode": {"mode": "fanout"},
    "auto_reconnect": True,
    "heartbeat_interval": 30.0,
    "token_refresh_before": 60.0,
    "retry": {
        "initial_delay": 1.0,
        "max_delay": 64.0,
        "max_attempts": 0,
    },
    "timeouts": {
        "connect": 5.0,
        "call": 10.0,
        "http": 30.0,
    },
})
```

`connect()` 会在需要时自动执行认证，并使用自动发现得到的 Gateway。不要把 `access_token` 或 `gateway` 作为公开连接参数传入。

## 连接状态

公开状态是九态：

```text
no_identity / standby / authenticated / connecting / ready /
retry_backoff / reconnecting / connection_failed / closed
```

```python
print(client.state)
print(client.can_connect, client.can_send, client.is_online)
```

## slot_id

`slot_id` 允许 `/`、`:`、空格作为共享隔离键分隔符。隔离键是第一个分隔符之前的部分：

```text
evolclaw daemon   -> evolclaw
evolclaw:cli      -> evolclaw
evolclaw/netcheck -> evolclaw
```

同一 `(aid, device_id, slotIsolationKey(slot_id))` 下允许 1 条长连接和多条短连接共存。

## 事件

连接相关事件通过 `client.on()` 订阅：

| 事件名 | 说明 |
|--------|------|
| `state_change` | 状态变化，payload 中含九态公开值 |
| `connection.error` | 连接、认证或重连错误 |
| `token.refreshed` | token 自动刷新完成 |

建议在 `connect()` 前注册事件处理器。

详细说明见 [sdk-core/04-连接与认证.md](../sdk-core/04-连接与认证.md)。
