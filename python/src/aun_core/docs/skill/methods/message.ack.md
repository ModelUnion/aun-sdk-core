# message.ack

确认消息送达，将 ack_seq 游标推进到指定值。seq 小于等于该值的所有消息视为已确认。

## 调用示例

```python
result = await client.call("message.ack", {
    "seq": 101
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `seq` | integer | 是 | — | 确认 seq ≤ 此值的所有消息 |

## 返回值

```json
{
    "success": true,
    "ack_seq": 101,
    "event_published": true
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 操作是否成功 |
| `ack_seq` | integer | 当前 ack_seq 游标位置 |
| `event_published` | boolean | 可选。ack 已写入数据库且事件成功发布时为 `true` |
| `event_error` | string | 可选。ack 已写入数据库但事件发布失败时返回错误说明 |

## 副作用

调用成功后，服务端会触发 `event/message.ack` 事件推送给消息的发送方。事件 payload 中的 `to` 字段为**确认方（接收方）AID**，即执行 ack 操作的一方；当前实现还会携带 `device_id` / `slot_id`。

当 ack 游标已经成功推进，但事件发布失败时，服务端会返回：

```json
{
    "success": true,
    "ack_seq": 101,
    "event_published": false,
    "event_error": "..."
}
```

这表示状态已经提交成功，调用方不应仅因事件发布失败而重试同一个 ack。

## 相关方法

- [message.pull](message.pull.md) — 增量拉取消息
- [message.send](message.send.md) — 发送消息
