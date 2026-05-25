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
    "ack_seq": 101
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | boolean | 操作是否成功 |
| `ack_seq` | integer | 当前 ack_seq 游标位置 |

## 副作用

调用成功后仅推进接收方消费游标。服务端不会向发送方或其他客户端推送 `message.ack` 事件，也不会把对端已读状态作为协议通知暴露。

## 相关方法

- [message.pull](message.pull.md) — 增量拉取消息
- [message.send](message.send.md) — 发送消息
