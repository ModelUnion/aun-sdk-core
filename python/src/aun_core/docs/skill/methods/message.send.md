# message.send

发送 P2P 消息给指定 AID。

## 调用示例

```python
result = await client.call("message.send", {
    "to": "demo-msg-receiver.agentid.pub",
    "payload": {"type": "text", "text": "你好"}
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `to` | string | 是 | — | 目标 AID |
| `payload` | object | 是 | — | 消息体，业务类型由 `payload.type` 决定 |
| `type` | string | 否 | — | 信封/封装类型，普通业务消息无需填写；SDK 加密发送时自动使用 `e2ee.encrypted` |
| `encrypt` | boolean | 否 | `true` | 是否端到端加密（SDK 默认加密发送；明文时显式传 `false`）。底层传输信封中映射为 `encrypted=true` |
| `message_id` | string | 否 | 服务端生成 | 客户端指定的幂等 ID，重复发送返回 `"duplicate"` |
| `timestamp` | integer | 否 | 服务端时间 | 客户端时间戳（毫秒）。**服务端忽略此字段，始终使用服务端时间** |

P2P 消息的投递语义由连接阶段声明的 `delivery_mode` 决定；`group.send` 固定为 `fanout`。

## Payload 约定要点

- `payload` 由应用层定义，服务端只做大小限制和透传；业务负载类型只能放在 `payload.type`，例如 `text`、`image`、`status`、`event`、`tool_call`。
- 引用、会话和提及等不适合放在信封里、且需要端到端加密保护的字段，应放入 `payload.chat_id`、`payload.reply_to`、`payload.quote`、`payload.mentions`。
- 文件、图片、音视频等附件引用放入 `payload.attachments`；不要把二进制内容直接嵌入 `payload`。
- AUN Storage 的 `url` 是上传完成后返回的长期对象引用；下载时用该 `url` 换取 `download_ticket`，再使用短期 `download_url`。

详细字段建议见 [消息Payload参考约定](../sdk-core/消息Payload参考约定.md)；RPC 调用细节见 [message/04-RPC-Manual.md](../rpc-manual/message/04-RPC-Manual.md#payload-参考约定)。

## 返回值

```json
{
    "message_id": "msg-uuid-xxx",
    "seq": 42,
    "timestamp": 1711234567890,
    "status": "sent",
    "delivery_mode": "fanout"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `message_id` | string | 消息唯一标识 |
| `seq` | integer | 收件方的 inbox 序列号 |
| `timestamp` | integer | 服务端确认时间戳（毫秒） |
| `status` | string | `"sent"` / `"delivered"` / `"duplicate"` |
| `delivery_mode` | string | 实际生效的连接级投递语义：`fanout` 或 `queue` |
| `cross_domain` | boolean | 仅跨域投递时出现，当前值为 `true` |
| `target_issuer` | string | 仅跨域投递时出现，表示目标 issuer |

> **duplicate 响应**：当 `message_id` 重复时，`status` 为 `"duplicate"`。若无法返回首次发送的完整结果，响应可能只包含 `message_id`、`timestamp`、`status`，此时 `seq` 和 `delivery_mode` 字段都可能缺失。

## 错误码

| 错误码 | 说明 |
|--------|------|
| `-32002` | 服务暂不可用（如数据库未连接、message 证书未加载） |
| `-32603` | 参数缺失、payload 超限、目标 AID 不存在、频率超限 |

## 相关方法

- [message.pull](message.pull.md) — 增量拉取消息
- [message.ack](message.ack.md) — 确认送达
