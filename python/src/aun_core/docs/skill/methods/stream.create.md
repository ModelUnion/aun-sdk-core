# stream.create

创建一条新的实时流，返回推流和拉流地址。

## 调用示例

```python
result = await client.call("stream.create", {
    "content_type": "text/plain",
    "metadata": {"model": "gpt-4"},
    "target_aid": "bob.aid.net",  # 可选，绑定拉流方
})
push_url = result["push_url"]    # WebSocket 推流地址
pull_url = result["pull_url"]    # HTTP SSE 拉流地址
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `content_type` | string | 否 | `"text/plain"` | 内容类型（`text/plain` / `application/json-stream` / `text/event-stream`） |
| `metadata` | object | 否 | `{}` | 自定义元数据 |
| `target_aid` | string | 否 | — | 绑定拉流方 AID。当前实现中，只有拉流方显式提供 `aid` 时才会做该匹配校验 |

## 返回值

```json
{
    "stream_id": "4d5067f203cf42ba",
    "push_url": "wss://stream.aid.com:9490/push/4d5067f203cf42ba?token=ec80...",
    "pull_url": "https://stream.aid.com:9490/pull/4d5067f203cf42ba?token=c438...",
    "push_token": "ec80...",
    "pull_token": "c438953be0ca887b...",
    "push_headers": {"Authorization": "Bearer ec80..."},
    "pull_headers": {"Authorization": "Bearer c438953be0ca887b..."}
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `stream_id` | string | 流唯一 ID |
| `push_url` | string | 推流 WebSocket URL（含 push_token） |
| `pull_url` | string | 拉流 HTTP SSE URL（含 pull_token） |
| `push_token` | string | 推流凭证 |
| `pull_token` | string | 拉流凭证（可通过 message.send 传递给接收方） |
| `push_headers` | object | 推流推荐使用的 Header（`Authorization: Bearer {push_token}`） |
| `pull_headers` | object | 拉流推荐使用的 Header（`Authorization: Bearer {pull_token}`） |

## 典型流程

1. 调用 `stream.create` 获取 URL
2. 通过 `message.send` 将 `pull_url` 发给接收方
3. 推流方用 WebSocket 连接 `push_url` 发送数据帧
4. 接收方用 HTTP SSE 连接 `pull_url` 接收数据

> 当前实现仍在 `push_url` / `pull_url` 中保留 query token 以兼容旧客户端；新客户端优先使用 `push_headers` / `pull_headers`，减少 token 暴露在日志、Referer 和浏览器历史中的机会。

## 错误

| code | message |
|------|---------|
| -32000 | 达到最大流数限制 (`达到最大流数限制 (N)`) |
