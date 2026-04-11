# stream.close

关闭一条流。仅流的创建者可调用。关闭后所有拉流端收到 SSE `event: done`。

## 调用示例

```python
await client.call("stream.close", {"stream_id": "4d5067f203cf42ba"})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `stream_id` | string | 是 | 要关闭的流 ID |

## 返回值

```json
{"success": true}
```

## 说明

- 也可以通过推流 WebSocket 发送 `{"cmd": "close"}` 关闭流，效果相同
- 流关闭后资源不会立即释放，无拉流端的已关闭流在 60 秒后自动清理

## 错误

| code | message |
|------|---------|
| -32000 | `流不存在: {stream_id}` |
| -32000 | `只有流创建者可以关闭流` |
