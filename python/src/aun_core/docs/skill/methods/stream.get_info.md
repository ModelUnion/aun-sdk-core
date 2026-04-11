# stream.get_info

获取一条流的状态和统计信息。

## 调用示例

```python
info = await client.call("stream.get_info", {"stream_id": "4d5067f203cf42ba"})
print(f"状态: {info['status']}, 已推送: {info['frames_pushed']} 帧")
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `stream_id` | string | 是 | 流 ID |

## 返回值

| 字段 | 类型 | 说明 |
|------|------|------|
| `stream_id` | string | 流 ID |
| `creator_aid` | string | 创建者 AID |
| `content_type` | string | 内容类型 |
| `metadata` | object | 自定义元数据 |
| `status` | string | `"waiting"`（等待推流）/ `"active"`（推流中）/ `"done"`（已关闭） |
| `is_online` | boolean | 推流端是否在线 |
| `seq` | integer | 当前最大序列号 |
| `frames_pushed` | integer | 已推送帧数 |
| `bytes_pushed` | integer | 已推送字节数 |
| `puller_count` | integer | 当前拉流端数量 |
| `age_seconds` | float | 流存活时间（秒） |
| `idle_seconds` | float | 距最近活动的秒数 |

## 错误

| code | message |
|------|---------|
| -32000 | `流不存在: {stream_id}` |
