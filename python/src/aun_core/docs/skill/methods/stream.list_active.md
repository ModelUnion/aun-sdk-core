# stream.list_active

列出当前 AID 创建的所有活跃流（未关闭的流）。

## 调用示例

```python
result = await client.call("stream.list_active", {})
for s in result["streams"]:
    print(f"{s['stream_id']}: {s['status']}, {s['frames_pushed']} frames")
```

## 参数

无。

## 返回值

```json
{
    "streams": [
        {
            "stream_id": "4d5067f203cf42ba",
            "creator_aid": "alice.aid.com",
            "content_type": "text/plain",
            "status": "active",
            "seq": 42,
            "frames_pushed": 42,
            "bytes_pushed": 1024,
            "puller_count": 1
        }
    ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `streams` | array | StreamInfo 对象数组，格式同 `stream.get_info` 返回值 |
