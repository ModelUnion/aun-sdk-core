# storage.fs.df

POSIX `df`：配额/用量报告，含每 owner 卷（过期卷重新计算）。

## 调用示例

```python
result = await client.call("storage.fs.df", {})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

| 字段 | 类型 | 说明 |
|------|------|------|
| `used_bytes` | integer | 已用字节 |
| `object_count` | integer | 对象数 |
| `quota_bytes` | integer | 配额上限 |
| `avail_bytes` | integer | 剩余可用 |
| `volumes` | array | 每卷用量明细 |

## 相关方法

- [storage.volume.create](storage.volume.create.md) — 创建配额卷
