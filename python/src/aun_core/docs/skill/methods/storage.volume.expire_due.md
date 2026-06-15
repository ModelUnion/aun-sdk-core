# storage.volume.expire_due

过期所有到期卷并标记其挂载为 unavailable。

## 调用示例

```python
result = await client.call("storage.volume.expire_due", {})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `now` | integer | 否 | 当前时间 | 判定基准时间 |

## 返回值

`{owner_aid, bucket, expired, mounts_unavailable, volumes, mounts}`。

## 相关方法

- [storage.volume.renew](storage.volume.renew.md) — 续期防过期
