# storage.volume.renew

续期卷过期时间/状态（owner 校验，owner 不符抛 PermissionError）。

## 调用示例

```python
result = await client.call("storage.volume.renew", {"volume_id": "vol_xxx", "expires_at": 1767225600})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `volume_id` | string | 是 | — | 卷 ID（服务端别名 `id`） |
| `expires_at` | integer | 是 | — | 新过期时间 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `status` | string | 否 | — | 卷状态 |

## 返回值

`{volume, ...卷视图}`。

## 相关方法

- [storage.volume.expire_due](storage.volume.expire_due.md) — 过期到期卷
