# storage.volume.create

创建/upsert 配额卷（含 mount_point）。卷生命周期：active → grace（只读宽限）→ expired。

## 调用示例

```python
result = await client.call("storage.volume.create", {
    "size_bytes": 1073741824,
    "mount_point": "data/"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `size_bytes` | integer | 是 | — | 卷容量（>0） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `volume_id` | string | 否 | 自动 | 卷 ID |
| `used_bytes` | integer | 否 | — | 已用字节 |
| `status` | string | 否 | `active` | `active`/`grace`/`expired` |
| `mount_point` | string | 否 | — | 挂载点 |
| `expires_at` | integer | 否 | — | 过期时间 |

## 返回值

`{volume, ...卷视图}`。

## 相关方法

- [storage.volume.renew](storage.volume.renew.md) — 续期
- [storage.fs.df](storage.fs.df.md) — 查用量
