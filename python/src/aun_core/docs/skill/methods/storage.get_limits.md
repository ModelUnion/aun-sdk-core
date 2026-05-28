# storage.get_limits

查询当前用户的上传限制和配额使用情况。

## 调用

```python
limits = await client.call("storage.get_limits", {})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 查询指定用户的配额，默认当前用户 |

## 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `max_inline_bytes` | integer | `put_object` 内联上限（当前 64KB） |
| `max_file_size_bytes` | integer | 单文件大小上限（当前 10MB） |
| `quota_total_bytes` | integer | 用户总配额（0 表示无限制） |
| `quota_used_bytes` | integer | 已用配额 |

## 说明

- 客户端应在上传前调用此方法，判断文件是否超限
- `max_inline_bytes` 是 `storage.put_object` 的内联上限，超过此大小需使用 `storage.create_upload_session`
- `max_file_size_bytes` 是单文件绝对上限，超过此大小服务端会拒绝

## 相关

- [storage.check_upload](storage.check_upload.md) — 带 SHA-256 的预检（秒传检测）
- [storage.put_object](storage.put_object.md) — 小文件直接上传
- [storage.create_upload_session](storage.create_upload_session.md) — 大文件上传
