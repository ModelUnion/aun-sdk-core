# group.fs.check_upload

上传前检查群文件目标，执行配额、权限、秒传和目标存在检查。普通应用优先使用 SDK 的 `client.group.fs` 上传门面。

## 调用示例

```python
check = await client.call("group.fs.check_upload", {
    "path": "team.agentid.pub:/docs/a.bin",
    "size_bytes": 1024,
    "sha256": "..."
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 上传目标群路径 |
| `size_bytes` | integer | 是 | — | 文件大小 |
| `sha256` | string | 否 | — | 内容 SHA-256，用于秒传 |
| `content_type` | string | 否 | — | MIME 类型 |
| `parents` | boolean | 否 | `true` | 是否递归创建父目录 |
| `expected_version` | integer | 否 | — | 可选乐观锁版本 |
| `force` / `overwrite` | boolean | 否 | `false` | 目标存在时覆盖 |
| `metadata` | object | 否 | — | 元数据 |

## 返回值

预检结果 + `{path, group_id, group_aid, area, storage}`，可包含 `target_exists`、`within_limit`、`instant`、`dedup_hit` 或 `skip_upload`。

## 相关方法

- [group.fs.create_upload_session](group.fs.create_upload_session.md) — 创建上传会话
- [group.fs.complete_upload](group.fs.complete_upload.md) — 完成上传
