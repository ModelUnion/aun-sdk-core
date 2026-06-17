# group.fs.create_upload_session

创建群文件上传会话。返回 `upload_url` 后，SDK 使用 HTTP PUT 走数据面上传。

## 调用示例

```python
session = await client.call("group.fs.create_upload_session", {
    "path": "team.agentid.pub:/docs/a.bin",
    "size_bytes": 1024,
    "sha256": "..."
})
```

## 参数

参数同 [group.fs.check_upload](group.fs.check_upload.md)，额外会把 `overwrite` 设置为 `force` / `overwrite` 的布尔值。

## 返回值

上传会话字段（如 `session_id`、`upload_url`、`headers`）+ `{path, group_id, group_aid, area, storage}`。

## 相关方法

- [group.fs.complete_upload](group.fs.complete_upload.md) — 上传后确认
