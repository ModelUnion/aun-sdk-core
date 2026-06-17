# group.fs.complete_upload

完成群文件上传，会把已上传的数据提交为群文件节点并发布群变更事件。

## 调用示例

```python
node = await client.call("group.fs.complete_upload", {
    "path": "team.agentid.pub:/docs/a.bin",
    "session_id": "sess_xxx",
    "size_bytes": 1024,
    "sha256": "..."
})
```

## 参数

参数同 [group.fs.check_upload](group.fs.check_upload.md)，通常还包含 `session_id` 或服务端上传会话要求的确认字段。

## 返回值

上传后的节点视图。

## 相关方法

- [group.fs.create_upload_session](group.fs.create_upload_session.md) — 创建上传会话
