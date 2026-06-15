# storage.fs.stat

POSIX `stat`：查节点元数据，跟随末级软链（`follow_final=true`）。

## 调用示例

```python
result = await client.call("storage.fs.stat", {"path": "projects/readme.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 节点路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `token` | string | 否 | — | 访问 token |

## 返回值

fs 节点视图：`{type, node_type, name, path, mode, size, mtime, owner_principal, ...}`。

## 相关方法

- [storage.fs.lstat](storage.fs.lstat.md) — 不跟随软链
