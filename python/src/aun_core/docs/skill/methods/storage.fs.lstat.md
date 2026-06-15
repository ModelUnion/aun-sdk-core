# storage.fs.lstat

POSIX `lstat`：查节点，**不跟随末级软链**——返回软链本身（携带 `dangling` 悬空标志）。

## 调用示例

```python
result = await client.call("storage.fs.lstat", {"path": "releases/latest"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 节点路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `token` | string | 否 | — | 访问 token |

## 返回值

fs 节点视图；若为软链，返回软链节点本身（含 `dangling` 标志），不解析 target。

## 相关方法

- [storage.fs.stat](storage.fs.stat.md) — 跟随软链
- [storage.readlink](storage.readlink.md) — 读软链 target
