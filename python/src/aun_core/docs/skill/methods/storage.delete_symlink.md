# storage.delete_symlink

删软链记录（不动 target 对象）。

## 调用示例

```python
result = await client.call("storage.delete_symlink", {"path": "public/latest.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 软链路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

`{deleted: boolean, owner_aid, bucket, path, symlink_id, target}`。

## 相关方法

- [storage.create_symlink](storage.create_symlink.md) — 创建软链
