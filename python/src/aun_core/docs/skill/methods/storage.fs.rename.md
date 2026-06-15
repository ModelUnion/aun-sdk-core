# storage.fs.rename

POSIX `mv`：同 owner/bucket 内移动或改名。**跨 owner/bucket 被拒**；按节点类型分派到 move_folder / rename_symlink / move_object。

## 调用示例

```python
result = await client.call("storage.fs.rename", {"src": "a/x.md", "dst": "b/y.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `src` | string | 是 | — | 源路径 |
| `dst` | string | 是 | — | 目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在目标 |
| `expected_version` | integer | 否 | — | 乐观锁版本号 |

## 返回值

被重命名节点的 fs 节点视图。

## 相关方法

- [storage.fs.copy](storage.fs.copy.md) — 复制
