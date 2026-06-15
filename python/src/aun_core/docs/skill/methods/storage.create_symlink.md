# storage.create_symlink

创建软链。target 受限于 owner 命名空间；拒绝同名 file/dir；父路径不可含软链前缀。软链是元数据库一行，不在对象存储。

## 调用示例

```python
# 软链进 /public 即对外发布
result = await client.call("storage.create_symlink", {
    "path": "public/latest.md",
    "target": "private/v2.md"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 软链路径 |
| `target` | string | 是 | — | 指向目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在软链 |

## 返回值

软链视图（含 `dangling` 悬空标志）。

## 相关方法

- [storage.readlink](storage.readlink.md) — 读 target
- [storage.atomic_repoint](storage.atomic_repoint.md) — 原子重指
