# storage.fs.copy

POSIX `cp`：复制对象或软链（目录复制暂不支持）。CAS blob 引用计数复用，支持跨 owner 对象复制。

## 调用示例

```python
result = await client.call("storage.fs.copy", {"src": "a/x.md", "dst": "b/x.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `src` | string | 是 | — | 源路径 |
| `dst` | string | 是 | — | 目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 源所有者 AID |
| `bucket` | string | 否 | `"default"` | 源存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在目标 |
| `follow_symlinks` | boolean | 否 | `false` | 复制 target 而非软链本身 |
| `dst_owner_aid` | string | 否 | 同源 | 目标所有者（SDK 形参 `dst_owner`） |
| `dst_bucket` | string | 否 | 同源 | 目标存储桶 |

## 返回值

被复制节点的 fs 节点视图。

## 相关方法

- [storage.fs.rename](storage.fs.rename.md) — 移动/改名
