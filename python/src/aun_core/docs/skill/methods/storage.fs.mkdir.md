# storage.fs.mkdir

POSIX `mkdir`：建目录。委托 `storage.create_folder`。

## 调用示例

```python
result = await client.call("storage.fs.mkdir", {"path": "projects/myapp", "parents": True})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 目录路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `parents` | boolean | 否 | `false` | 递归创建父目录（类 `mkdir -p`） |

## 返回值

fs 目录节点视图。

## 相关方法

- [storage.fs.remove](storage.fs.remove.md) — 删除
