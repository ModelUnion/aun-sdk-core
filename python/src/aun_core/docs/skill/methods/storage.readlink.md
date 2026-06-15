# storage.readlink

读软链 target（owner 校验）。

## 调用示例

```python
result = await client.call("storage.readlink", {"path": "public/latest.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 软链路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

软链视图 `{symlink, target, version, ...}`。

## 相关方法

- [storage.create_symlink](storage.create_symlink.md) — 创建软链
