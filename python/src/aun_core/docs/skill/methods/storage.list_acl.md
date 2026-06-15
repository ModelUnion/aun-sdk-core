# storage.list_acl

列出路径上的 ACL 授权（owner 校验）。

## 调用示例

```python
result = await client.call("storage.list_acl", {"path": "projects/myapp/"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

`{owner_aid, bucket, path, acls}`。

## 相关方法

- [storage.set_acl](storage.set_acl.md) — 授予 ACL
