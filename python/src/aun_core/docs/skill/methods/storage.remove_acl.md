# storage.remove_acl

移除路径 ACL 授权。

## 调用示例

```python
result = await client.call("storage.remove_acl", {"path": "projects/myapp/", "grantee_aid": "bob.aid.pub"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 授权路径前缀 |
| `grantee_aid` | string | 是 | — | 被授权 AID |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

`{removed: boolean, owner_aid, bucket, path, grantee_aid}`。

## 相关方法

- [storage.set_acl](storage.set_acl.md) — 授予 ACL
