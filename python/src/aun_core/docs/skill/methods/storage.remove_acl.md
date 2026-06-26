# storage.remove_acl

移除路径 ACL 授权。对 AID storage，这是撤销写/删除授权的入口；读分享撤销使用 `storage.revoke_share_link`。群自有区 admin 角色写授权撤销使用 `group.fs.remove_acl`。

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
- [storage.revoke_share_link](storage.revoke_share_link.md) — 撤销读分享
- [group.fs.remove_acl](group.fs.remove_acl.md) — 撤销群自有区 admin 写授权
