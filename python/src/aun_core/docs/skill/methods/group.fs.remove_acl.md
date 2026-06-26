# group.fs.remove_acl

撤销群自有区 `role:admin` 写 ACL。只能由当前 group owner 调用；撤销的是角色策略，不与成员升降级、退群或踢出联动。

## 调用示例

```python
result = await client.call("group.fs.remove_acl", {
    "path": "team.agentid.pub:/archive",
    "grantee_aid": "role:admin",
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群自有区路径 |
| `grantee_aid` | string | 否 | `role:admin` | 当前只允许 `role:admin` |

## 返回值

ACL 操作结果，包含 `acl_action="remove_acl"`、`removed`、`group_aid`、`grantee_aid`、`storage`。

## 相关方法

- [group.fs.set_acl](group.fs.set_acl.md) — 授予 admin 角色写 ACL
- [group.fs.get_acl](group.fs.get_acl.md) — 查询 admin 角色 ACL
- [storage.remove_acl](storage.remove_acl.md) — AID storage 写授权撤销
