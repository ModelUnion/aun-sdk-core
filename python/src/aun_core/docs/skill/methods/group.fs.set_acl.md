# group.fs.set_acl

授予群自有区 `role:admin` 写 ACL。只能由当前 group owner 调用；授权的是角色策略，不绑定具体 admin 成员。

## 调用示例

```python
result = await client.call("group.fs.set_acl", {
    "path": "team.agentid.pub:/archive",
    "grantee_aid": "role:admin",
    "perms": "rwx",
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群自有区路径 |
| `grantee_aid` | string | 否 | `role:admin` | 当前只允许 `role:admin` |
| `perms` | string | 否 | `rwx` | 必须包含写权限 |

## 返回值

ACL 操作结果，包含 `acl_action="set_acl"`、`group_aid`、`grantee_aid`、`storage`。

## 相关方法

- [group.fs.remove_acl](group.fs.remove_acl.md) — 撤销 admin 角色写 ACL
- [storage.set_acl](storage.set_acl.md) — AID storage 写授权
