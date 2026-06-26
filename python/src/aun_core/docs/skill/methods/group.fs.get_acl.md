# group.fs.get_acl

查询群自有区角色 ACL。只能由当前 group owner 调用；当前查询的是 `role:admin` 角色策略，不绑定具体 admin 成员。

## 调用示例

```python
result = await client.call("group.fs.get_acl", {
    "path": "team.agentid.pub:/archive",
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群自有区路径 |
| `group_id` | string | 否 | — | 使用裸路径时指定群 ID |

## 返回值

包含 `group_id`、`group_aid`、`path`、`area`、`storage` 和 `acls`。`acls[].perms` 使用 POSIX 视图，删除权限显示为 `x`，例如 `rwx`。

## 相关方法

- [group.fs.set_acl](group.fs.set_acl.md) — 授予 admin 角色写 ACL
- [group.fs.remove_acl](group.fs.remove_acl.md) — 撤销 admin 角色写 ACL
- [group.fs.list_acl](group.fs.list_acl.md) — 查询 ACL 别名
