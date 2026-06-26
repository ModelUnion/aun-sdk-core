# group.fs.list_acl

`group.fs.get_acl` 的别名，用于查询群自有区角色 ACL。只能由当前 group owner 调用。

## 调用示例

```python
result = await client.call("group.fs.list_acl", {
    "path": "team.agentid.pub:/archive",
})
```

## 参数

同 [group.fs.get_acl](group.fs.get_acl.md)。

## 返回值

同 [group.fs.get_acl](group.fs.get_acl.md)，包含 `group_id`、`group_aid`、`path`、`area`、`storage` 和 `acls`。

## 相关方法

- [group.fs.get_acl](group.fs.get_acl.md) — 查询 ACL
- [group.fs.set_acl](group.fs.set_acl.md) — 授予 admin 角色写 ACL
- [group.fs.remove_acl](group.fs.remove_acl.md) — 撤销 admin 角色写 ACL
