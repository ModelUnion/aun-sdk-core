# storage.set_acl

授予路径前缀 ACL grant。普通 AID storage 的 `grantee_aid` 必须是具体 AID，主要用于写/删除授权；子路径默认继承（最近祖先覆盖）。读取应使用 share link，不通过 AID ACL 直接授权。

`role:*` 伪主体只允许可信 group 内部门面管理；群自有区 admin 写授权使用 `group.fs.set_acl`。

## 调用示例

```python
result = await client.call("storage.set_acl", {
    "path": "projects/myapp/",
    "grantee_aid": "bob.aid.pub",
    "perms": "rw"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 授权路径前缀 |
| `grantee_aid` | string | 是 | — | 被授权 AID；`role:*` 仅限 group 内部调用 |
| `perms` | string | 是 | — | `r`/`w`/`rw`/`rwx`（`rwx` 含删除） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `expires_at` | integer | 否 | — | 授权过期时间 |
| `max_uses` | integer | 否 | — | 最大使用次数 |

## 返回值

ACL 视图。

## 相关方法

- [storage.remove_acl](storage.remove_acl.md) — 移除授权
- [storage.list_acl](storage.list_acl.md) — 列出授权
- [group.fs.set_acl](group.fs.set_acl.md) — 群自有区 admin 写授权
