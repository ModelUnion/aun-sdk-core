# storage.set_visibility

切换对象或目录的公开/私有（软链不支持）。`allow_roles` 是低层兼容字段，不能作为群自有区 admin 写授权入口；群自有区角色写授权必须使用 `group.fs.set_acl/remove_acl`。

## 调用示例

```python
result = await client.call("storage.set_visibility", {"path": "public/site/", "visibility": "public"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 路径 |
| `visibility` | string | 是 | — | `public` / `private` |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `allow_roles` | array | 否 | — | 允许的角色列表；不要用于群自有区 admin 写授权 |

## 返回值

fs 节点视图（可能含 `allow_roles`）。

## 相关方法

- [storage.set_acl](storage.set_acl.md) — 细粒度授权
- [group.fs.set_acl](group.fs.set_acl.md) — 群自有区 admin 写授权
