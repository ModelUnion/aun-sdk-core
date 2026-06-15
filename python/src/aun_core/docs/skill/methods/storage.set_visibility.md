# storage.set_visibility

切换对象或目录的公开/私有（软链不支持）。`allow_roles` 替换 `role:` 类 ACL。

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
| `allow_roles` | array | 否 | — | 允许的角色列表（替换 role ACL） |

## 返回值

fs 节点视图（含 `allow_roles`）。

## 相关方法

- [storage.set_acl](storage.set_acl.md) — 细粒度授权
