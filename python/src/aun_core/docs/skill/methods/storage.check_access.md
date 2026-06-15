# storage.check_access

非抛错的访问探测——探测某操作在某路径是否放行（内部捕获 NotFound/Dangling/Permission）。

## 调用示例

```python
result = await client.call("storage.check_access", {"path": "projects/x.md", "operation": "write"})
if result["allowed"]:
    ...
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 路径（服务端别名 `object_key`） |
| `operation` | string | 否 | `"read"` | `read`/`write`/`delete`（服务端别名 `op`） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `token` | string | 否 | — | 访问 token |
| `follow_symlinks` | boolean | 否 | `true` | 跟随软链 |

## 返回值

`{allowed, reason, message, requester_aid, owner_aid, bucket, path, operation}`。

## 相关方法

- [storage.issue_token](storage.issue_token.md) — 签发访问 token
