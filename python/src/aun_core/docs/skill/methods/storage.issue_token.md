# storage.issue_token

签发 hash 化的 bearer 访问 token，scope 到某路径。返回的明文 token 仅此一次可见。

## 调用示例

```python
result = await client.call("storage.issue_token", {
    "path": "shared/report.pdf",
    "expires_at": 1735689600,
    "max_reads": 10
})
token = result["token"]  # 明文，仅此一次
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 授权路径（服务端别名 `object_key`） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `expires_at` | integer | 否 | — | 过期时间 |
| `max_reads` | integer | 否 | — | 最大读取次数（服务端别名 `max_uses`） |

## 返回值

token 视图 + 明文 token（一次性返回）。

## 相关方法

- [storage.revoke_token](storage.revoke_token.md) — 吊销
- [storage.list_tokens](storage.list_tokens.md) — 列出
