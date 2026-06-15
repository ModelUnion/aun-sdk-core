# storage.revoke_token

按明文 token 值吊销（内部 hash 后查找）。

## 调用示例

```python
result = await client.call("storage.revoke_token", {"path": "shared/report.pdf", "token": "tk_..."})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 路径（服务端别名 `object_key`） |
| `token` | string | 是 | — | 要吊销的明文 token |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

`{revoked: boolean, owner_aid, bucket, path}`。

## 相关方法

- [storage.issue_token](storage.issue_token.md) — 签发
