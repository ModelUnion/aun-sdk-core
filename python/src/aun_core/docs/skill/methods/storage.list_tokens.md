# storage.list_tokens

列出路径上的 token（owner 校验，不返回明文）。

## 调用示例

```python
result = await client.call("storage.list_tokens", {"path": "shared/report.pdf"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

token 列表（hash 摘要 + 元数据，无明文）。

## 相关方法

- [storage.issue_token](storage.issue_token.md) — 签发
