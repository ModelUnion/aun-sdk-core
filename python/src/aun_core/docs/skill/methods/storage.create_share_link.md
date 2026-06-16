# storage.create_share_link

创建分享链接。生成一个 10 位 Base62 短码（share_id），通过短码可访问对象，支持授权 AID 白名单、有效期、使用次数限制。

## 调用示例

```python
result = await client.call("storage.create_share_link", {
    "object_key": "docs/report.pdf",
    "allowed_aids": ["alice.agentid.pub"],
    "expire_in_seconds": 3600,
    "max_uses": 5,
})
share_url = result["url"]  # https://my-agent.agentid.pub/s/Abc1234567
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `object_key` | string | 是 | — | 被分享对象的路径 |
| `bucket` | string | 否 | `"default"` | 存储桶名称 |
| `owner_aid` | string | 否 | 当前用户 | 对象所有者 AID（仅可分享自己的对象） |
| `allowed_aids` | string[] | 否 | `["*"]` | 授权访问的 AID 列表，默认任意 AID 可访问；含 `"*"` 即视为公开 |
| `expire_in_seconds` | integer | 否 | `86400` | 有效期（秒），1 天；`0` 表示永不过期 |
| `max_uses` | integer | 否 | `0` | 最大使用次数，`0` 表示无限制 |

## 返回值

```json
{
    "share_id": "Abc1234567",
    "url": "https://my-agent.agentid.pub/s/Abc1234567",
    "aid_share_url": "https://my-agent.agentid.pub/s/Abc1234567",
    "share_url": "https://storage.agentid.pub/s/Abc1234567",
    "expire_at": 1711238167,
    "max_uses": 5,
    "allowed_aids": ["alice.agentid.pub"]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `share_id` | string | 10 位 Base62 分享短码 |
| `url` | string | **默认分享 URL（隐藏路径）**：`https://{owner_aid}/s/{share_id}`，最短直链 |
| `path_url` | string | **可选分享 URL（暴露路径）**：`https://{owner_aid}/{object_key}?t={share_id}`，可读性强 |
| `aid_share_url` | string | 同 `url`（兼容旧字段） |
| `share_url` | string | storage 直链：`https://storage.{issuer}/s/{share_id}`，兼容字段 |
| `expire_at` | integer | 过期时间戳（Unix 秒），`0` 表示永不过期 |
| `max_uses` | integer | 最大使用次数，`0` 表示无限制 |
| `allowed_aids` | string[] | 授权 AID 列表，`["*"]` 表示公开 |

## 当前实现说明

- 两种格式都通过 `share_id` 定位到 `share_links` 记录鉴权。`url` 隐藏文件结构，`path_url` 暴露文件名便于识别
- 访问 `url` 时经 NameService 302 跳转到 `storage.{issuer}/s/{share_id}`；访问 `path_url` 时经 NameService fallback 到 storage，由 `?t=` token 鉴权
- share_id 指向 `(owner_aid, bucket, object_key)` 逻辑引用，非内容快照：对象改名/移动后原 share_id 失效，内容覆盖后下载到新内容

## 相关方法

- [storage.list_share_links](storage.list_share_links.md) — 列举分享链接
- [storage.revoke_share_link](storage.revoke_share_link.md) — 撤销分享链接
