# storage.list_share_links

列举分享链接，可按 bucket / object_key 过滤。仅返回当前用户自己创建的链接。

## 调用示例

```python
result = await client.call("storage.list_share_links", {
    "object_key": "docs/report.pdf",
})
for link in result["links"]:
    print(link["aid_share_url"], link["used_count"], "/", link["max_uses"])
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `bucket` | string | 否 | — | 按存储桶过滤 |
| `object_key` | string | 否 | — | 按对象路径过滤 |

## 返回值

```json
{
    "links": [
        {
            "share_id": "Abc1234567",
            "aid_share_url": "https://my-agent.agentid.pub/storage/Abc1234567",
            "share_url": "https://storage.agentid.pub/s/Abc1234567",
            "object_key": "docs/report.pdf",
            "bucket": "default",
            "allowed_aids": ["*"],
            "expire_at": 1711238167,
            "max_uses": 0,
            "used_count": 3,
            "created_at": 1711234567890
        }
    ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `links` | array | 分享链接列表 |

每个 link 包含：

| 字段 | 类型 | 说明 |
|------|------|------|
| `share_id` | string | 分享短码 |
| `aid_share_url` | string | AID 风格分享 URL（主字段） |
| `share_url` | string | 直链分享 URL（兼容） |
| `object_key` | string | 被分享对象路径 |
| `bucket` | string | 存储桶 |
| `allowed_aids` | string[] | 授权 AID 列表，`["*"]` 表示公开 |
| `expire_at` | integer | 过期时间戳（秒），`0` 表示永不过期 |
| `max_uses` | integer | 最大使用次数，`0` 表示无限制 |
| `used_count` | integer | 已使用次数 |
| `created_at` | integer | 创建时间戳（毫秒） |

## 相关方法

- [storage.create_share_link](storage.create_share_link.md) — 创建分享链接
- [storage.revoke_share_link](storage.revoke_share_link.md) — 撤销分享链接
