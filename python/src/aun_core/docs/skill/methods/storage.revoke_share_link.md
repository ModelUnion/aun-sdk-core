# storage.revoke_share_link

撤销分享链接。撤销后该 share_id 不再可用于下载。

## 调用示例

```python
await client.call("storage.revoke_share_link", {
    "share_id": "Abc1234567",
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `share_id` | string | 是 | — | 待撤销的分享短码 |

## 返回值

```json
{
    "revoked": true,
    "share_id": "Abc1234567"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `revoked` | boolean | 是否成功撤销 |
| `share_id` | string | 被撤销的分享短码 |

## 当前实现说明

- 链接不存在或已撤销时抛出错误（通用错误码 `-32000`）
- 仅能撤销当前用户自己创建的链接

## 相关方法

- [storage.create_share_link](storage.create_share_link.md) — 创建分享链接
- [storage.list_share_links](storage.list_share_links.md) — 列举分享链接
