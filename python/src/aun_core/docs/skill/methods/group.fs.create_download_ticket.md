# group.fs.create_download_ticket

为群文件创建下载票据。返回的 `download_url` 是可直接用于 HTTP GET 的数据面 URL。

## 调用示例

```python
ticket = await client.call("group.fs.create_download_ticket", {
    "path": "team.agentid.pub:/docs/a.md",
    "expire_in_seconds": 600
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 文件路径，不能是目录 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |
| `expire_in_seconds` | integer | 否 | 服务端配置 | 票据有效期 |

## 返回值

下载票据字段 + `{path, group_id, group_aid, area, storage}`。若服务端返回 `logical_url`，SDK/服务会同步填入 `download_url`。

## 相关方法

- [group.fs.stat](group.fs.stat.md) — 查看文件
