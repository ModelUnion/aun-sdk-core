# storage.fs.find

POSIX `find`：递归查找，支持 name/type/size/mtime 过滤与分页。Group FS 与 `.collab` 注册表有回退。

## 调用示例

```python
result = await client.call("storage.fs.find", {
    "path": "projects/",
    "name": "*.md",
    "type": "f"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 起始目录 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `name` | string | 否 | — | 名称 glob（如 `*.md`） |
| `type` | string | 否 | — | 类型过滤 `f`/`d`/`l`（SDK 形参 `node_type`） |
| `size` | string | 否 | — | 大小表达式（如 `+1M`） |
| `mtime` | string | 否 | — | 修改时间表达式 |
| `page` | integer | 否 | `1` | 页码 |
| `page_size` | integer | 否 | `1000` | 每页条数 |
| `token` | string | 否 | — | 访问 token |

## 返回值

同 `storage.fs.list`：`{nodes, items, total, page, size, next_marker}`。

## 相关方法

- [storage.fs.list](storage.fs.list.md) — 列单层目录
