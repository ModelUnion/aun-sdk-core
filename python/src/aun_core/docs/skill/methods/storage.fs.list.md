# storage.fs.list

POSIX `ls`：列目录。混合返回子目录/对象/软链/挂载点，排序 dir < file < symlink < mount。群 owner 路径回退到群资源子节点。

## 调用示例

```python
result = await client.call("storage.fs.list", {
    "path": "projects/",
    "page": 1,
    "size": 100
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 否 | `""` | 目录路径（空=根） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `page` | integer | 否 | `1` | 页码 |
| `size` | integer | 否 | `100` | 每页条数（受 `list_max_limit` 约束） |
| `marker` | string | 否 | — | 分页游标 |
| `token` | string | 否 | — | 访问 token |

## 返回值

| 字段 | 类型 | 说明 |
|------|------|------|
| `nodes` | array | 节点列表，每项 `{type, node_type, name, path, mode, size, mtime, owner_principal}` |
| `items` | array | 同 `nodes`（兼容别名） |
| `total` | integer | 总数 |
| `next_marker` | string | 下一页游标 |

`type` 取值：`file` / `dir` / `symlink` / `mount`。

## 相关方法

- [storage.fs.find](storage.fs.find.md) — 递归查找
- [storage.fs.stat](storage.fs.stat.md) — 查单个节点
