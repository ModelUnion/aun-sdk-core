# group.fs.ls

列出群文件系统目录。路径使用 POSIX 风格 group path，例如 `group_aid:/docs/` 或 `https://{group_aid}/docs/`；裸路径需同时传 `group_id` 或 `group_aid`。

## 调用示例

```python
result = await client.call("group.fs.ls", {"path": "team.agentid.pub:/docs", "size": 100})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群路径 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |
| `page` | integer | 否 | `1` | 页码；不能与 `offset` 同时使用 |
| `size` | integer | 否 | `100` | 每页条数；不能与 `limit` 同时使用 |
| `limit` | integer | 否 | — | `size` 兼容别名 |
| `offset` | integer | 否 | — | `page` 兼容分页模式 |

## 返回值

`{path, group_id, group_aid, items, total, page, size}`。`items` 为节点视图；`/memberdata` 根会返回成员虚拟目录。

## 相关方法

- [group.fs.find](group.fs.find.md) — 递归查找
- [group.fs.stat](group.fs.stat.md) — 查看节点
