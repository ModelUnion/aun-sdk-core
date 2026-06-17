# group.fs.find

递归查找群文件系统节点。路径和身份规则同 `group.fs.ls`。

## 调用示例

```python
result = await client.call("group.fs.find", {"path": "team.agentid.pub:/docs", "name": "*.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群路径 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |
| `name` | string | 否 | — | 名称匹配，透传给 storage.fs.find |
| `type` | string | 否 | — | 节点类型过滤 |
| `limit` | integer | 否 | — | 返回上限 |

## 返回值

`{path, group_id, group_aid, items, total}`，`items` 为群路径视角的节点视图。

## 相关方法

- [group.fs.ls](group.fs.ls.md) — 列目录
- [group.fs.stat](group.fs.stat.md) — 查看节点
