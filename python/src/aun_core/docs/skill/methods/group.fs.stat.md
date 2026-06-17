# group.fs.stat

查看群文件系统节点。会跟随链接并返回群路径视角的节点信息。

## 调用示例

```python
node = await client.call("group.fs.stat", {"path": "team.agentid.pub:/docs/a.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群路径 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |

## 返回值

节点视图，包含 `path`、`group_id`、`group_aid`、`type` / `node_type`、`size`、`mtime` 等字段。`/memberdata` 和成员槽位可返回虚拟节点。

## 相关方法

- [group.fs.lstat](group.fs.lstat.md) — 查看链接本身
- [group.fs.ls](group.fs.ls.md) — 列目录
