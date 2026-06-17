# group.fs.rm

删除群文件系统节点。删除成员槽位路径时等价于 `group.fs.umount`；不能删除 `/memberdata` 根。

## 调用示例

```python
result = await client.call("group.fs.rm", {"path": "team.agentid.pub:/docs/old.md"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 要删除的群路径 |
| `recursive` | boolean | 否 | `false` | 删除目录时是否递归 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |

## 返回值

删除结果 + `{path, group_id, group_aid, area, storage}`。

## 相关方法

- [group.fs.umount](group.fs.umount.md) — 卸载成员数据区
