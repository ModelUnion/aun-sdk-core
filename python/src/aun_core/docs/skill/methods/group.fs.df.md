# group.fs.df

查看群文件系统路径对应存储区的用量。`/memberdata` 根是虚拟目录，会返回成员数量和虚拟用量视图。

## 调用示例

```python
usage = await client.call("group.fs.df", {"path": "team.agentid.pub:/"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 群路径 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |

## 返回值

包含 `used_bytes`、`object_count`、`quota_bytes`、`avail_bytes`、`storage`、`group_id`、`group_aid` 等字段。

## 相关方法

- [group.fs.ls](group.fs.ls.md) — 列目录
