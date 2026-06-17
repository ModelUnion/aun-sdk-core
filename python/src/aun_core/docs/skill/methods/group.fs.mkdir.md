# group.fs.mkdir

创建群文件系统目录。群自有区写入使用 `group_aid` 身份；`memberdata/{member_ref}` 写入映射到对应成员的 `groupdata/{group_id}`，SDK 不拼接真实 storage 路径。

## 调用示例

```python
node = await client.call("group.fs.mkdir", {"path": "team.agentid.pub:/docs/specs", "parents": True})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 目录路径 |
| `parents` | boolean | 否 | `false` | 递归创建父目录 |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |

## 返回值

目录节点视图。

## 相关方法

- [group.fs.rm](group.fs.rm.md) — 删除节点
- [group.fs.ls](group.fs.ls.md) — 列目录
