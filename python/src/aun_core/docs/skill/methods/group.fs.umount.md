# group.fs.umount

卸载成员数据区。当前只允许作用于 `/memberdata/{member_ref}`。

## 调用示例

```python
result = await client.call("group.fs.umount", {
    "path": "team.agentid.pub:/memberdata/alice.agentid.pub"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 必须是 `/memberdata/{member_ref}` |
| `group_id` | string | 否 | — | 裸路径时用于定位群 |
| `group_aid` | string | 否 | — | 裸路径时用于定位命名群 |

## 返回值

卸载结果 + `{path, group_id, group_aid, area}`。

## 相关方法

- [group.fs.mount](group.fs.mount.md) — 挂载成员数据区
