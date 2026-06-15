# group.resources.confirm_mount

成员挂载区挂载完成回调记账。成员以自己 AID 自助 `storage.fs.mount` 到 `/memberdata/{自己}/` 成功后，调此方法让 group 服务标记槽位 active、更新注册表。

## 调用示例

```python
result = await client.call("group.resources.confirm_mount", {
    "group_id": "team",
    "mount_id": "mnt_xxx"
})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群 ID |
| `mount_id` | string | 是 | 来自 `storage.fs.mount` 返回 |

## 返回值

`{group_id, group_aid, mount: {mount_id, mount_path, member_aid, ...}}`。

## 相关方法

- [storage.fs.mount](storage.fs.mount.md) — 成员自助挂载
- [group.resources.get_df](group.resources.get_df.md) — 群 df 视图
