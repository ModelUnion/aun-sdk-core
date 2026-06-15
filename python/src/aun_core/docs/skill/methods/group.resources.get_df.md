# group.resources.get_df

群存储 df 视图：聚合群自有卷 + 各成员挂载卷的用量与状态（由 group 服务聚合记账表，不触发 storage 扇出）。

## 调用示例

```python
result = await client.call("group.resources.get_df", {"group_id": "team"})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群 ID |

## 返回值

`{group_id, group_aid, volumes: [...], mounts: [...]}`。成员挂载卷过期标 ⚠ unavailable。

## 相关方法

- [group.resources.confirm_mount](group.resources.confirm_mount.md) — 挂载记账
