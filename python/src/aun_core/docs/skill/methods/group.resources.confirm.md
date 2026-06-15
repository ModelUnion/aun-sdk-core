# group.resources.confirm

写操作完成回调记账（甲案最终一致）。群主以 group_aid 身份直调 storage 完成写入后，凭 `op_id` 调此方法让 group 服务幂等更新镜像节点。

> confirm 丢失时由对账任务按 group_aid 命名空间向 storage 拉取实际节点补齐（storage 是权威，镜像可重建）。

## 调用示例

```python
result = await client.call("group.resources.confirm", {
    "group_id": "team",
    "op_id": "op_xxx",
    "object_id": "obj_xxx"
})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `group_id` | string | 是 | 群 ID |
| `op_id` | string | 是 | 来自写操作返回的待签清单 |
| `object_id` / `resource_path` | string | 否 | 写入完成信息 |

## 返回值

`{group_id, group_aid, resource: {...}}`。

## 相关方法

- [group.resources.namespace_ready](group.resources.namespace_ready.md) — 命名空间初始化
- [group.resources.confirm_mount](group.resources.confirm_mount.md) — 挂载完成记账
