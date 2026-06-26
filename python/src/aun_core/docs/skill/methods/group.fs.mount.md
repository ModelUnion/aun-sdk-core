# group.fs.mount

挂载成员数据区。当前只允许挂载到 `/memberdata/{member_ref}`，服务端会把它映射为成员 storage 的 `group_data/{group_aid}`。

## 调用示例

```python
node = await client.call("group.fs.mount", {
    "path": "team.agentid.pub:/memberdata/alice.agentid.pub",
    "readonly": True,
    "require_approval": False
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 必须是 `/memberdata/{member_ref}` |
| `readonly` | boolean | 否 | `true` | 是否只读挂载 |
| `require_approval` / `requireApproval` | boolean | 否 | `false` | 是否要求成员批准 |
| `source_bucket` | string | 否 | — | 源 bucket |
| `expires_at` | integer/string | 否 | — | 过期时间 |
| `volume_id` | string | 否 | — | 关联卷 ID |

## 返回值

成员槽位虚拟节点视图。

## 相关方法

- [group.fs.umount](group.fs.umount.md) — 卸载成员数据区
