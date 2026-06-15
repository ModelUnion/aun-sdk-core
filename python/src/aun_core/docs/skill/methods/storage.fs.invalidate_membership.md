# storage.fs.invalidate_membership

群成员变更/群解散时失效群挂载（仅群 owner 或内部调用者）。

## 调用示例

```python
result = await client.call("storage.fs.invalidate_membership", {
    "group_id": "team",
    "group_owner_aid": "owner.aid.pub",
    "member_aid": "alice.aid.pub",
    "reason": "membership_changed"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `group_id` | string | 是 | — | 群 ID |
| `group_owner_aid` | string | 是 | — | 群 owner AID |
| `member_aid` | string | 否 | — | 成员 AID（不传=全员） |
| `reason` | string | 否 | `"membership_changed"` | `dissolved` / `membership_changed` |
| `status` | string | 否 | — | `inactive` / `unavailable` |

## 返回值

`{group_id, group_aid, group_owner_aid, member_aid, reason, status, invalidated}`（`invalidated`=失效挂载数）。

## 相关方法

- [storage.fs.unmount](storage.fs.unmount.md) — 主动卸载
