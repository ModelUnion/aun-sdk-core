# storage.fs.mount

挂载卷或他人子树进 owner 命名空间。`readonly` 默认 true；`require_approval=true` 进入 pending 直到源 owner 批准。群成员卷挂载场景：storage 通过 CA `aid_type=group` 识别群命名空间，命中 `/memberdata/` 时调 `group.check_membership` 实时校验。

## 调用示例

```python
# 虚拟卷：把自己 storage 的目录挂进群 memberdata
result = await client.call("storage.fs.mount", {
    "owner_aid": "team.aid.pub",
    "mount_path": "memberdata/alice.aid.pub/",
    "source_aid": "alice.aid.pub",
    "source_path": "alice.aid.pub/team.aid.pub"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `mount_path` | string | 是 | — | 挂载点路径 |
| `owner_aid` | string | 否 | 当前用户 | 命名空间所有者 |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `volume_id` | string | 否 | — | 挂载实体卷（与 source_* 互斥） |
| `source_aid` | string | 否 | — | 虚拟卷源 AID |
| `source_path` | string | 否 | — | 虚拟卷源路径 |
| `source_bucket` | string | 否 | — | 虚拟卷源存储桶 |
| `readonly` | boolean | 否 | `true` | 只读挂载 |
| `require_approval` | boolean | 否 | `false` | 需源 owner 批准 |
| `expires_at` | integer | 否 | — | 挂载过期时间 |

## 返回值

| 字段 | 类型 | 说明 |
|------|------|------|
| `mount` | object | 挂载视图 |
| `status` | string | `active` / `pending` |

## 相关方法

- [storage.fs.unmount](storage.fs.unmount.md) — 卸载
