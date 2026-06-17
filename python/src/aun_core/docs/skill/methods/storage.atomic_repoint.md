# storage.atomic_repoint

原子重指软链 target（乐观锁 CAS）。**collab commit / tag 并发正确性的底层核心**。`expected_version` 为 null 时跳过 CAS（普通发布场景）。

## 调用示例

```python
result = await client.call("storage.atomic_repoint", {
    "path": "design.md@current",
    "new_target": ".collab-versions/design.md/alice.aid.pub/v4.md",
    "expected_version": 3
})
if not result["ok"]:
    print("撞版本，当前 version:", result["current_version"])
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 软链路径 |
| `new_target` | string | 是 | — | 新 target |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `expected_version` | integer | 否 | — | CAS 期望版本（null=跳过 CAS） |

## 返回值

- **成功**：`{ok: true, ...软链视图}`（version+1）
- **CAS 失败**：`{ok: false, current_version, current_target}`

## 相关方法

- [storage.rename_symlink](storage.rename_symlink.md) — 改软链 key
