# storage.rename_symlink

改软链 key（同 owner/bucket 内移动/改名），target 不变。跨 owner 被拒。

## 调用示例

```python
result = await client.call("storage.rename_symlink", {
    "path": "spec.md@current",
    "new_path": "api-spec.md@current"
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 原软链路径（服务端 `src`） |
| `new_path` | string | 是 | — | 新软链路径（服务端 `dst`） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在 |
| `expected_version` | integer | 否 | — | CAS 期望版本 |

## 返回值

- **成功**：`{ok: true, ...软链视图}`
- **CAS 失败**：`{ok: false, current_version, current_path, current_target}`

## 相关方法

- [storage.delete_symlink](storage.delete_symlink.md) — 删软链
