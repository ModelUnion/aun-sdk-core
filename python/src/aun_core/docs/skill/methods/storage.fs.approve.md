# storage.fs.approve

源 owner 批准 pending 挂载（重新校验源路径存在）。`mount_id` 或 `(owner_aid, bucket, mount_path)` 二选一定位。

## 调用示例

```python
result = await client.call("storage.fs.approve", {"mount_id": "mnt_xxx"})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `mount_id` | string | 否 | 挂载 ID（或用下方三元组定位） |
| `owner_aid` | string | 否 | 命名空间所有者 |
| `bucket` | string | 否 | 存储桶 |
| `mount_path` | string | 否 | 挂载点路径 |

## 返回值

`{approved: true, mount}`。

## 相关方法

- [storage.fs.reject](storage.fs.reject.md) — 拒绝挂载
