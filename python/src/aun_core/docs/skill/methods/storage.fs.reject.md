# storage.fs.reject

源 owner 或挂载 owner 拒绝 pending 挂载。定位方式同 `storage.fs.approve`。

## 调用示例

```python
result = await client.call("storage.fs.reject", {"mount_id": "mnt_xxx"})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `mount_id` | string | 否 | 挂载 ID（或用三元组定位） |
| `owner_aid` | string | 否 | 命名空间所有者 |
| `bucket` | string | 否 | 存储桶 |
| `mount_path` | string | 否 | 挂载点路径 |

## 返回值

`{rejected: boolean, mount}`。

## 相关方法

- [storage.fs.approve](storage.fs.approve.md) — 批准挂载
