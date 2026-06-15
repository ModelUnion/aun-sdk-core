# storage.fs.unmount

卸载挂载点（仅 owner 可操作）。

## 调用示例

```python
result = await client.call("storage.fs.unmount", {"mount_path": "memberdata/alice.aid.pub/"})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `mount_path` | string | 是 | — | 挂载点路径 |
| `owner_aid` | string | 否 | 当前用户 | 命名空间所有者 |
| `bucket` | string | 否 | `"default"` | 存储桶 |

## 返回值

`{unmounted: boolean, owner_aid, bucket, path, mount_path}`。

## 相关方法

- [storage.fs.mount](storage.fs.mount.md) — 挂载
