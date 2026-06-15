# storage.fs.remove

POSIX `rm`：删除文件/目录/软链（目录用 `recursive`）。**拒绝删除挂载点**（须先 unmount）。

## 调用示例

```python
result = await client.call("storage.fs.remove", {"path": "projects/old", "recursive": True})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 节点路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `recursive` | boolean | 否 | `false` | 递归删除目录 |

## 返回值

| 字段 | 类型 | 说明 |
|------|------|------|
| `removed_count` | integer | 删除节点数 |
| `deleted` | boolean | 是否成功 |

## 相关方法

- [storage.fs.unmount](storage.fs.unmount.md) — 卸载挂载点（删挂载点前置）
