# storage.fs.touch

创建空文件或刷新已有节点的修改时间。已存在的文件、目录或软链会更新时间戳；不存在时默认创建 0 字节私有文件；`no_create=true` 时不存在不创建。

## 调用示例

```python
node = await client.call("storage.fs.touch", {
    "path": "docs/empty.txt",
    "parents": True,
    "mtime": 1700000000,
})
```

## 参数

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `path` | string | 是 | — | 目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `parents` | boolean | 否 | `false` | 创建文件时递归创建父目录 |
| `no_create` / `noCreate` | boolean | 否 | `false` | 目标不存在时不创建 |
| `mtime` | integer | 否 | 当前时间 | Unix 秒或毫秒；小于 `10000000000` 按秒解释 |
| `follow_symlinks` / `followSymlinks` | boolean | 否 | `false` | 目标为软链时是否跟随末级软链 |

## 返回值

fs 节点视图，并包含 `touched` 和 `created`。

## 相关方法

- [storage.fs.stat](storage.fs.stat.md) — 查看节点
- [storage.fs.mkdir](storage.fs.mkdir.md) — 创建目录
