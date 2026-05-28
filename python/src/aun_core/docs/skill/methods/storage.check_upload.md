# storage.check_upload

上传预检：一次调用同时回答"文件是否超限"和"是否可秒传（服务端已有相同内容）"。

## 调用

```python
import hashlib

data = open("file.bin", "rb").read()
sha256 = hashlib.sha256(data).hexdigest()

check = await client.call("storage.check_upload", {
    "sha256": sha256,
    "size_bytes": len(data),
})
```

## 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sha256` | string | 是 | 文件内容的 SHA-256 hex（64 字符） |
| `size_bytes` | integer | 是 | 文件大小（字节） |

## 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `within_limit` | boolean | 文件大小是否在限制内 |
| `exists` | boolean | 服务端是否已有相同内容的 blob |
| `skip_upload` | boolean | 是否可跳过上传（秒传） |

## 使用场景

```python
if not check["within_limit"]:
    raise ValueError("文件超限")

if check["skip_upload"]:
    # 秒传：跳过 HTTP PUT，直接 complete_upload
    await client.call("storage.complete_upload", {
        "object_key": "my/file.bin",
        "sha256": sha256,
        "size_bytes": len(data),
        "skip_blob": True,
    })
else:
    # 正常上传
    session = await client.call("storage.create_upload_session", {
        "object_key": "my/file.bin",
        "size_bytes": len(data),
    })
    async with aiohttp.ClientSession() as http:
        await http.put(session["upload_url"], data=data)
    await client.call("storage.complete_upload", {
        "object_key": "my/file.bin",
        "sha256": sha256,
        "size_bytes": len(data),
    })
```

## 说明

- `within_limit=false` 时客户端应直接拒绝上传，不要尝试 `create_upload_session`
- `exists=true` 表示服务端已有相同 SHA-256 的 blob，客户端可跳过实际上传
- `skip_upload=true` 时，`complete_upload` 需传 `skip_blob: true` 告知服务端复用已有 blob
- 此方法不要求本地有任何身份，只需已认证连接

## 相关

- [storage.get_limits](storage.get_limits.md) — 查询限制（不需要 SHA-256）
- [storage.create_upload_session](storage.create_upload_session.md) — 申请上传 URL
- [storage.complete_upload](storage.complete_upload.md) — 确认上传完成
