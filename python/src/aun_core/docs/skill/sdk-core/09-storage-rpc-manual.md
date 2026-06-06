# 存储 — RPC Manual

## 方法索引

### 控制面方法

| 方法 | 说明 |
|------|------|
| [storage.put_object](#storageput_object) | Inline 写入小对象 |
| [storage.get_object](#storageget_object) | Inline 读取小对象 |
| [storage.head_object](#storagehead_object) | 查询元数据 |
| [storage.delete_object](#storagedelete_object) | 删除对象 |
| [storage.list_objects](#storagelist_objects) | 列举对象 |
| [storage.list_prefixes](#storagelist_prefixes) | 列举子目录 |
| [storage.get_quota](#storageget_quota) | 查询配额 |
| [storage.get_limits](#storageget_limits) | 查询上传限制 |
| [storage.check_upload](#storagecheck_upload) | 上传预检（秒传检测 + 超限检测） |

### 数据面协调方法

| 方法 | 说明 |
|------|------|
| [storage.create_upload_session](#storagecreate_upload_session) | 申请上传 URL |
| [storage.complete_upload](#storagecomplete_upload) | 确认上传完成 |
| [storage.create_download_ticket](#storagecreate_download_ticket) | 申请下载 URL |

### 分享方法

| 方法 | 说明 |
|------|------|
| [storage.create_share_link](#storagecreate_share_link) | 创建分享链接 |
| [storage.list_share_links](#storagelist_share_links) | 列举分享链接 |
| [storage.revoke_share_link](#storagerevoke_share_link) | 撤销分享链接 |

---

> `object_key` 当前仅支持 ASCII 安全字符集合 `[A-Za-z0-9._/-]`，且不允许空路径段、`..`、反斜杠转义后的非法段。

## storage.put_object

上传小对象（内容 base64 编码通过 RPC 传输）。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `content` | string | 是 | base64 编码内容 |
| `content_type` | string | 否 | MIME 类型，默认 `"application/octet-stream"` |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `is_private` | boolean | 否 | 是否私有，默认 `true` |
| `overwrite` | boolean | 否 | 是否覆盖已有对象，默认 `true` |
| `expected_version` | integer | 否 | 乐观并发控制版本号 |
| `expire_in_seconds` | integer | 否 | 过期时间（秒），0 表示不过期 |
| `metadata` | object | 否 | 自定义元数据 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `url` | string | **AID 风格 URL（默认/推荐）**：`https://{owner_aid}/storage/{object_key}`，经 NameService 302 跳转到直链 |
| `logical_url` | string | 直链 URL：`https://storage.{issuer}/{user}/{object_key}`，直达 storage 服务，无跳转 |
| `owner_aid` | string | 所有者 AID |
| `bucket` | string | 存储桶 |
| `object_key` | string | 对象路径 |
| `size_bytes` | integer | 对象大小（字节） |
| `content_type` | string | MIME 类型 |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `etag` | string | 实体标签 |
| `updated_at` | integer | 更新时间戳 |

### 示例

```python
import base64

content = base64.b64encode(b"Hello World").decode()
result = await client.call("storage.put_object", {
    "object_key": "notes/hello.txt",
    "content": content,
    "content_type": "text/plain",
})
```

---

## storage.get_object

读取小对象，返回 base64 编码内容。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `owner_aid` | string | 所有者 AID |
| `bucket` | string | 存储桶 |
| `object_key` | string | 对象路径 |
| `content` | string | base64 编码内容 |
| `content_type` | string | MIME 类型 |
| `size_bytes` | integer | 对象大小（字节） |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `updated_at` | integer | 更新时间戳 |

> **注意**：实现不返回 `etag`（与 put_object/head_object 不同）。

### 示例

```python
result = await client.call("storage.get_object", {
    "object_key": "notes/hello.txt",
})
content = base64.b64decode(result["content"])
```

---

## storage.head_object

查询对象元数据，不返回内容。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `owner_aid` | string | 所有者 AID |
| `bucket` | string | 存储桶 |
| `object_key` | string | 对象路径 |
| `content_type` | string | MIME 类型 |
| `size_bytes` | integer | 对象大小（字节） |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `etag` | string | 实体标签 |
| `is_private` | boolean | 是否私有 |
| `expire_at` | integer | 过期时间戳（0 表示不过期） |
| `created_at` | integer | 创建时间戳 |
| `updated_at` | integer | 更新时间戳 |

---

## storage.delete_object

删除对象。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `deleted` | boolean | 是否成功删除（`false` 表示对象不存在） |
| `owner_aid` | string | 所有者 AID |
| `object_key` | string | 对象路径 |

---

## storage.list_objects

列出对象。

> 权限：仅允许查询自己的对象（`owner_aid` 默认为当前用户，不可指定他人的 AID）

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `prefix` | string | 否 | 路径前缀过滤 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `page` | integer | 否 | 页码，默认 1 |
| `size` | integer | 否 | 每页条数，默认 50（最大 200） |
| `marker` | string | 否 | 深度分页游标；传入时优先按游标分页 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `items` | array | 对象元数据列表 |
| `total` | integer | 总条数 |
| `page` | integer | 当前页码 |
| `size` | integer | 每页条数 |
| `marker` | string | 当前游标标记 |
| `next_marker` | string | 下一页游标标记（为空表示无更多数据） |

每个 item 包含：

| 字段 | 类型 | 说明 |
|------|------|------|
| `object_key` | string | 对象路径 |
| `size_bytes` | integer | 对象大小（字节） |
| `content_type` | string | MIME 类型 |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `is_private` | boolean | 是否私有 |
| `updated_at` | integer | 更新时间戳 |

### 示例

```python
result = await client.call("storage.list_objects", {
    "prefix": "notes/",
    "size": 20,
})
for obj in result["items"]:
    print(f"{obj['object_key']} ({obj['size_bytes']} bytes)")
```

---

## storage.list_prefixes

列出直接子目录（前缀）。

> 权限：仅允许查询自己的对象（`owner_aid` 默认为当前用户，不可指定他人的 AID）

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `prefix` | string | 否 | 路径前缀过滤 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `size` | integer | 否 | 每页条数上限 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `prefixes` | string[] | 直接子目录列表 |
| `count` | integer | 子目录数量 |
| `size` | integer | 实际生效的每页上限 |

---

## storage.get_quota

查询存储配额。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 查询指定 AID 的配额（默认为当前用户，仅允许查询自己的配额） |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `owner_aid` | string | 所有者 AID |
| `used_bytes` | integer | 已使用空间（字节） |
| `object_count` | integer | 对象数量 |
| `quota_bytes` | integer | 配额上限（字节），0 表示无限制 |

---

## storage.create_upload_session

获取上传用 presigned URL。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `size_bytes` | integer | 否 | 声明的文件大小（字节）。当前实现允许省略，但建议传入用于客户端追踪与最终校验 |
| `content_type` | string | 否 | MIME 类型，默认 `"application/octet-stream"` |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `expected_version` | integer | 否 | 乐观并发控制版本号 |
| `expire_in_seconds` | integer | 否 | URL 有效期（秒），默认 3600 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `upload_url` | string | 上传用 presigned URL |
| `blob_key` | string | Blob 存储 key |
| `expire_at` | integer | URL 过期时间戳 |
| `owner_aid` | string | 所有者 AID |
| `bucket` | string | 存储桶 |
| `object_key` | string | 对象路径 |
| `content_type` | string | MIME 类型 |
| `size_bytes` | integer | 声明的文件大小 |

客户端获得 `upload_url` 后，通过 HTTP PUT 上传文件数据。

> 当前实现会对 BlobStore 返回的 loopback URL 做对外地址规范化：优先使用 `KITE_STORAGE_EXTERNAL_URL`，否则按 `storage.{issuer}` 形式改写。对外地址不可使用 `127.0.0.1` 或 `localhost`。

> 当前实现不会在 `create_upload_session` 阶段强校验配额或最终文件大小；这些检查会在 `storage.complete_upload` 阶段执行。

---

## storage.complete_upload

完成上传，提交校验信息。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `sha256` | string | 否 | 文件 SHA-256 哈希；提供则校验完整性，`skip_blob=true` 时必填 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `content_type` | string | 否 | MIME 类型，默认 `"application/octet-stream"` |
| `is_private` | boolean | 否 | 是否私有，默认 `true` |
| `size_bytes` | integer | 否 | 预期文件大小（用于校验） |
| `skip_blob` | boolean | 否 | 秒传模式，默认 `false`；为 `true` 时跳过 blob 上传，必须提供 `sha256` 且服务端已存在对应内容 |
| `expected_version` | integer | 否 | 乐观并发控制版本号 |
| `expire_in_seconds` | integer | 否 | 过期时间（秒） |
| `metadata` | object | 否 | 自定义元数据 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `url` | string | **AID 风格 URL（默认/推荐）**：`https://{owner_aid}/storage/{object_key}`，经 NameService 302 跳转 |
| `logical_url` | string | 直链 URL：`https://storage.{issuer}/{user}/{object_key}`，无跳转 |
| `owner_aid` | string | 所有者 AID |
| `bucket` | string | 存储桶 |
| `object_key` | string | 对象路径 |
| `size_bytes` | integer | 对象大小（字节） |
| `content_type` | string | MIME 类型 |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `etag` | string | 实体标签 |
| `updated_at` | integer | 更新时间戳 |

---

## storage.create_download_ticket

获取下载 URL。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 对象路径 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户（公开对象可指定其他 AID） |
| `expire_in_seconds` | integer | 否 | URL 有效期（秒），默认 3600 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `url` | string | **AID 风格 URL（默认/推荐）**：`https://{owner_aid}/storage/{object_key}`，经 NameService 302 跳转 |
| `logical_url` | string | 直链 URL：`https://storage.{issuer}/{user}/{object_key}`，直达 storage 服务，无跳转 |
| `download_url` | string | 预签名下载 URL（有时效，签名形式由 BlobStore 后端决定） |
| `expire_at` | integer | `download_url` 的过期时间戳（Unix 秒） |
| `file_name` | string | 文件名（从 object_key 提取） |
| `size_bytes` | integer | 文件大小（字节） |
| `content_type` | string | MIME 类型 |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `etag` | string | 实体标签 |

客户端获得 `download_url` 后，通过 HTTP GET 下载文件。`url` 为永久可分享的 AID 风格链接，`logical_url` 为无跳转直链。

> 当前实现会对 BlobStore 返回的 loopback URL 做对外地址规范化：优先使用 `KITE_STORAGE_EXTERNAL_URL`，否则按 `storage.{issuer}` 形式改写。对外地址不可使用 `127.0.0.1` 或 `localhost`。

---

## 事件

### event/storage.object_changed

对象变更时推送。

**Payload**：

```json
{
    "module_id": "storage",
    "action": "put",
    "owner_aid": "alice.agentid.pub",
    "object_key": "notes/hello.txt"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `module_id` | string | 当前模块 ID，通常为 `"storage"` |
| `action` | string | `"put"` 或 `"delete"` |
| `owner_aid` | string | 对象所有者 AID |
| `object_key` | string | 对象路径 |

> 当前实现在 `storage.put_object` 成功后推送 `action="put"`，`storage.delete_object` 返回 `deleted=true` 时推送 `action="delete"`，`storage.complete_upload` 成功后也会推送 `action="put"` 事件。

---

## storage.get_limits

查询当前用户的上传限制和配额使用情况。客户端可在上传前调用此方法，避免超限后浪费流量。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `owner_aid` | string | 否 | 查询指定用户的配额，默认当前用户 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `max_inline_bytes` | integer | `put_object` 内联上限（当前 64KB） |
| `max_file_size_bytes` | integer | 单文件大小上限（当前 10MB） |
| `quota_total_bytes` | integer | 用户总配额（0 表示无限制） |
| `quota_used_bytes` | integer | 已用配额 |

### 示例

```python
limits = await client.call("storage.get_limits", {})
print(f"单文件上限: {limits['max_file_size_bytes']} bytes")
print(f"配额: {limits['quota_used_bytes']}/{limits['quota_total_bytes']}")
```

---

## storage.check_upload

上传预检：一次调用同时回答"文件是否超限"和"是否可秒传"。客户端应在计算完文件 SHA-256 后、实际上传前调用。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sha256` | string | 是 | 文件内容的 SHA-256 hex（64 字符） |
| `size_bytes` | integer | 是 | 文件大小（字节） |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `within_limit` | boolean | 文件大小是否在限制内 |
| `exists` | boolean | 服务端是否已有相同内容 |
| `skip_upload` | boolean | 是否可跳过上传（秒传） |

### 使用场景

```python
import hashlib

data = open("large_file.bin", "rb").read()
sha256 = hashlib.sha256(data).hexdigest()

check = await client.call("storage.check_upload", {
    "sha256": sha256,
    "size_bytes": len(data),
})

if not check["within_limit"]:
    print("文件超限，无法上传")
elif check["skip_upload"]:
    # 秒传：服务端已有相同内容，跳过上传直接 complete
    await client.call("storage.complete_upload", {
        "object_key": "my/file.bin",
        "sha256": sha256,
        "size_bytes": len(data),
        "skip_blob": True,
    })
else:
    # 正常上传流程
    session = await client.call("storage.create_upload_session", {
        "object_key": "my/file.bin",
        "size_bytes": len(data),
    })
    # HTTP PUT ...
    await client.call("storage.complete_upload", {
        "object_key": "my/file.bin",
        "sha256": sha256,
        "size_bytes": len(data),
    })
```

---

## storage.create_share_link

创建分享链接。生成一个短码（share_id），通过短码可访问对象，支持授权 AID 白名单、有效期、使用次数限制。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `object_key` | string | 是 | 被分享对象的路径 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 对象所有者 AID，默认当前用户（仅可分享自己的对象） |
| `allowed_aids` | string[] | 否 | 授权访问的 AID 列表，默认 `["*"]`（任意 AID 可访问）；含 `"*"` 即视为公开 |
| `expire_in_seconds` | integer | 否 | 有效期（秒），默认 86400（1 天），`0` 表示永不过期 |
| `max_uses` | integer | 否 | 最大使用次数，默认 `0`（无限制） |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `share_id` | string | 10 位 Base62 分享短码 |
| `aid_share_url` | string | **AID 风格分享 URL（默认/推荐）**：`https://{owner_aid}/storage/{share_id}`，体现分享者身份 |
| `share_url` | string | 直链分享 URL：`{base_url}/s/{share_id}`，兼容字段 |
| `expire_at` | integer | 过期时间戳（Unix 秒），`0` 表示永不过期 |
| `max_uses` | integer | 最大使用次数，`0` 表示无限制 |
| `allowed_aids` | string[] | 授权 AID 列表，`["*"]` 表示公开 |

> 访问 `aid_share_url` 时经 NameService 302 跳转到 `share_url`。share_id 是 10 位无斜杠 Base62，与 object_key 路径天然区分（object_key 含 `/` 或非 10 位）。
> share_id 指向 `(owner_aid, bucket, object_key)` 逻辑引用，非内容快照：对象改名/移动后原 share_id 失效，内容覆盖后下载到新内容。

### 示例

```python
result = await client.call("storage.create_share_link", {
    "object_key": "docs/report.pdf",
    "allowed_aids": ["alice.agentid.pub"],
    "expire_in_seconds": 3600,
    "max_uses": 5,
})
share_url = result["aid_share_url"]
```

---

## storage.list_share_links

列举分享链接，可按 bucket / object_key 过滤。仅返回当前用户自己创建的链接。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `bucket` | string | 否 | 按存储桶过滤 |
| `object_key` | string | 否 | 按对象路径过滤 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `links` | array | 分享链接列表 |

每个 link 包含：

| 字段 | 类型 | 说明 |
|------|------|------|
| `share_id` | string | 分享短码 |
| `aid_share_url` | string | AID 风格分享 URL（主字段） |
| `share_url` | string | 直链分享 URL（兼容） |
| `object_key` | string | 被分享对象路径 |
| `bucket` | string | 存储桶 |
| `allowed_aids` | string[] | 授权 AID 列表，`["*"]` 表示公开 |
| `expire_at` | integer | 过期时间戳（秒），`0` 表示永不过期 |
| `max_uses` | integer | 最大使用次数，`0` 表示无限制 |
| `used_count` | integer | 已使用次数 |
| `created_at` | integer | 创建时间戳（毫秒） |

---

## storage.revoke_share_link

撤销分享链接。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `share_id` | string | 是 | 待撤销的分享短码 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `revoked` | boolean | 是否成功撤销 |
| `share_id` | string | 被撤销的分享短码 |

> 链接不存在或已撤销时返回通用错误（`-32000`）。

---

## 错误码

| code | 说明 |
|------|------|
| -32002 | 服务暂不可用（数据库未连接） |
| -32004 | 权限拒绝（requester 不是对象 owner，或非公开对象的读权限不足） |
| -32008 | 对象不存在（`ErrNotFound`） |
| -32009 | 版本冲突（`ErrVersionConflict`，`expected_version` 与实际版本不匹配） |
| -32000 | 通用错误（参数校验失败、配额不足、base64 解码失败、文件大小超限等） |
