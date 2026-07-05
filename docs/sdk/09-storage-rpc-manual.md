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

### 目录树方法

| 方法 | 说明 |
|------|------|
| [storage.create_folder](#storagecreate_folder) | 创建目录 |
| [storage.get_folder](#storageget_folder) | 查询目录 |
| [storage.list_children](#storagelist_children) | 列出目录子节点 |
| [storage.rename_folder](#storagerename_folder) | 重命名目录 |
| [storage.move_folder](#storagemove_folder) | 移动目录 |
| [storage.delete_folder](#storagedelete_folder) | 删除目录 |
| [storage.resolve_path](#storageresolve_path) | 按路径解析节点 |

### 对象管理方法

| 方法 | 说明 |
|------|------|
| [storage.move_object](#storagemove_object) | 移动或重命名对象 |
| [storage.copy_object](#storagecopy_object) | 复制对象 |
| [storage.batch_delete](#storagebatch_delete) | 批量删除对象/目录 |
| [storage.batch_head_object](#storagebatch_head_object) | 批量查询对象元数据 |
| [storage.set_object_meta](#storageset_object_meta) | 更新对象元数据 |
| [storage.get_object_url](#storageget_object_url) | 获取稳定对象 URL |
| [storage.append_object](#storageappend_object) | 追加写对象 |

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
| [storage.get_by_share](#storageget_by_share) | 通过分享短码读取对象 |

### POSIX VFS 方法

> 在对象存储之上提供 Linux 文件系统语义（`ls/find/df/stat/lstat/mkdir/touch/rm/mv/cp/mount`）。节点类型：`file` / `dir` / `symlink` / `mount`。

| 方法 | 说明 |
|------|------|
| [storage.fs.list](#storagefslist) | 列目录（ls） |
| [storage.fs.find](#storagefsfind) | 递归查找（find，支持 name/type/size/mtime 过滤） |
| [storage.fs.df](#storagefsdf) | 配额/用量报告（df） |
| [storage.fs.stat](#storagefsstat) | 查节点（stat，跟随末级软链） |
| [storage.fs.lstat](#storagefslstat) | 查节点（lstat，不跟随软链） |
| [storage.fs.mkdir](#storagefsmkdir) | 建目录（mkdir） |
| [storage.fs.touch](#storagefstouch) | 创建空文件或更新时间戳（touch） |
| [storage.fs.remove](#storagefsremove) | 删除文件/目录/软链（rm） |
| [storage.fs.rename](#storagefsrename) | 同 owner 内移动/改名（mv） |
| [storage.fs.copy](#storagefscopy) | 复制对象或软链（cp） |
| [storage.fs.mount](#storagefsmount) | 挂载卷或他人子树 |
| [storage.fs.approve](#storagefsapprove) | 源 owner 批准待审挂载 |
| [storage.fs.reject](#storagefsreject) | 拒绝待审挂载 |
| [storage.fs.unmount](#storagefsunmount) | 卸载挂载点 |
| [storage.fs.invalidate_membership](#storagefsinvalidate_membership) | 群成员变更时失效群挂载 |

### 软链方法

| 方法 | 说明 |
|------|------|
| [storage.create_symlink](#storagecreate_symlink) | 创建软链 |
| [storage.readlink](#storagereadlink) | 读软链 target |
| [storage.atomic_repoint](#storageatomic_repoint) | 原子重指 target（CAS 乐观锁） |
| [storage.rename_symlink](#storagerename_symlink) | 改软链 key（target 不变） |
| [storage.delete_symlink](#storagedelete_symlink) | 删软链记录（不动 target） |

### ACL / 权限方法

> 统一权限求值顺序（硬顺序）：公开位 → token → ACL（最近祖先前缀）→ 角色 → owner → 拒绝。
>
> AID storage 的 `storage.set_acl/remove_acl` 面向具体 AID，当前主要用于写/删除授权；直接读授权不通过 ACL 下发，读访问应使用 `storage.create_share_link` / `storage.get_by_share`，撤销分享使用 `storage.revoke_share_link`。`role:*` 伪主体只允许可信 group 内部门面管理，客户端不得直接对 `group_aid` 空间设置角色 ACL；群自有区 admin 写授权使用 `group.fs.set_acl/remove_acl`。

| 方法 | 说明 |
|------|------|
| [storage.set_acl](#storageset_acl) | 授予路径前缀 ACL |
| [storage.remove_acl](#storageremove_acl) | 移除 ACL 授权 |
| [storage.list_acl](#storagelist_acl) | 列出路径 ACL |
| [storage.set_visibility](#storageset_visibility) | 切换公开/私有 |
| [storage.check_access](#storagecheck_access) | 非抛错的访问探测 |
| [storage.issue_token](#storageissue_token) | 签发路径访问 token |
| [storage.revoke_token](#storagerevoke_token) | 吊销 token |
| [storage.list_tokens](#storagelist_tokens) | 列出 token |

### 卷方法

| 方法 | 说明 |
|------|------|
| [storage.volume.create](#storagevolumecreate) | 创建/upsert 配额卷 |
| [storage.volume.renew](#storagevolumerenew) | 续期卷 |
| [storage.volume.expire_due](#storagevolumeexpire_due) | 过期到期卷并失效其挂载 |

---

> `object_key` 当前仅支持 ASCII 安全字符集合 `[A-Za-z0-9._/-]`，且不允许空路径段、`..`、反斜杠转义后的非法段。

## SDK 封装状态

Python / Go / TypeScript / JavaScript SDK 均提供 storage low-level 与 VFS 门面。普通应用优先使用 SDK VFS：`write_bytes` / `upload_file` 会先 `check_upload`，小对象走 `put_object`，大对象走 `create_upload_session` → HTTP PUT → `complete_upload`，秒传路径用 `complete_upload(skip_blob=true)`；`read_bytes` / `download_file` 优先尝试 inline `get_object`，超限时回退 `create_download_ticket`；`touch` 直接封装 `storage.fs.touch`。需要精确控制 ACL、token、软链、卷、批量操作或 URL 字段时，再直接调用本手册中的 `storage.*` RPC。

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
| `url` | string | **AID 风格 URL（默认/推荐）**：`https://{owner_aid}/{object_key}`，经 NameService fallback 302 跳转到 storage 服务 |
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

## storage.create_folder

创建目录节点。目录和对象共用同一个 `bucket`，默认 bucket 为 `"default"`。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | 否 | 完整目录路径；提供时优先使用 |
| `name` | string | 否 | 目录名；未提供 `path` 时必填 |
| `parent_folder_id` | string | 否 | 父目录 ID |
| `parent_path` | string | 否 | 父目录路径，默认根目录 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `mkdirs` | boolean | 否 | 是否递归创建父目录 |
| `metadata` | object | 否 | 目录元数据 |
| `conflict_policy` | string | 否 | `"reject"` / `"return_existing"` |

**响应**：返回 `folder`，同时在顶层展开 `folder_id`、`path`、`name`、`parent_folder_id`、`version` 等字段。

---

## storage.get_folder

查询目录节点。

**参数**：`folder_id` 或 `path` 至少提供一个；可选 `bucket`、`owner_aid`。

**响应**：同 `storage.create_folder` 的 `folder` 视图。

---

## storage.list_children

列出目录下的直接子目录和对象。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `folder_id` / `path` | string | 否 | 目标目录；都不传表示根目录 |
| `type` | string | 否 | `"all"` / `"folder"` / `"object"`，默认 `"all"` |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |
| `page` | integer | 否 | 页码，默认 1 |
| `size` | integer | 否 | 每页数量，最大受服务配置限制 |
| `order_by` | string | 否 | `"name"` / `"updated_at"` / `"size_bytes"` |
| `order` | string | 否 | `"asc"` / `"desc"` |
| `include_metadata` | boolean | 否 | 是否返回元数据，默认 `true` |
| `include_urls` | boolean | 否 | 是否返回 URL 字段，默认 `true` |

**响应**：`folder`、`items`、`total`、`page`、`size`、`next_marker`。`items[].node_type` 区分 `folder` / `object`。

---

## storage.rename_folder

重命名目录。根目录不可改名。

**参数**：`folder_id` 或 `path`，`new_name` 必填；可选 `bucket`、`owner_aid`、`expected_version`。

**响应**：更新后的 `folder` 视图。

---

## storage.move_folder

移动目录。不能移动到自身或自身子目录。

**参数**：`folder_id` 或 `path`，目标目录通过 `dst_parent_folder_id` 或 `dst_parent_path` 指定；可选 `new_name`、`bucket`、`owner_aid`、`expected_version`。

**响应**：更新后的 `folder` 视图。

---

## storage.delete_folder

删除目录。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `folder_id` / `path` | string | 是 | 待删除目录 |
| `recursive` | boolean | 否 | 非空目录必须传 `true` |
| `dry_run` | boolean | 否 | 只预览将删除的目录/对象 |
| `bucket` | string | 否 | 存储桶，默认 `"default"` |
| `owner_aid` | string | 否 | 所有者 AID，默认当前用户 |

**响应**：`deleted_folders`、`deleted_objects`、`deleted_object_items`、`errors`；`dry_run=true` 时返回预览列表。

---

## storage.resolve_path

按路径解析目录或对象。

**参数**：`path` 必填；可选 `expected_type`（`"any"` / `"object"` / `"folder"`）、`bucket`、`owner_aid`。

**响应**：`type`、`folder_id` 或 `object_id`、`path`、`status`。

---

## storage.move_object

移动或重命名对象。

**参数**：对象选择器（`object_id` / `object_key` / `path`），目标目录 `dst_parent_folder_id` 或 `dst_parent_path`；可选 `new_name`、`conflict_policy`（`"reject"` / `"replace"` / `"keep_both"`）、`expected_version`。

**响应**：返回 `object`，同时在顶层展开对象视图字段。

---

## storage.copy_object

复制对象，底层内容按 CAS 引用计数复用。

**参数**：源对象选择器（`object_id` / `object_key` / `path`，也接受 `src_object_key` / `src_path`），目标 `dst_object_key` / `dst_path` 或目标父目录 + `new_name`；可选 `conflict_policy`、`copy_metadata`。

**响应**：新对象视图。

---

## storage.batch_delete

批量删除对象或目录。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `items` | array | 否 | 每项含 `type`、`object_id` / `object_key` / `path` / `folder_id` |
| `object_keys` | string[] | 否 | 兼容简写，转为对象删除 |
| `recursive` | boolean | 否 | 删除目录时是否递归 |
| `dry_run` | boolean | 否 | 只预览 |

**响应**：`deleted`、`errors`、`deleted_count`、`summary`。

---

## storage.batch_head_object

批量查询对象元数据。

**参数**：`object_ids`、`paths` 至少提供一类；可选 `owner_aid`、`bucket`、`include_missing`、`include_metadata`、`include_urls`。

**响应**：`items` 和 `errors`。

---

## storage.set_object_meta

更新对象元数据和可选 MIME 类型。

**参数**：对象选择器，`metadata`；可选 `merge`（默认 `true`）、`content_type`、`expected_version`。

**响应**：更新后的对象视图。

---

## storage.get_object_url

获取稳定对象 URL。

**参数**：对象选择器；可选 `include_path_url`。

**响应**：`object_id`、`object_url`、`path_url`、`stable`。

---

## storage.append_object

向对象尾部追加 base64 内容；对象不存在时创建。

**参数**：与 `storage.put_object` 类似，`content` 必填；可选 `object_key` / `path` / `name`、`bucket`、`owner_aid`、`content_type`、`metadata`、`expected_version`、`is_private`。

**响应**：对象视图。

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
| `skip_blob` | boolean | 否 | 秒传模式，默认 `false`；为 `true` 时跳过 blob 上传，必须提供 `sha256`，且当前 owner 已拥有相同内容 |
| `expected_version` | integer | 否 | 乐观并发控制版本号 |
| `expire_in_seconds` | integer | 否 | 过期时间（秒） |
| `metadata` | object | 否 | 自定义元数据 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `url` | string | **AID 风格 URL（默认/推荐）**：`https://{owner_aid}/{object_key}`，经 NameService fallback 302 跳转 |
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
| `url` | string | **AID 风格 URL（默认/推荐）**：public 文件为 `https://{owner_aid}/{object_key}`，private 文件为 `https://{owner_aid}/{object_key}?t={token}`。经 NameService fallback 302 跳转到 storage 服务，storage 实时鉴权后出文件（302 到 blob 后端，对客户端透明） |
| `logical_url` | string | 直链 URL：`https://storage.{issuer}/{user}/{object_key}`，直达 storage 服务，无 NameService 跳转 |
| `download_url` | string | 同 `url`（兼容旧客户端，格式已统一） |
| `expire_at` | integer | token 过期时间戳（Unix 秒），public 文件此字段无实际约束 |
| `token` | string | private 文件的不透明访问 token（10 位 Base62），public 文件无此字段 |
| `file_name` | string | 文件名（从 object_key 提取） |
| `size_bytes` | integer | 文件大小（字节） |
| `content_type` | string | MIME 类型 |
| `sha256` | string | SHA-256 哈希 |
| `version` | integer | 版本号 |
| `etag` | string | 实体标签 |

`url` 是推荐使用的干净链接。访问时 storage 服务实时鉴权：public 文件直接通过，private 文件需 `?t=` token 或 `Authorization: Bearer <AID JWT>` 头证明 owner 身份。鉴权通过后 storage 302 到 blob 后端完成实际下载，这一步对客户端完全透明。

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

上传预检：一次调用同时回答"文件是否超限"和"当前 owner 是否可秒传"。客户端应在计算完文件 SHA-256 后、实际上传前调用。

> `check_upload` / `complete_upload(skip_blob=true)` 只允许复用当前 owner 已拥有的内容，避免跨 owner 暴露全局 CAS 存在性或跳过上传克隆他人私有内容。不同 owner 上传相同内容时，仍会在完成上传后归一到同一个 CAS blob，由服务端引用计数管理物理去重。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sha256` | string | 是 | 文件内容的 SHA-256 hex（64 字符） |
| `size_bytes` | integer | 是 | 文件大小（字节） |
| `owner_aid` | string | 否 | 检查指定 owner 是否可秒传，默认当前用户；必须等于当前登录 AID |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `within_limit` | boolean | 文件大小是否在限制内 |
| `exists` | boolean | 当前 owner 是否已拥有相同内容且 CAS blob 可用 |
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
    # 秒传：当前 owner 已拥有相同内容，跳过上传直接 complete
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
| `url` | string | **默认分享 URL（隐藏路径）**：`https://{owner_aid}/s/{share_id}`，最短直链 |
| `path_url` | string | **可选分享 URL（暴露路径）**：`https://{owner_aid}/{object_key}?t={share_id}`，可读性强 |
| `aid_share_url` | string | 同 `url`（兼容旧字段） |
| `share_url` | string | storage 直链：`https://storage.{issuer}/s/{share_id}`，兼容字段 |
| `expire_at` | integer | 过期时间戳（Unix 秒），`0` 表示永不过期 |
| `max_uses` | integer | 最大使用次数，`0` 表示无限制 |
| `allowed_aids` | string[] | 授权 AID 列表，`["*"]` 表示公开 |

> 两种格式都通过 `share_id` 定位到 `share_links` 记录鉴权。`url` 隐藏文件结构，`path_url` 暴露文件名便于识别，调用者按需选择。
> 访问 `url` 时经 NameService 302 跳转到 `storage.{issuer}/s/{share_id}`；访问 `path_url` 时经 NameService fallback 到 storage，由 `?t=` token 鉴权。
> share_id 指向 `(owner_aid, bucket, object_key)` 逻辑引用，非内容快照：对象改名/移动后原 share_id 失效，内容覆盖后下载到新内容。

### 示例

```python
result = await client.call("storage.create_share_link", {
    "object_key": "docs/report.pdf",
    "allowed_aids": ["alice.agentid.pub"],
    "expire_in_seconds": 3600,
    "max_uses": 5,
})
share_url = result["url"]  # https://alice.agentid.pub/s/Ab3xK9mZ2q
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
| `url` | string | 默认分享 URL（隐藏路径）：`https://{owner_aid}/s/{share_id}` |
| `path_url` | string | 可选分享 URL（暴露路径）：`https://{owner_aid}/{object_key}?t={share_id}` |
| `aid_share_url` | string | 同 `url`（兼容旧字段） |
| `share_url` | string | storage 直链（兼容） |
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

## storage.get_by_share

通过分享短码读取对象。公开分享无需额外授权；私有白名单分享需要请求者 AID 在 `allowed_aids` 内。

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `share_id` | string | 是 | 分享短码 |

**响应**：小对象返回 `content`；大对象返回 `download_url`。同时返回 `object_id`、`object_key`、`path`、`size_bytes`、`content_type`、`sha256`。

---

## storage.fs.list

列目录（POSIX `ls`）。混合返回子目录/对象/软链/可用挂载点，排序 dir < file < symlink < mount。群 owner 路径回退到 Group FS 子节点。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 否 | `""` | 目录路径（空=根） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `page` | integer | 否 | `1` | 页码 |
| `size` | integer | 否 | `100` | 每页条数（受 `list_max_limit` 上限约束） |
| `marker` | string | 否 | — | 分页游标 |
| `token` | string | 否 | — | 访问 token |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `nodes` | array | 节点列表，每项 `{type, node_type, name, path, mode, size, mtime, owner_principal}` |
| `items` | array | 同 `nodes`（兼容别名） |
| `total` | integer | 总数 |
| `page` / `size` | integer | 分页 |
| `next_marker` | string | 下一页游标 |

`type` 取值：`file` / `dir` / `symlink` / `mount`。

---

## storage.fs.find

递归查找（POSIX `find`），支持 name/type/size/mtime 过滤与分页。Group FS 与 `.collab` 注册表有回退。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 起始目录 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `name` | string | 否 | — | 名称 glob（如 `*.md`） |
| `type` | string | 否 | — | 节点类型过滤：`f`/`d`/`l`（SDK 形参 `node_type`） |
| `size` | string | 否 | — | 大小表达式（如 `+1M`） |
| `mtime` | string | 否 | — | 修改时间表达式 |
| `page` | integer | 否 | `1` | 页码 |
| `page_size` | integer | 否 | `1000` | 每页条数 |
| `token` | string | 否 | — | 访问 token |

### 响应

同 `storage.fs.list`：`{nodes, items, total, page, size, next_marker}`。

---

## storage.fs.df

配额/用量报告（POSIX `df`），含每 owner 卷（过期卷重新计算）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `owner_aid` / `bucket` | string | 所有者 / 桶 |
| `used_bytes` | integer | 已用字节 |
| `object_count` | integer | 对象数 |
| `quota_bytes` | integer | 配额上限 |
| `avail_bytes` | integer | 剩余可用 |
| `volumes` | array | 每卷用量明细 |

---

## storage.fs.stat

查节点元数据（POSIX `stat`）。`follow_final=true`，解析末级软链 target。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 节点路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `token` | string | 否 | — | 访问 token |

### 响应

fs 节点视图：`{type, node_type, name, path, mode, size, mtime, owner_principal, ...}`。

---

## storage.fs.lstat

查节点（POSIX `lstat`），**不跟随末级软链**——返回软链本身（携带 `dangling` 悬空标志），不返回 target。

### 参数

同 `storage.fs.stat`。

### 响应

fs 节点视图；若为软链，返回软链节点本身（含 `dangling` 标志）。

---

## storage.fs.mkdir

建目录（POSIX `mkdir`）。委托 `create_folder`。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 目录路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `parents` | boolean | 否 | `false` | 递归创建父目录（类 `mkdir -p`） |

### 响应

fs 目录节点视图。

---

## storage.fs.touch

创建空文件或刷新已有节点的修改时间（POSIX `touch`）。已存在的文件、目录或软链会更新时间戳；不存在时默认创建 0 字节私有文件；`no_create=true` 时不存在不创建并返回 `{touched:false, created:false}`。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `parents` | boolean | 否 | `false` | 创建文件时是否递归创建父目录 |
| `no_create` / `noCreate` | boolean | 否 | `false` | 目标不存在时不创建 |
| `mtime` | integer | 否 | 当前时间 | Unix 秒或毫秒；小于 `10000000000` 按秒解释 |
| `follow_symlinks` / `followSymlinks` | boolean | 否 | `false` | 目标为软链时是否跟随末级软链 |
| `content_type` | string | 否 | `"application/octet-stream"` | 新建空文件的 MIME 类型 |
| `metadata` | object | 否 | `{}` | 新建空文件的元数据 |
| `expire_in_seconds` | integer | 否 | `0` | 新建空文件的过期秒数 |

### 响应

成功返回 fs 节点视图，并额外包含：

| 字段 | 类型 | 说明 |
|------|------|------|
| `touched` | boolean | 是否实际更新或创建 |
| `created` | boolean | 是否新建了空文件 |

---

## storage.fs.remove

删除文件/目录/软链（POSIX `rm`，目录用 `recursive`）。**拒绝删除挂载点**（须先 unmount）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 节点路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `recursive` | boolean | 否 | `false` | 递归删除目录 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `owner_aid` / `bucket` / `path` | string | 目标 |
| `removed_count` | integer | 删除节点数 |
| `deleted` | boolean | 是否删除成功 |

---

## storage.fs.rename

同 owner/bucket 内移动或改名（POSIX `mv`）。**跨 owner/bucket 被拒**；按节点类型分派到 move_folder / rename_symlink / move_object。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `src` | string | 是 | — | 源路径 |
| `dst` | string | 是 | — | 目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在目标 |
| `expected_version` | integer | 否 | — | 乐观锁版本号 |

### 响应

被重命名节点的 fs 节点视图。

---

## storage.fs.copy

复制对象或软链（POSIX `cp`，目录复制暂不支持）。CAS blob 引用计数复用，支持跨 owner 对象复制。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `src` | string | 是 | — | 源路径 |
| `dst` | string | 是 | — | 目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 源所有者 AID |
| `bucket` | string | 否 | `"default"` | 源存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在目标 |
| `follow_symlinks` | boolean | 否 | `false` | 复制软链 target 而非软链本身 |
| `dst_owner_aid` | string | 否 | 同源 | 目标所有者（SDK 形参 `dst_owner`） |
| `dst_bucket` | string | 否 | 同源 | 目标存储桶 |

### 响应

被复制节点的 fs 节点视图。

---

## storage.fs.mount

挂载卷或他人子树进 owner 命名空间。`readonly` 默认 true；`require_approval=true` 时进入 pending 直到源 owner 批准。群成员卷挂载场景下，storage 通过 CA `aid_type=group` 识别群命名空间，命中 `/memberdata/` 时调 `group.check_membership` 实时校验成员身份。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `mount_path` | string | 是 | — | 挂载点路径 |
| `owner_aid` | string | 否 | 当前用户 | 命名空间所有者 |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `volume_id` | string | 否 | — | 挂载实体卷（与 source_* 互斥） |
| `source_aid` | string | 否 | — | 虚拟卷源 AID（与 volume_id 互斥） |
| `source_path` | string | 否 | — | 虚拟卷源路径 |
| `source_bucket` | string | 否 | — | 虚拟卷源存储桶 |
| `readonly` | boolean | 否 | `true` | 只读挂载 |
| `require_approval` | boolean | 否 | `false` | 需源 owner 批准 |
| `expires_at` | integer | 否 | — | 挂载过期时间 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `mount` | object | 挂载视图 |
| `status` | string | `active`（直接生效）/ `pending`（待批准） |

> `status` 字段仅在直接调用 lowlevel RPC（`fs_mount`/`FSMount`/`fsMount` 原始返回）时可见。四语言 SDK 的高层 VFS 门面（`vfs.mount()`/`StorageVFS.Mount()`/`vfs.mount()`）会把响应解析为通用 NodeView，该视图不保留顶层 `status` 字段；需要判断是否 `pending` 时请改用 lowlevel 接口读取原始响应，或检查服务端在 `pending` 场景下额外写入的 `request_id`。

---

## storage.fs.approve

源 owner 批准 pending 挂载（重新校验源路径存在）。`mount_id` 或 `(owner_aid, bucket, mount_path)` 二选一定位。

### 参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `mount_id` | string | 否 | 挂载 ID（或用下方三元组定位） |
| `owner_aid` | string | 否 | 命名空间所有者 |
| `bucket` | string | 否 | 存储桶 |
| `mount_path` | string | 否 | 挂载点路径 |

### 响应

| 字段 | 类型 | 说明 |
|------|------|------|
| `approved` | boolean | `true` |
| `mount` | object | 挂载视图 |

---

## storage.fs.reject

源 owner 或挂载 owner 拒绝 pending 挂载。定位方式同 `fs.approve`。

### 响应

`{rejected: boolean, mount}`。

---

## storage.fs.unmount

卸载挂载点（仅 owner 可操作）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `mount_path` | string | 是 | — | 挂载点路径 |
| `owner_aid` | string | 否 | 当前用户 | 命名空间所有者 |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

`{unmounted: boolean, owner_aid, bucket, path, mount_path}`。

---

## storage.fs.invalidate_membership

群成员变更/群解散时失效群挂载（仅群 owner 或内部调用者）。SDK 形参不带 owner/bucket。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `group_id` | string | 是 | — | 群组标识兼容字段，值语义为目标态 `group_aid` |
| `group_owner_aid` | string | 是 | — | 群 owner AID |
| `member_aid` | string | 否 | — | 成员 AID（不传=全员） |
| `reason` | string | 否 | `"membership_changed"` | `dissolved` / `membership_changed` |
| `status` | string | 否 | — | `inactive` / `unavailable` |

### 响应

`{group_id, group_aid, group_owner_aid, member_aid, reason, status, invalidated}`（`invalidated`=失效挂载数）。

---

## storage.create_symlink

创建软链。target 受限于 owner 命名空间；拒绝同名 file/dir；父路径不可含软链前缀。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 软链路径 |
| `target` | string | 是 | — | 指向目标路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在软链 |

### 响应

软链视图（含 `dangling` 悬空标志）。

---

## storage.readlink

读软链 target（owner 校验）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 软链路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

软链视图 `{symlink, target, version, ...}`。

---

## storage.atomic_repoint

原子重指软链 target（乐观锁 CAS）。**collab commit / tag 并发正确性的底层核心**。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 软链路径 |
| `new_target` | string | 是 | — | 新 target |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `expected_version` | integer | 否 | — | CAS 期望版本（null=跳过 CAS） |

### 响应

**成功**：`{ok: true, ...软链视图}`（version+1）。
**CAS 失败**：`{ok: false, current_version, current_target}`。

---

## storage.rename_symlink

改软链 key（同 owner/bucket 内移动/改名），target 不变。跨 owner 被拒。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 原软链路径（SDK 形参 `path`/服务端 `src`） |
| `new_path` | string | 是 | — | 新软链路径（服务端 `dst`） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `overwrite` | boolean | 否 | `false` | 覆盖已存在 |
| `expected_version` | integer | 否 | — | CAS 期望版本 |

### 响应

**成功**：`{ok: true, ...软链视图}`。
**CAS 失败**：`{ok: false, current_version, current_path, current_target}`。

---

## storage.delete_symlink

删软链记录（不动 target 对象）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 软链路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

`{deleted: boolean, owner_aid, bucket, path, symlink_id, target}`。

---

## storage.set_acl

授予路径前缀 ACL grant。普通 AID storage 的 `grantee_aid` 必须是具体 AID，主要用于授予写/删除权限；子路径默认继承（最近祖先覆盖）。读取不通过 AID ACL 直接授权，应用应改用 `storage.create_share_link` 并在需要时用 `storage.revoke_share_link` 撤销。

`role:*` 伪主体只允许可信 group 内部门面写入。客户端不能直接对 `group_aid` 空间调用 `storage.set_acl` 设置 `role:admin`；群自有区角色写授权统一使用 `group.fs.set_acl`。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 授权路径前缀 |
| `grantee_aid` | string | 是 | — | 被授权 AID；`role:*` 仅限 group 内部调用 |
| `perms` | string | 是 | — | 权限位：`r`/`w`/`rw`/`rwx`（`rwx` 含删除） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `expires_at` | integer | 否 | — | 授权过期时间 |
| `max_uses` | integer | 否 | — | 最大使用次数 |

### 响应

ACL 视图。

---

## storage.remove_acl

移除路径 ACL 授权。对 AID storage，这是撤销写/删除授权的入口；读分享的撤销入口是 `storage.revoke_share_link`。群自有区角色写授权撤销使用 `group.fs.remove_acl`，不要由客户端直接调用 `storage.remove_acl` 操作 `role:*`。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 授权路径前缀 |
| `grantee_aid` | string | 是 | — | 被授权 AID |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

`{removed: boolean, owner_aid, bucket, path, grantee_aid}`。

---

## storage.list_acl

列出路径上的 ACL 授权（owner 校验）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

`{owner_aid, bucket, path, acls}`。

---

## storage.set_visibility

切换对象或目录的公开/私有（软链不支持）。`allow_roles` 是低层兼容字段，不能作为群自有区 admin 写授权入口；群自有区角色写授权必须使用 `group.fs.set_acl/remove_acl`。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 路径 |
| `visibility` | string | 是 | — | `public` / `private` |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `allow_roles` | array | 否 | — | 低层兼容字段，仅表示可见性读角色；不能用于群自有区写授权 |

### 响应

fs 节点视图（含 `allow_roles`）。

---

## storage.check_access

非抛错的访问探测——探测某操作在某路径是否放行（内部捕获 NotFound/Dangling/Permission）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 路径（服务端别名 `object_key`） |
| `operation` | string | 否 | `"read"` | `read` / `write` / `delete`（服务端别名 `op`） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `token` | string | 否 | — | 访问 token |
| `follow_symlinks` | boolean | 否 | `true` | 跟随软链 |

### 响应

`{allowed: boolean, reason, message, requester_aid, owner_aid, bucket, path, operation}`。

---

## storage.issue_token

签发 hash 化的 bearer 访问 token，scope 到某路径。返回的明文 token 仅此一次可见。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 授权路径（服务端别名 `object_key`） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `expires_at` | integer | 否 | — | 过期时间 |
| `max_reads` | integer | 否 | — | 最大读取次数（服务端别名 `max_uses`） |

### 响应

token 视图 + 明文 token（一次性返回）。

---

## storage.revoke_token

按明文 token 值吊销（内部 hash 后查找）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 路径（服务端别名 `object_key`） |
| `token` | string | 是 | — | 要吊销的明文 token |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

`{revoked: boolean, owner_aid, bucket, path}`。

---

## storage.list_tokens

列出路径上的 token（owner 校验，不返回明文）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `path` | string | 是 | — | 路径 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |

### 响应

token 列表（hash 摘要 + 元数据）。

---

## storage.volume.create

创建/upsert 配额卷（含 mount_point）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `size_bytes` | integer | 是 | — | 卷容量（>0） |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `volume_id` | string | 否 | 自动 | 卷 ID |
| `used_bytes` | integer | 否 | — | 已用字节 |
| `status` | string | 否 | `active` | `active` / `grace` / `expired` |
| `mount_point` | string | 否 | — | 挂载点 |
| `expires_at` | integer | 否 | — | 过期时间 |

### 响应

`{volume, ...卷视图}`。

---

## storage.volume.renew

续期卷过期时间/状态（owner 校验，owner 不符抛 PermissionError）。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `volume_id` | string | 是 | — | 卷 ID（服务端别名 `id`） |
| `expires_at` | integer | 是 | — | 新过期时间 |
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `status` | string | 否 | — | 卷状态 |

### 响应

`{volume, ...卷视图}`。

---

## storage.volume.expire_due

过期所有到期卷并标记其挂载为 unavailable。

### 参数

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `owner_aid` | string | 否 | 当前用户 | 所有者 AID |
| `bucket` | string | 否 | `"default"` | 存储桶 |
| `now` | integer | 否 | 当前时间 | 判定基准时间 |

### 响应

`{owner_aid, bucket, expired, mounts_unavailable, volumes, mounts}`。

## 错误码

| code | 说明 |
|------|------|
| -32002 | 服务暂不可用（数据库未连接） |
| -32004 | 权限拒绝（requester 不是对象 owner，或非公开对象的读权限不足） |
| -32008 | 对象不存在（`ErrNotFound`） |
| -32009 | 版本冲突（`ErrVersionConflict`，`expected_version` 与实际版本不匹配） |
| -32000 | 通用错误（参数校验失败、配额不足、base64 解码失败、文件大小超限等） |
