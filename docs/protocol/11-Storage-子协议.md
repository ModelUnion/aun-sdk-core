# 11. Storage 子协议

> **适用版本**：AUN 1.0 | **状态**：Draft

Storage 服务是 AUN 协议的应用层扩展，提供对象存储能力。负责大文件、附件、二进制数据的上传、下载与持久保存。客户端通过 `storage.*` 命名空间方法访问，小对象（≤64KB）通过 RPC 内联传输，大对象通过预签名 URL 直接 HTTP 传输。

---

## 11.1 设计原则

- **控制面与数据面分离**：小对象内联 RPC；大对象通过 `create_upload_session` / `create_download_ticket` 获取预签名 URL，走 HTTP 数据面
- **per-AID 隔离**：每个 AID 拥有独立的存储命名空间和配额，跨 AID 访问受 `is_private` 控制
- **对象键路径化**：`object_key` 支持 `/` 分隔的层级路径，便于组织和前缀查询
- **版本化**：每次写入递增 `version`，支持 `expected_version` 做 CAS（Compare-And-Swap）并发控制

---

## 11.2 约束与限制

| 约束 | 默认值 | 说明 |
|------|--------|------|
| 内联内容上限 | 64 KB | `put_object` / `get_object` 的 base64 内容上限 |
| 单对象上限 | 10 MB | 含数据面上传 |
| 对象键长度 | ≤ 1024 字节 | 不含 `..`，不含前导/尾随/连续 `/` |
| 列表分页上限 | 200 条/页 | `list_objects` 单次最大返回 |
| 预签名 URL 有效期 | 3600 秒 | upload / download ticket |

对象键合法字符：字母、数字、`.`、`_`、`/`、`-`。

---

## 11.3 控制面方法

### `storage.put_object`

内联写入小对象（≤ 内联上限）。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `object_key` | string | ✅ | 对象路径 |
| `content` | string | ✅ | base64 编码的内容 |
| `content_type` | string | ❌ | MIME 类型，默认 `application/octet-stream` |
| `is_private` | boolean | ❌ | 默认 `true`，公开对象可被其他 AID 读取 |
| `overwrite` | boolean | ❌ | 默认 `true`，`false` 时对象已存在则拒绝 |
| `expected_version` | integer | ❌ | CAS 并发控制，版本不匹配则拒绝 |
| `expire_in_seconds` | integer | ❌ | 过期时间，`0` 表示永不过期 |
| `metadata` | object | ❌ | 用户自定义元数据 |

**响应**：`{ owner_aid, bucket, object_key, size_bytes, content_type, sha256, version, etag, updated_at }`

**权限**：仅对象所有者可写（`requester_aid == owner_aid`）。

**副作用**：成功后发布 `event/storage.object_changed`（`action: "put"`）。

### `storage.get_object`

内联读取小对象。对象超过内联上限时须使用 `create_download_ticket`。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `object_key` | string | ✅ | 对象路径 |

**响应**：`{ owner_aid, bucket, object_key, content (base64), content_type, size_bytes, sha256, version, updated_at }`

**权限**：私有对象仅所有者可读；公开对象（`is_private=false`）任何 AID 可读。

### `storage.head_object`

查询对象元数据，不返回内容。

**参数**：同 `get_object`。

**响应**：`{ owner_aid, bucket, object_key, content_type, size_bytes, sha256, version, etag, is_private, expire_at, created_at, updated_at }`

**权限**：同 `get_object`。

### `storage.delete_object`

删除单个对象。

**参数**：同 `get_object`。

**响应**：`{ deleted (bool), owner_aid, object_key }`

**权限**：仅所有者可删。

**副作用**：成功后发布 `event/storage.object_changed`（`action: "delete"`）。

### `storage.list_objects`

列出对象，支持前缀过滤和分页。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `prefix` | string | ❌ | 路径前缀过滤 |
| `page` | integer | ❌ | 页码，默认 1 |
| `size` | integer | ❌ | 每页条数，默认 50，最大 200 |
| `marker` | string | ❌ | 深度分页游标；传入时优先按游标分页 |

**响应**：`{ items: [{ object_key, size_bytes, content_type, sha256, version, is_private, updated_at }...], total, page, size, marker, next_marker }`

**权限**：仅所有者可列。

### `storage.list_prefixes`

列出指定前缀下的子目录（类似 S3 CommonPrefixes）。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `prefix` | string | ❌ | 路径前缀 |
| `size` | integer | ❌ | 返回上限，默认 50，最大 200 |

**响应**：`{ prefixes: [string...], count, size }`

**权限**：仅所有者可列。

### `storage.get_quota`

查询存储配额使用情况。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |

**响应**：`{ owner_aid, used_bytes, object_count, quota_bytes }`

**权限**：仅所有者可查。

---

## 11.4 数据面方法

用于超过内联上限的大对象传输。客户端通过 RPC 获取预签名 URL，然后直接 HTTP PUT/GET。

### `storage.create_upload_session`

申请上传预签名 URL。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `object_key` | string | ✅ | 对象路径 |
| `size_bytes` | integer | ❌ | 预期大小（客户端追踪用） |
| `content_type` | string | ❌ | 默认 `application/octet-stream` |
| `expected_version` | integer | ❌ | CAS 版本检查（签 URL 前校验） |
| `expire_in_seconds` | integer | ❌ | URL 有效期，默认 3600 秒 |

**响应**：`{ upload_url, blob_key, expire_at, owner_aid, bucket, object_key, content_type, size_bytes }`

**权限**：仅所有者可申请。

**流程**：客户端获取 `upload_url` 后，直接 HTTP PUT 上传文件内容，完成后调用 `complete_upload` 确认。

**当前实现补充**：`create_upload_session` 签发 URL 时不做配额与最终文件大小的强校验；配额、`max_file_size_bytes`、SHA-256/size 校验在 `complete_upload` 阶段执行。

### `storage.complete_upload`

确认上传完成，将 blob 关联为正式对象。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `object_key` | string | ✅ | 对象路径 |
| `content_type` | string | ❌ | 默认 `application/octet-stream` |
| `is_private` | boolean | ❌ | 默认 `true` |
| `sha256` | string | ❌ | 期望哈希，服务端校验 |
| `size_bytes` | integer | ❌ | 期望大小，服务端校验 |
| `expire_in_seconds` | integer | ❌ | 过期时间，默认永不过期 |
| `metadata` | object | ❌ | 用户自定义元数据 |
| `expected_version` | integer | ❌ | CAS 并发控制 |

**响应**：`{ owner_aid, bucket, object_key, size_bytes, content_type, sha256, version, etag, updated_at }`

**权限**：仅所有者可确认。

### `storage.create_download_ticket`

申请下载预签名 URL。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|:----:|------|
| `owner_aid` | string | ❌ | 默认调用者 AID |
| `bucket` | string | ❌ | 默认 `"default"` |
| `object_key` | string | ✅ | 对象路径 |
| `expire_in_seconds` | integer | ❌ | URL 有效期，默认 3600 秒 |

**响应**：`{ download_url, expire_at, file_name, size_bytes, content_type, sha256, version, etag }`

**权限**：私有对象仅所有者；公开对象任何 AID 可申请。

---

## 11.5 POSIX VFS 与命名空间扩展

> 在 11.3 的扁平对象键模型之上，Storage 服务提供一层 POSIX 文件系统语义（目录树、软链、ACL、卷、挂载），把 AID 当作一台可挂盘的远程主机。寻址统一为 `<AID>:<Unix 绝对路径>`。
>
> 本节定义方法命名空间与关键语义；逐方法参数/响应以 SDK RPC 手册 `docs/sdk/09-storage-rpc-manual.md` 为准（避免协议层与 SDK 层双写漂移）。

### 11.5.1 目录树与对象管理

控制面在 11.3 基础上扩展目录树方法：`storage.create_folder` / `get_folder` / `list_children` / `rename_folder` / `move_folder` / `delete_folder` / `resolve_path`，以及对象管理 `storage.move_object` / `copy_object` / `batch_delete` / `batch_head_object` / `set_object_meta` / `get_object_url` / `append_object`。`storage.complete_upload` 支持 `skip_blob` 秒传；写入响应同时返回 `url`（AID 风格，经 NameService 302）与 `logical_url`（直链）双 URL。

### 11.5.2 fs.* POSIX 命令层

| 方法 | POSIX 对应 | 语义要点 |
|------|-----------|---------|
| `storage.fs.list` | `ls` | 混合返回 dir/file/symlink/mount，排序 dir<file<symlink<mount |
| `storage.fs.find` | `find` | name(glob)/type/size/mtime 过滤 + 分页 |
| `storage.fs.df` | `df` | 配额/用量，含每 owner 卷（过期卷重算） |
| `storage.fs.stat` / `lstat` | `stat`/`lstat` | stat 跟随末级软链；lstat 返回软链本身（带 `dangling`） |
| `storage.fs.mkdir` | `mkdir` | `parents` 类 `-p` |
| `storage.fs.remove` | `rm` | 目录 `recursive`；拒绝删挂载点 |
| `storage.fs.rename` | `mv` | 同 owner/bucket 内；跨 owner 拒绝 |
| `storage.fs.copy` | `cp` | 对象/软链复制，CAS blob 引用计数复用，支持跨 owner |
| `storage.fs.mount` / `unmount` / `approve` / `reject` | 挂载 | 挂卷或他人子树；`require_approval` → pending |
| `storage.fs.invalidate_membership` | — | 群成员变更/解散时失效群挂载 |

### 11.5.3 软链原语

`storage.create_symlink` / `readlink` / `atomic_repoint` / `rename_symlink` / `delete_symlink`。软链是元数据库一行，不在对象存储。`atomic_repoint` 用单事务 `UPDATE ... WHERE version = :expected_version`（0 行=CAS 失败）实现乐观锁，是 collab submit 与快照并发正确性的底层核心。目标删除后软链悬空，访问报 `EDANGLING`（区别于 `ENOENT`）。

### 11.5.4 ACL / token / 可见性

统一权限求值顺序（硬顺序，不可调换）：① 公开位（`set_visibility`/`is_public`，仅读）→ ② token（`issue_token` 签发，scope 到路径）→ ③ 路径前缀 ACL（`set_acl`，最近祖先匹配，权限位 `r`/`w`/`rw`/`rwx`）→ ④ 角色（群内）→ ⑤ owner → ⑥ 拒绝 `EACCES`。方法：`storage.set_acl` / `remove_acl` / `list_acl` / `set_visibility` / `check_access`（非抛错探测）/ `issue_token` / `revoke_token` / `list_tokens`。

AID storage 的 ACL 面向具体 AID，主要用于写/删除授权；撤销写授权使用 `storage.remove_acl`。读权限不通过 AID ACL 直接下发，应用应使用 `storage.create_share_link` / `storage.get_by_share` 间接读取，撤销读分享使用 `storage.revoke_share_link`。`role:*` 伪主体只允许可信 group 内部门面管理；普通客户端不得直接对 `group_aid` 空间设置或删除角色 ACL，群自有区 `role:admin` 写授权统一由 `group.fs.set_acl/remove_acl` 管理。

### 11.5.5 卷与配额

`storage.volume.create`（upsert 配额卷 + mount_point）/ `volume.renew`（续期）/ `volume.expire_due`（过期到期卷并标记其挂载 unavailable）。卷生命周期：active → grace（只读宽限，df 标 *）→ expired。

### 11.5.6 群命名空间识别

Storage 通过 CA 的 `aid_type` 字段（`normal`/`group`）识别群命名空间。命中 `aid_type=group` 且挂载路径落在 `/memberdata/` 时，放宽 owner 校验，改为调 `group.check_membership` RPC 实时校验成员身份 + 路径约束（mount_path 第一级 == requester_aid）。详见 `10-Group-子协议.md` 与 `docs/aun-fs/topics/group-space.md`。

成员个人 Storage 内的 `group_data` 是系统级真实存储根，Storage 服务端必须对普通 `storage.*` / `storage.fs.*` 请求隐藏并拒绝直接写入、删除、重命名或挂载；`aun fs` / Storage VFS 只呈现服务端返回结果，不新增保护逻辑。`group_data` 只能由可信 `group.fs.*` 内部上下文间接访问，占用的空间仍必须计入真实 owner AID 的 Storage 配额。完整规则见 [16-系统目录保护方案.md](16-系统目录保护方案.md)。

### 11.5.7 collab 协作编排

协作层 `collab.*`（版本化文档 + 目录快照）的编排已并入 Storage 服务进程，handler 与 `storage.*` 并列注册，以调用者身份直调 storage 原语，授权下沉 storage ACL，无特权通道。方法清单与语义见 SDK 手册 `docs/sdk/09-collab-rpc-manual.md`。

---

## 11.6 事件

### `event/storage.object_changed`

对象变更时推送给所有者。

```json
{
  "jsonrpc": "2.0",
  "method": "event/storage.object_changed",
  "params": {
    "module_id": "storage",
    "action": "put",
    "owner_aid": "alice.aid.pub",
    "object_key": "docs/report.pdf"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `action` | string | `"put"` 或 `"delete"` |
| `owner_aid` | string | 对象所有者 AID |
| `object_key` | string | 变更的对象路径 |

---

## 11.7 错误码

| 错误码 | 含义 | 说明 |
|--------|------|------|
| -32008 | Object not found | 对象不存在 |
| -32009 | Version conflict | CAS 版本不匹配 |
| -32004 | Permission denied | 非所有者访问私有对象 |

---

## 11.8 大对象上传流程

```
客户端                          Storage 服务                    HTTP 数据面
  │                                │                              │
  │─ storage.create_upload_session ►│                              │
  │◄─ { upload_url, blob_key }  ───│                              │
  │                                │                              │
  │─────────── HTTP PUT upload_url ─────────────────────────────► │
  │◄──────────────── 200 OK ─────────────────────────────────────│
  │                                │                              │
  │─ storage.complete_upload ─────►│                              │
  │◄─ { object_key, sha256, ... } ─│                              │
```

大对象下载流程类似：`create_download_ticket` 获取 `download_url`，客户端直接 HTTP GET。


