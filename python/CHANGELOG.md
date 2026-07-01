# Changelog

本文件记录 fastaun (Python) SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

---

## 0.5.1 — 2026-07-01

### ⚠️ 重大变更（Breaking Changes）

#### 群组标识符统一为 GROUP_AID
- **GROUP_ID 废弃**：历史 `group.{domain}/{base}` 格式已废弃，统一为 `{base}.{issuer}` 格式（group_aid）
- **兼容转换**：`normalize_group_id()` 函数保留向后兼容，自动转换旧格式到新格式
- **新增函数**：`convert_to_group_aid()` 显式转换任意历史格式到标准 group_aid
- **RPC 参数**：`group_id` 字段名保留但值为 group_aid；新增 `group_aid` 参数与 `group_id` 等价
- **影响范围**：所有群组相关 API（`group.send` / `group.pull` / `group.fs.*` 等）

#### 移除 V1 E2EE 实现
- **完全移除**：删除所有 V1 端到端加密代码（epoch key、`GroupE2EEManager`、V1 群组加密）
- **仅保留 V2**：E2EE 功能完全迁移到 V2 协议（消息级密钥 + 逐设备 wrap + 状态签名）
- **删除文件**：
  - `tests/e2e_test_group_e2ee.py` — V1 群组加密 E2E 测试
  - `tests/e2e_test_v2_group_e2ee.py` — V2 群组加密 E2E 测试（已合并到主测试套件）
  - `tests/unit/test_e2ee.py` — V1 E2EE 单元测试
- **简化接口**：`e2ee.py` 仅保留 V2 路径和元数据认证函数，文件从 3500+ 行精简到 78 行
- **注意**：此版本不向后兼容 V1 加密消息

### 新功能

#### Storage & Group FS 能力扩展
- **Storage VFS P4**：新增 `touch()` 方法，支持创建空文件或更新文件时间戳
- **Storage VFS P4**：新增 `du()` 方法，支持查询目录或文件的磁盘使用统计
- **Storage VFS P6**：扩展 `get_acl()` / `list_acl()` 方法，支持 ACL 权限查询
- **Group FS**：新增 `get_acl()` / `list_acl()` / `remove_acl()` 方法，完善群文件 ACL 管理
- **Storage LowLevel**：补齐底层 RPC 映射，覆盖 `storage.fs.*` / `storage.object.*` 完整能力

#### CLI 增强
- **fs 命令**：新增 `aun fs touch` / `aun fs du` 支持文件创建和磁盘使用查询
- **group fs 命令**：新增 `aun group fs get-acl` / `aun group fs list-acl` / `aun group fs remove-acl` 支持群文件 ACL 管理

### 修复

#### Storage & Group FS
- 修复 `group.send` / `group.pull` 缺失 `group_id` 必填校验问题
- 修复 `group.fs` 权限角色 (`role`) 在 ACL 展示中的格式错误
- 修复 `storage.fs.symlink` 符号链接操作的路径解析问题
- 修复 `storage.fs.memberdata` 路由逻辑错误
- 修复 `storage.fs.mount` 挂载点权限校验问题

#### 服务端性能优化（影响 SDK 行为）
- Gateway 连接池改为可配置，降低高并发下的连接瓶颈
- Group 推送改为异步化，提升大群消息分发性能
- Message seq 号段化分配，减少数据库争抢
- Message 短暂消息 (`persist=false`) 改用内存缓冲 + 异步推送

### 改进

- 路径校验增强：`storage.fs` / `group.fs` 路径参数增加规范化校验，拒绝 `..` / 空路径 / 非法字符
- 系统目录保护：`memberdata` / `group_data` 写操作增加保护，防止误删系统目录
- Validators：新增跨语言 `validate_path()` / `validate_aid()` 等校验函数，四语言行为对齐

### 测试

- 新增 `test_storage_vfs_p4.py` 单元测试（`touch` / `du`）
- 新增 `test_cli_fs_p4.py` CLI 测试（fs touch / du）
- 新增 `test_cli_group_fs.py` CLI 测试（group fs ACL 操作）
- 扩展 `e2e_test_fs_p3.py` / `e2e_test_group_fs_sdk.py` E2E 测试覆盖新增能力

---

## 0.5.0 — 2026-06-17

### 新功能

#### Storage 子协议（重大新增）
- **Storage VFS（虚拟文件系统）**：新增 `StorageVFS` 类，支持 P1-P6 全栈能力
  - P1: `put_object` / `get_object` / `delete_object` / `list_objects` / `head_object`
  - P2: `create_folder` / `rename_folder` / `move_folder` / `delete_folder` / `move_object` / `copy_object` / `batch_delete`
  - P3: `set_object_meta` / `append_object`
  - P4: `mount` / `unmount` / `stat` / `list` / `find`
  - P5: `copy` / `rename` / `remove` / `create_symlink` / `delete_symlink` / `rename_symlink` / `readlink` / `atomic_repoint`
  - P6: `set_acl` / `remove_acl` / `list_acl` / `check_access` / `issue_token` / `revoke_token` / `list_tokens` / `create_volume` / `renew_volume` / `expire_due_volume` / `set_visibility`
- **Storage LowLevel（底层存储）**：新增 `StorageLowLevel` 类，提供对象级存储操作
- **Group FS（`group.fs` POSIX 群文件系统）**：新增 `GroupFSVFS` 类，通过 `client.group.fs` 暴露群共享文件系统门面，替代 0.4.x 草案中的 `group.resources`
  - POSIX 控制面：`ls` / `find` / `stat` / `lstat` / `mkdir` / `rm` / `cp` / `mv` / `df` / `mount` / `umount`
  - `cp` 支持三种路径组合：本地 → 群文件、群文件 → 本地、群文件 → 群文件；本地路径支持 `local:` 前缀，Windows 盘符不会被误判为远程路径
  - 上传数据面：`group.fs.check_upload` / `create_upload_session` / `complete_upload` + HTTP PUT，支持秒传、dedup、`force` 覆盖和 sha256 校验
  - 下载数据面：`group.fs.create_download_ticket` + HTTP GET，自动携带 Bearer token，下载后校验 sha256，默认拒绝覆盖本地文件
  - 群自有区写身份：写操作支持 `sign_as` / `aid_store`，SDK 本地加载 `group_aid` 私钥注入 `client_signature`，不会把签名身份参数透传给服务端
  - CLI：新增 `aun group fs ls/find/stat/lstat/mkdir/rm/cp/mv/df/mount/umount`，裸路径默认绑定当前 active group

#### Collab 协作编辑子协议（重大新增）
- **CollabClient**：新增协作编辑客户端，支持多人实时文档协作
  - Diff3 三路合并算法（`diff3_merge`）
  - 快照管理（`create_snapshot` / `list_snapshots` / `get_snapshot` / `restore_snapshot`）
  - 标签管理（`create_tag` / `list_tags` / `get_tag` / `restore_tag`）
  - 群组权限验证和冲突解决
- **CollabError / CollabConflictError**：新增协作编辑专用异常类型
- **Python CLI collab 命令**：新增 `aun collab` 命令行工具，支持本地协作编辑操作

#### Facade 架构（API 重构）
- **AUNClient Facade 属性**：新增统一的子系统访问入口
  - `client.storage` → `StorageVFS` 实例
  - `client.message` → `MessageFacade` 实例
  - `client.group` → `GroupFacade` 实例（含 `client.group.fs`）
  - `client.stream` → `StreamFacade` 实例
  - `client.collab` → `CollabClient` 实例
- **GroupFacade / MessageFacade / StreamFacade / ThoughtFacade**：新增 facade 类封装高级操作，简化常用场景

#### Python CLI 增强
- **fs 命令**：新增/完善文件系统操作命令
  - `aun fs mount` / `unmount` / `stat` / `list` / `find`
  - `aun fs copy` / `rename` / `remove`
  - `aun fs symlink` / `readlink` / `repoint`
- **storage 命令**：新增/完善存储操作命令
  - `aun storage put` / `get` / `delete` / `list` / `head`
  - `aun storage folder` / `move` / `copy` / `batch-delete`
- **fs_utils / storage_core**：新增 CLI 工具核心模块

### 架构变更

#### 身份管理职责剥离（重大重构）
- **AID 持私钥**：`AID` 类现在直接持有明文私钥（`private_key_pem`），不再依赖外部密钥管理
- **AIDStore 简化**：`AIDStore` 职责收窄为纯存储层，移除加密/签名等密码学操作
- **AUNClient 职责清晰化**：`AUNClient` 专注连接和消息传输，不再承担身份管理职责
- **导入群组身份**：新增 `import_group_identity()` 支持群组身份导入和迁移

### 修复

#### 群撤回相关
- 修复群撤回时间源不一致问题
- 修复后加入成员收到撤回通知泄漏历史消息问题
- 修复空 `message_ids` 列表处理异常
- 修复 V2 重复撤回导致的状态不一致

#### 存储相关
- 修复 `group.fs` 签名集合缺失导致的签名验证失败
- 修复幂等性集合缺失导致的重试异常
- 修复 `memberdata` 路由逻辑错误

### 优化

#### 性能优化（服务端协同）
- **Gateway**：证书验签 LRU 缓存（1024），Nonce 池淘汰 O(1)
- **Group**：DB 连接池可配置（默认 40），`_require_group` 短 TTL 缓存，`list_members` 支持跳过 COUNT(*)
- **Message**：DB 连接池可配置（默认 30），合并查询减少 acquire，思维锁改为分桶锁

### 测试

#### 新增测试
- Storage VFS P1-P6 层级单元测试（`test_storage_vfs_*.py`）
- Storage LowLevel 单元测试（`test_storage_lowlevel.py`）
- Group FS 单元测试（`test_group_fs_contract.py` / `test_group_fs_vfs.py`）
- Group FS CLI 单元测试（`test_cli_group_fs.py` / `test_cli_group_fs_contract.py`）
- Collab Client 单元测试（`test_collab_client.py`）
- Collab Diff3 单元测试（`test_collab_diff3.py`）
- Collab CLI 单元测试（`test_collab_cli.py`）
- CLI fs 命令单元测试（`test_cli_fs_*.py`）
- CLI storage 命令单元测试（`test_cli_storage.py`）
- Group identity / `group_aid` 生命周期单元测试（`test_group_identity.py`）

#### 集成/E2E 测试
- Storage 集成测试（`integration_test_storage.py`）
- Collab 集成测试（`integration_test_collab.py`）
- Collab Docker 跨域测试（`e2e_test_collab_docker.py`）
- Group FS CLI E2E 测试（`e2e_test_group_fs_cli.py`）
- Storage VFS P1-P6 集成/E2E 测试

### 文档

- 更新 `docs/INDEX.md` 和 `docs/KITE_DOCS_GUIDE.md` 索引
- 新增 Storage/Group FS/Collab RPC 手册
- 更新 `docs/sdk/09-group-rpc-manual.md` 群组方法文档
- 新增示例代码（`collab_edit.py` / `storage_vfs.py`）

### 依赖

- 保持现有依赖版本不变

---

## 0.4.13 — 2026-06-09

### 新功能
- **发送结果回填 envelope**：`message.send` / `group.send` / `message.thought.put` / `group.thought.put` 的返回结果新增规范化 `envelope` 字段，使发送方回执与接收端信封元数据一致；新增 `MessageDeliveryEngine.send_result_envelope()` / `attach_send_result_envelope()`，`RpcPipeline.call_after_pipeline` 在 `postprocess_result` 后统一附加，V2 加密路径经内部参数 `_skip_send_result_envelope` 跳过明文附加、由自身在加密后补挂避免重复（四语言对齐）

### 修复
- **refresh_token 失效自愈**：新增 `_refresh_failure_requires_relogin()` 判定（命中 `relogin_required` 或 `missing refresh_token` / `invalid_or_expired_refresh_token` / `refresh not supported`）与 `_clear_cached_tokens()`；刷新失败需重登时清空本地 `access_token`/`refresh_token`/`kite_token` 并持久化，`LifecycleController` 的 token 刷新循环捕获到需重登的 `AuthError` 时发布 `token.refresh_exhausted` 事件（带 `relogin_required: True`）、关闭 transport 触发重连，下次 `connect_session` 因无可用 token 自动走两步登录，解决 refresh_token 过期后客户端无限失败刷新无法自愈的问题；`_refresh_access_token` 补传 `aid`/`device_id`/`slot_id`/`access_token`/`sdk_lang`/`sdk_version` 并通过 `AuthError(data=result)` 透传服务端响应（四语言对齐）
- **protected_headers 类型归一**：新增 `_protected_headers_dict()`，V2 四个发送方法改用 `_protected_headers_from_params()` 取值再归一，修复传入 `ProtectedHeaders` 对象（非 dict）时 protected_headers 被丢弃的问题（四语言对齐）

### 优化
- **app_message_envelope 字段收窄**：`_APP_MESSAGE_ENVELOPE_KEYS` 移除 `message_id`/`seq`/`status`/`device_id`/`slot_id`/`delivery_mode`/`dispatch*` 等本地与传输层字段，新增 `context`/`protected_headers`/`headers`/`payload_type`，不再向应用层泄漏内部字段；`app_message_envelope` 改为类方法从多来源归一语义元数据，新增 `envelope_metadata()` 过滤 `_auth` 字段（四语言对齐）
- **RPC 日志 token 脱敏**：新增 `_redact_rpc_log_payload()` 与 `_SENSITIVE_RPC_LOG_KEYS`，`_short_rpc` 的请求/响应 debug 日志对 `access_token`/`refresh_token`/`kite_token`/`token` 及 `_token` 结尾键递归脱敏（`<redacted len=.. sha256=..>`），避免明文 token 落日志（四语言对齐）

### 测试
- `test_refresh_failure_clears_cached_tokens`：验证刷新失败后本地 token 被清空并持久化
- `test_connect_session_relogins_after_refresh_failure`：验证刷新失败后 `connect_session` 自动走重新登录
- `test_message_delivery_envelope_keeps_only_forwardable_metadata`：验证只保留可转发元数据且 `context`/`headers` 中的 `_auth` 被剔除
- 更新 `test_published_message_events_fallback_current_instance_context` 与撤回墓碑事件断言为收窄字段集

### 服务端协同（本版本配套）
- **`auth.refresh_token` 响应结构化**：新增 `relogin_required` / `retryable` / `diagnostic` / `aid` / `refresh_count` 字段，SDK 据 `relogin_required`/`retryable` 区分"重新登录"与"退避重试"，不再单纯按 `error` 字符串判断
- **auth token 存储升级为数据库主存储**：`DBAccessTokenStore`/`DBRefreshTokenStore` 优先，配置缺失自动降级 JSONL；旧数据迁移受 `KITE_AUTH_MIGRATE_LEGACY_JSONL` 控制
- **JWT 老 SDK 兼容与即时吊销**：`AUN_JWT_LEGACY_ACCESS_TOKEN_COMPAT`（默认开）放行合法 JWT 避免迁移期重连风暴；`auth.token.revoked` 事件携带 `jti`/`expires_at`，gateway 按真实 TTL 缓存吊销
- **V2 P2P 写入幂等**：`v2_write_peer_message`/`v2_write_peer_wrap` 捕获唯一键冲突逐字段比对，重发相同 message_id 幂等返回、不再产生 seq 空洞；自发自收跳过重复 self-sync 推送

---

## 0.4.12 — 2026-06-08

### 新功能
- **应用层事件信封（envelope）**：`message.*` 与 `group.changed` 事件发布给应用层时注入 `envelope` 字段，聚合 `message_id`/`seq`/`from`/`to`/`group_id`/`action` 等元数据；顶层别名字段在兼容期保留，计划于 `0.5.*` 移除，请改用 `envelope.*` 访问（四语言对齐）
- **撤回事件携带 message_id 与自身信封**：`message.recalled` / `group.message_recalled` 通知补全 `message_id` 字段并继承原消息的信封键，应用层可直接定位被撤回消息（四语言对齐）

### 修复
- **入群首个事件被旧序号阻塞**：自己入群（`member_added`/`joined`/`join_approved`/`invite_code_used`）后，若本地 `group_event` seq 基线为 0 而服务端首个 `event_seq>1`，将基线对齐到 `event_seq-1`，避免被入群前不可见事件挡住（四语言对齐）
- **过期 token 重连死循环**：重连前若缓存身份的 `access_token` 已失效，清空它以触发两阶段重新登录，避免反复用旧 token 触发 4001（四语言对齐）
- **Service Proxy 持久隧道重连**：新增指数退避（上限 60s，成功后重置）；认证类错误（`AuthError`）触发重新获取 access_token 后再重连，区别于普通错误（四语言对齐）
- **配额语义修正**：移除 `device → aid 数` 超限（`device_aids`）这一不存在的踢出场景，`4015` 仅覆盖 `aid_device_slot` / `aid_devices`

### 测试
- `TestReconnectTokenRefresh`：验证过期 token 重连前被清空、有效 token 被复用
- `test_group_changed_self_join_sets_visible_event_baseline`：验证入群事件基线对齐
- `test_group_changed_gap_fill_skips_permanent_hole_and_publishes_ordered`：验证永久空洞不阻塞后续群事件
- `test_service_proxy_serve_forever.py`：新增退避递增/成功重置/auth 错误重认证 4 个用例
- `integration_test_gateway_quota.py`：改为验证 `device_aids` 不再限流（`test_device_aids_not_quota_limited`）
- `integration_test_replay_guard.py` / `integration_test_signature.py` / `integration_test_storage.py` / `integration_test_service_proxy.py`：用例隔离与断言补强

---

## 0.4.11 — 2026-06-08

### 新功能
- **Storage 目录树与扩展操作**：`storage.*` 新增 `create_folder`/`rename_folder`/`move_folder`/`delete_folder`/`move_object`/`copy_object`/`batch_delete`/`set_object_meta`/`append_object` 等目录与对象操作，支持递归删除和 `dry_run` 模式（四语言+服务端对齐）
- **group.resources 树形资源系统**：新增 `create_folder`/`rename`/`move`/`mount_object`/`unmount`/`cleanup_by_storage_ref`/`request_mount_object`/`resolve_access_ticket` 等资源管理方法，支持挂载、卸载、跨域访问票据、冲突策略（`reject`/`replace`/`keep_both`）（四语言+服务端对齐）
- **group.changed 事件保序去重**：新增 `handle_group_changed_event()` 按 `group_event:{group_id}` namespace 保序消费，支持事件序号解析和空洞检测补拉；新增 `publish_ordered_queue_item()` / `publish_ordered_group_changed()` 路由有序事件发布（四语言对齐）
- **群解散本地清理**：新增 `_cleanup_dissolved_group()`，群解散后清理 V2 缓存、seq_tracker、有序队列和推送记录（四语言对齐）
- **SPK 上传失败回滚**：`delete_group_spk()` 支持上传失败时回滚本地新 SPK，避免本地/服务端 `spk_id` 不一致
- **群 SPK 注册并发保护**：`ensure_group_registered()` 新增 `_group_register_lock`，防止群 SPK 注册竞态
- **IK/SPK 缓存容量限制**：IK 公钥缓存改为 LRU 淘汰（上限 200），已验证 SPK 缓存上限 500；sender IK pending 队列限制 1000 条，超限淘汰最旧条目并告警

### 修复
- **群事件 ACK 命名空间**：`group.ack_events` 使用 `group_event:{group_id}` 而非 `group:{group_id}`（四语言对齐）
- **超时错误分类**：`code=-32004` + `"rpc handler timeout"` 前缀映射为 `TimeoutError`，支持重试（四语言对齐）
- **V2 sender IK 未解密重试**：改为保留队列中继续重试而非直接删除，同时发射 `undecryptable` 事件通知应用层（四语言对齐）
- **`_pushed_seqs` 初始化防护**：访问前检查属性存在性，避免连接初期空指针异常
- **`is_published_seq()` 空值处理**：属性不存在时返回 `False` 而非报错
- **storage/group.resources 签名和幂等性补全**：补全写操作方法进入签名集合与非幂等集合的检查

### 优化
- **群事件 gap 填充路径**：已填充事件通过 `_from_gap_fill` 标记避免二次补拉；群解散事件跳过持久化 cursor
- **错误日志细化**：SPK 旋转失败、V2 会话操作异常增加详细日志
- **Trace observer 过滤**：支持后台 RPC 与事件混合时按类型筛选目标事件

### 测试
- `test_group_changed_push_persists_and_acks_contiguous_event_seq`：验证事件 cursor 持久化和 ACK
- `test_group_changed_gap_fill_publishes_ordered_and_deduped_to_app`：验证补洞后保序去重
- `test_group_pull_events_acks_once_after_event_publish_final_contiguous`：修正 ACK 序号断言（4→3）
- 新增参数化测试验证 `storage.*` 和 `group.resources.*` 方法的签名与幂等性
- 新增 4 个群资源完整流程集成测试（树形结构、清理、卸载、冲突策略）和 3 个存储功能集成测试（目录树、对象移动/复制/批删、元数据）
- Trace E2E 测试改进事件等待机制（`wait_for` + `target_received Event`），解决时序竞态

---

## 0.4.10 — 2026-06-06

### 新功能
- **Service Proxy 服务代理**：新增 `service_proxy` 客户端模块（控制面 `proxy.register`/`unregister`/`list_services` + 数据面隧道），含 holder/visitor 工具与协议探测（四语言对齐）
- **notify() 单向通知**：新增 `notify()` 公开 API，发送无 id 的 JSON-RPC 2.0 Notification，只面向在线长连接、不落库、不分配 seq、无 ack（四语言对齐）
- **Storage 逻辑下载 URL**：支持干净逻辑下载 URL `storage.{issuer}/{user_name}/{object_key}`，无签名无 CAS，localfs 逻辑解析器 + CAS 物理缺失兜底校验

### 修复
- **群消息撤回（`group.message_recalled`）端到端打通**：新增在线 push 通道（`_raw.group.message_recalled`），与 pull 双 tombstone（占位 + 通知）兜底互补；push 路径推进 `notice_seq` 的 seq/ack 与普通群消息对齐，避免 seq 留洞导致重复拉取；按 `(group_id, message_ids)` 去重（去重键不含 `recalled_at`），确保应用层只回调一次；V2 pull 路径同样归一化撤回 tombstone（四语言+服务端对齐）
- `group.recall` 加入 RPC 白名单；`transport` 事件名映射补充 `group.message_recalled`

### 优化
- **ChangeSeed 健壮性增强**：key.json 重写改用递增版本备份（`.v1`/`.v2`…）替代单一 `.bak`，迁移失败时从版本备份回滚，成功后保留备份供审计；`LocalIdentityStore` 覆盖已有 key.json 前先做版本备份，写入统一走原子 tmp+rename（四语言对齐）

### 测试
- `e2e_test_group_e2ee.py` 补充群撤回收发端断言；`integration_test_storage.py` 补充逻辑下载 URL 用例

---

## 0.4.9 — 2026-06-03

### 修复
- V2 明文消息（P2P 和群组）投递时补充调用 `attach_gateway_proximity()`，消息事件 payload 现可携带 `proximity`（`same_network`/`same_device`/`basis`/`asserted_by`）字段（四语言对齐）

### 优化
- `AUNClient` 运行时状态全面迁移至 `ClientRuntime` 统一抽象层，生命周期、消息投递、RPC 路由、身份、V2 E2EE、群组状态各子组件构造函数统一接收 `runtime` 参数，消除组件间直接引用主客户端对象
- `LifecycleController`、`MessageDeliveryEngine`、`GroupStateCoordinator`、`IdentityRuntimeManager` 的状态读写全部改为通过 `runtime.*` setter/getter，提升可测试性
- `RpcPipeline` 接管原 `AUNClient.call()` 全部路由逻辑，主客户端 `call()` 直接委托

### 测试
- `test_client.py` 补充针对运行时抽象层重构后的单元测试覆盖

---

## 0.4.8 — 2026-06-03

### 新功能
- `_cert_utils.py` 新增 `normalize_fingerprint_hex`、`cert_fingerprint_hexes`、`cert_matches_fingerprint`、`public_key_matches_fingerprint`、`public_key_fingerprint` 指纹工具函数，支持 16 位短指纹、`sha256:` 前缀、冒号分隔等多种格式（四语言对齐）
- `build_agent_md_signature_block` 新增可选 `public_key_fingerprint` 字段写入签名块（四语言对齐）
- `aid.py` 签名时写入 `public_key_fingerprint`；验签返回结果携带该字段（四语言对齐）
- `_v2_sender_pub_der_from_cache_or_cert` 新增 `cert_fingerprint` 参数，缓存命中和 PKI 拉取后均做指纹比对（四语言对齐）
- `agent_md.py` `_resolve_peer` 新增 `cert_fingerprint` 参数，从签名块提取指纹后精确匹配对端 AID（四语言对齐）

### 修复
- `aid.py` 证书指纹比较改用 `cert_matches_fingerprint`，兼容短指纹和 SPKI 指纹（四语言对齐）
- `_fetch_peer_cert` 移除带指纹失败后降级无指纹请求的回退逻辑（四语言对齐）
- 带指纹的证书缓存只写入带指纹 key，无指纹时才写裸 key，防止旧证书污染新版本查询（四语言对齐）
- 证书缓存命中时增加指纹二次校验，避免裸缓存被错误复用于带指纹查询（四语言对齐）
- `AUNClient.__init__` 构建 `raw_config` 时补充 `verify_ssl`、`debug`、`root_ca_path` 字段透传，防止身份加载后配置丢失
- `_verify_event_signature` 证书指纹比对改用 `cert_matches_fingerprint`（四语言对齐）

### 优化
- `AUNClient` 大规模拆分重构：核心逻辑分散至 `LifecycleController`、`MessageDeliveryEngine`、`RpcPipeline`、`PeerDirectory`、`IdentityRuntimeManager`、`V2E2EECoordinator`、`GroupStateCoordinator` 子组件（四语言对齐）
- `AIDStore.__init__` 移除 `device_id` 参数，改为直接调用 `get_device_id`（四语言对齐）
- `config.py` 以 `get_device_id` 替换 `normalize_device_id`（四语言对齐）
- `aid_store.py` `resolve_peer` 回调支持按 `cert_fingerprint` 精确拉取对应版本证书（四语言对齐）

---

## 0.4.7 — 2026-06-01

### Added
- **`AIDStore.upload_agent_md(aid, content=None)`**：将 `upload_agent_md` 从 `AUNClient` 迁移到 `AIDStore`，支持指定任意本地 AID 上传 agent.md；内部独立创建 `LocalTokenStore` 和 `AuthFlow` 完成认证，不依赖 `AUNClient` 实例。
- **`UploadAgentMdResult` TypedDict**：新增上传结果类型（`aid`、`etag`、`last_modified`、`agent_md_url`）。

### Changed
- **`AUNClient.upload_agent_md()`**：移除，功能迁移至 `AIDStore.upload_agent_md(aid)`。
- **CLI `agentmd upload` 命令**：不再通过 `CLISession`（`AUNClient`）执行，改为直接调用 `AIDStore.upload_agent_md()`。
- **`sqlite_db.py`**：`slot_id_full` 列补齐逻辑提取为独立函数，供多处复用。

---

## 0.4.6 — 2026-06-01

### Added
- **`LocalIdentityStore` 类**（`keystore/local_identity_store.py`）：`KeyStore` Protocol 的文件系统 + SQLite 实现，支持私钥加密存储、证书管理、信任根管理、pending 原子注册。替代 `FileKeyStore`。
- **`LocalTokenStore` 类**（`keystore/local_token_store.py`）：`TokenStore` Protocol 的文件系统实现，不含私钥操作，供 `AuthFlow` / `AUNClient` 持有。
- **`AgentMdManager` 类**（`agent_md.py`）：独立的 agent.md 管理器，负责下载、验证、ETag 缓存、TTL 检查、签名验证，通过回调获取 token/gateway/AID，避免反向依赖 `AUNClient`。
- **`GatewayCertificateVerifier` 类**（`cert_verifier.py`）：独立的网关证书验证器，支持证书链缓存、CRL/OCSP 撤销检查、信任根管理。
- **`KeyStore` 接口新增方法**：`load_cert` / `save_cert`（证书管理）、`change_seed`（种子变更）、`trust_root_dir` / `save_trust_roots` / `save_issuer_root_cert`（信任根管理）。
- **`TokenStore` 接口新增方法**：`get_metadata_value` / `set_metadata_value`（元数据 KV 操作）。
- **`RegisterFlow` 新增公开方法**：`validate_aid_name`、`fetch_peer_cert`、`short_rpc`、`generate_identity`、`new_client_nonce`、`verify_phase1_response`、`reload_trusted_roots`。
- **`AuthFlow` 新增方法**：`cache_gateway_ca_chain` / `discard_gateway_ca_chain`（网关 CA 链缓存管理）。
- **`AIDStore` 新增方法**：`download_agent_md`（替代 `fetch_agent_md`）、`check_agent_md`（替代 `head_agent_md`）。
- **`AUNClient.upload_agent_md()`**：`content` 参数改为可选（`str | None = None`）。

### Changed
- **Keystore 架构重构**：`FileKeyStore` 拆分为 `LocalIdentityStore`（含私钥）和 `LocalTokenStore`（仅 token）；`__all__` 同步更新。
- **Agent.md 管理重构**：缓存、同步逻辑从 `AUNClient` / `AIDStore` 提取到 `AgentMdManager`；`AUNClient` 移除 `_agent_md_path`、`_local_agent_md_etag`、`_remote_agent_md_etag`、`_agent_md_cache` 等内部字段。
- **`AIDStore.fetch_agent_md()`** 重命名为 `download_agent_md()`，返回类型 `FetchAgentMdResult` 重命名为 `DownloadAgentMdResult`。
- **证书验证职责分离**：`AuthFlow` 中的证书验证逻辑提取到 `GatewayCertificateVerifier`；`RegisterFlow` 持有该实例。
- **`AID` 验证、短连接 RPC、身份生成**：从 `AuthFlow` 内部方法迁移到 `RegisterFlow` 公开方法，`AIDStore` 内部调用同步更新。

### Removed
- **`FileKeyStore` 类**：拆分为 `LocalIdentityStore` 和 `LocalTokenStore`，不再导出。
- **`AIDStore.head_agent_md()`**：功能并入 `check_agent_md()`。
- **`AIDStore._agent_md_url()`、`_agent_md_cache`**：由 `AgentMdManager` 接管。

---

## 0.4.5 — 2026-05-31

### Added
- **`RegisterFlow` 独立模块**（`register_flow.py`）：将 AID 注册流程从 `AuthFlow` 中剥离为独立类，负责 keypair 生成、服务端 RPC、pending 目录原子提交、崩溃恢复。
- **`KeyStore` 接口扩展**：新增 pending 目录操作协议（`pending_identity_dir` / `save_pending_key_pair` / `promote_pending_identity` / `discard_pending_identity` 等），支持注册原子性。
- **`FullKeyStore` 组合类型**：`TokenStore + KeyStore` 的组合 Protocol，供注册流程显式使用。

### Changed
- **`AuthFlow` 改用 `TokenStore`**：构造参数 `keystore` 重命名为 `token_store`，类型收窄为 `TokenStore`（不含私钥读写），私钥操作全部移出 `AuthFlow`。
- **`AuthFlow.set_identity()`**：新增方法，由 `AUNClient.load_identity` 注入内存私钥；`AuthFlow` 内部不再从 `token_store` 解密私钥。
- **`AIDStore.register()` 私钥写入职责转移**：注册结果由 `AIDStore` 负责调用 `keystore.save_cert` / `save_key_pair` 写入，`RegisterFlow` 不再直接写 key.json。

---

## 0.4.4 — 2026-05-31

### Added
- **`AID` 新增 `private_key_pem` 只读字段**：`AIDStore.load()` 加载时注入明文私钥，`AUNClient` 直接从 `AID` 读取，无需再经 keystore 解密。

### Changed
- **`AUNClient` 剥离私钥读写**：V2 session 初始化、`_sign_client_operation`、`propose_state` 签名均改从 `_current_aid.private_key_pem` 读取，删除 keystore fallback 重解密路径。
- **`auth._persist_identity` 不再写私钥**：写入前剥离 `private_key_pem` / `public_key_der_b64` / `curve`，AUNClient 的 keystore 只持久化 token / cert / instance_state，彻底避免用空 seed 覆盖写入 key.json。
- **`AUNClient` keystore 构造不再传 `encryption_seed`**：seed 作用域收窄至 AIDStore，不外漏。
- **SQLite 明文化清理**：删除 `_reveal_text` / `_protect_text` 等加密兼容残留代码，所有 SQLite 字段（prekey / group secret / session）直接明文读写。

---

## 0.4.3 — 2026-05-31

### Added
- **`normalize_slot_id` / `slot_isolation_key`**：新增 slot_id 校验与隔离键提取工具函数，支持 `/` `:` 空格作为分隔符（首字符不允许）。
- **`ConnectOptions` 新增字段**：`connection_kind`、`short_ttl_ms`、`extra_info`、`delivery_mode`、`background_sync`，与 Go / TS / JS SDK 对齐。

### Changed
- **`delivery_mode` 语义简化**：移除 `queue_routing` / `affinity_ttl_ms` 便捷字段，统一走 `delivery_mode` dict。
- **slot_id 隔离逻辑**：`connect` 时若目标 slot_id 隔离键与当前不同，自动拒绝跨 slot 连接。

---

## 0.4.2 — 2026-05-30

### Added
- **`AIDStore` 新增结构化返回类型**：`FetchAgentMdResult`、`HeadAgentMdResult`、`CheckAgentMdResult`、`DiagnoseResult`、`RenewCertResult`、`RekeyResult`、`ChangeSeedResult`、`ResolveResult`、`ListResult`（均为 `TypedDict`），替代原来的裸 `dict`。
- **`AUNClientOptions` 新增 `root_ca_path`**：支持私有部署指定自定义根证书路径。
- **`AUNClientOptions` 新增 `debug`**：可在构造时直接传入调试模式开关。

### Changed
- **移除 `discovery_port`**：`AUNClientOptions` 删除 `discovery_port` 字段，gateway URL 改为纯自动发现。
- **`fetch_agent_md` 透传 `verify_ssl` / `root_ca_path` / `debug`**：内部创建 `AIDStore` 时自动注入这三个配置项。

---

## 0.4.0 — 2026-05-30

> **破坏性重构版本。** 身份管理从 `AUNClient` 中剥离为独立的 `AID` / `AIDStore`；删除 `auth` / `custody` / `meta` 三个公开命名空间；引入统一的 `Result` 与字符串错误码；连接状态机扩展为 9 态。升级前请阅读 Breaking Changes。

### Breaking Changes
- **删除公开命名空间**：移除 `client.auth` / `client.custody` / `client.meta`。身份相关功能迁移到 `AIDStore` 与 `AID`，其余 RPC 走 `client.call()`。
- **构造函数签名变更**：`AUNClient.__init__(config)` → `AUNClient(aid: AID | None)`。身份先由 `AIDStore.load()` 离线加载，再传入 client。
- **`connect()` 签名变更**：移除 `auth` 参数，改为 `connect(options)`；身份与认证在 connect 之前完成。
- **连接状态枚举重命名**：`IDLE → NO_IDENTITY`、`CONNECTED → READY`、`TERMINAL_FAILED → CONNECTION_FAILED`，并区分内部状态 `_state` 与对外状态 `_public_state`。
- **目录约定变更**：`{aun_path}/AgentMDs/` → `{aun_path}/AIDs/`。

### Added
- **`AID` 值对象**（`aid.py`）：封装证书 + 可选私钥，提供 `sign` / `verify` / `sign_agent_md` / `verify_agent_md` / `is_cert_valid` / `is_private_key_valid`。
- **`AIDStore` 身份管理器**（`aid_store.py`）：离线 `load` / `list` / `exists`，联网 `register` / `resolve` / `fetch_agent_md` / `diagnose` / `renew_cert` / `rekey` / `change_seed`。
- **`Result[T]` / `ErrorInfo`**（`result.py`）：统一结果类型（`ok` / `data` 或 `error`）。
- **字符串错误码**（`error_codes.py`）：标准化常量（`CERT_NOT_FOUND`、`IDENTITY_CONFLICT`、`KEYPAIR_MISMATCH` 等），跨语言一致。
- **`client.authenticate()`**：完成两阶段认证并缓存 token，但不建立长连接。
- **`client.call()`**：统一 RPC 调用入口（替代已删除命名空间的方法）。
- **实例级 `protected_headers`**：`set_protected_headers()` 设置后自动合并到 `message.send` / `group.send` / `*.thought.put`，调用方显式传参优先。
- **对端 AID 缓存**：peer cache 减少重复 PKI 解析。
- **9 态连接状态机**：`NO_IDENTITY → STANDBY → AUTHENTICATED → CONNECTING → READY`，外加 `RETRY_BACKOFF` / `RECONNECTING` / `CONNECTION_FAILED` / `CLOSED`，重连状态可观测。

### Changed
- **CLI 适配**：`identity list/check/register` 改用 `AIDStore`；移除 `--gateway`（改为自动发现）；新增 `encryption_seed` 配置项。
- **WebSocket 连接超时**：新增 10s 连接超时；`verify_ssl=False` 时跳过 WSS 证书校验。
- **新增 `_cert_utils.py`**：抽取证书签名 / 验证 / 指纹等工具函数。

### Fixed
- **per-namespace 消息处理锁**：防止同一 namespace 并发处理导致的乱序。

### Removed
- 删除 `namespaces/auth_namespace.py`、`namespaces/custody_namespace.py`、`namespaces/meta_namespace.py`（合计约 1763 行）。

---

## 0.3.6 — 2026-05-28

### Added
- **Encrypted push 解密管线**：收到加密推送时即时尝试 V2 解密，成功则发 `message.received` / `group.message_created`（含明文 payload + e2ee 元数据），失败则发 `message.undecryptable` / `group.message_undecryptable`（含诊断字段 `_decrypt_error` / `_decrypt_stage` / `_envelope_type`）
- **`auth.fetch_peer_cert(gateway_url, aid)`**：公开 API 实现落地（v0.3.5 声明，v0.3.6 实现独立方法体）
- **`storage.get_limits` RPC**：查询上传限制和配额使用情况
- **`storage.check_upload` RPC**：上传预检（秒传检测 + 超限检测）

### Fixed
- **Identity cache 自愈**：V2 session init 时检测 `private_key_pem` 缺失，自动从 keystore 重新加载并清理脏 instance_state
- **`_load_identity` 字段白名单**：`load_identity` 只合并 `_INSTANCE_STATE_FIELDS` 定义的字段，防止 instance_state 表中的脏数据覆盖核心字段（如 `private_key_pem`）

### Changed
- **transport 诊断字段**：`_DIAG_PARAM_FIELDS` 新增 `force` 字段

---

## 0.3.5 — 2026-05-28

### Breaking Changes
- **`create_aid()` → `register_aid()`**：客户端 API 重命名，旧方法已移除（服务端 RPC 方法名 `auth.create_aid` 不变）
- **注册与认证分离**：`authenticate()` 不再隐式注册；身份不完整时直接抛 `StateError`，应用层必须先显式调 `register_aid()`

### Added
- **`IdentityConflictError`**：新增错误类型（继承 `AuthError`），AID 注册冲突时抛出（code 4090）
- **`auth.load_identity()`**：公开 API，只读加载本地已注册身份（密钥对 + 证书 + 实例状态），无副作用
- **`auth.load_identity_or_none()`**：同上，不存在时返回 None
- **`auth.fetch_peer_cert()`**：公开 API，获取对端 AID 证书 PEM（本地缓存优先，未命中走 PKI HTTP + 链验证）
- **Pull Gate**：per-key 序列化 pull 操作（`message.pull` / `group.pull` / `group.pull_events`），防止同一 namespace 并发 pull
- **RPC Inflight 限制**：transport 层全局最大 16 个并发 RPC + 后台 RPC 独立限制 8 个，排队超时抛 `TimeoutError`
- **`_assert_cert_matches_local_keypair`**：authenticate 前显式校验 cert 公钥与本地 keypair 一致

### Changed
- **`register_aid` 半成品恢复**：本地有 keypair 无 cert 时，查服务端恢复（而非拒绝）；服务端无记录则用现有 keypair 注册
- **agent.md 元数据存储**：从全局 `list.json` 改为 per-AID `agentmd.json`（与 TS/C++ 对齐）
- **agent.md 下载**：改为无条件 GET（移除 If-None-Match/If-Modified-Since）；304 时本地有缓存直接用，无缓存重试
- **`_load_identity_or_raise`**：增加 keypair 完整性检查（缺 private_key_pem 或 public_key_der_b64 直接抛错）
- **`ensure_authenticated`**：移除隐式创建逻辑，无 cert 直接抛 `StateError`
- **`.seed` fallback 迁移**：启动时检测旧 `.seed` 文件，自动迁移到 `seed_password` 派生方式；迁移失败时 fallback 到旧 seed 内容
- **`ChangeSeed` API**：支持运行时更换 seed（重加密所有私钥和 DB 加密字段）

### Removed
- **`_ensure_local_identity` / `_ensure_identity`**：已移除，注册路径不再隐式生成密钥

## 0.3.3 — 2026-05-25

### Added
- **V2 Thought 加解密**：`_decrypt_group_thoughts` / `_decrypt_message_thoughts` 支持 `group.thought.get` / `message.thought.get` 返回值自动解密；发送端 `message.thought.put` 自动加密
- **V2 Sender IK 延迟解密**：`_schedule_v2_sender_ik_pending` / `_schedule_v2_sender_ik_fetch` / `_resolve_v2_sender_ik_pending`，对端 IK 未缓存时挂起消息、异步拉取后重试解密
- **agent.md 本地缓存体系**：`set_agent_md_path` / `check_agent_md` / `publish_agent_md` / `fetch_agent_md`；基于文件系统的 list.json 索引 + 按 AID 存储内容 + etag 比对 + 自动拉取缺失
- **KeyStore agent_md_cache 持久化**：`FileKeyStore.load_agent_md_cache` / `upsert_agent_md_cache`；SQLite 版本同步支持
- **`auth.head_agent_md` handler**：仅获取对端 agent.md 元信息（etag/last_modified），不下载内容
- **`SeqTracker.update_max_seen` / `repair_contiguous_seq`**：支持 server_ack_seq 推进 retention floor
- **`GatewayDiscovery.discover_all`**：返回所有可用网关 URL 列表（多网关容灾）
- **DNS 容灾连接工厂**：`_make_connection_factory` 支持 `net` 参数注入 DNS 容灾层
- **V2 SPK 设备验签**：`_v2_verify_spk_device` 验证对端 SPK 签名合法性
- **签名跳过策略**：`_should_skip_client_signature` / `_should_skip_event_signature` 对内部方法和系统事件跳过签名
- **`_clamp_ack_params`**：message.ack seq 参数自动钳位，防止客户端发送超前 seq

### Changed
- **V2 消息处理路径重构**：`_decrypt_v2_message` 统一 P2P/Group 解密入口，支持 `allow_pending` 延迟解密模式
- **`_process_and_publish_message`**：增加 slot_id 传递、V2 envelope metadata 附加
- **CLI `aun_cli`**：group 子命令增强（create/join/leave/info/list/send/pull）、diag 子命令增强、config 支持多 profile 切换
- **session 默认选项**：新增 `background_sync: True`

### Fixed
- **service-plane envelope 解包**：修复 Kernel trace 字段传递丢失
- **trace 树状展示**：enter/exit 配对 + 嵌套缩进 + 按 ts 排序 + offset 时间轴

---

## 0.3.1 — 2026-05-22

### Added
- **CLI 工具 `aun_cli`**：基于 typer 的命令行工具，支持 identity（register / login / whoami / list）、message（send / pull）、group、diag 等子命令；TOML profile 配置；统一 table/json/dict/error 输出格式
- **RPC trace 增强**：`RPCTransport` 增加 `set_trace_mode()` / `set_trace_observer()`；client trace 树状展示按 ts 排序 + 嵌套缩进，enter span 携带业务字段、exit span 携带结果或失败上下文
- **`auth.check_aid` handler**：本地证书自检 + 远端注册状态查询
- **V2 群组 SPK 生命周期**：`V2KeyStore.{save,load,load_current}_group_spk`、`V2Session.ensure_group_spk` / `ensure_group_registered` / `rotate_group_spk` / `get_group_decrypt_keys` / `is_last_uploaded_group_spk`
- **`SeqTracker.has_pending_gaps(ns)`**：Pull 返回空时判断是否仍有 push 标记的上界，用于双重修复机制
- **AUNClient 群组 SPK 调度**：`_schedule_group_spk_registration` / `_schedule_group_spk_rotation` / `_schedule_group_spk_registration_after_peer_fallback`
- **消息载荷调试日志**：`_log_message_debug` / `_log_app_message_publish` / `_message_payload_for_debug` 等内部诊断辅助

### Changed
- **`AUNClient._publish_app_event`** 与消息发布路径重构，`_normalize_outbound_message_payload` 在发送前规范化 message params

### Fixed
- short RPC 请求/响应增加完整报文 debug 日志，便于跨语言诊断

---

## 0.3.0 — 2026-05-21 ⚠️ BREAKING CHANGE

> **V2-only 版本**：移除全部 V1 E2EE（含群组加密），新增 V2 加密原语，API 不向后兼容。

### BREAKING
- **移除 V1 E2EE 全部实现**：`GroupE2EEManager`、`e2ee_group.py`、epoch key 相关逻辑全部删除
- **移除 V1 群组加密测试**：`e2e_group_test`、`integration_epoch_key_server_test`、`integration_group_e2ee_test` 等
- **E2EE 接口简化**：`e2ee.py` 仅保留 V2 路径，V1 加解密方法不再可用
- **配置变更**：`AUNConfig` 移除 V1 相关配置项

### Added
- **agent.md 主 API**：`AUNClient.publish_agent_md(path)` 一键完成"读文件 → 签名 → 上传 → 刷新本地 etag"；`AUNClient.fetch_agent_md(aid=None, save_path=None)` 一键完成"下载 → 自动验签 → 可选写盘 → 刷新本地 etag（aid 是自己时）"
- **V2 加密原语**（跨语言 golden vector 一致性）：ECDH P-256、HKDF-SHA256、AES-256-GCM、ECDSA-SHA256 RAW、1DH/3DH wrap_key、Recipients Merkle、State Commitment

### Removed
- `AUNClient.set_local_agent_md_path()` / `get_local_agent_md_etag()` / `get_remote_agent_md_etag()` — 由主 API 自动维护

### Deprecated
- `client.auth.sign_agent_md` / `verify_agent_md` / `upload_agent_md` / `download_agent_md` — 建议迁移到 `client.publish_agent_md` / `client.fetch_agent_md`

---

## 0.2.20 — 2026-05-18

### Added
- **agent.md 版本一致性 API**：`AUNClient.set_local_agent_md_path(path)` / `get_local_agent_md_etag()` / `get_remote_agent_md_etag()`。SDK 自动从 RPC envelope `_meta.agent_md_etag` 提取服务端 etag，应用层订阅 `message.received` / `group.message_created` 等事件时 payload 多 `_agent_md.{local_etag, remote_etag}` 字段供版本比对。
- **`download_agent_md` 条件请求缓存**：内部维护 ETag/Last-Modified，未变化时返回上次缓存内容；外部 API 形态不变。
- **transport meta observer**：`RPCTransport.set_meta_observer(fn)` 透传 envelope `_meta`，observer 抛错被吞，不影响 RPC result。

### Changed
- **RPC call 默认超时 10s → 35s**：与服务端 30s handler timeout 对齐，留 5s buffer，避免短超时把慢路径误判为失败。
- **multi-device 架构**：对端无 prekey 时 `_send_encrypted` 直接抛错（`no registered device prekeys for ...`），不再降级到 `long_term_key`。无 prekey 的接收方需先连一次以上传 prekey。
- **Python `_publish_app_event`**：在 dict payload 上 `setdefault("_agent_md", ...)`，不覆盖业务已有同名字段。

### Fixed
- **Python `_process_and_publish_message` 缺失 `_t_start`**：P2P push 处理在某些路径下抛 `name '_t_start' is not defined`，导致 group/E2EE 测试间歇失败。
- **测试环境 dedup 标记泄漏**：跨域 `message.send` 走 dedup 后若中间步骤抛错（如 self_copies 落库失败），dedup 标记泄漏，重试同 message_id 拿到 `{status: "duplicate", result: None}` 假成功。改为 try/finally 保证 record_result 或 dedup_remove 必有其一。

### Docs
- 仓库根 `docs/`（agent.md 规范、protocol、SDK 手册）随 wheel 打包到 `aun_core/_packed_docs/`，pip 安装后可读。`.gitignore` 排除项（如内部测试指南）不进包。

---
