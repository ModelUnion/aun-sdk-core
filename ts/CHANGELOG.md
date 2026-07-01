# Changelog

本文件记录 `@agentunion/fastaun` (Node.js) SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

---

## 0.5.1 — 2026-07-01

### ⚠️ 重大变更（Breaking Changes）

#### 群组标识符统一为 GROUP_AID
- **GROUP_ID 废弃**：历史 `group.{domain}/{base}` 格式已废弃，统一为 `{base}.{issuer}` 格式（group_aid）
- **兼容转换**：`normalizeGroupId()` 函数保留向后兼容，自动转换旧格式到新格式
- **新增函数**：`convertToGroupAid()` 显式转换任意历史格式到标准 group_aid
- **RPC 参数**：`group_id` 字段名保留但值为 group_aid；新增 `group_aid` 参数与 `group_id` 等价
- **影响范围**：所有群组相关 API（`group.send` / `group.pull` / `group.fs.*` 等）

#### 移除 V1 E2EE 实现
- **完全移除**：删除所有 V1 端到端加密代码（epoch key、群组加密管理器、V1 群组加密）
- **仅保留 V2**：E2EE 功能完全迁移到 V2 协议（消息级密钥 + 逐设备 wrap + 状态签名）
- **简化接口**：V2 E2EE 协调器大幅重构，移除 V1 兼容层
- **注意**：此版本不向后兼容 V1 加密消息

### 新功能

#### Storage & Group FS 能力扩展
- **Storage VFS P4**：新增 `touch()` 方法，支持创建空文件或更新文件时间戳
- **Storage VFS P4**：新增 `du()` 方法，支持查询目录或文件的磁盘使用统计
- **Storage VFS P6**：扩展 `getAcl()` / `listAcl()` 方法，支持 ACL 权限查询
- **Group FS**：新增 `getAcl()` / `listAcl()` / `removeAcl()` 方法，完善群文件 ACL 管理
- **Storage LowLevel**：补齐底层 RPC 映射，覆盖 `storage.fs.*` / `storage.object.*` 完整能力

#### 本地文件路径支持（Node.js 环境）
- **Group FS `cp()`**：收敛到 Python/Go 的本地文件路径语义，支持 `local:` 前缀 + Windows 盘符识别
- **Storage VFS 上传/下载**：Node.js 环境支持本地文件路径参数，与 Python/Go SDK 行为对齐

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
- Validators：新增跨语言 `validatePath()` / `validateAid()` 等校验函数，四语言行为对齐

### 测试

- 新增 `storage-vfs-p5.test.ts` 单元测试扩展（`touch` / `du`）
- 新增 `group-fs.test.ts` 集成测试（ACL 操作）
- 扩展 cross-sdk-agent 支持 `group.fs` / `storage.fs` 新增能力

---

## 0.5.0 — 2026-06-17

### 新功能

#### Storage 子协议（重大新增）
- **Storage VFS（虚拟文件系统）**：新增 `StorageVFS` 类，支持 P1-P6 全栈能力
  - P1: `putObject` / `getObject` / `deleteObject` / `listObjects` / `headObject`
  - P2: `createFolder` / `renameFolder` / `moveFolder` / `deleteFolder` / `moveObject` / `copyObject` / `batchDelete`
  - P3: `setObjectMeta` / `appendObject`
  - P4: `mount` / `unmount` / `stat` / `list` / `find`
  - P5: `copy` / `rename` / `remove` / `createSymlink` / `deleteSymlink` / `renameSymlink` / `readlink` / `atomicRepoint`
  - P6: `setAcl` / `removeAcl` / `listAcl` / `checkAccess` / `issueToken` / `revokeToken` / `listTokens` / `createVolume` / `renewVolume` / `expireDueVolume` / `setVisibility`
- **Storage LowLevel（底层存储）**：新增 `StorageLowLevel` 类，提供对象级存储操作
- **Group FS（`group.fs` POSIX 群文件系统）**：新增 `GroupFSVFS` 类，通过 `client.group.fs` 暴露群共享文件系统门面，替代 0.4.x 草案中的 `group.resources`
  - POSIX 控制面：`ls` / `find` / `stat` / `lstat` / `mkdir` / `rm` / `cp` / `mv` / `df` / `mount` / `umount`
  - `cp` 支持三种路径组合：本地 → 群文件、群文件 → 本地、群文件 → 群文件；本地路径支持 `local:` 前缀，Windows 盘符不会被误判为远程路径
  - 上传数据面：`group.fs.check_upload` / `create_upload_session` / `complete_upload` + HTTP PUT，支持秒传、dedup、`force` 覆盖和 sha256 校验
  - 下载数据面：`group.fs.create_download_ticket` + HTTP GET，自动携带 Bearer token，下载后校验 sha256，默认拒绝覆盖本地文件
  - 群自有区写身份：写操作支持 `signAs` / `aidStore`，SDK 本地加载 `group_aid` 私钥注入 `client_signature`，不会把签名身份参数透传给服务端
  - Cross-SDK agent 新增 `group.fs` 调用入口，用于跨 SDK 一致性测试

#### Collab 协作编辑子协议（重大新增）
- **CollabClient**：新增协作编辑客户端，支持多人实时文档协作
  - Diff3 三路合并算法（`diff3Merge`）
  - 快照管理（`createSnapshot` / `listSnapshots` / `getSnapshot` / `restoreSnapshot`）
  - 标签管理（`createTag` / `listTags` / `getTag` / `restoreTag`）
  - 群组权限验证和冲突解决
- **CollabError / CollabConflictError**：新增协作编辑专用异常类型

#### Facade 架构（API 重构）
- **AUNClient Facade 属性**：新增统一的子系统访问入口
  - `client.storage` → `StorageVFS` 实例
  - `client.message` → `MessageFacade` 实例
  - `client.group` → `GroupFacade` 实例（含 `client.group.fs`）
  - `client.stream` → `StreamFacade` 实例
  - `client.collab` → `CollabClient` 实例
- **GroupFacade / MessageFacade / StreamFacade / ThoughtFacade**：新增 facade 类封装高级操作，简化常用场景

### 架构变更

#### 身份管理职责剥离（重大重构）
- **AID 持私钥**：`AID` 类现在直接持有明文私钥（`privateKeyPem`），不再依赖外部密钥管理
- **AIDStore 简化**：`AIDStore` 职责收窄为纯存储层，移除加密/签名等密码学操作
- **AUNClient 职责清晰化**：`AUNClient` 专注连接和消息传输，不再承担身份管理职责
- **导入群组身份**：新增 `importGroupIdentity()` 支持群组身份导入和迁移

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
- Storage VFS P1-P6 层级单元测试
- Storage LowLevel 单元测试
- Group FS VFS 单元测试（`tests/unit/group-fs-vfs.test.ts`）
- Collab Client 单元测试
- Collab Diff3 单元测试
- Facades 单元测试
- AIDStore 重构测试

#### 集成/E2E 测试
- Storage 集成测试
- Collab 集成测试
- Storage VFS 集成测试

### 文档

- 更新索引和导航文档
- 新增 Storage/Group FS/Collab RPC 手册
- 更新群组方法文档
- 新增示例代码

### 依赖

- 保持现有依赖版本不变

---

## 0.4.13 — 2026-06-09

### 新功能
- **发送结果回填 envelope**：`message.send` / `group.send` / `message.thought.put` / `group.thought.put` 的返回结果新增规范化 `envelope` 字段，使发送方回执与接收端信封元数据一致；新增 `APP_SEND_ENVELOPE_METHODS` 与 `sendResultEnvelope()` / `attachSendResultEnvelope()`，rpc-pipeline 在 `postprocess` 后统一附加，V2 加密路径经 `_skipSendResultEnvelope` 标志跳过明文附加、由外层 V2 协调器在加密后补挂避免重复（四语言对齐）

### 修复
- **refresh_token 失效自愈**：新增需重登判定（命中 `relogin_required` 或 `missing refresh_token` / `invalid_or_expired_refresh_token` / `refresh not supported`）与清缓存逻辑；刷新失败需重登时清空本地 `access_token`/`refresh_token`/`kite_token` 并持久化，client 层 token 刷新循环检测到需重登时发布 `token.refresh_exhausted` 事件（带 `relogin_required: true`）、断连触发重连，下次 `connectSession` 因无可用 token 自动走两步登录；refresh RPC 补传 `aid`/`device_id`/`slot_id`/`access_token`/`sdk_lang`/`sdk_version`，`AuthError` 携带 `data` 透传服务端响应（四语言对齐）
- **重连状态位修复**：断连分支补齐 `_reconnectActive = false`，token 循环中 `publish`/`_handleTransportDisconnect` 改为 `await`，避免重连标志残留导致后续重连被跳过
- **protected_headers 类型归一**：V2 发送方法的 envelope 元数据归一时识别 `ProtectedHeaders` 对象（经 `toObject()` 探测）并转 dict，修复传入对象（非 dict）时 protected_headers 被丢弃的问题（四语言对齐）

### 优化
- **app_message_envelope 字段收窄**：envelope 键收窄为可转发元数据（`from`/`to`/`group_id`/`type`/`kind`/`version`/`timestamp`/`encrypted`/`context`/`protected_headers`/`payload_type`），移除 `message_id`/`seq`/`device_id`/`slot_id` 等本地与传输层字段，不再向应用层泄漏内部字段并剔除 `_auth`（四语言对齐）
- **RPC 日志 token 脱敏**：短 RPC 请求/响应 debug 日志对 `access_token`/`refresh_token`/`kite_token`/`token` 及 `_token` 结尾键递归脱敏（`<redacted len=.. sha256=..>`），避免明文 token 落日志（四语言对齐）

### 测试
- `refresh 业务失败且要求重登时应清掉本地 token 缓存`
- `connectSession 在 refresh 失败后应继续走两步登录`
- `应用层消息 envelope 只保留可转发字段并归一化 headers`
- 更新 `publishAppEvent` 与群撤回相关用例断言 envelope 收窄、不含 `message_id`/`seq`/`device_id`/`slot_id`

### 服务端协同（本版本配套）
- **`auth.refresh_token` 响应结构化**：新增 `relogin_required` / `retryable` / `diagnostic` / `aid` / `refresh_count` 字段，SDK 据 `relogin_required`/`retryable` 区分"重新登录"与"退避重试"，不再单纯按 `error` 字符串判断
- **JWT 老 SDK 兼容与即时吊销**：`AUN_JWT_LEGACY_ACCESS_TOKEN_COMPAT`（默认开）放行合法 JWT 避免迁移期重连风暴；`auth.token.revoked` 事件携带 `jti`/`expires_at`，gateway 按真实 TTL 缓存吊销
- **V2 P2P 写入幂等**：服务端 `v2_write_peer_message`/`v2_write_peer_wrap` 捕获唯一键冲突逐字段比对，重发相同 message_id 幂等返回、不再产生 seq 空洞；自发自收跳过重复 self-sync 推送

---

## 0.4.12 — 2026-06-08

### 新功能
- **应用层事件信封（envelope）**：`message.*` 与 `group.changed` 事件发布给应用层时注入 `envelope` 字段，聚合 `message_id`/`seq`/`from`/`to`/`group_id`/`action` 等元数据；顶层别名字段在兼容期保留，计划于 `0.5.*` 移除，请改用 `envelope.*` 访问（四语言对齐）
- **撤回事件携带 message_id 与自身信封**：`message.recalled` / `group.message_recalled` 通知补全 `message_id` 字段并继承原消息的信封键（四语言对齐）

### 修复
- **入群首个事件被旧序号阻塞**：`isSelfJoinGroupChanged` 识别自己入群后，将本地 `group_event` seq 基线对齐到 `eventSeq-1`，避免被入群前不可见事件挡住（四语言对齐）
- **群事件补洞使用服务端 cursor**：`group.pull_events` 补洞时取 `retention_floor` 与 `cursor.current_seq` 的较大值推进本地 tracker，避免本地落后于服务端游标
- **过期 token 重连死循环**：重连前同步 `_identity` 中的 token 状态到 `_sessionParams`，过期或缺失则清空以触发两阶段重新登录，避免反复用旧 token 触发 4001（四语言对齐）
- **Service Proxy 持久隧道重连**：新增指数退避（上限 60s，成功后重置）；`AuthError` 触发 `_authenticateForAccessToken` 重新登录后再重连（四语言对齐）
- **protected_headers 参数兼容**：`mergeInstanceProtectedHeaders` 同时识别 `protected_headers` 与 `headers` 别名

### 测试
- `group.pull_events 补洞应使用服务端 cursor.current_seq 推进本地 tracker`
- `自己入群首个 event_seq>1 不应被入群前不可见事件阻塞`
- `pull 缺失中间 event_seq 时视为永久空洞，不阻塞已拿到的群事件发布`
- `publishAppEvent 为群事件注入 envelope 并保留顶层兼容字段`
- `撤回事件发布给应用层时带撤回通知自身 envelope`

---

## 0.4.11 — 2026-06-08

### 新功能
- **Storage 目录树与扩展操作**：`storage.*` 新增 16 个目录/对象操作方法，加入签名集合和非幂等集合（四语言+服务端对齐）
- **group.resources 树形资源系统**：新增 `create_folder`/`rename`/`move`/`mount_object`/`unmount`/`cleanup_by_storage_ref`/`request_mount_object`/`resolve_access_ticket` 等方法，加入签名和非幂等集合；支持跨域访问票据（四语言+服务端对齐）
- **V2 会话初始化并发锁**：新增初始化 Promise 锁，防止并发多次初始化导致重复操作
- **group.changed 事件保序去重**：`handleGroupChangedEventSeq` 重构，支持有序队列项发布、gap 补洞后保序、自动 ack（四语言对齐）

### 修复
- **重连竞态**：进入重连前原子化设置 `_reconnectActive` 标志，避免 await 期间并发重连
- **重连 sleep 可取消**：监听 `_reconnectAbort` 信号提前中断延迟等待
- **群解散清理**：将清理操作移入交付引擎有序处理流程，添加 `group_event` 命名空间清理（四语言对齐）
- **SPK 过期时间计算**：`Date.now() / 1000` 改为 `Date.now()`（毫秒单位修正）
- **重复 ack 事件**：`group.changed` push 已有序号时跳过；补洞事件进入有序队列而非直接发布
- **V2 E2EE bootstrap 缓存**：避免不必要的重复写入
- **`group.thought.put` 错误类型**：改为 `ValidationError` 并补充 `group_id` 验证
- **storage/group.resources 签名和幂等性补全**：补全写操作方法进入签名集合与非幂等集合（四语言对齐）

### 优化
- **群事件 gap 填充路径**：已填充事件进入有序队列而非直接发布；群解散事件跳过持久化
- **公共发布方法**：提取 `publishOrderedQueueItem` / `publishOrderedGroupChanged`，统一有序事件处理路径
- **联邦消息测试**：使用事件订阅替代轮询拉取，减少测试延迟

### 测试
- 新增群资源跨域树形访问集成测试（创建目录、挂载对象、重命名、跨域访问）
- 新增群资源跨域申请清理边界集成测试（挂载申请、批量清理、卸载）
- 新增签名方法覆盖测试，验证 `storage.*` 和 `group.resources.*` 进入签名和非幂等长超时集合
- 新增有序事件去重测试，验证高序号 push 先到时补洞后 SDK 内部和应用层消费顺序
- 修复 `fillGroupEventGap` 单元测试预期行为（进入有序队列而非直接标记已交付）

---

## 0.4.10 — 2026-06-06

### 新功能
- **Service Proxy 服务代理**：新增 `service-proxy.ts` 客户端（控制面 `proxy.register`/`unregister`/`list_services` + 数据面隧道）及 `tools/service-proxy-holder.mjs`、`tools/service-proxy-visitor.mjs` 工具（四语言对齐）
- **notify() 单向通知**：新增 `notify()` 公开 API，发送无 id 的 JSON-RPC 2.0 Notification，只面向在线长连接、不落库、不分配 seq、无 ack（四语言对齐）
- **Storage 逻辑下载 URL**：支持干净逻辑下载 URL `storage.{issuer}/{user_name}/{object_key}`，无签名无 CAS

### 修复
- **群消息撤回（`group.message_recalled`）端到端打通**：新增在线 push 通道（`_raw.group.message_recalled`），与 pull 双 tombstone（占位 + 通知）兜底互补；push 路径推进 `notice_seq` 的 seq/ack 与普通群消息对齐，避免 seq 留洞导致重复拉取；按 `(group_id, message_ids)` 去重（去重键不含 `recalled_at`），确保应用层只回调一次（四语言+服务端对齐）
- `group.recall` 加入 RPC 白名单；`transport` 事件名映射补充 `group.message_recalled`

### 优化
- **ChangeSeed 健壮性增强**：`changeSeedBytes` 覆盖 key.json 前先做递增版本备份（`.v1`/`.v2`…），写入改用 `writeKeyJsonAtomic`（tmp+rename）；`LocalIdentityStore` 覆盖已有 key.json 前同样做版本备份（四语言对齐）

### 测试
- `tests/e2e/notify.test.ts`/`tests/integration/notify.test.ts`/`federation-notify.test.ts` 覆盖 notify；`service-proxy` 系列单元+集成+E2E 测试；`tests/unit/keystore.test.ts` 补充版本备份断言

---

## 0.4.9 — 2026-06-03

### 修复
- V2 明文消息（P2P 和群组）投递时补充调用 `attachGatewayProximity()`，消息事件 payload 现可携带 `proximity`（`same_network`/`same_device`/`basis`/`asserted_by`）字段（四语言对齐）

### 优化
- `AUNClient` 运行时状态全面迁移至 `ClientRuntime` 统一抽象层，生命周期、消息投递、RPC 路由、身份、V2 E2EE、群组状态各子组件构造函数统一接收 `runtime` 参数，消除组件间直接引用主客户端对象
- `LifecycleController`、`MessageDeliveryEngine`、`GroupStateCoordinator`、`IdentityRuntimeManager` 的状态读写全部改为通过 `runtime.*` setter/getter，提升可测试性
- `RpcPipeline` 接管原 `AUNClient.call()` 全部路由逻辑，主客户端 `call()` 直接委托
- `ConnectionOptions` 新增 `retry` 配置项，支持自定义重连策略

### 测试
- 补充针对运行时抽象层重构后的单元测试覆盖（`slot-id-separator`、`group-event-ack`、重连场景）

---

## 0.4.8 — 2026-06-03

### 新功能
- `cert-utils.ts` 新增 `publicKeyFingerprint`、`certMatchesFingerprint`、`publicKeyMatchesFingerprint`、`normalizeFingerprintHex` 工具函数，支持 DER/SPKI 双格式及 16/64 位短格式（四语言对齐）
- agent.md 签名块新增 `public_key_fingerprint` 可选字段，签名时自动附加 SPKI 指纹验证时同时校验（四语言对齐）
- `peerResolver` 接口新增 `certFingerprint` 参数，`AgentMdManager._resolvePeer` 从签名块提取指纹后传入（四语言对齐）
- `AIDStore.peerResolver` 改造：按指纹优先从 keystore 加载缓存；有指纹时从 PKI 精确拉取并缓存（四语言对齐）
- `pkiCertUrl` 新增 `certFingerprint` 参数（四语言对齐）
- 新增 `_v2SessionMatchesIdentity` / `_resetV2IdentityRuntime`，V2 session 校验升级为身份匹配（四语言对齐）
- 新增在线未读 hint 队列（`_onlineUnreadHintQueue`），同 group 去重 + 延迟 drain（四语言对齐）
- `_getV2SenderPubDer` 新增 `certFingerprint` 参数，解密时精确锁定发送方证书（四语言对齐）

### 修复
- `AIDStore` 构造函数移除 `deviceId` 可选参数，统一使用 `getDeviceId(aunPath)` 读取（四语言对齐）
- `_applyAidRuntimeContext` 切换 AID 时新增旧 transport 清理并调用 `_resetV2IdentityRuntime`，防止 V2 session 残留（四语言对齐）
- `_fetchPeerCert` 移除带指纹失败后的降级无指纹兜底请求（四语言对齐）
- cert 缓存只在无 `certFingerprint` 时写裸 key，避免缓存污染（四语言对齐）
- 指纹验证统一改用 `certMatchesFingerprint`（四语言对齐）
- 解密结果新增 `attachGatewayProximity`，透传 `proximity`/`same_device`/`same_network`/`same_egress_ip` 字段（四语言对齐）

### 优化
- `AUNClient` 大规模拆分重构：client.ts 变为薄壳委托层，核心逻辑分散至 `client/` 子目录的 `ClientRuntime`、`LifecycleController`、`RpcPipeline`、`MessageDeliveryEngine`、`V2E2EECoordinator`、`GroupStateCoordinator`、`PeerDirectory`、`IdentityRuntimeManager` 子模块（四语言对齐）

---

## 0.4.7 — 2026-06-01

### Added
- **`AIDStore.uploadAgentMd(aid, content?)`**：将 `uploadAgentMd` 从 `AUNClient` 迁移到 `AIDStore`，支持指定任意本地 AID 上传 agent.md；内部独立创建 `LocalTokenStore` 和 `AuthFlow` 完成认证，不依赖 `AUNClient` 实例。
- **`UploadAgentMdResult` 类型**：新增上传结果类型导出。

### Changed
- **`AUNClient.uploadAgentMd()`**：移除，功能迁移至 `AIDStore.uploadAgentMd(aid)`。
- **`AIDStore`**：新增内部 `_tokenStore`（`LocalTokenStore`）和 `_crypto`（`CryptoProvider`）字段，供 upload 认证流程使用。
- **`aid-db.ts`**：`slot_id_full` 列补齐逻辑提取为 `_ensureSlotIdFullColumns()` 私有方法，供多处复用。

---

## 0.4.6 — 2026-06-01

### Added
- **`LocalIdentityStore` 类**（`keystore/local-identity-store.ts`）：基于文件系统 + SQLite 的 `KeyStore` 实现，支持私钥加密存储、证书管理、pending 身份崩溃恢复、信任根管理。替代 `FileKeyStore`。
- **`LocalTokenStore` 类**（`keystore/local-token-store.ts`）：基于 SQLite 的 `TokenStore` 实现，不含私钥操作，支持证书管理、实例状态、seq 跟踪、E2EE prekey/session/群组密钥存储。
- **`AgentMdManager` 类**（`agent-md.ts`）：独立的 agent.md 管理器，支持并发下载控制、ETag 缓存、本地/远程同步状态追踪、内容签名验证。
- **`KeyStore` 接口新增方法**：`loadCert(aid, certFingerprint?)` / `saveCert(aid, certPem, certFingerprint?, opts?)`。
- **`RegisterFlow` 新增公开方法**：`validateAidName`、`fetchPeerCert`、`shortRpc`、`generateIdentity`、`newClientNonce`、`verifyPhase1Response`。
- **`AIDStore` 新增方法**：`downloadAgentMd`（替代 `fetchAgentMd`）、`checkAgentMd`（替代 `headAgentMd`）。
- **`AUNClient.uploadAgentMd()`**：新增方法，签名并上传当前 AID 的 agent.md。
- **导出新增**：`LocalIdentityStore`、`LocalTokenStore`、`TokenStore` 接口。

### Changed
- **`AIDStore`**：内部存储从 `FileKeyStore` 改为 `LocalIdentityStore`；证书获取和续签/重钥流程改为调用 `RegisterFlow` 公开方法。
- **`AUNClient` 架构**：移除 agent.md 内部字段（`_agentMdPath`、`_agentMdCache` 等），改由 `AgentMdManager` 统一管理；新增 `createAgentMdManagerForRuntime()` 工厂函数。
- **`AIDStore.fetchAgentMd()`** 重命名为 `downloadAgentMd()`，返回类型更新为 `DownloadAgentMdResult`。
- **`RegisterFlow` 类型签名**：`PendingKeyStore` 从 `FullKeyStore & {...}` 改为 `KeyStore & {...}`。

### Removed
- **`FileKeyStore` 类**（`keystore/file.ts`）：完整移除，功能分解为 `LocalIdentityStore` 和 `LocalTokenStore`。
- **`FullKeyStore` 类型别名**：不再需要。
- **`AIDStore.headAgentMd()`**：功能整合到 `AgentMdManager`。
- **`AUNClient` 中的 agent.md 内部方法**：`_saveAgentMdRecord`、`_observeAgentMdMeta`、`_observeAgentMdEtag` 等。

---

## 0.4.5 — 2026-05-31

### Added
- **`RegisterFlow` 独立类**（`register-flow.ts`）：将 AID 注册流程从 `AuthFlow` 中剥离，负责 keypair 生成、服务端 RPC、pending 目录原子提交、崩溃恢复。
- **`FileKeyStore` pending 目录 API**：`pendingIdentityDir` / `savePendingKeyPair` / `loadPendingKeyPair` / `savePendingCert` / `promotePendingIdentity` / `discardPendingIdentity`，支持注册原子性。
- **`TokenStore` 接口**：从 `KeyStore` 中拆分出不含私钥操作的子接口，供 `AuthFlow` 使用。

### Changed
- **`AuthFlow` 改用 `TokenStore`**：构造参数 `keystore` 重命名为 `tokenStore`，类型收窄为 `TokenStore`；私钥操作全部移出 `AuthFlow`。
- **`AuthFlow.setIdentity()`**：新增方法，由 `AUNClient` 注入内存私钥；`AuthFlow` 内部不再从 `tokenStore` 解密私钥。
- **`AIDStore.register()` 私钥写入职责转移**：注册结果由 `AIDStore` 负责调用 `keystore.saveCert` / `saveKeyPair` 写入。
- **`AIDStore.load()` 错误处理**：`loadKeyPair` 失败时捕获异常并返回 `resultErr`，不再抛出。

---

## 0.4.4 — 2026-05-31

### Added
- **`AID` 新增 `privateKeyPem` 只读字段**：`AIDStore.load()` 加载时注入明文私钥，`AUNClient` 直接从 `AID` 读取，无需再经 keystore 解密。

### Changed
- **`AUNClient` 剥离私钥读写**：V2 session 初始化、`_signClientOperation`、propose_state 签名均改从 `_currentAid.privateKeyPem` 读取，删除 keystore fallback 重解密路径。
- **`auth._persistIdentity` 不再写私钥**：写入前剥离 `private_key_pem` / `public_key_der_b64` / `curve`，AUNClient 的 keystore 只持久化 token / cert / instance_state。
- **`AUNClient` keystore 构造不再传 `encryptionSeed`**：seed 作用域收窄至 AIDStore，不外漏。
- **SQLite 明文化清理**：删除 `_protectText` / `_revealText` 等加密兼容残留，所有 SQLite 字段直接明文读写。

---

## 0.4.3 — 2026-05-31

### Added
- **`normalizeSlotId` / `slotIsolationKey`**：新增 slot_id 校验与隔离键提取工具函数，支持 `/` `:` 空格作为分隔符（首字符不允许）。
- **keystore schema 迁移至 v2**：`instance_state` / `seq_tracker` 表新增 `slot_id_full` 列，保存完整 slot_id（隔离键仅用于索引）；首次启动自动 `ALTER TABLE` 升级。

### Changed
- **slot_id 存储策略**：keystore 读写统一使用 `slotIsolationKey` 作为索引键，`slot_id_full` 保存原始完整值，与 Python / Go SDK 对齐。
- **`AUNClient` 构造**：传入 `aid` 参数时增加类型守卫（检查 `aunPath` 字段与 `isPrivateKeyValid` 方法），避免误传非 AID 对象。

---

## 0.4.2 — 2026-05-30

### Added
- **`AIDStore` 新增具名返回类型**：`ResolveResult`、`FetchAgentMdResult`、`HeadAgentMdResult`、`CheckAgentMdResult`、`DiagnoseResult`、`RenewCertResult`、`RekeyResult`、`ChangeSeedResult`、`ListResult`，替代原来的 `Record<string, unknown>`。
- **`AID` 新增 `verifySsl` 只读字段**：创建时由 `AIDStore` 注入，供内部 HTTP 请求使用。
- **`AUNClientOptions` 新增 `rootCaPath` / `debug`**：支持私有部署自定义根证书路径，以及构造时直接传入调试开关。

### Changed
- **移除 `discoveryPort`**：`AIDStore` 构造选项删除 `discoveryPort`，gateway URL 改为纯自动发现。
- **`fetchAgentMd` 新增 `timeoutMs` 参数**（默认 30000ms），`resolve` 内部调用时透传 `opts.timeout`（默认 10000ms）。
- **返回字段精简**：`fetchAgentMd` / `headAgentMd` / `checkAgentMd` / `diagnose` 移除冗余的 camelCase 别名字段，统一使用 snake_case。
- **`resolve` 返回 `source` 字段精简**：移除 `certFromCache` / `agentMdFetched` camelCase 别名，只保留 `cert_from_cache` / `agent_md_fetched`。
- **`AID._create` 透传 `verifySsl` / `rootCaPath` / `debug`**：`AIDStore` 在 `load` / `resolve` 时自动注入这三个配置项到 `AID` 实例。

---

## 0.4.0 — 2026-05-30

> **破坏性重构版本。** 与 Python SDK 0.4.0 对齐：身份管理剥离为 `AID` / `AIDStore`；删除 `auth` / `custody` / `meta` 公开命名空间；引入 `Result` 与字符串错误码；连接状态机扩展为 9 态。

### Breaking Changes
- **删除公开命名空间**：移除 `client.auth` / `client.custody` / `client.meta`。身份相关功能迁移到 `AIDStore` 与 `AID`，其余 RPC 走 `client.call()`。
- **构造函数签名变更**：`constructor(config?, debug?)` → `constructor(aid?: AID, options?: AUNClientOptions)`；移除 `debug` 布尔参数。
- **初始连接状态变更**：`'idle'` → `'no_identity'`。
- **目录约定变更**：`{aun_path}/AgentMDs/` → `{aun_path}/AIDs/`。

### Added
- **`AID` 类**：封装证书 + 可选私钥，提供 `sign` / `verify` / `signAgentMd` / `verifyAgentMd` / `isCertValid` / `isPrivateKeyValid`。
- **`AIDStore` 类**：离线 `load` / `list` / `exists`，联网 `register` / `resolve` / `fetchAgentMd` / `checkAgentMd` / `diagnose` / `renewCert` / `rekey` / `changeSeed`。
- **`Result<T>` 类型**：统一结果类型（`{ ok: true; data: T }` 或 `{ ok: false; error: ErrorInfo }`）。
- **新增错误类**：`NotFoundError` / `IdentityConflictError` / `VersionConflictError` / `ClientSignatureError`。
- **`ConnectionState` 枚举**：9 态（`NO_IDENTITY` / `STANDBY` / `CONNECTING` / `READY` / `RETRY_BACKOFF` / `RECONNECTING` / `CONNECTION_FAILED` / `CLOSED`）。
- **实例级 `protected_headers`**：`setProtectedHeaders()` 自动合并到 `message.send` / `group.send` / `*.thought.put`。
- **重连状态可观测**：`nextRetryAt` / `retryAttempt` / `retryMaxAttempts` / `lastError` / `lastErrorCode` 属性。
- **客户端属性**：`currentAid` / `hasIdentity` / `canSign` / `canConnect` / `canSend`。
- **导出**：`VERSION` 常量、`STATE_TO_PUBLIC` 映射表。
- **keystore 扩展**：新增 `prekeys` / `group_current` / `group_old_epochs` / `e2ee_sessions` 表及相关读写方法；新增字段级加解密（旧 E2EE 互操作）。

### Fixed
- **agent.md 请求超时**：新增 `fetchWithTimeout()` 防止挂起。
- **agent.md 下载并发控制**：新增 `AGENT_MD_DOWNLOAD_CONCURRENCY` 限制。

### Removed
- 删除 `ts/src/namespaces/auth.ts`、`ts/src/namespaces/custody.ts`、`ts/src/namespaces/meta.ts`。

---

## 0.3.6 — 2026-05-28

### Added
- **Encrypted push 解密管线**：收到加密推送时即时尝试 V2 解密，成功则发 `message.received` / `group.message_created`（含明文 payload + e2ee 元数据），失败则发 `message.undecryptable` / `group.message_undecryptable`（含诊断字段 `_decrypt_error` / `_decrypt_stage` / `_envelope_type`）
- **`auth.fetchPeerCert(gatewayUrl, aid)`**：公开 API 实现落地（v0.3.5 声明，v0.3.6 实现独立方法体）
- **`storage.get_limits` RPC**：查询上传限制和配额使用情况
- **`storage.check_upload` RPC**：上传预检（秒传检测 + 超限检测）

### Fixed
- **Identity cache 自愈**：V2 session init 时检测 `private_key_pem` 缺失，自动从 keystore 重新加载并清理脏 instance_state
- **`loadIdentity` 字段白名单**：只合并 `_INSTANCE_STATE_FIELDS` 定义的字段，防止 instance_state 表中的脏数据覆盖核心字段
- **`.seed.migrated` 兼容**：`FileSecretStore` 解密失败时自动尝试 `.seed.migrated.*` 文件作为 fallback（半迁移状态兼容）

### Changed
- **Auth namespace gateway_url 持久化**：`registerAid` / `authenticate` 成功后自动持久化 gateway_url 到 instance_state

---

## 0.3.5 — 2026-05-28

### Breaking Changes
- **`createAid()` 兼容别名移除**：仅保留 `registerAid()`，旧 `createAid` 已删除
- **注册与认证分离**：`authenticate()` 不再隐式注册；身份不完整时抛 `StateError`

### Added
- **`IdentityConflictError`**：新增错误类型（继承 `AuthError`），AID 注册冲突时抛出
- **`auth.loadIdentityOrNull()`**：公开 API，只读加载本地已注册身份，不存在时返回 null（`auth.loadIdentity()` 已有）
- **`auth.fetchPeerCert()`**：公开 API，获取对端 AID 证书 PEM（本地缓存优先，未命中走 PKI HTTP + 链验证）（已有）

### Changed
- **`registerAid` 半成品恢复**：本地有 keypair 无 cert 时，查服务端恢复；服务端无记录则用现有 keypair 注册（不再直接拒绝）
- **agent.md 下载**：改为无条件 GET（移除条件头）；304 时本地有缓存直接用，无缓存重试
- **错误消息**：所有 `createAid` 引用更新为 `registerAid`
- **`.seed` fallback 迁移**：`FileSecretStore` 启动时检测旧 `.seed` 文件，自动迁移到 `seed_password` 派生方式
- **`ChangeSeed` API**：`FileKeyStore.ChangeSeed()` / `FileKeyStore.changeSeed()` 支持运行时更换 seed

### Removed
- **`namespaces/auth.ts` 中 `createAid` 兼容别名**

---

## 0.3.3 — 2026-05-25

### Added
- **V2 Thought 加解密**：`group.thought.get` / `message.thought.get` 返回值自动解密；发送端自动加密；`attachV2EnvelopeMetadata` 附加 E2EE 元数据
- **V2 Sender IK 延迟解密**：`_v2SenderIKPending` / `_v2SenderIKFetching` 机制，对端 IK 未缓存时挂起消息、异步拉取后重试解密
- **agent.md 本地缓存体系**：`setAgentMdPath` / `publishAgentMd()` / `fetchAgentMd(aid?)`；基于文件系统的 list.json 索引 + 按 AID 存储 + etag 比对 + 自动拉取缺失
- **KeyStore agent_md_cache 持久化**：文件系统 + SQLite 双后端支持
- **V2 辅助函数**：`getV2DeviceId` / `_v2B64ToBytesStrict` / `_v2BytesEqual` / `_v2ConcatBytes` / `_v2LengthPrefixedTextKey` / `_v2LengthPrefixedBytes`
- **V2 envelope 元数据**：`attachV2EnvelopeMetadata` / `attachV2EnvelopeMetadataFromSource` / `extractV2EnvelopeFromSource` / `metadataWithoutAuth`
- **签名跳过策略**：对内部方法和系统事件跳过签名验证

### Changed
- **V2 消息处理路径重构**：统一 P2P/Group 解密入口，支持 sender IK pending 延迟模式
- **V2 SPK rotation**：thought 解密失败时触发 group SPK rotation / registration after peer fallback
- **消息调试日志增强**：thought.get 全链路 debug 日志

### Fixed
- **service-plane envelope 解包**：修复 Kernel trace 字段传递丢失
- **trace 树状展示**：enter/exit 配对 + 嵌套缩进

---

## 0.3.1 — 2026-05-22

### Added
- **`auth.checkAid` handler**：本地证书自检（解析有效期、公钥）+ 远端注册状态查询；新增 `parseCertValidity` / `parseAsn1Time` ASN.1 时间解析
- **RPC trace 增强**：`RPCTransport` 增加 `setTraceMode()` / `setTraceObserver()`；`sortTraceSpansForDisplay` / `formatTraceTree` / `traceDisplay` 树状展示按 ts 排序 + 嵌套缩进；`TraceObserver` 类型导出
- **V2 群组 SPK 生命周期**：`V2KeyStore.saveGroupSPK` / `loadGroupSPK` / `loadCurrentGroupSPK`；`V2Session.ensureGroupRegistered` / `rotateGroupSPK` / `_publishGroupSPK`；`DESTROY_DELAY_MS = 7d`
- **V2 P2P push 解密**：`AUNClient._onV2PushNotification` / `_decryptV2PushMessage` 实现带 payload 的就地解密 + 失败回退到 pull

### Changed
- **`SeqTracker.forceContiguousSeq`**：原 `contiguousSeq = minSeq` 跳过空洞（会丢消息），改为 `contiguousSeq = minSeq - 1` 由连续前缀自然推进，避免误丢

### Fixed
- **`client.ts:4026` 类型错误**：`_publishOrderedMessage` 的 `decrypted` 实参补 `as EventPayload` 断言（`Record<string, unknown>` 与 `JsonValue | Error` 不兼容）
- short RPC 请求增加 `debug` 完整报文日志，便于跨语言诊断

---

## 0.3.0 — 2026-05-21 ⚠️ BREAKING CHANGE

> **V2-only 版本**：移除全部 V1 E2EE（含群组加密），新增 V2 加密原语，API 不向后兼容。

### BREAKING
- **移除 V1 E2EE 全部实现**：`GroupE2EEManager`、V1 epoch key 逻辑全部删除
- **移除 V1 群组加密测试**：`e2ee.test.ts`、`e2ee-group.test.ts`、`epoch-key-server.spec.ts` 等
- **E2EE 接口简化**：`e2ee.ts` 仅保留 V2 路径，V1 加解密方法不再可用
- **配置变更**：`AUNConfig` 移除 V1 相关配置项
- **KeyStore 重构**：`keystore/` 目录结构调整，`aid-db.ts` / `file.ts` 接口变更

### Added
- **agent.md 主 API**：`AUNClient.publishAgentMd(path)` / `AUNClient.fetchAgentMd(aid?, savePath?)`
- **V2 加密原语**（跨语言 golden vector 一致性）：ECDH P-256、HKDF-SHA256、AES-256-GCM、ECDSA-SHA256 RAW (RFC 6979)、1DH/3DH wrap_key、Recipients Sort + Merkle Digest、State Commitment

### Removed
- `AUNClient.setLocalAgentMdPath()` / `getLocalAgentMdEtag()` / `getRemoteAgentMdEtag()` — 由主 API 自动维护

### Deprecated
- `client.auth.signAgentMd` / `verifyAgentMd` / `uploadAgentMd` / `downloadAgentMd` — 建议迁移到 `client.publishAgentMd` / `client.fetchAgentMd`

---

## 0.2.20 — 2026-05-18

### Added
- **agent.md 版本一致性 API**：`AUNClient.setLocalAgentMdPath(path)` / `getLocalAgentMdEtag()` / `getRemoteAgentMdEtag()`。Node 用 `fs.readFileSync` + `crypto.createHash` 计算 etag，浏览器场景返回空串并 warn。SDK 自动从 RPC envelope `_meta.agent_md_etag` 提取服务端 etag，应用层订阅 `message.received` / `group.message_created` 等事件时 payload 多 `_agent_md.{local_etag, remote_etag}` 字段供版本比对。
- **`downloadAgentMd` 条件请求缓存**：内部维护 ETag/Last-Modified，未变化时返回上次缓存内容；外部 API 形态不变。
- **transport meta observer**：`RPCTransport.setMetaObserver(fn)` 透传 envelope `_meta`，observer 抛错被吞，不影响 RPC result。

### Changed
- **RPC call 默认超时 10s → 35s**：与服务端 30s handler timeout 对齐，留 5s buffer。
- **multi-device 架构**：对端无 prekey 时 `_sendEncrypted` 直接抛错（`no registered device prekeys for ...`），不再降级到 `long_term_key`。

### Docs
- 仓库根 `docs/`（agent.md 规范、protocol、SDK 手册）随 npm tarball 打包到 `_packed_docs/`，安装后可读。`.gitignore` 排除项（如内部测试指南）不进包。

---
