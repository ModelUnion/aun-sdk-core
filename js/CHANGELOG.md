# Changelog

本文件记录 `@agentunion/fastaun-browser` SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

---

## 0.5.4 — 2026-07-09

### 新功能

#### 通用 indexed document settings
- 浏览器 `GroupFacade` 新增 `getSettingWithIndex()` / `updateSettingWithIndex()`，支持按 `keyName` 管理 `{keyName}.content` 与 `{keyName}.attachments` 两类文档型 indexed settings。
- `keyName` 增加统一校验：必须匹配 `^[A-Za-z][A-Za-z0-9_-]{0,63}$`，并拒绝 `join`、`group`、`index`、`visibility` 等保留基名。
- `getAnnouncement()` / `updateAnnouncement()` 与 `getRules()` / `updateRules()` 复用通用 indexed document setting 路径，继续通过 signed `group.index` + `expected_index_etag` CAS 写入。

#### 入群要求附件
- `getJoinRequirements()` / `updateJoinRequirements()` 支持 `attachments`，对应服务端 `join.attachments` indexed setting。
- `join.attachments` 与公告/群规附件保持同一类 `group.fs` 引用结构，可通过 group.index 签名索引同步。

#### Group FS 角色 ACL
- 服务端 group.fs 命名空间新增受保护 `.group` 控制目录，并为 owner/admin 同步基线角色 ACL。
- owner/admin 默认可写群自有区；admin 可管理群自有区角色 ACL。
- `role:member` 支持按具体业务目录授予 `rw`，允许成员创建/上传，但不允许删除、重命名或移动群自有区内容。

### 修复

- 修复 Storage 直接入口对群自有区删除/移动/重命名权限检查不足的问题，删除类操作统一走 `delete` 权限判定。
- 修复旧 group AID 证书类型仍为 normal 时，Storage 无法通过 group resolver 判定群空间的问题。
- 兼容 CA 续期时 PEM 公钥与 SPKI base64 的等价比较，并兼容托管续期返回 `cert_pem` / `new_cert` 字段。

### 改进

- message/group WAL writer 的 `micro_wait` 支持 auto 预算模型，并扩展性能统计输出，便于观察批量写入队列深度与 pending 状态。
- group.fs 命名空间在读取 group 记录时支持懒修复，缺失 baseline ACL 时可重试同步。
- SDK 包版本、运行时 `VERSION` 和 conformance 期望版本更新为 `0.5.4`。

### 测试

- 扩展浏览器 GroupFacade group index 单元测试，覆盖通用 indexed document setting、`join.attachments` 缓存读取和 group.index 写入路径。
- 更新 conformance 版本期望到 `0.5.4`。
- 服务端测试扩展 group settings、group.fs namespace / role ACL、Storage 群自有区权限和 CA 续期兼容性。

---

## 0.5.3 — 2026-07-07

### 新功能

#### group.index 索引化群设置
- 新增浏览器 `group.index` JSONL 工具：支持 canonical entries、body hash、etag、ECDSA P-256 签名/验签，以及将 settings 更新合并为带 `group.index` 的原子写入。
- `GroupFacade` 新增 `checkGroupIndex` / `getGroupIndex` / `updateGroupIndex`，写入时携带 `expected_index_etag` 做 CAS，并在冲突后重拉索引重试。
- 浏览器 IndexedDB TokenStore 新增 `group_index_cache`，按 local AID + group AID 持久化 index JSONL、remote meta、本地 etag、settings cache 和 entry etags。
- 入口导出 `GROUP_INDEX_KEY`、`GROUP_INDEX_SCHEMA`、`GroupIndexMetaCache`、`buildSignedGroupIndex`、`verifyGroupIndex`、`prepareGroupSettingsWithIndex` 等 group.index API。

### 修复

#### 撤回去重与有序投递
- `message.recalled` 改为专用处理路径，支持 P2P 撤回 tombstone 的有序投递、自动 ack、gap fill 和按原消息标识去重，避免 push / pull 对同一次撤回重复回调。
- 群撤回去重键改为规范化 group id + 原消息 id/seq，忽略 `recalled_at`，并补齐顶层 recall 字段归一化。
- 群消息 pull / legacy fallback 识别 `group.message_recalled` tombstone，避免把撤回通知作为普通群消息投递。
- P2P 与群 push 按 namespace 串行化处理，降低异步解密和投递导致的乱序风险。
- V2 P2P / Group pull 页内消息按 `seq` 排序后处理，避免服务端返回无序时影响本地 seq 推进。

### 改进

- `RPCTransport` 的 `_meta` observer 支持异步回调；RPC 成功响应会等待 observer 完成，事件/通知路径统一走安全的 meta observer 分发。
- `getAnnouncement` / `getRules` / `getJoinRequirements` 优先使用 group.index settings cache；`updateAnnouncement` / `updateRules` / `updateJoinRequirements` 改走 `updateGroupIndex`，保持索引与设置同步。
- cross-sdk JS agent 支持 `sdk.update_group_index` 调用，便于跨 SDK 测试索引化群设置。
- SDK 包版本、运行时 `VERSION` 和 conformance 期望版本更新为 `0.5.3`。

### 测试

- 新增 group.index 单元测试，覆盖 hash/etag、签名/验签、settings merge、RPC meta stale/fresh、async meta observer 和 IndexedDB 持久化恢复。
- 新增 GroupFacade group.index 单元测试，覆盖 CAS 写入、冲突重试、远端索引验签、tamper 拒绝、settings cache 和便利方法索引化写入。
- 新增浏览器 E2E：验证签名 `group.index` 写入、裸 settings 写入拒绝、CAS 冲突重试和最终 settings 一致性。
- 扩展撤回投递测试，覆盖 P2P/group recall 顶层字段归一化、push/pull tombstone 去重和有序投递。
- 更新 group settings 与签名审计 E2E，使公告/群规等索引化 settings 通过 `updateGroupIndex` 写入。

---

## 0.5.2 — 2026-07-05

### 新功能

#### agent.md 元数据
- 支持从 RPC `_meta.agent_md_etags.group` 和 V2 envelope `agent_md.group` 观察群组 agent.md ETag / Last-Modified，并自动维护群 AID 的本地缓存。
- 群消息 agent.md 观察逻辑补齐 sender / group 两类来源，提升浏览器端跨设备、跨群消息场景下的版本一致性提示能力。

### 修复

#### V2 P2P / Group 拉取
- `message.v2.pull` / `group.v2.pull` 自动 ack 改为通过下一次 pull 的 `ack_up_to_seq` piggyback，减少独立 ack RPC。
- 修复非满页返回 `has_more=true` 时盲目续拉的问题；满页继续立即拉，非满页仅在有待合并 ack 时追加一页。
- 过滤 `seq <= after_seq` 的 stale 原始消息，避免重复处理或错误推进 ack。
- stale 原始页未推进 contiguous seq 时不再发送自动 ack，避免把未真正拉齐的数据误确认。

### 改进

- V2 pull 默认/最大 page limit 收敛为 50，并对传入 `limit` 做 1..50 夹取。
- V2 pull 增加非满页 tail delay：`1000ms / (pulled_messages + 1)`，最大 500ms；满页和空页仍立即结束或续拉。
- SDK 包版本、运行时 `VERSION` 和 conformance 期望版本更新为 `0.5.2`。

### 测试

- 扩展 V2 P2P / Group pull 单元测试，覆盖 `ack_up_to_seq` piggyback、非满页 tail delay、stale 过滤和 max pages flush。
- 新增 `v2-e2ee-coordinator` 组件边界测试，验证自动 ack 通过下一页 pull piggyback。
- 扩展 agent.md 和 conformance 测试，覆盖群组 ETag 观察及 0.5.2 版本声明。

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
- 浏览器环境保持 Blob/Uint8Array/ArrayBuffer 数据源支持，无本地文件路径依赖

### 测试

- 新增 `storage.spec.ts` E2E 测试（浏览器环境 `touch` / `du`）
- 新增 `group-fs.spec.ts` E2E 测试（浏览器环境 ACL 操作）
- 扩展 `storage-vfs-p5.test.ts` 单元测试覆盖新增能力

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
  - 浏览器环境支持 Blob/Uint8Array/ArrayBuffer 数据源；Node-like 环境可通过本地文件路径上传/下载

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
- Group FS 单元测试（`tests/unit/group-fs.test.ts` / `tests/unit/group-fs-node.test.ts`）
- Collab Client 单元测试
- Collab Diff3 单元测试
- Facades 单元测试
- AIDStore 重构测试

#### 单元/浏览器 E2E 测试
- Group FS 跨运行时单元测试
- Collab 浏览器协作测试（Playwright）

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
- **token 刷新日志文案修正**：修复连续刷新失败日志拼写错误（`token refreshconsecutivefailed` → 规范文案），token 循环中 `publish`/`_handleTransportDisconnect` 补齐 `await`
- **protected_headers 类型归一**：V2 发送方法的 envelope 元数据归一时识别 `ProtectedHeaders` 对象（经 `toObject()` 探测）并转 dict，修复传入对象（非 dict）时 protected_headers 被丢弃的问题（四语言对齐）

### 优化
- **app_message_envelope 字段收窄**：envelope 键收窄为可转发元数据（`from`/`to`/`group_id`/`type`/`kind`/`version`/`timestamp`/`encrypted`/`context`/`protected_headers`/`payload_type`），移除 `message_id`/`seq`/`device_id`/`slot_id` 等本地与传输层字段，不再向应用层泄漏内部字段并剔除 `_auth`（四语言对齐）
- **RPC 日志 token 脱敏**：短 RPC 请求/响应 debug 日志对 `access_token`/`refresh_token`/`kite_token`/`token` 及 `_token` 结尾键递归脱敏，避免明文 token 落日志；浏览器环境受 crypto 限制只输出 `<redacted len=N>`（不含 sha256，与 Node/Go 略有差异）

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
- **过期 token 重连死循环**：重连前同步 `_identity` 中的 token 状态到 `_sessionParams`，过期或缺失则清空以触发两阶段重新登录，避免反复用旧 token 触发 4001（四语言对齐）
- **Service Proxy 持久隧道重连**：新增指数退避（上限 60s，成功后重置）；`AuthError` 触发 `_authenticateForAccessToken` 重新登录后再重连（四语言对齐）
- **protected_headers 参数兼容**：`mergeInstanceProtectedHeaders` 同时识别 `protected_headers` 与 `headers` 别名

### 测试
- `自己入群首个 event_seq>1 不应被入群前不可见事件阻塞`
- `pull 缺失中间 event_seq 时视为永久空洞，不阻塞已拿到的群事件发布`
- `publishAppEvent 为群事件注入 envelope 并保留顶层兼容字段`
- `撤回事件发布给应用层时带撤回通知自身 envelope`

---

## 0.4.11 — 2026-06-08

### 新功能
- **Storage 目录树与扩展操作**：`storage.*` 新增 15 个存储操作方法（含 `create_folder`/`rename_folder`/`move_object`/`batch_delete` 等），加入签名集合和非幂等集合（四语言+服务端对齐）
- **group.resources 树形资源系统**：新增 11 个资源管理方法，加入签名和非幂等集合；支持跨域访问票据（四语言+服务端对齐）
- **group.changed 事件保序去重**：新增 `handleGroupChangedEventSeq` 支持 event_seq 追踪和有序消息队列，空洞先到时缓存补洞；新增 `_isEventSignatureVerified()` 区分 pending 不标记已验签（四语言对齐）
- **V2 E2EE 注册并发保护**：SPK 注册改用 `_registeringPromise` 缓存并发请求，多并发调用时等待同一 Promise（四语言对齐）

### 修复
- **IndexedDB 事务原子性**：`addSPK` 改用单事务处理原始记录和别名，避免独立事务导致一致性问题
- **SPK 销毁顺序**：`_doAutoDestroy` 中先删设备级密钥再删存储级密钥
- **sdk_version 拼写**：`sdk_vesion` → `sdk_version`
- **V2 并发冲突检测**：检查对端操作的 `inflightSet`，防止 SPK 注册与轮换并发冲突
- **storage/group.resources 签名和幂等性补全**：补全写操作方法进入签名集合与非幂等集合（四语言对齐）

### 优化
- **群事件处理流程重构**：`group.changed` 事件分发逻辑从 `client.ts` 迁移到 `delivery.ts`，支持按 event_seq 保序发布；新增 `publishOrderedQueueItem()` / `publishOrderedGroupChanged()`
- **群组解散清理**：解散事件处理改为异步 `drainOrderedMessages`，保证 seq 追踪一致性
- **群事件自动 ack**：`handleGroupChangedEventSeq` 无需补洞时直接 ack event cursor
- **错误日志补充**：V2Session SPK 销毁异常捕获并输出日志

### 测试
- 新增事件验签状态单元测试（pending 状态不标记已验签）
- 新增消息乱序补洞保序测试（高序号 push 先到时 SDK 内部消费和应用层发布的保序去重）
- 新增签名方法覆盖测试（storage 写操作和有副作用读操作进入非幂等集合）
- 新增 RPC 管道非幂等超时测试（storage/resources 方法按非幂等长超时 35s 发送）
- 修复 `handleGroupChangedEventSeq` 单元测试 async/await 标记和 ack cursor 验证

---

## 0.4.10 — 2026-06-06

### 新功能
- **Service Proxy 服务代理**：新增 `service-proxy.ts` 客户端（控制面 `proxy.register`/`unregister`/`list_services` + 数据面隧道）及 `tools/service-proxy-holder-boundary.mjs`、`tools/service-proxy-visitor.mjs` 工具（四语言对齐）
- **notify() 单向通知**：新增 `notify()` 公开 API，发送无 id 的 JSON-RPC 2.0 Notification，只面向在线长连接、不落库、不分配 seq、无 ack（四语言对齐）
- **Storage 逻辑下载 URL**：支持干净逻辑下载 URL `storage.{issuer}/{user_name}/{object_key}`，无签名无 CAS

### 修复
- **群消息撤回（`group.message_recalled`）端到端打通**：新增在线 push 通道（`_raw.group.message_recalled`），与 pull 双 tombstone（占位 + 通知）兜底互补；push 路径推进 `notice_seq` 的 seq/ack 与普通群消息对齐，避免 seq 留洞导致重复拉取；按 `(group_id, message_ids)` 去重（去重键不含 `recalled_at`），确保应用层只回调一次（四语言+服务端对齐）
- `group.recall` 加入 RPC 白名单；`transport` 事件名映射补充 `group.message_recalled`

### 测试
- `tests/e2e-browser/notify.spec.ts`/`tests/integration/notify.test.ts` 覆盖 notify；`service-proxy` 系列单元+集成+E2E 测试；`tests/e2e-browser/v2-group.spec.ts` 补充群撤回断言

---

## 0.4.9 — 2026-06-03

### 修复
- V2 明文消息（P2P 和群组）投递时补充调用 `attachGatewayProximity()`，消息事件 payload 现可携带 `proximity`（`same_network`/`same_device`/`basis`/`asserted_by`）字段（四语言对齐）

### 优化
- `AUNClient` 运行时状态全面迁移至 `ClientRuntime` 统一抽象层，生命周期、消息投递、RPC 路由、身份、V2 E2EE、群组状态各子组件构造函数统一接收 `runtime` 参数，消除组件间直接引用主客户端对象
- `LifecycleController`、`MessageDeliveryEngine`、`GroupStateCoordinator`、`IdentityRuntimeManager` 的状态读写全部改为通过 `runtime.*` setter/getter，提升可测试性
- `RpcPipeline` 接管原 `AUNClient.call()` 全部路由逻辑，主客户端 `call()` 直接委托
- `ConnectionOptions` 新增 `retry` 配置项，支持自定义重连策略
- 移除 `PEER_PREKEYS_CACHE_TTL` 常量，相关逻辑统一收归运行时

### 测试
- 补充针对运行时抽象层重构后的浏览器 E2E 及单元测试覆盖

---

## 0.4.8 — 2026-06-03

### 新功能
- `cert-utils.ts` 新增 `normalizeFingerprintHex`、`publicKeyFingerprint`、`certMatchesFingerprint`、`publicKeyMatchesFingerprint` 工具函数，支持 DER/SPKI 双格式及 16/64 位短格式（四语言对齐）
- `buildAgentMdSignatureBlock` 新增可选 `public_key_fingerprint` 字段输出（四语言对齐）
- `AID.signAgentMd` 签名块中写入 `public_key_fingerprint`；`verifyAgentMd` 同时校验证书指纹和公钥指纹，`VerifyResult` 新增 `public_key_fingerprint` 字段（四语言对齐）
- `AgentMdManager.download()` 从签名块提取指纹传入 `_resolvePeer`，实现验证时精确锁定证书（四语言对齐）
- `peerResolver` 接口新增 `certFingerprint` 参数（四语言对齐）
- `AIDStore.peerResolver` 支持按指纹从 keystore 查缓存或从 PKI 精确拉取证书（四语言对齐）
- `pkiCertUrl` 新增 `certFingerprint` 参数，生成带 `cert_fingerprint` 查询参数的 URL（四语言对齐）
- `_getV2SenderPubDer()` 新增 `certFingerprint` 参数，解密时精确匹配发送方证书（四语言对齐）
- 新增在线未读 hint 队列（`_onlineUnreadHintQueue` + 定时 drain）（四语言对齐）
- 新增 `_resetV2IdentityRuntime` / `_v2SessionMatchesIdentity`，V2 session 校验升级为身份匹配（四语言对齐）

### 修复
- `_resolvePeer()` 当 self AID 与期望指纹不匹配时抛 `StateError`，修复旧版直接返回 self 的安全漏洞（四语言对齐）
- `_fetchPeerCert()` 移除带指纹失败后的无指纹降级请求（四语言对齐）
- 指纹验证统一改用 `certMatchesFingerprint`，`_verifyEventSignature` 同步更新（四语言对齐）
- cert 缓存只在无 `certFingerprint` 时写裸 key，避免缓存污染（四语言对齐）
- `disconnect()` 允许状态范围扩大（增加 AUTHENTICATED/CONNECTING/RETRY_BACKOFF/CONNECTION_FAILED），修复原来只允许 connected/reconnecting 的限制
- `_connectOnce()` / `disconnect()` / `_handleTransportDisconnect()` 断连后状态统一改为 `standby`，与 Python 对齐
- `_applyAidRuntimeContext()` 新增旧 transport 清理，防止切换身份时旧连接泄漏（四语言对齐）
- `parseAgentMdTailSignature` 改用 `normalizeFingerprintHex` 替换旧正则，支持更宽松指纹格式（四语言对齐）
- SPK hash 计算改用 `exactArrayBuffer()` 防止 TypedArray offset 错误

### 优化
- `AUNClient` 大规模拆分重构：拆分出 `ClientRuntime`、`LifecycleController`、`RpcPipeline`、`MessageDeliveryEngine`、`V2E2EECoordinator`、`GroupStateCoordinator`、`PeerDirectory`、`IdentityRuntimeManager` 子模块（四语言对齐）
- `AIDStore` 构造函数移除 `deviceId` 入参，统一使用 `getDeviceId()` 自动生成（四语言对齐）
- `_decryptV2Message()` 透传 `proximity`/`same_device`/`same_network`/`same_egress_ip` 字段到解密后事件

---

## 0.4.7 — 2026-06-01

### Added
- **`AIDStore.uploadAgentMd(aid, content?)`**：将 `uploadAgentMd` 从 `AUNClient` 迁移到 `AIDStore`，支持指定任意本地 AID 上传 agent.md；内部独立创建 `IndexedDBTokenStore` 和 `AuthFlow` 完成认证，不依赖 `AUNClient` 实例。
- **`UploadAgentMdResult` 类型**：新增上传结果类型导出。

### Changed
- **`AUNClient.uploadAgentMd()`**：移除，功能迁移至 `AIDStore.uploadAgentMd(aid)`。
- **`AIDStore`**：新增内部 `_tokenStore`（`IndexedDBTokenStore`）和 `_crypto`（`CryptoProvider`）字段，供 upload 认证流程使用；`connect()` 时同步初始化，`close()` 时释放。
- **`AIDStore._hasLocalAidMaterial()`**：新增私有方法，通过检查证书或密钥对判断 AID 是否有本地身份材料，用于 `connect()` 前置校验。

---

## 0.4.6 — 2026-06-01

### Added
- **IndexedDB 存储拆分**：将单一 `IndexedDBKeyStore` 拆分为两个专职类：
  - `IndexedDBIdentityStore`（`keystore/indexeddb-identity-store.ts`）：负责私钥、密钥对、完整身份、pending 注册、证书、metadata KV。
  - `IndexedDBTokenStore`（`keystore/indexeddb-token-store.ts`）：负责 prekeys、群组密钥、sessions、seq 跟踪、agent.md 缓存、群组状态、信任根。
  - 共享基础设施提取到 `keystore/indexeddb-shared.ts`。
- **`AgentMdManager` 类**（`agent-md.ts`）：独立的 agent.md 管理器，支持 ETag/Last-Modified 缓存验证、TTL 策略、内容签名验证、信任根存储（虚拟路径 `indexeddb://trust-roots/...`）。
- **`KeyStore` 接口新增方法**：`loadCert(aid, certFingerprint?)` / `saveCert(aid, certPem, certFingerprint?, opts?)`。
- **`RegisterFlow` 新增公开方法**：`validateAidName`、`fetchPeerCert`、`shortRpc`、`generateIdentity`、`newClientNonce`、`verifyPhase1Response`。
- **`AIDStore` 新增方法**：`downloadAgentMd`（替代 `fetchAgentMd`）、`checkAgentMd`（替代 `headAgentMd`）。
- **`AUNClient.uploadAgentMd()`**：新增方法，签名并上传当前 AID 的 agent.md。
- **IndexedDB 新增对象仓库**：`agent_md_cache`、`group_state`、`pending_identities`、`e2ee_sessions`；数据库版本升级至 v7。
- **导出新增**：`IndexedDBIdentityStore`、`IndexedDBTokenStore`、`TokenStore` 类型。

### Changed
- **`AUNClient` 架构**：移除内部 agent.md 缓存字段（`_agentMdCache`、`_agentMdFetchInflight` 等），改由 `AgentMdManager` 统一管理。
- **`AIDStore`**：使用 `IndexedDBIdentityStore` 替代 `IndexedDBKeyStore`；移除内部 `AuthFlow` 实例，改为按需创建。
- **`AIDStore.fetchAgentMd()`** 重命名为 `downloadAgentMd()`，返回类型同步更新为 `DownloadAgentMdResult`。
- **私钥加密**：默认启用 AES-256-GCM + PBKDF2（100,000 迭代）；支持 `changeSeed()` 密码迁移。

### Removed
- **`IndexedDBKeyStore` 类**（`keystore/indexeddb.ts`，2280 行）：完整移除，功能分解为 `IndexedDBIdentityStore` 和 `IndexedDBTokenStore`。
- **`FullKeyStore` 类型别名**：不再需要。
- **`AIDStore.headAgentMd()`**：功能整合到 `AgentMdManager.check()`。

---

## 0.4.5 — 2026-05-31

### Added
- **`RegisterFlow` 独立类**（`register-flow.ts`）：将 AID 注册流程从 `AuthFlow` 中剥离，负责 keypair 生成、服务端 RPC、pending 目录（IndexedDB）原子提交、崩溃恢复。
- **`TokenStore` 接口**：从 `KeyStore` 中拆分出不含私钥操作的子接口，供 `AuthFlow` 使用。

### Changed
- **`AuthFlow` 改用 `TokenStore`**：构造参数 `keystore` 重命名为 `tokenStore`，类型收窄为 `TokenStore`；私钥操作全部移出 `AuthFlow`。
- **`AuthFlow.setIdentity()`**：新增方法，由 `AUNClient` 注入内存私钥；`AuthFlow` 内部不再从 `tokenStore` 解密私钥。
- **`AIDStore.register()` 私钥写入职责转移**：注册结果由 `AIDStore` 负责调用 `keystore.saveCert` / `saveKeyPair` 写入，与 Python / Go / TS SDK 对齐。

---

## 0.4.4 — 2026-05-31

### Added
- **`AID` 新增 `privateKeyPem` 只读字段**：`AIDStore.load()` 加载时注入明文私钥，`AUNClient` 直接从 `AID` 读取，无需再经 keystore 解密。

### Changed
- **`AUNClient` 剥离私钥读写**：V2 session 初始化、`_signClientOperation`、propose_state 签名均改从 `_currentAid.privateKeyPem` 读取，删除 keystore fallback 重解密路径。
- **`auth._persistIdentity` 不再写私钥**：写入前剥离 `private_key_pem` / `public_key_der_b64` / `curve`，AUNClient 的 keystore 只持久化 token / cert / instance_state。
- **`AUNClient` keystore 构造不再传 `encryptionSeed`**：seed 作用域收窄至 AIDStore，不外漏。

---

## 0.4.3 — 2026-05-31

### Added
- **`normalizeSlotId` / `slotIsolationKey`**：新增 slot_id 校验与隔离键提取工具函数，支持 `/` `:` 空格作为分隔符（首字符不允许）。
- **`ConnectOptions` 新增字段**：`connection_kind`、`short_ttl_ms`、`delivery_mode`、`extra_info`、`background_sync`，与 Python / Go / TS SDK 对齐。

### Changed
- **`AUNClient` 构造**：传入 `aid` 参数时增加类型守卫（检查 `aunPath` 字段与 `isPrivateKeyValid` 方法），避免误传非 AID 对象。
- **slot_id 隔离逻辑**：`connect` 时若目标 slot_id 隔离键与当前不同，自动拒绝跨 slot 连接。
- **`background_sync` 触发时机**：连接成功后仅在 `sessionOptions.background_sync !== false` 时触发 P2P gap fill。
- **`verify_ssl=false` 浏览器警告**：浏览器环境不支持关闭 SSL 校验，传入时输出 warn 并强制保持启用。

---

## 0.4.2 — 2026-05-30

### Added
- **`AIDStore` 新增具名返回类型**：`ResolveResult`、`FetchAgentMdResult`、`HeadAgentMdResult`、`CheckAgentMdResult`、`DiagnoseResult`、`RenewCertResult`、`RekeyResult`、`ChangeSeedResult`、`ListResult`，替代原来的 `Record<string, unknown>`。

### Changed
- **移除 `discoveryPort`**：`AIDStore` 构造选项删除 `discoveryPort`，gateway URL 改为纯自动发现。
- **`fetchAgentMd` 新增 `timeoutMs` 参数**（默认 30000ms），`resolve` 内部调用时透传 `opts.timeout`。
- **返回字段精简**：`fetchAgentMd` / `headAgentMd` / `checkAgentMd` / `diagnose` 移除冗余的 camelCase 别名字段，统一使用 snake_case。
- **`resolve` 返回 `source` 字段精简**：移除 `certFromCache` / `agentMdFetched` camelCase 别名，只保留 `cert_from_cache` / `agent_md_fetched`。

---

## 0.4.0 — 2026-05-30

> **破坏性重构版本。** 与 Python SDK 0.4.0 对齐：身份管理剥离为 `AID` / `AIDStore`；删除 `auth` / `custody` / `meta` 公开命名空间；引入 `Result` 与字符串错误码；连接状态机扩展为 9 态。浏览器环境下 `AID` 创建和签名/验证均为异步。

### Breaking Changes
- **删除公开命名空间**：移除 `client.auth` / `client.custody` / `client.meta`。身份相关功能迁移到 `AIDStore` 与 `AID`，其余 RPC 走 `client.call()`。
- **`AID` 创建改为异步**：使用 `await AID.create(...)` 工厂方法（浏览器 Web Crypto API 限制）；`sign` / `verify` / `signAgentMd` / `verifyAgentMd` 均为 `async`。
- **目录约定变更**：`{aun_path}/AgentMDs/` → `{aun_path}/AIDs/`（IndexedDB key 前缀同步变更）。

### Added
- **`AID` 类**（异步）：`AID.create()` 工厂方法；`sign` / `verify` / `signAgentMd` / `verifyAgentMd` 均返回 Promise；`isCertValid` / `isPrivateKeyValid` 同步。
- **`AIDStore` 类**：离线 `load` / `list` / `exists`，联网 `register` / `resolve` / `fetchAgentMd` / `checkAgentMd` / `diagnose` / `renewCert` / `rekey` / `changeSeed`；存储后端为 IndexedDB。
- **`Result<T>` 类型**：统一结果类型（`{ ok: true; data: T }` 或 `{ ok: false; error: ErrorInfo }`）。
- **新增错误类**：`NotFoundError` / `IdentityConflictError` / `E2EEGroupSecretMissingError` / `E2EEGroupEpochMismatchError`。
- **`ConnectionState` 枚举**：9 态（`NO_IDENTITY` / `STANDBY` / `CONNECTING` / `READY` / `RETRY_BACKOFF` / `RECONNECTING` / `CONNECTION_FAILED` / `CLOSED`）。
- **实例级 `protected_headers`**：`setProtectedHeaders()` 自动合并到 `message.send` / `group.send` / `*.thought.put`。
- **重连状态可观测**：`nextRetryAt` / `retryAttempt` / `retryMaxAttempts` / `lastError` / `lastErrorCode` 属性。
- **导出**：`__version__` 常量、`STATE_TO_PUBLIC` 映射表、`ROOT_CA_PEM` 根证书。

### Removed
- 删除 `js/src/namespaces/auth.ts`、`js/src/namespaces/custody.ts`、`js/src/namespaces/meta.ts`。

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

---

## 0.3.5 — 2026-05-28

### Breaking Changes
- **`createAid()` → `registerAid()`**：客户端 API 重命名，旧方法已移除
- **注册与认证分离**：`authenticate()` 不再隐式注册；身份不完整时抛 `StateError`

### Added
- **`IdentityConflictError`**：新增错误类型（继承 `AuthError`），AID 注册冲突时抛出
- **`auth.loadIdentity()` / `auth.loadIdentityOrNull()`**：公开 API，只读加载本地已注册身份（密钥对 + 证书 + 实例状态），无副作用
- **`auth.fetchPeerCert()`**：公开 API，获取对端 AID 证书 PEM（本地缓存优先，未命中走 PKI HTTP + 链验证）
- **Pull Gate**：per-key 序列化 pull 操作，防止同一 namespace 并发 pull
- **RPC Inflight 限制**：transport 层全局最大 16 个并发 RPC + 后台 RPC 独立限制 8 个，排队超时抛 `TimeoutError`
- **`_assertCertMatchesLocalKeypair`**：authenticate 前显式校验 cert 公钥与本地 keypair 一致
- **`_downloadRegisteredCert`**：注册前查服务端证书的辅助方法

### Changed
- **`registerAid` 半成品恢复**：本地有 keypair 无 cert 时，查服务端恢复；服务端无记录则用现有 keypair 注册
- **agent.md 元数据存储**：从全局 `list.json` key 改为 per-AID `{aid}/agentmd.json` key（IndexedDB）
- **agent.md 下载**：改为无条件 GET；302 显式跟随；304 时本地有缓存直接用，无缓存重试
- **`_loadIdentityOrRaise`**：增加 keypair 完整性检查
- **`ChangeSeed` API**：`IndexedDBKeyStore.changeSeed()` 支持更换 seed（重加密私钥）

### Removed
- **`_ensureLocalIdentity` / `_ensureIdentity`**：已移除，注册路径不再隐式生成密钥
- **`createAid` 方法**：已移除

---

## 0.3.3 — 2026-05-25

### Added
- **V2 Thought 加解密**：`group.thought.get` / `message.thought.get` 返回值自动解密；发送端自动加密；`attachV2EnvelopeMetadata` 附加 E2EE 元数据
- **V2 Sender IK 延迟解密**：`_v2SenderIKPending` / `_v2SenderIKFetching` 机制，对端 IK 未缓存时挂起消息、异步拉取后重试解密
- **agent.md 本地缓存体系（浏览器版本）**：`publishAgentMd(content?)` / `fetchAgentMd(aid?)`；基于 IndexedDB/localStorage 的 list + 按 AID 存储 + etag 比对 + 自动拉取缺失
- **V2 辅助函数**：`getV2DeviceId` / `_v2B64ToBytesStrict` / `_v2BytesEqual` / `_v2ConcatBytes` / `_v2LengthPrefixedTextKey` / `_v2LengthPrefixedBytes`
- **V2 envelope 元数据**：`attachV2EnvelopeMetadata` / `attachV2EnvelopeMetadataFromSource` / `extractV2EnvelopeFromSource` / `metadataWithoutAuth`

### Changed
- **V2 消息处理路径重构**：统一 P2P/Group 解密入口，支持 sender IK pending 延迟模式
- **V2 SPK rotation**：thought 解密失败时触发 group SPK rotation / registration after peer fallback

### Fixed
- **service-plane envelope 解包**：修复 Kernel trace 字段传递丢失
- **trace 树状展示**：enter/exit 配对 + 嵌套缩进

---

## 0.3.1 — 2026-05-22

### Added
- **`auth.checkAid` handler**：本地证书自检 + 远端注册状态查询（与 Node 版对齐）
- **RPC trace 增强（浏览器版本）**：`RPCTransport` 增加 `setTraceMode()` / `setTraceObserver()`；`sortTraceSpansForDisplay` / `formatTraceTree` / `traceDisplay` 树状展示
- **V2 群组 SPK 生命周期**：`V2KeyStore.saveGroupSPK` / `loadGroupSPK` / `loadCurrentGroupSPK` 基于 IndexedDB 持久化；`V2Session.ensureGroupSPK` / `ensureGroupRegistered` / `rotateGroupSPK` / `getGroupDecryptKeys`；`DESTROY_DELAY_MS = 7d`
- **V2 P2P push 解密**：`AUNClient` 增加 push payload 就地解密路径，失败回退到 pull

### Changed
- **`SeqTracker.forceContiguousSeq`**：原 `contiguousSeq = minSeq` 跳过空洞（会丢消息），改为 `contiguousSeq = minSeq - 1` 由连续前缀自然推进

### Fixed
- short RPC 请求增加 `debug` 完整报文日志，便于跨语言诊断

---

## 0.3.0 — 2026-05-21 ⚠️ BREAKING CHANGE

> **V2-only 版本**：移除全部 V1 E2EE（含群组加密），新增 V2 加密原语，API 不向后兼容。

### BREAKING
- **移除 V1 E2EE 全部实现**：`e2ee-group.ts`、V1 epoch key 逻辑全部删除
- **移除 V1 群组加密测试**：`e2ee.spec.ts`、`epoch-key-server.spec.ts`、`group-e2ee.spec.ts`、`group-join-key-recovery.spec.ts` 等
- **E2EE 接口简化**：`e2ee.ts` 仅保留 V2 路径，V1 加解密方法不再可用
- **配置变更**：`config.ts` 移除 V1 相关配置项

### Added
- **agent.md 主 API（浏览器版本）**：`AUNClient.publishAgentMd(content)` / `AUNClient.fetchAgentMd(aid?)`
- **V2 加密原语**（跨语言 golden vector 一致性）：ECDH P-256、HKDF-SHA256、AES-256-GCM、ECDSA-SHA256 RAW、1DH/3DH wrap_key、Recipients Sort + Merkle Digest、State Commitment
- **V2 Session**：SPK 生命周期 + 对端 IK 缓存 + PFS 三重销毁
- **V2 KeyStore**：IndexedDB 持久化 SPK/IK 异步实现

### Removed
- `AUNClient.setLocalAgentMdContent()` / `getLocalAgentMdEtag()` / `getRemoteAgentMdEtag()` — 由主 API 自动维护

### Deprecated
- `client.auth.signAgentMd` / `verifyAgentMd` / `uploadAgentMd` / `downloadAgentMd` — 建议迁移到 `client.publishAgentMd` / `client.fetchAgentMd`

---

## 0.2.20 — 2026-05-18

### Added
- **agent.md 版本一致性 API（浏览器版本）**：
  - `AUNClient.setLocalAgentMdContent(content: string): Promise<string>`：浏览器无法读本地文件，改为接收 markdown 文本字符串，用 `crypto.subtle.digest('SHA-256', ...)` 计算 etag。业务侧可用 `<input type=file>` 读出文本传入。
  - `AUNClient.getLocalAgentMdEtag(): string` / `getRemoteAgentMdEtag(): string`。
- SDK 自动从 RPC envelope `_meta.agent_md_etag` 提取服务端 etag，应用层订阅 `message.received` / `group.message_created` 等事件时 payload 多 `_agent_md.{local_etag, remote_etag}` 字段供版本比对。
- **`downloadAgentMd` 条件请求缓存**：内部维护 ETag/Last-Modified，未变化时返回上次缓存内容；外部 API 形态不变。
- **transport meta observer**：`RPCTransport.setMetaObserver(fn)` 透传 envelope `_meta`，observer 抛错被吞，不影响 RPC result。

### Changed
- **RPC call 默认超时 10s → 35s**：与服务端 30s handler timeout 对齐，留 5s buffer。
- **multi-device 架构**：对端无 prekey 时 `_sendEncrypted` 直接抛错（`no registered device prekeys for ...`），不再降级到 `long_term_key`。

### Docs
- 仓库根 `docs/`（agent.md 规范、protocol、SDK 手册）随 npm tarball 打包到 `_packed_docs/`，安装后可读。`.gitignore` 排除项（如内部测试指南）不进包。

---
