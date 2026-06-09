# Changelog

本文件记录 AUN Go SDK（`github.com/modelunion/aun-sdk-core/go`）的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

> Go SDK 通过 git tag 发布版本，无需上传到 npm/PyPI；用户用 `go get` 拉取指定 tag。

---

## 0.4.13 — 2026-06-09

### 新功能
- **发送结果回填 envelope**：`message.send` / `group.send` / `message.thought.put` / `group.thought.put` 的返回结果新增规范化 `envelope` 字段，使发送方回执与接收端信封元数据一致；新增 `appSendEnvelopeMethods` 与 `sendResultEnvelope()` / `attachSendResultEnvelope()`，rpc-pipeline 在 postprocess 后统一附加，V2 加密路径经 `_skipSendResultEnvelope` 标志跳过明文附加、由外层 V2 协调器在加密后补挂避免重复（四语言对齐）

### 修复
- **refresh_token 失效自愈**：新增需重登判定（命中 `relogin_required` 或 `missing refresh_token` / `invalid_or_expired_refresh_token` / `refresh not supported`）与清缓存逻辑；刷新失败需重登时清空本地 `access_token`/`refresh_token`/`kite_token` 并持久化，client 层 token 刷新循环检测到需重登时发布 `token.refresh_exhausted` 事件（带 `relogin_required: true`）、断连触发重连，下次 `connectSession` 因无可用 token 自动走两步登录；refresh RPC 补传 `aid`/`device_id`/`slot_id`/`access_token`/`sdk_lang`/`sdk_version`，`AuthError` 携带 `data` 透传服务端响应（四语言对齐）
- **protected_headers 类型归一**：V2 发送方法的 envelope 元数据归一时用类型 switch 识别 `*ProtectedHeaders`/`ProtectedHeaders` 并转 dict，修复传入对象（非 map）时 protected_headers 被丢弃的问题（四语言对齐）
- **V2 thought protected_headers 透传**：`v2_thought.go` 的 P2P/群组 thought 路径将 `protectedHeaders` 透传进 V2 envelope 构造（`buildV2P2PEnvelope`/`buildV2GroupEnvelope`），补齐与普通消息一致的受保护头处理

### 优化
- **app_message_envelope 字段收窄**：envelope 键收窄为可转发元数据（`from`/`to`/`group_id`/`type`/`kind`/`version`/`timestamp`/`encrypted`/`context`/`protected_headers`/`payload_type`），移除 `message_id`/`seq`/`device_id`/`slot_id` 等本地与传输层字段，不再向应用层泄漏内部字段并剔除 `_auth`（四语言对齐）
- **RPC 日志 token 脱敏**：`authRedactRPCLogPayload` 对短 RPC 请求/响应 debug 日志中 `access_token`/`refresh_token`/`kite_token`/`token` 及 `_token` 结尾键递归脱敏（`<redacted len=.. sha256=..>`），避免明文 token 落日志（四语言对齐）
- **V2 内部发送透传 message_id/timestamp**：`v2_routing.go` 将 `message_id`/`timestamp` 透传到 `EncryptOptions`，保证 V2 P2P/群组加密 envelope 携带稳定标识

### 测试
- `TestTokenGatewayReuse_RefreshFailureClearsCachedTokens`：验证刷新失败后本地 token 被清空
- `TestTokenGatewayReuse_ReloginRequiredRefreshError`：验证需重登错误触发清缓存与重登流程
- `TestAppMessageEnvelopeKeepsForwardableMetadata`：验证只保留可转发元数据
- 改写 `TestP2PRecallTombstonePublishesRecalledEvent` / `TestGroupRecallTombstonePublishesNoticeEnvelope` / `TestPublishedMessageEventsFallbackCurrentInstanceContext` 断言 envelope 收窄

### 服务端协同（本版本配套）
- **`auth.refresh_token` 响应结构化**：新增 `relogin_required` / `retryable` / `diagnostic` / `aid` / `refresh_count` 字段，SDK 据 `relogin_required`/`retryable` 区分"重新登录"与"退避重试"，不再单纯按 `error` 字符串判断
- **JWT 老 SDK 兼容与即时吊销**：`AUN_JWT_LEGACY_ACCESS_TOKEN_COMPAT`（默认开）放行合法 JWT 避免迁移期重连风暴；`auth.token.revoked` 事件携带 `jti`/`expires_at`，gateway 按真实 TTL 缓存吊销
- **V2 P2P 写入幂等**：服务端 `v2_write_peer_message`/`v2_write_peer_wrap` 捕获唯一键冲突逐字段比对，重发相同 message_id 幂等返回、不再产生 seq 空洞；自发自收跳过重复 self-sync 推送

---

## 0.4.12 — 2026-06-08

### 新功能
- **应用层事件信封（envelope）**：`message.*` 与 `group.changed` 事件发布给应用层时注入 `envelope` 字段，聚合 `message_id`/`seq`/`from`/`to`/`group_id`/`action` 等元数据；顶层别名字段在兼容期保留，计划于 `0.5.*` 移除，请改用 `envelope.*` 访问（四语言对齐）
- **撤回事件携带 message_id 与自身信封**：`recallEventFromMessage` / `recallEventFromGroupMessage` 补全 `message_id` 字段并继承原消息的信封键（四语言对齐）

### 修复
- **入群首个事件被旧序号阻塞**：`isSelfJoinGroupChanged` 识别自己入群后，将本地 `group_event` seq 基线对齐到 `event_seq-1`，避免被入群前不可见事件挡住（四语言对齐）
- **过期 token 重连死循环**：`reconnectLoop` 重连前同步 identity 中的 token 状态到 `sessionParams`，过期或缺失则清空以触发两阶段重新登录，避免反复用旧 token 触发 4001（四语言对齐）
- **Service Proxy 持久隧道重连**：新增指数退避（上限 60s，成功后重置）；`AuthError` 经 `handlePersistentTunnelError` 触发重新获取 access_token 后再重连（四语言对齐）
- **protected_headers 参数兼容**：`protectedHeadersFromParams` 同时识别 `protected_headers` 与 `headers` 别名，并兼容 `map[string]any` / `map[string]string` 两种类型；V2 P2P/群组加密路径同步使用
- **配额语义修正**：移除不存在的 `device_aids` 踢出场景描述，`4015` 仅覆盖 `aid_device_slot` / `aid_devices`

### 测试
- `TestProtectedHeadersFromParamsSupportsHeadersAlias`：验证 headers 别名与类型兼容
- `TestOnRawGroupChangedSelfJoinStartsVisibleEventBaseline`：验证入群事件基线对齐
- `TestOrderedGroupEventPullSkipsPermanentHoleAndPublishesReadyEvents`：验证永久空洞不阻塞后续群事件
- `TestGroupRecallTombstonePublishesNoticeEnvelope`：验证撤回通知携带自身信封

---

## 0.4.11 — 2026-06-08

### 新功能
- **Storage 目录树与扩展操作**：`storage.*` 新增 `create_folder`/`rename_folder`/`move_folder`/`delete_folder`/`move_object`/`copy_object`/`batch_delete`/`set_object_meta`/`append_object` 等方法，加入签名集合和非幂等集合（四语言+服务端对齐）
- **group.resources 树形资源系统**：新增 `create_folder`/`rename`/`move`/`mount_object`/`unmount`/`cleanup_by_storage_ref`/`request_mount_object`/`resolve_access_ticket` 等方法，加入签名集合和非幂等集合（四语言+服务端对齐）
- **group.changed 事件保序去重**：`handleGroupChangedEventSeq` 完整重构，支持 event_seq 去重、contiguous seq 追踪、空洞检测、自动 ack 机制（四语言对齐）
- **群解散本地清理**：`fillGroupEventGap` 中群解散事件不持久化 seq tracker 状态；解散时清理本地 V2 缓存和 seq 追踪（四语言对齐）

### 修复
- **RenewCert 签名协议**：改为仅对 raw nonce 签名，移除 `client_time` 参数，解决签名协议不一致问题
- **错误码映射**：`-32013` 从 `SessionError` 改为 `ClientSignatureError`
- **V2 E2EE goroutine use-after-close**：`scheduleGroupSpkRegistration`/`scheduleGroupSpkRotation` 改为捕获 session 局部变量，避免 goroutine 关闭后访问
- **V2 sender IK pending 批量删除**：改为锁外处理，避免长锁持有
- **storage/group.resources 签名和幂等性补全**：补全写操作方法进入签名集合与非幂等集合（四语言对齐）

### 优化
- **v2GetSecurityState 懒初始化**：改为 `sync.Once`，避免并发初始化竞态
- **群事件 gap 填充路径**：已填充事件进入有序队列而非直接发布；群解散事件跳过持久化

### 测试
- `TestAIDStoreRenewCertSignsRawNonce`：验证 RenewCert 签名协议修复
- `TestOrderedGroupEventPublishWaitsForGapFillAndDedups`：验证群事件去重和补洞
- `TestOnRawGroupChangedPushPersistsAndAcksContiguousEventSeq`：验证 push 事件 seq 持久化和 ack
- `TestStorageMutationMethodsAreNonIdempotent` / `TestGroupResourceSideEffectMethodsAreNonIdempotent`：验证签名方法覆盖
- `TestGroupEventGapFillAcksFinalContiguousAfterPublish`：修正预期 ack_seq（4→3）

---

## 0.4.10 — 2026-06-06

### 新功能
- **Service Proxy 服务代理**：新增 `service_proxy.go` 客户端（控制面 `proxy.register`/`unregister`/`list_services` + 数据面隧道）及 `cmd/service-proxy-holder`、`cmd/service-proxy-visitor` 工具（四语言对齐）
- **notify() 单向通知**：新增 `Notify()` 公开 API，发送无 id 的 JSON-RPC 2.0 Notification，只面向在线长连接、不落库、不分配 seq、无 ack（四语言对齐）
- **Storage 逻辑下载 URL**：支持干净逻辑下载 URL `storage.{issuer}/{user_name}/{object_key}`，无签名无 CAS

### 修复
- **群消息撤回（`group.message_recalled`）端到端打通**：新增在线 push 通道（`_raw.group.message_recalled`），与 pull 双 tombstone（占位 + 通知）兜底互补；push 路径推进 `notice_seq` 的 seq/ack 与普通群消息对齐，避免 seq 留洞导致重复拉取；按 `(group_id, message_ids)` 去重（去重键不含 `recalled_at`），确保应用层只回调一次（四语言+服务端对齐）
- `group.recall` 加入 RPC 白名单；`transport` 事件名映射补充 `group.message_recalled`

### 优化
- **ChangeSeed 健壮性增强**：key.json 重写覆盖前先做递增版本备份（`.v1`/`.v2`…），写入改用 `writeFileAtomic`（tmp+rename）；`LocalIdentityStore.saveKeyPairAtPath` 覆盖已有 key.json 前同样做版本备份并改用带 pid/时间戳的临时文件名（四语言对齐）

### 测试
- `notify_test.go`/`federation_notify_test.go`/`integration_notify_test.go` 覆盖 notify；`integration_service_proxy_test.go`/`service_proxy_test.go` 覆盖 service proxy；`keystore/file_test.go`/`go_fixes_test.go` 覆盖 ChangeSeed 版本备份

---

## 0.4.9 — 2026-06-03

### 修复
- V2 明文消息（P2P 和群组）投递时补充调用 `attachGatewayProximity()`，消息事件 payload 现可携带 `proximity`（`same_network`/`same_device`/`basis`/`asserted_by`）字段（四语言对齐）

### 优化
- `AUNClient` 运行时状态全面迁移至 `ClientRuntime` 统一抽象层，生命周期、消息投递、RPC 路由、身份、V2 E2EE、群组状态各子组件构造函数统一接收 `runtime` 参数，消除组件间直接引用主客户端对象
- `LifecycleController`、`MessageDeliveryEngine`、`GroupStateCoordinator`、`IdentityRuntimeManager` 的状态读写全部改为通过 `runtime.*` setter/getter，提升可测试性
- `RpcPipeline` 接管原 `AUNClient.Call()` 全部路由逻辑，主客户端 `Call()` 直接委托
- `Disconnect()` 和 `Close()` 委托给 `LifecycleController`，移除主客户端内联的状态管理代码

---

## 0.4.8 — 2026-06-03

### 新功能
- `AID` 新增 `PublicKeyFingerprint` 字段（SPKI SHA-256），构造时自动计算
- agent.md 签名块新增 `public_key_fingerprint` 字段，签名与验签均支持（四语言对齐）
- 新增 `normalizeFingerprintHex` / `matchPublicKeyFingerprint` 工具函数，支持 16 位短格式指纹匹配（四语言对齐）
- 新增在线未读 hint 队列（`onlineUnreadHintQueue`），同 group 去重 + 延迟 drain，降低登录瞬时拉取压力（四语言对齐）
- `verifyAgentMD` 支持从签名块提取 `expectedFP`，优先精确拉取对端证书（四语言对齐）
- `verifyAgentMDResultToMap` 输出 `public_key_fingerprint` 字段

### 修复
- agent.md 验签指纹比对改用 `matchCertFingerprint`（兼容 DER/SPKI 双格式），替代原直接字符串比较（四语言对齐）
- `fetchPeerCert` 移除带指纹失败后降级无指纹重试的回退逻辑（四语言对齐）
- `resolveAgentMDPeer` 支持按 `certFingerprint` 定向拉取并校验证书（四语言对齐）
- `DownloadAgentMD` 解析签名块指纹后定向拉取匹配证书（四语言对齐）
- `GetDeviceID` 目录创建失败时降级返回 `"default"`，修复原有 MkdirAll 失败后仍继续读写的问题

### 优化
- `AUNClient` 大规模拆分重构：client.go 变为薄层协调者，核心逻辑分散至 `LifecycleController`、`RpcPipeline`、`MessageDeliveryEngine`、`V2E2EECoordinator`、`GroupStateCoordinator`、`PeerDirectory`、`IdentityRuntimeManager` 等子组件
- `AIDStoreOptions` 移除 `DeviceID` 字段，改为内部自动调用 `GetDeviceID`（四语言对齐）

---

## 0.4.7 — 2026-06-01

### Added
- **`AIDStore.UploadAgentMD(ctx, aid, content...)`**：将 `UploadAgentMD` 从 `AUNClient` 迁移到 `AIDStore`，支持指定任意本地 AID 上传 agent.md；内部独立创建 `LocalTokenStore` 和 `AuthFlow` 完成认证，不依赖 `AUNClient` 实例。
- **`LocalIdentityStore.promotePendingIntoMetadataOnlyDir()`**：新增私有方法，支持将 pending 目录合并到仅含 metadata（无私钥/证书文件）的目标目录，修复特定场景下 pending 提升失败问题。

### Changed
- **`AUNClient.UploadAgentMD()`**：移除，功能迁移至 `AIDStore.UploadAgentMD(ctx, aid)`。
- **`AIDStore`**：新增内部 `tokenStore`（`*keystore.LocalTokenStore`）字段，供 upload 认证流程使用；`Close()` 时同步释放。
- **`keystore/aid_db.go`**：`slot_id_full` 列补齐逻辑提取为 `ensureSlotIDFullColumns()` 函数，供 `LocalIdentityStore` 和 `LocalTokenStore` 共用。
- **`transport.go`**：重连逻辑优化，补充测试覆盖。

---

## 0.4.6 — 2026-06-01

### Added
- **`LocalIdentityStore` 类型**（`keystore/local_identity_store.go`）：基于文件（key.json/cert.pem）+ SQLite 的身份存储，实现 `KeyStore` + `PendingIdentityKeyStore` + `MetadataKeyStore` + `TrustRootStore` 接口，支持 pending 崩溃恢复。替代 `FileKeyStore`。
- **`LocalTokenStore` 类型**（`keystore/local_token_store.go`）：基于文件 + SQLite 的 token/状态存储，实现 `TokenStore` + `StructuredKeyStore` + `InstanceStateStore` + `SeqTrackerStore` 接口，供 `AUNClient` / `AuthFlow` 使用。
- **`shared_utils.go`**（`keystore/shared_utils.go`）：提取公共工具函数（`safeRename`、`safeAID`、`normalizeCertFingerprint` 等），供两个 store 复用。
- **`AgentMdManager` 结构体**（`agent_md_manager.go`）：独立的 agent.md 管理器，提供 `Upload()`、`Download()`、`Check()` 方法，支持 ETag 缓存、后台自动拉取。
- **`agent_md_http.go`**：底层 HTTP 操作（`agentMDDownloadHTTP`、`agentMDHeadHTTP`、`agentMDUploadHTTP`），支持条件请求（304 Not Modified）。
- **`KeyStore` 接口新增方法**：`LoadCert(aid string)` / `SaveCert(aid string, certPEM string)`。
- **`RegisterFlow` 新增公开方法**：`ValidateAIDName`、`FetchPeerCert`、`ShortRPC`、`GenerateIdentity`、`NewClientNonce`、`SignLoginNonce`、`VerifyPhase1Response`、`ReloadTrustedRoots`。

### Changed
- **`AIDStore` 独立化**：移除对 `AUNClient` 的依赖，直接持有 `LocalIdentityStore`、`GatewayDiscovery`、`DnsResilientNet`；`NewAIDStore()` 不再创建完整客户端。
- **`AUNClient` 简化**：移除 agent.md 内部字段（`agentMdMu`、`agentMDPath` 等），改由 `AgentMdManager` 统一管理；keystore 初始化从 `NewFileKeyStore()` 改为 `NewLocalTokenStore()`。
- **`namespace.AuthNamespace` 瘦身**：移除 `SignAgentMD`、`VerifyAgentMD`、`UploadAgentMD`、`DownloadAgentMD` 等方法（约 650 行），相关类型一并移除。
- **`RegisterFlow` 配置**：`RegisterFlowConfig.Keystore` 类型从 `FullKeyStore` 改为 `pendingIdentityKeyStore`（`KeyStore + PendingIdentityKeyStore`）。
- **`keystore.SetLogger()`**：同时设置 `secretstore` 的 logger，确保日志一致性。

### Removed
- **`go/keystore/file.go`**（1323 行）：`FileKeyStore` 完整移除，功能分解为 `LocalIdentityStore` 和 `LocalTokenStore`。
- **`newClientForStore()` 函数**：`AIDStore` 不再依赖此内部构造函数。
- **`HeadAgentMdResult` 结构体**：HEAD 操作结果改由 `AgentMdManager` 内部处理。

### Fixed
- **Windows 文件重命名**（`keystore/shared_utils.go`）：`safeRename()` 在目标文件已存在时先删除再重命名，修复 Windows 下 `os.Rename()` 失败问题。

---

## 0.4.5 — 2026-05-31

### Added
- **`RegisterFlow` 独立结构体**（`register_flow.go`）：将 AID 注册流程从 `AuthFlow` 中剥离，负责 keypair 生成、服务端 RPC、pending 目录原子提交、崩溃恢复（`_pending` 目录扫描）。
- **`FileKeyStore` pending 目录 API**：`PendingIdentityDir` / `ListPendingIdentityDirs` / `SavePendingKeyPair` / `LoadPendingKeyPair` / `SavePendingCert` / `PromotePendingIdentity` / `DiscardPendingIdentity` / `CleanupPendingDirs`，支持注册原子性。
- **`keystore.FullKeyStore` 接口**：`TokenStore + KeyStore` 组合接口，供注册流程显式使用。

### Changed
- **`AuthFlow` 改用 `TokenStore`**：构造参数 `Keystore` 重命名为 `TokenStore`，类型收窄为不含私钥读写的接口；私钥操作全部移出 `AuthFlow`。
- **`AuthFlow.SetIdentity()`**：新增方法，由 `AUNClient` 注入内存私钥；`AuthFlow` 内部不再从 `tokenStore` 解密私钥。
- **`AIDStore` 持有独立 `keyStore` 和 `registerFlow`**：注册结果由 `AIDStore` 负责调用 `keyStore.SaveCert` / `SaveKeyPair` 写入，`RegisterFlow` 不直接写磁盘。
- **`FileKeyStore.restoreKeyPair`**：签名变更，新增 `persistPath` 可选参数，支持 pending 目录写入。

---

## 0.4.4 — 2026-05-31

### Added
- **`AID` 新增 `PrivateKeyPem` 字段**：`AIDStore.Load()` 加载时注入明文私钥，`AUNClient` 直接从 `AID` 读取，无需再经 keystore 解密。

### Changed
- **`AUNClient` 剥离私钥读写**：`initV2Session`、`signClientOperation`、`v2AutoProposeStateLocked` 均改从 `currentAIDObj.PrivateKeyPem` 读取，删除 keystore fallback 重解密路径。
- **`auth.persistIdentity` 不再写私钥**：写入前剥离 `private_key_pem` / `public_key_der_b64` / `curve`，AUNClient 的 keystore 只持久化 token / cert / instance_state。
- **`AUNClient` keystore 构造不再传 `encryptionSeed`**：seed 作用域收窄至 AIDStore，不外漏。
- **SQLite 明文化清理**：删除 `encryptText` / `decryptText` / `secretStore` 字段等加密残留，所有 SQLite 字段直接明文读写；删除 `resolveActiveEncryptionSeed`（`.seed` 文件自动迁移逻辑）。

---

## 0.4.3 — 2026-05-31

### Added
- **`NormalizeSlotID` / `SlotIsolationKey`**：新增 slot_id 校验与隔离键提取工具函数，支持 `/` `:` 空格作为分隔符（首字符不允许）。
- **`AUNLogger.Debug()`**：新增方法，返回 logger 当前 debug 开关状态。
- **`RPCTransport.SetVerifySSL` / `SetDnsNet`**：新增 setter，支持在未连接状态下动态更新 TLS 校验开关和 DNS 容灾网络层。
- **`NewAUNClient(aid)` 重构**：统一构造入口，`aid=nil` 等价于 `NewAUNClientEmpty()`；内部新增 `newClientForStore` 供 `AIDStore` 注入无身份客户端。
- **`CacheDiscoveredGatewayURL`**：新增公开方法，供 `namespace/auth` 层缓存 discovery 得到的 Gateway URL。
- **`buildSessionOptions`**：新增内部方法，统一合并 session 级参数（`connection_kind` / `short_ttl_ms` / `extra_info` / `delivery_mode` / `background_sync`）。
- **`rebuildRuntimeForIdentity`**：加载新 AID 时若 `aun_path` / `verify_ssl` 发生变化，自动重建 logger / keystore / dnsNet / discovery / auth 运行时组件。
- **keystore `columnExists`**：新增辅助函数，支持 schema 迁移时安全检测列是否存在。

### Changed
- **`ConnectOptions.DeliveryMode`**：注释更新，明确 fanout/queue 语义由后端配置决定；移除 `QueueRouting` / `AffinityTtlMs` 便捷字段（统一走 `DeliveryMode` map）。
- **`background_sync` 传参方式**：改为从 `sessionOptions` 读取，不再直接从 `opts.BackgroundSync` 注入，与 Python SDK 对齐。

---

## 0.4.2 — 2026-05-30

### Added
- **`AIDStore` 新增结构化返回类型**：`LoadResult`、`ListResult`、`RegisterResult`、`ExistsResult`、`HeadAgentMdResult`、`CheckAgentMdResult`、`ChangeSeedResult` 等，替代原来的裸字段返回。
- **`AID` 新增 `VerifySSL` / `RootCaPath` / `Debug` 字段**：由 `AIDStore` 在创建 `AID` 实例时注入，供内部 HTTP 请求使用。
- **`AUNClientOptions` 新增 `RootCaPath`**：支持私有部署指定自定义根证书路径。

### Changed
- **`AIDStore.Load` 返回类型变更**：`(*AID, error)` → `Result[LoadResult]`，与其他方法统一为 `Result[T]` 风格。
- **移除 `DiscoveryPort`**：`AUNClientOptions` 删除 `DiscoveryPort` 字段，gateway URL 改为纯自动发现。
- **`AIDStore` 内部注入 `verifySSL` / `rootCaPath` / `debug`**：创建 client 时自动透传这三个配置项。

---

## 0.4.0 — 2026-05-30

> **破坏性重构版本。** 与 Python SDK 0.4.0 对齐：身份管理剥离为 `AID` / `AIDStore`；删除 `Auth` / `Custody` / `Meta` 公开命名空间；引入字符串错误码；连接状态机扩展为 9 态；大量内部方法改为非导出。

### Breaking Changes
- **删除公开命名空间字段**：移除 `c.Auth`（公开访问）、`c.Custody`（`namespace/custody.go` 删除）、`c.Meta`（`namespace/meta.go` 删除）。
- **大量方法改为非导出**：`NewClient → newClient`、`SendV2 / PullV2 / AckV2 / SendGroupV2 / PullGroupV2 / AckGroupV2 → sendV2 / ...`、`FetchAgentMD / CheckAgentMD / Ping / Status / TrustRoots / ListIdentities / CheckGatewayHealth → fetchAgentMD / ...`。这些功能现通过 `AIDStore` 或 `client.Call()` 访问。
- **构造函数变更**：新增 `NewAUNClient(aid, opts)` / `NewAUNClientEmpty(opts)` 作为统一入口；`NewClient()` 改为非导出。
- **`Connect` 签名变更**：`Connect(ctx, auth, opts)` → `Connect(ctx, ...args)`；身份须先通过 `NewAUNClient(aid)` 或 `LoadIdentity(aid)` 加载。
- **连接状态类型变更**：对外 API 改为 9 态 `ConnectionState`（`ConnStateNoIdentity` / `ConnStateStandby` / `ConnStateAuthenticated` / `ConnStateConnecting` / `ConnStateReady` / `ConnStateRetryBackoff` / `ConnStateReconnecting` / `ConnStateConnectionFailed` / `ConnStateClosed`）；旧 `ClientState` 仅内部使用。
- **目录约定变更**：`{aun_path}/AgentMDs/` → `{aun_path}/AIDs/`。

### Added
- **`AID` 值对象**（`go/aid.go`）：封装证书 + 可选私钥，提供 `IsCertValid` / `IsPrivateKeyValid` / `Sign` / `Verify` / `SignAgentMd` / `VerifyAgentMd`。
- **`AIDStore` 身份管理器**（`go/aid_store.go`）：离线 `Load` / `List` / `Exists`，联网 `Register` / `Resolve` / `FetchAgentMD` / `Diagnose` / `RenewCert` / `Rekey` / `ChangeSeed`。
- **字符串错误码**（`go/error_codes.go`）：与 Python SDK 对齐的常量（`CERT_NOT_FOUND`、`IDENTITY_CONFLICT`、`KEYPAIR_MISMATCH` 等）；`AUNError` 新增 `StringCode` 字段，错误消息带 `[CODE]` 前缀。
- **`Authenticate(ctx, opts?)`**：完成两阶段认证并缓存 token，不建立长连接。
- **身份管理方法**：`LoadIdentity` / `CurrentAID` / `HasIdentity` / `CanSign` / `CanConnect`。
- **实例级 `protected_headers`**：`SetProtectedHeaders` / `GetProtectedHeaders`，自动合并到 `message.send` / `group.send` / `*.thought.put`。
- **对端 AID 缓存**：`CachePeer` / `GetPeer` / `LookupPeer` / `Peers`。
- **重连状态可观测**：`nextRetryAt` 字段，事件中携带 `next_retry_at` 时间戳。

### Fixed
- **事件 handler 执行顺序**：改为按注册顺序同步执行（原为独立 goroutine 异步，ISSUE-GO-006），与 Python / TS / JS SDK 对齐。
- **重连延迟随机数**：改用 `crypto/rand`（原 `math/rand`，ISSUE-GO-007，并发安全）。
- **手动重连恢复**：允许从 `reconnecting` / `disconnected` / `terminal_failed` 状态手动调 `Connect()` 恢复（ISSUE-GO-009）。
- **V2 session 初始化顺序**：提前到补拉前执行，避免 `message.pull` 提前 ack V2 设备副本。
- **移除 `PullV2` / `PullGroupV2` 强制 contiguous 逻辑**：不再强制推进 firstSeq，与 Python SDK 对齐。
- **Token 刷新竞态**：刷新期间检查连接状态，避免写回 stale identity。

### Removed
- 删除 `go/namespace/custody.go`、`go/namespace/meta.go`、`go/namespace/meta_test.go`。

---

## 0.3.6 — 2026-05-28

### Added
- **Encrypted push 解密管线**：收到加密推送时即时尝试 V2 解密，成功则发 `message.received` / `group.message_created`（含明文 payload + e2ee 元数据），失败则发 `message.undecryptable` / `group.message_undecryptable`（含诊断字段 `_decrypt_error` / `_decrypt_stage` / `_envelope_type`）
- **`Auth.FetchPeerCert(ctx, gatewayURL, aid)`**：公开 API 实现落地（v0.3.5 声明，v0.3.6 实现独立方法体）
- **`storage.get_limits` RPC**：查询上传限制和配额使用情况
- **`storage.check_upload` RPC**：上传预检（秒传检测 + 超限检测）

### Fixed
- **Identity cache 自愈**：V2 session init（`InitV2Session`）时检测 `private_key_pem` 缺失，自动从 keystore 重新加载并清理脏 instance_state
- **`LoadIdentity` 字段白名单**：只合并 `authInstanceStateFields` 定义的字段，防止 instance_state 表中的脏数据覆盖核心字段

### Changed
- **`PullV2` 支持 `force` 参数**：内部路由 `pullV2Internal` 透传 `force` 字段，跳过 SeqTracker contiguous_seq 优化
- **transport 诊断字段**：`diagParamFields` 新增 `force` 字段

---

## 0.3.5 — 2026-05-28

### Breaking Changes
- **`CreateAID` → `RegisterAID`**：客户端 API 重命名，旧方法已移除；`AuthCreateAID` → `AuthRegisterAID`
- **注册与认证分离**：`Authenticate()` 不再隐式注册；`EnsureAuthenticated()` 不再隐式创建身份

### Added
- **`IdentityConflictError`**：新增错误类型，AID 注册冲突时返回
- **`Auth.LoadIdentity()` / `Auth.LoadIdentityOrNil()`**：公开 API，只读加载本地已注册身份（密钥对 + 证书 + 实例状态），无副作用
- **`Auth.FetchPeerCert()`**：公开 API，获取对端 AID 证书 PEM（本地缓存优先，未命中走 PKI HTTP + 链验证）
- **Pull Gate**（`pull_gate.go`）：per-key 序列化 pull 操作，防止同一 namespace 并发 pull
- **RPC Inflight 限制**：transport 层 semaphore 控制（全局 16 + 后台 8），超时返回 `TimeoutError`
- **`assertCertMatchesLocalKeypair`**：Authenticate 前显式校验 cert 公钥与本地 keypair 一致
- **`authCertMatchesPubKey`**：辅助函数，比较 PEM 证书公钥与 base64 SPKI

### Changed
- **`RegisterAID` 半成品恢复**：本地有 keypair 无 cert 时，查服务端恢复；服务端无记录则用现有 keypair 注册
- **agent.md 元数据存储**：从全局 `list.json` 改为 per-AID `agentmd.json`
- **agent.md 下载**：改为无条件 GET；304 时本地有缓存直接用，无缓存重试
- **`loadIdentityOrRaise`**：`authValidateLoadedIdentity` 检查 keypair 完整性
- **`.seed` fallback 迁移**：`resolveActiveEncryptionSeed` 启动时检测旧 `.seed` 文件，自动迁移；迁移失败时 fallback 到旧 seed 内容
- **`ChangeSeed` API**：支持运行时更换 seed（重加密私钥和 DB 加密字段）

### Removed
- **`CreateAID` / `ensureLocalIdentity` / `ensureIdentity`**：已移除

## 0.3.3 — 2026-05-25

### Added
- **V2 Thought 加解密**：`attachV2EnvelopeMetadata` / `v2EnvelopePayloadType` 支持 thought 消息的 V2 envelope 元数据附加与类型判断
- **V2 Sender IK 延迟解密**：`scheduleV2SenderIKPending` / `scheduleV2SenderIKFetch` / `resolveV2SenderIKPending` / `decryptV2MessageWithPending`，对端 IK 未缓存时挂起消息、异步拉取后重试
- **V2 Group 事件处理**：`onRawGroupChangedV2` 处理群组变更事件的 V2 路径
- **agent.md 本地缓存体系**：`SetAgentMDPath` / `CheckAgentMD` / `PublishAgentMD` / `FetchAgentMD`；基于文件系统的 list.json 索引 + 按 AID 存储 + etag 比对
- **KeyStore agent_md_cache 持久化**：`AgentMDCacheRecord` / `AgentMDCacheUpsert` 结构体 + `LoadAgentMDCache` / `UpsertAgentMDCache`
- **`AuthLoadKeyPair` / `AuthLoadCert`**：从持久化 keystore 直接加载身份材料的便捷方法
- **`SeqTracker.UpdateMaxSeen` / `RepairContiguousSeq`**：支持 server_ack_seq 推进 retention floor
- **`GatewayDiscovery.DiscoverAll`**：返回所有可用网关 URL 列表（多网关容灾）
- **DNS 容灾**：`NewRPCTransport` / `NewGatewayDiscovery` 支持 `DnsResilientNet` 参数注入
- **签名跳过策略**：`shouldSkipClientSignature` / `shouldSkipEventSignature` 对内部方法和系统事件跳过签名
- **`clampAckSeq` / `clampAckParams`**：message.ack seq 参数自动钳位
- **`normalizeOutboundMessagePayload`**：发送前规范化消息载荷
- **`resolveGateways`**：从连接参数解析多网关列表

### Changed
- **V2 P2P 解密路径重构**：`getV2SenderPubDER` + `cacheV2PeerIKFromDevice` 统一对端 IK 获取与缓存
- **消息调试日志增强**：`logMessageDebug` / `logMessageDebugWithPayload` / `messagePayloadForDebug` / `messageEnvelopeFieldsForDebug`

### Fixed
- **service-plane envelope 解包**：修复 Kernel trace 字段传递丢失
- **trace 树状展示**：enter/exit 配对 + 嵌套缩进 + 按 ts 排序

---

## 0.3.1 — 2026-05-22

### Added
- **`AuthNamespace.CheckAID`**：本地证书自检（`inspectCert` 解析 X.509 有效期与公钥）+ 远端注册状态查询（`checkRemoteAIDRegistration`）；新增 `authValidateAIDName` / `checkLocalAID`
- **`AUNClient.AuthLoadKeyPair` / `AuthLoadCert`**：从持久化 keystore 直接加载身份材料的便捷方法
- **RPC trace 增强**：`RPCTransport` 增加 `SetTraceMode` / `GetTraceMode` / `SetTraceObserver`；`handleResponseTrace` / `invokeTraceObserver` 实现 enter/exit span 收集与树状展示
- **V2 群组 SPK 生命周期**：`V2KeyStore.SaveGroupSPK` / `LoadGroupSPK` / `LoadCurrentGroupSPK`；`V2Session.EnsureGroupSPK` / `EnsureGroupRegistered` / `RotateGroupSPK` / `GetGroupDecryptKeys` / `IsLastUploadedSPK` / `IsLastUploadedGroupSPK` / `publishGroupSPKLocked`

### Fixed
- short RPC 请求/响应增加 `Debug` 完整报文日志（`shortRPC` 双向打点），便于跨语言诊断

---

## 0.3.0 — 2026-05-21 ⚠️ BREAKING CHANGE

> **V2-only 版本**：移除全部 V1 E2EE（含群组加密），新增 V2 加密原语，API 不向后兼容。

### BREAKING
- **移除 V1 E2EE 全部实现**：`e2ee_group.go`、`e2ee_group_funcs.go`、epoch key 相关逻辑全部删除
- **移除 V1 群组加密测试**：`e2e_group_test.go`、`integration_epoch_key_server_test.go`、`integration_group_e2ee_test.go`
- **E2EE 接口简化**：`e2ee.go` 仅保留 V2 路径，V1 加解密方法不再可用
- **配置变更**：移除 V1 相关配置项

### Added
- **agent.md 主 API**：`AUNClient.PublishAgentMD(ctx, path)` / `AUNClient.FetchAgentMD(ctx, aid, savePath)` 返回 `*AgentMDInfo`
- **V2 加密原语**（跨语言 golden vector 一致性）：ECDH P-256、HKDF-SHA256、AES-256-GCM、ECDSA-SHA256 RAW (RFC 6979)、1DH/3DH wrap_key、Recipients Sort + Merkle Digest、State Commitment
- **V2 canonical JSON**：`v2/crypto/canonical.go`

### Removed
- `AUNClient.SetLocalAgentMDPath()` / `GetLocalAgentMDEtag()` / `GetRemoteAgentMDEtag()` — 由主 API 自动维护

### Deprecated
- `client.Auth.SignAgentMD` / `VerifyAgentMD` / `UploadAgentMD` / `DownloadAgentMD` — 建议迁移到 `client.PublishAgentMD` / `client.FetchAgentMD`

---

## 0.2.20 — 2026-05-18

### Added
- **agent.md 版本一致性 API**：`AUNClient.SetLocalAgentMDPath(path) string` / `GetLocalAgentMDEtag() string` / `GetRemoteAgentMDEtag() string`。用 `os.ReadFile` + `crypto/sha256` 计算 etag，`sync.RWMutex` 保护字段。SDK 自动从 RPC envelope `_meta.agent_md_etag` 提取服务端 etag，应用层订阅 `message.received` / `group.message_created` 等事件时 payload 多 `_agent_md.{local_etag, remote_etag}` 字段供版本比对。
- **`DownloadAgentMD` 条件请求缓存**：内部维护 ETag/Last-Modified，未变化时返回上次缓存内容；外部 API 形态不变。
- **transport meta observer**：`RPCTransport.SetMetaObserver(func(map[string]any))` 透传 envelope `_meta`，observer panic 被 recover 吞掉，不影响 RPC result。

### Changed
- **RPC call 默认超时 10s → 35s**：与服务端 30s handler timeout 对齐，留 5s buffer。
- **multi-device 架构**：对端无 prekey 时 `Send(encrypt: true)` 直接返回错误（`no registered device prekeys for ...`），不再降级到 `long_term_key`。

---
