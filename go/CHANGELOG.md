# Changelog

本文件记录 AUN Go SDK（`github.com/modelunion/aun-sdk-core/go`）的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

> Go SDK 通过 git tag 发布版本，无需上传到 npm/PyPI；用户用 `go get` 拉取指定 tag。

---

## 0.3.4 — 2026-05-28

### Breaking Changes
- **`CreateAID` → `RegisterAID`**：客户端 API 重命名，旧方法已移除；`AuthCreateAID` → `AuthRegisterAID`
- **注册与认证分离**：`Authenticate()` 不再隐式注册；`EnsureAuthenticated()` 不再隐式创建身份

### Added
- **`IdentityConflictError`**：新增错误类型，AID 注册冲突时返回
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
