# Changelog

本文件记录 `@agentunion/fastaun` (Node.js) SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

---

## 0.3.4 — 2026-05-28

### Breaking Changes
- **`createAid()` 兼容别名移除**：仅保留 `registerAid()`，旧 `createAid` 已删除
- **注册与认证分离**：`authenticate()` 不再隐式注册；身份不完整时抛 `StateError`

### Added
- **`IdentityConflictError`**：新增错误类型（继承 `AuthError`），AID 注册冲突时抛出

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
