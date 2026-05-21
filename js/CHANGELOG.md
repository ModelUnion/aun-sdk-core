# Changelog

本文件记录 `@agentunion/fastaun-browser` SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

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
