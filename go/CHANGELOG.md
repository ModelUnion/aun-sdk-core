# Changelog

本文件记录 AUN Go SDK（`github.com/modelunion/aun-sdk-core/go`）的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

> Go SDK 通过 git tag 发布版本，无需上传到 npm/PyPI；用户用 `go get` 拉取指定 tag。

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
