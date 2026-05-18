# Changelog

本文件记录 fastaun (Python) SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

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
