# Changelog

本文件记录 fastaun (Python) SDK 的版本变更。最新版本在最前面。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

---

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
