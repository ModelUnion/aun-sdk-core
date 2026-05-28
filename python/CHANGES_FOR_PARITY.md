# Python SDK 变更清单（v0.3.3 → v0.3.6）— 跨 SDK 对齐参考

本文档供 Go / TypeScript / JavaScript / C++ SDK 进行功能对齐时使用，详尽列出从 v0.3.3
到 v0.3.6 期间 Python SDK 的实际变更，定位到具体类、函数与代码行。按重要程度
（Breaking → 安全/认证 → API 公开面 → 内部机制 → CLI/工具 → Bug 修复）排序。

涉及提交：`af5c6ed7` (v0.3.3) → `5b75e33e` (v0.3.4) → `74d4fb7a` (OCSP/CRL fail-open + check_agent_md) → `33344726` (旧 SPK 私钥内存缓存) → `fef5a6ee` (v0.3.5) → 工作区 (v0.3.6)。

CHANGELOG（接口级摘要）：见 `python/CHANGELOG.md`。本文档为**实现级别详尽清单**。

---

## 0. v0.3.5 → v0.3.6 变更（最新，优先对齐）

### 0.1 Encrypted Push 解密管线（核心新功能，所有 SDK 必须对齐）

收到加密推送消息时，SDK 在 push 路径即时尝试 V2 解密，而非等待应用层手动处理。

#### `client.py — AUNClient`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `_is_encrypted_push_message(msg)` | 判断推送消息是否为加密消息（检查 `encrypted` 标志或 payload 结构） |
| 新增 | `_is_encrypted_envelope_payload(payload)` | 判断 payload 是否为 E2EE 信封（`type` 以 `e2ee.` 开头，或含 `ciphertext` + 密码学字段） |
| 新增 | `_encrypted_push_envelope(msg)` | 从 `msg.payload` 或 `msg.envelope_json` 提取加密信封 |
| 新增 | `_is_v2_encrypted_envelope_payload(envelope)` | 判断信封是否为 V2 格式（`e2ee.p2p_encrypted` / `e2ee.group_encrypted`） |
| 新增 | `_decrypt_encrypted_push_payload(msg, group=)` | 尝试 V2 解密，成功返回明文 dict，失败返回 None |
| 新增 | `_safe_undecryptable_push_event(msg, group=)` | 构造 undecryptable 事件 payload（含 `_decrypt_error` / `_decrypt_stage` / `_envelope_type` / `_suite`） |
| 新增 | `_publish_encrypted_push_message(event, undecryptable_event, ns, seq, msg, group=)` | 编排：尝试解密 → 成功发 normal event → 失败发 undecryptable event |
| 修改 | `_handle_message_push(msg)` | P2P 推送路径：检测到加密消息时走 `_publish_encrypted_push_message` 而非直接 `_publish_ordered_message` |
| 修改 | `_handle_raw_group_message_created(data)` | 群推送路径：同上，加密消息走新管线 |

**对齐要点**：
- 事件名：P2P 成功 `message.received`，失败 `message.undecryptable`；群成功 `group.message_created`，失败 `group.message_undecryptable`
- undecryptable payload 必须包含：`message_id`, `from`, `seq`, `timestamp`, `_decrypt_error`, `_decrypt_stage`
- 解密成功时 payload 中附加 `encrypted: True` + `e2ee` 元数据字典
- 群消息的 seq tracking / ack 逻辑在加密路径中也必须正确执行

### 0.2 Identity Cache 自愈（Bug 修复，所有 SDK 必须对齐）

#### `client.py — _init_v2_session` 区域

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | V2 session init 时 `private_key_pem` 缺失检测 | 若缓存的 `self._identity` 无 `private_key_pem`，从 keystore 重新加载 |
| 新增 | 自愈持久化 | 重新加载成功后调用 `self._auth._persist_identity(reloaded)` 清理脏 instance_state |
| 日志 | `"V2 session init: identity cache was stale, reloaded from keystore"` | WARN 级别 |

**对齐要点**：所有 SDK 的 V2 session 初始化路径必须有此 fallback，否则 instance_state 被污染后 V2 E2EE 永久不可用。

### 0.3 `load_identity` 字段白名单（Bug 修复，所有 SDK 必须对齐）

#### `auth.py — AuthFlow._load_identity`

| 状态 | 符号 | 说明 |
|---|---|---|
| 修改 | `identity.update(instance_state)` → 白名单合并 | 只合并 `_INSTANCE_STATE_FIELDS` 中定义的字段，防止 instance_state 表中的脏数据覆盖 `private_key_pem` 等核心字段 |

**对齐要点**：各 SDK 的 `loadIdentity` / `LoadIdentity` 必须同步此修复。白名单字段列表参考 Python `AuthFlow._INSTANCE_STATE_FIELDS`。

### 0.4 Storage 新增 RPC（功能扩展）

| 方法 | 说明 | 对齐要点 |
|---|---|---|
| `storage.get_limits` | 查询上传限制和配额 | 纯 RPC 调用，无客户端特殊逻辑 |
| `storage.check_upload` | 上传预检（秒传 + 超限） | 纯 RPC 调用，客户端可在上传前调用优化流程 |

### 0.4b `auth.fetch_peer_cert` 公开 API（所有 SDK 必须对齐）

v0.3.5 新增了 `auth.load_identity` / `auth.fetch_peer_cert` 等公开 API，但 `fetch_peer_cert` 在 v0.3.6 才真正暴露为独立公开方法（之前仅作为内部 `_download_registered_cert` 存在）。

| 语言 | 方法签名 | 说明 |
|---|---|---|
| Python | `await auth.fetch_peer_cert(gateway_url, aid) -> str | None` | 未注册返回 None |
| TS | `await auth.fetchPeerCert(gatewayUrl, aid): Promise<string | null>` | 未注册返回 null |
| JS | `await auth.fetchPeerCert(gatewayUrl, aid): Promise<string | null>` | 同 TS |
| Go | `auth.FetchPeerCert(ctx, gatewayURL, aid) (string, error)` | 未注册返回空串 |

**对齐要点**：纯代理到内部 `downloadRegisteredCert`，无额外逻辑。

### 0.5 TS 特有变更

| 模块 | 变更 | 说明 |
|---|---|---|
| `secret-store/file-store.ts` | `.seed.migrated.*` fallback | 解密失败时自动尝试旧 seed 文件，兼容半迁移状态 |
| `namespaces/auth.ts` | `_persistGatewayUrl` | `registerAid` / `authenticate` 成功后持久化 gateway_url |

### 0.6 Transport 诊断字段扩展

#### `transport.py` / `transport.go` / `transport.ts`

| 状态 | 符号 | 说明 |
|---|---|---|
| 修改 | `_DIAG_PARAM_FIELDS` / `diagParamFields` | 新增 `"force"` 字段到诊断参数白名单 |

**对齐要点**：各 SDK transport 层的诊断参数白名单需同步添加 `force`。

### 0.7 Go `PullV2` 支持 `force` 参数

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `pullV2WithForce(ctx, afterSeq, limit, force)` | 内部方法，`force=true` 时跳过 SeqTracker contiguous_seq 优化 |
| 修改 | `pullV2Internal` | 从 params 提取 `force` 字段并透传 |

**对齐要点**：Python 已在 v0.3.5 支持 `force` 参数（`message.v2.pull` 的 `force` 字段），Go 在 v0.3.6 补齐。TS/JS 需确认是否已支持。

---

## 1. 注册与认证彻底分离（Breaking，最高优先级）

> 设计原则：`authenticate()` / `ensure_authenticated()` 绝不再隐式生成密钥或注册新 AID。
> 所有新身份必须由应用层显式调用 `register_aid()`。

### 1.1 `auth.py — AuthFlow`

| 状态 | 符号 | 说明 |
|---|---|---|
| 重命名 | `create_aid()` → `register_aid()` | 客户端 API 重命名。服务端 RPC 方法名 `auth.create_aid` 不变，仅 SDK 对外接口改名 |
| 重写 | `register_aid(gateway_url, aid)` | 6 步严格流程：① 本地 keypair 存在 → 查服务端做幂等/恢复；② 本地无 keypair → 先查服务端确认未占用；③ 生成 keypair；④ RPC 注册；⑤ 校验 cert 公钥 == keypair 公钥；⑥ 持久化。冲突场景统一抛 `IdentityConflictError` |
| 移除 | `_ensure_local_identity(aid)` | 已彻底删除。原行为：本地无身份时自动生成密钥 |
| 移除 | `_ensure_identity()` | 已彻底删除。原行为：异常时自动生成密钥 |
| 修改 | `ensure_authenticated(gateway_url)` | 不再调用 `_ensure_identity`，改为调用 `_load_identity_or_raise()`；无 cert 直接抛 `StateError`，不再触发 `_create_aid` |
| 修改 | `authenticate()` 内部 | 移除 "not registered" 自动重注册分支；登录失败原样上抛，绝不回退到注册 |
| 新增 | `_assert_cert_matches_local_keypair(identity)` | "防线 B"：发起两阶段登录前显式校验 cert 公钥与本地 keypair 公钥一致；不一致抛 `AuthError` |
| 加固 | `_load_identity_or_raise(aid)` | "防线 A"：拒绝半成品 identity（缺 `private_key_pem` 或 `public_key_der_b64` 任一字段都直接抛 `StateError`） |
| 修改 | 错误消息 | 所有 `auth.create_aid()` 引用更新为 `auth.register_aid()` |

### 1.2 `namespaces/auth_namespace.py — AuthNamespace`

| 状态 | 符号 | 说明 |
|---|---|---|
| 重命名 | `create_aid()` → `register_aid()` | namespace 方法重命名 |
| 重写 | `register_aid(params)` | 调用 `AuthFlow.register_aid()`，不再有半成品兜底 |

### 1.3 `errors.py`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `IdentityConflictError(AuthError)` | AID 注册冲突专用错误类型，code 4090 |
| 导出 | `__init__.py` 导出 `IdentityConflictError` | 可直接 `from aun_core import IdentityConflictError` |

**对齐要点**：所有 SDK 必须将"已存在 AID 注册"或"公钥不匹配"场景统一映射到该错误类型；
登录失败绝不能触发自动注册（防止密钥被静默覆盖）。

---

## 2. RPC 并发与超时治理（核心机制）

### 2.1 `transport.py — RPCTransport`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增常量 | `_MAX_RPC_INFLIGHT = 16` | 全局最大并发 RPC 数 |
| 新增常量 | `_MAX_BACKGROUND_RPC_INFLIGHT = 8` | 后台 RPC 独立限制（避免后台流量挤占前台） |
| 新增字段 | `_rpc_semaphore: asyncio.Semaphore(16)` | 全局信号量 |
| 新增字段 | `_background_rpc_semaphore: asyncio.Semaphore(8)` | 后台信号量 |
| 修改签名 | `call(method, params, *, timeout, trace, background=False)` | 新增 `background` 入参 |
| 拆分 | `call()` → `_call_inner()` | 外层做信号量获取/释放（先全局后后台），内层做实际 RPC；排队超时抛 `TimeoutError(retryable=True)` |
| 错误细化 | `"rpc queue timeout before send: <method>"` / `"rpc background queue timeout before send: <method>"` | 区分两种排队超时 |

**对齐要点**：所有 SDK 必须在 transport 层引入并发限制，否则服务端易被后台同步类调用打爆。
各语言可用对应同步原语（Go: `chan struct{}`/`semaphore.Weighted`；TS/JS: `p-limit` 或自实现）。

### 2.2 `client.py — Pull Gate（per-key 序列化）`

防止同一 namespace 的 `message.pull` / `group.pull` / `group.pull_events` 并发执行。

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增字段 | `self._pull_gates: dict[str, dict]` | per-key 闸门状态 `{inflight, started_at, token}` |
| 新增 | `_pull_gate_key_for_call(method, params)` | 根据方法和参数派生闸门 key |
| 新增 | `_try_acquire_pull_gate(key)` → `int | None` | 非阻塞 try-acquire，返回 token；冲突返回 None |
| 新增 | `_release_pull_gate(key, token)` | token 校验防错误释放 |
| 新增 | `_run_pull_serialized(key, operation)` | 协程级串行化包装器 |

**对齐要点**：被关进 gate 的方法清单需对齐：`message.pull` / `group.pull` /
`group.pull_events`。其他 namespace（`storage.pull`、`stream.pull`）暂不限制。

### 2.3 `client.py — P2P Pull 待补机制`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增字段 | `self._pending_p2p_pull_upper: dict[str, int]` | per-namespace 已 push 但未拉到的 seq 上界 |
| 新增 | `_record_pending_p2p_pull(ns, seq)` | 标记需要 pull 的最高 seq |
| 新增 | `_schedule_pending_p2p_pull_if_needed(ns, *, reason)` → `bool` | 视情况派发后台 pull；reason 用于诊断日志 |
| 新增清理 | `disconnect()` / `close()` | 清空 `_pending_p2p_pull_upper`，避免跨连接残留 |

**对齐要点**：该机制是双重修复（push 通知 + 主动 pull）的核心，所有 SDK 都必须实现，否则消息丢失场景下无法自愈。

---

## 3. E2EE V2 — 1DH Per-AID Wrap + Wrap Policy（协议级，必须对齐）

### 3.1 `client.py — V2 Wrap Policy`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `_v2_normalize_wrap_policy(raw) -> dict[str,str] | None` | 规范化服务端下发的 wrap policy（"1DH" / "3DH" / "1DH+3DH"） |
| 新增 | `_v2_wrap_capabilities() -> dict` | 上行声明本端支持的 wrap 协议组合 |
| 新增 | `_v2_apply_wrap_policy_to_targets(targets, wrap_policy)` | 将 policy 应用到 target 列表（决定每个 target 走哪条 wrap 路径） |
| 修改 | `bootstrap` 处理 | 解析 `bootstrap.e2ee_wrap_policy` 字段并落到 prekey/peer 缓存元组（cached[4] / cached[7]） |
| 修改 | 上行 hello 增加 | `client.e2ee_wrap_capabilities = _v2_wrap_capabilities()`，多个 hello/bootstrap 路径都注入 |

**对齐要点**：服务端通过 bootstrap 下发的 `e2ee_wrap_policy` 决定接收方如何解 wrap。
未对齐的 SDK 可能在 1DH-only 场景下仍尝试 3DH，导致解密失败。

### 3.2 `v2/e2ee/encrypt_p2p.py`

| 状态 | 改动 | 说明 |
|---|---|---|
| 改字段名 | `protected_headers["sdk_vesion"]` → `["sdk_version"]` | **修复历史拼写错误**。所有 SDK 必须同步修复 |
| 改取值 | `_SDK_VERSION = "0.3.2"` 硬编码 → `from ...version import __version__` | 版本号自动跟随包 |

### 3.3 `v2/e2ee/decrypt.py — `_find_my_row`

| 状态 | 改动 | 说明 |
|---|---|---|
| 修改 | `if row[0] == self_aid and row[1] == self_device_id` → `... and (row[1] == self_device_id or row[1] == "")` | 兼容 server 把 device_id 留空（per-AID wrap）的场景 |

**对齐要点**：1DH Per-AID Wrap 场景下，发送方不知道接收方具体 device_id，会用空串作为 row[1]
进行 wrap。各 SDK 解密时必须放行 `row[1] == ""` 的匹配。

### 3.4 `v2/session.py — V2Session 旧 SPK 私钥内存缓存`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增字段 | `self._spk_cache: dict[str, bytes]` | 旧 SPK ID → 私钥的内存缓存 |
| 修改 | `get_decrypt_keys(spk_id)` | 命中缓存直接返回；DB 命中后写入缓存 |

**对齐要点**：避免每次解旧消息都查 DB，P95 延迟改善明显。Go/TS/JS/C++ 已同步对齐（commit 33344726）。

---

## 4. 公开 API 扩展（v0.3.5 新增）

### 4.1 `namespaces/auth_namespace.py`

| 状态 | 符号 | 签名 | 副作用 |
|---|---|---|---|
| 新增 | `load_identity(params)` | `dict | None → dict` | 无；身份不存在抛 `StateError` |
| 新增 | `load_identity_or_none(params)` | `dict | None → dict | None` | 无；身份不存在返回 None |
| 新增 | `fetch_peer_cert(params)` | `dict → str (PEM)` | 本地缓存 miss 时走 PKI HTTP；缓存到 keystore `public/certs/` |

跨语言对照：

| 语言 | 方法名 |
|---|---|
| Python | `client.auth.load_identity` / `load_identity_or_none` / `fetch_peer_cert` |
| TS | `client.auth.loadIdentity` / `loadIdentityOrNull` / `fetchPeerCert` |
| JS | `client.auth.loadIdentity` / `loadIdentityOrNull` / `fetchPeerCert` |
| Go | `client.Auth.LoadIdentity` / `LoadIdentityOrNil` / `FetchPeerCert` |

### 4.2 `auth.py — AuthFlow`（被 namespace 转发的内部方法）

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `load_identity(aid)` | 加载完整身份（keypair + cert + instance_state 合并） |
| 新增 | `load_identity_or_none(aid)` | 同上，不存在返回 None |
| 新增 | `get_access_token_expiry(identity)` | 从 identity 提取 access_token 过期时间 |
| 新增 | `set_instance_context(*, device_id, slot_id)` | 配置当前实例上下文 |

### 4.3 `auth.py — login hello 增加 client metadata`

```python
"client": {
    "slot_id": ...,
    "sdk_lang": "python",      # 新增
    "sdk_version": __version__, # 新增
}
```

**对齐要点**：服务端用这两个字段做客户端版本统计与兼容处理。所有 SDK 必须在 hello/login 上行
同样位置加上 sdk_lang / sdk_version。

---

## 5. agent.md 元数据存储重构

### 5.1 `client.py — 全局 list.json → per-AID agentmd.json`

| 状态 | 旧符号 | 新符号 |
|---|---|---|
| 重构 | `_agent_md_list_path()` | `_agent_md_meta_path(aid)` |
| 重构 | `_agent_md_list_lock()` | `_agent_md_record_lock(aid)` |
| 重构 | `_write_agent_md_list_unlocked(records)` | `_write_agent_md_record_unlocked(aid, record)` |
| 重构 | `_read_agent_md_list_unlocked()` | `_read_agent_md_record_unlocked(aid)` |
| 重构 | `_normalize_agent_md_list(data)` | `_normalize_agent_md_record(aid, data)` |
| 移除 | `_rebuild_agent_md_list_unlocked()` | 不再需要全局重建 |

**对齐要点**：旧版所有 SDK 共用 `list.json` 单文件存所有 AID 的元数据，多进程写易冲突。
新版按 AID 分文件存 `{aid}/agentmd.json`。TS / C++ 已对齐。Go / JS 须按此模式重构。

### 5.2 `client.py — agent.md 下载策略变更`

| 改动 | 说明 |
|---|---|
| 移除 If-None-Match / If-Modified-Since | 改为无条件 GET |
| 304 处理 | 本地有缓存直接用；无缓存重试无条件 GET |

**理由**：双重缓存（HTTP cache + 本地 etag 比对）会导致 etag 不一致时无法收敛。

### 5.3 `client.py — check_agent_md 增强`（commit 74d4fb7a）

| 状态 | 改动 | 说明 |
|---|---|---|
| 新增分支 | 远端有 + 本地无 | 自动调度 `_schedule_agent_md_fetch_if_missing` 后台拉取 |
| 新增分支 | 远端无 + 本地无 + 在缓存窗口内 | 跳过 HEAD 请求，直接返回 `cached: True` |
| 修复 | `checked_at` fallback 到 `fetched_at` | fetch 后缓存能被 fresh 判定识别 |

---

## 6. KeyStore 加密与 Seed 迁移（数据安全级）

### 6.1 `keystore/seed_migration.py`（**新文件，416 行**）

提供 `.seed` fallback 迁移和 `change_seed` 两个核心能力。

| 符号 | 说明 |
|---|---|
| `class SeedMigrationError` | 迁移错误基类 |
| `class SeedMigrationResult` | 携带 `migrated/skipped/active_seed/private_keys_migrated/seed_files_renamed` 等结果 |
| `migrate_seed_materials(root, seed_password) -> SeedMigrationResult` | 启动时检测旧 `.seed` 文件，自动迁移到 `seed_password` 派生方式；迁移失败时 fallback 到旧 seed 内容；旧 `.seed` 重命名为 `.seed.migrated.<ts>` 保留 |
| `change_seed(root, old_seed, new_seed, *, logger=None) -> SeedMigrationResult` | 运行时换 seed：解密所有私钥（PEM）+ DB 加密字段，用新 seed 重新加密 |

### 6.2 `keystore/sqlite_db.py`

| 状态 | 改动 | 说明 |
|---|---|---|
| 改写 | `load_or_create_seed(root, *, encryption_seed)` | 不再生成随机 .seed；直接用 encryption_seed 派生；存在旧 .seed 时调 `migrate_seed_materials` |
| 增强 | `_decode_secret_part(value)` | 支持 hex 与 base64 双格式解码（迁移期间兼容） |
| 修改 | `_protect_text` / `_reveal_text` | 移除 `not self._seed_bytes` 短路（空 seed 也加密） |

### 6.3 `keystore/file.py — FileKeyStore`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `FileKeyStore.ChangeSeed(aun_path, old_seed, new_seed)` (静态) | 类方法变体 |
| 新增 | `FileKeyStore.change_seed(old_seed, new_seed)` (实例) | 关闭当前 DB → 调 `change_seed()` → 重置 `_seed_bytes` 与 `_sqlite_key` |

**对齐要点**：所有 SDK 都必须支持 seed 迁移；尤其 SQLCipher 后端，old seed → new seed
切换需要原子完成（中途崩溃不能损坏数据）。Go / TS 已实现，JS（IndexedDB）适配后已对齐。

---

## 7. PKI / 对端证书获取重构

### 7.1 `client.py — _fetch_peer_cert 拆分`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `_normalize_bootstrap_ca_chain(material)` (静态) | 兼容 `ca_chain` / `ca_chain_pems` / `cert_chain` / `chain` 多种字段名 |
| 新增 | `_validate_and_cache_peer_cert(...)` | PKI 链校验 + AID 绑定校验 + 缓存到 `cert_cache` 与 keystore `public/certs/` |
| 新增 | `_prime_bootstrap_peer_certs(bootstrap, peer_aid)` | 从 bootstrap 内嵌的 ca_chain 直接导入对端证书，避免发首条消息时再做 HTTP |
| 重构 | `_fetch_peer_cert(aid, cert_fingerprint)` | 拆分为：本地 keystore → cache → bootstrap 预加载 → HTTP PKI；任一阶段成功后落 cache |

### 7.2 跨域证书路由

| 改动 | 说明 |
|---|---|
| `_resolve_peer_gateway_url(gateway_url, aid)` 用法 | 验证 + OCSP + CRL 都用 peer 域 Gateway，不再用本端 Gateway |

**对齐要点**：跨域消息收发必须能从 peer 所在域获取证书；Gateway 同时具备代理 fallback 能力。

---

## 8. CLI 增强（`aun_cli`）

### 8.1 `aun_cli/commands/agentmd.py`（**新文件，143 行**）

新增 `aun_cli agentmd` 子命令树：

| 命令 | 说明 |
|---|---|
| `agentmd path [PATH]` / `set-path` / `set_agent_md_path` | 设置/查询 agent.md 本地存储根目录（保存到 profile） |
| 其他子命令 | 与 SDK `publish/fetch/check_agent_md` 对应 |

### 8.2 `aun_cli/commands/keys.py`

| 状态 | 符号 | 说明 |
|---|---|---|
| 新增 | `keys change-seed --old-seed --new-seed [--aun-path]` | CLI 暴露 seed 迁移；`--old-seed=.seed` 表示读取数据目录下的 `.seed` 文件 |

---

## 9. 版本号统一

| 文件 | 0.3.3 → 0.3.5 |
|---|---|
| `pyproject.toml` | `version = "0.3.5"` |
| `src/aun_core/__init__.py` | `__version__ = "0.3.5"` |
| `src/aun_core/version.py`（新文件） | `__version__ = "0.3.5"` |
| `src/aun_core/v2/e2ee/encrypt_p2p.py` | 移除硬编码常量，改 `from ...version import __version__` |

**对齐要点**：所有 SDK 在 V2 envelope `protected_headers.sdk_version` 字段写入实际版本号，
不要硬编码。

---

## 10. 测试新增

| 文件 | 内容 |
|---|---|
| `tests/unit/test_seed_migration.py`（**新**，152 行） | 旧 `.seed` → 新 seed_password 迁移单元测试 |
| `tests/unit/test_cli_agentmd.py`（**新**，214 行） | CLI agent.md 子命令测试 |
| `tests/e2e_test_v2_1dh_wrap.py`（**新**，252 行） | 1DH Per-AID Wrap 端到端 |
| `tests/conformance/test_e2ee_v2_spk_id_semantics.py` | spk_id 语义对齐 |
| `tests/conformance/test_m2_p2p_encrypt.py` | 统一 sdk_version 引用 |
| `tests/unit/test_auth.py` / `test_connection_kind.py` | hello.client.sdk_lang/sdk_version 断言更新 |
| `tests/unit/test_client.py` | Pull Gate / pending p2p pull 测试 |

---

## 11. 文档更新（仅信息同步）

| 文件 | 关键改动 |
|---|---|
| `python/CHANGELOG.md` | 新增 0.3.5 节 |
| `docs/sdk/04-连接与认证.md` | v0.3.4 行为变更说明、半成品恢复说明、v0.3.5 身份查询 API 说明 |
| `docs/sdk/06-API手册.md` | `register_aid` / `load_identity` / `fetch_peer_cert` API 文档 |
| `src/aun_core/docs/skill/...` | 同步快速开始、认证文档；移除 create_aid 引用 |

---

## 跨 SDK 对齐优先级建议

1. **P0（不对齐会破坏互操作）**
   - 注册和认证彻底分离（移除登录路径下的隐式注册）
   - V2 1DH Per-AID Wrap：`row[1] == ""` 兼容 + wrap_policy 协商
   - `protected_headers.sdk_version`（修复 `sdk_vesion` 拼写）
   - `IdentityConflictError` 错误类型

2. **P1（功能等价）**
   - `auth.load_identity` / `auth.fetch_peer_cert` 公开 API
   - RPC inflight 限制（16 / 8）
   - Pull Gate per-key 串行化
   - `agent.md` 元数据 per-AID 分文件
   - V2Session 旧 SPK 私钥内存缓存

3. **P2（运维体验）**
   - `change_seed` API + CLI 命令
   - bootstrap 内嵌 ca_chain 预加载对端证书
   - check_agent_md 自动下载缺失文件

---

## 引用

- 提交：`af5c6ed7` / `5b75e33e` / `74d4fb7a` / `33344726` / `fef5a6ee`
- 主要源文件：`python/src/aun_core/{auth,client,transport,errors,version}.py`、
  `python/src/aun_core/keystore/{file,sqlite_db,seed_migration}.py`、
  `python/src/aun_core/namespaces/auth_namespace.py`、
  `python/src/aun_core/v2/{session,e2ee/encrypt_p2p,e2ee/decrypt}.py`
