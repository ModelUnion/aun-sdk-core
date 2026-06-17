# AUNClient 拆分重构执行方案

## 背景

当前 Python / Go / TypeScript / JavaScript SDK 的 `AUNClient` 都承担了过多职责。以 Python SDK 为例，`python/src/aun_core/client.py` 已超过 7000 行，`AUNClient` 同时管理身份运行时、认证连接、RPC 调用、事件分发、消息顺序、补洞、自动 ack、V2 E2EE、群状态链、证书缓存、后台任务和重连状态。

重构目标不是拆公开 API，而是把内部状态机和编排逻辑拆成可测试、可迁移、跨 SDK 一致的内部组件。外部业务代码继续使用现有入口：

- `AUNClient()` / `AUNClient(aid)`
- `load_identity(aid)`
- `authenticate()` / `connect()` / `disconnect()` / `close()`
- `call(method, params)`
- `on(event, handler)` / `off(event, handler)`
- 状态与能力属性，如 `state`、`can_send`、`gateway_url`、`access_token`

## 总原则

1. 不改公开 API，不新增公开 namespace，不新增业务 RPC。
2. 不改协议字段、事件名、错误类型和默认行为。
3. 先拆内部组件，再迁移私有方法；`AUNClient` 保留兼容 shim，直到测试和调用点全部收敛。
4. 每一步只移动一个职责域，移动后立即跑对应单测；不要一次性搬 V2 E2EE 和生命周期。
5. Python 先落地，形成组件边界后再按同一边界迁移 Go / TS / JS；四个 SDK 仍各自独立实现，不共享代码。

## 目标架构

### AUNClient 门面

保留公开入口和属性，只持有内部组件：

- `runtime: ClientRuntime`
- `identity: IdentityRuntimeManager`
- `lifecycle: LifecycleController`
- `rpc: RpcPipeline`
- `delivery: MessageDeliveryEngine`
- `e2ee: V2E2EECoordinator`
- `group_state: GroupStateCoordinator`
- `peers: PeerDirectory`

`AUNClient` 的职责降为：

- 构造并组装组件。
- 暴露公开 API。
- 注册内部事件订阅。
- 为旧私有测试点保留转发方法。

### ClientRuntime

集中保存运行时依赖和共享状态：

- 配置：`AUNConfig`、`config` snapshot。
- 身份：`_aid`、`_current_aid`、`_identity`、`_device_id`、`_slot_id`。
- 基础组件：logger、token store、auth flow、transport、dispatcher、discovery、net、agent.md manager。
- 会话：`_gateway_url`、`_session_params`、`_session_options`、`_loop`、`_closing`。
- 错误与重试：`_next_retry_at`、`_retry_attempt`、`_retry_max_attempts`、`_last_error`、`_last_error_code`。

执行约束：

- 不放业务流程，只提供字段、快照和重建基础组件的方法。
- Python 可先用 dataclass + 明确方法，避免把所有字段继续暴露成随意字典。
- Go 用未导出 struct，TS/JS 用 private class 或内部模块。

### IdentityRuntimeManager

负责身份加载和运行时重建：

- `load_identity(aid)` 的校验与状态切换。
- 当前 AID 所属 `aun_path` / `verify_ssl` 变化时，重建 logger、keystore、net、discovery、auth、transport、agent.md manager。
- 维护 `current_aid`、`aid`、`aun_path`、`has_identity`、`can_sign`。

迁移来源：

- `AUNClient.__init__` 中的身份初始化片段。
- `_rebuild_runtime_for_identity`
- `load_identity`
- `current_aid` / `aun_path` / `has_identity` / `can_sign` 相关属性逻辑。

### PeerDirectory

负责 peer AID 与证书发现：

- `cache_peer` / `get_peer` / `lookup_peer` / `peers`
- peer gateway cache
- `_discover_gateway_for_aid`
- `_discover_gateway_for_peer_aid`
- `_load_cached_gateway_url`
- `_persist_gateway_url`
- `_resolve_peer_aid`
- `_public_aid_from_cert`
- peer cert fetch 的外层入口

保留在 E2EE coordinator 的内容：

- 证书指纹校验、CA 链校验、sender cert 缓存策略可以先留在 E2EE，第二轮再移动到 `CertificateVerifier`。

### LifecycleController

负责连接生命周期：

- `authenticate`
- `connect`
- `disconnect`
- `close`
- `_connect_once`
- `_normalize_connect_params`
- `_build_session_options`
- `_resolve_gateway` / `_resolve_gateways`
- `_start_background_tasks`
- `_stop_background_tasks`
- `_heartbeat_loop`
- `_token_refresh_loop`
- `_handle_transport_disconnect`
- `_reconnect_loop`

关键边界：

- 只负责连接状态和后台任务，不处理消息解密、不处理群状态自动提案。
- connect 成功后的动作通过 hook 调用：`delivery.on_connected()`、`e2ee.on_connected()`、`group_state.on_connected()`。
- transport 断开回调仍由 runtime 绑定，实际委托给 lifecycle。

### RpcPipeline

负责公开 `call()` 的内部流水线：

1. 校验 client state 和 method。
2. 合并 instance protected headers。
3. 规范化 message/group 参数。
4. 注入 device/slot/cursor 上下文。
5. 按 method 路由到 V2 E2EE 或原始 RPC。
6. 关键操作签名。
7. pull gate 序列化。
8. transport call。
9. 按 method 做结果后处理。

迁移来源：

- `call`
- `_sign_client_operation`
- `_merge_instance_protected_headers`
- `_protected_headers_from_params`
- `_validate_outbound_call`
- `_inject_message_cursor_context`
- `_pull_gate_key_for_call`
- `_run_pull_serialized`
- `_try_acquire_pull_gate`
- `_release_pull_gate`

关键约束：

- `AUNClient.call()` 只委托 `runtime.rpc.call(...)`。
- 递归调用要用 raw call guard，避免 `message.send` 加密路径再次进入完整公开流水线时重复签名或重复路由。
- `message.v2.*`、`group.v2.*` 内部 RPC 仍由 pipeline 统一签名和超时，但必须保留 internal-only 拦截规则。

### MessageDeliveryEngine

负责消息事件、seq 和 ack：

- 原始 push 订阅处理。
- P2P / group namespace lock。
- `SeqTracker` 恢复、保存、迁移。
- push / pull / gap fill 的去重。
- ordered publish。
- auto-ack 和 ack clamp。
- online unread hint。
- 明文消息与 undecryptable 事件投递。

迁移来源：

- `_on_raw_message_received`
- `_process_and_publish_message`
- `_on_raw_group_message_created`
- `_on_raw_group_v2_message_created`
- `_fill_p2p_gap`
- `_fill_group_event_gap`
- `_publish_ordered_message`
- `_publish_pulled_message`
- `_safe_ack`
- `_clamp_ack_params`
- seq tracker 相关 `_restore_*` / `_save_*` / `_persist_*`

关键约束：

- 先只移动 P2P 明文和 ordered publish，再移动 group，最后移动 V2 push。
- 所有应用层事件仍经同一个 dispatcher。
- `message.received`、`group.message_created`、`message.undecryptable`、`group.message_undecryptable` 的 payload 字段保持不变。

### V2E2EECoordinator

负责 V2 加解密编排：

- V2 session 初始化。
- P2P encrypted send / pull / ack。
- group encrypted send / pull / ack。
- thought put/get 加解密。
- bootstrap 缓存。
- sender IK pending 队列。
- peer device target 构造。
- encrypted push 解密与 undecryptable 降级。
- group SPK 注册和轮换调度。

迁移来源：

- `_init_v2_session`
- `_send_encrypted_v2`
- `_pull_v2_internal`
- `_ack_v2_internal`
- `_send_group_encrypted_v2`
- `_pull_group_v2_internal`
- `_ack_group_v2_internal`
- `_build_v2_p2p_envelope`
- `_build_v2_group_envelope`
- `_decrypt_v2_message`
- `_decrypt_v2_envelope_for_thought`
- `_put_message_thought_encrypted_v2`
- `_put_group_thought_encrypted_v2`

关键约束：

- 底层纯计算继续使用 `python/src/aun_core/v2/e2ee/*`，不要搬算法。
- `V2Session` 继续只负责本设备密钥、注册和密钥读取。
- coordinator 使用 `rpc.raw_call` 或受控 `rpc.call_internal`，避免递归走公开加密路由。

### GroupStateCoordinator

负责群 V2 state chain 和自动提案：

- state signature 验证。
- fork check。
- pending proposal confirm。
- auto propose。
- state committed 事件处理。
- group security level 事件。
- membership 变更后的自动 state 推进。

迁移来源：

- `_v2_verify_state_signature`
- `_v2_check_fork`
- `_v2_auto_propose_state`
- `_do_v2_auto_propose_state`
- `_v2_confirm_pending_proposal`
- `_v2_auto_confirm_pending_proposals`
- `_on_v2_state_proposed`
- `_on_v2_state_retry_needed`
- `_on_v2_state_confirmed`
- `_on_group_state_committed`

关键约束：

- 先从 `AUNClient.call()` 后处理中的 group membership hook 抽起。
- 再迁移事件 handler。
- 最后迁移 state verification 细节。

## 详细执行步骤

### 第 0 步：建立行为基线

执行点：

- 不改代码。
- 记录当前 Python 单测命令和结果。
- 确认重点测试文件：`python/tests/unit/test_client.py`、`test_client_state_machine.py`、`test_client_signature.py`、`test_client_protected_headers.py`、`test_connection_kind.py`、`test_p0_common_gaps.py`、`test_group_state.py`。

验收：

- 当前基线失败项要单独记录，后续重构不把既有失败当成新失败。
- 不启动 Kite 主工程，不运行 `python main.py`。

### 第 1 步：创建内部包骨架

执行点：

- 新增 `python/src/aun_core/_client/__init__.py`
- 新增 `runtime.py`
- 新增 `identity.py`
- 新增 `peers.py`
- 新增 `lifecycle.py`
- 新增 `rpc_pipeline.py`
- 新增 `delivery.py`
- 新增 `v2_e2ee.py`
- 新增 `group_state.py`

初始实现：

- 每个文件先定义空壳类和构造参数。
- `AUNClient` 暂不迁移逻辑，只在构造末尾创建这些组件。
- 组件持有 `client` 或 `runtime` 的引用。第一阶段可持有 `client`，后续再收敛到 `runtime`，降低一次性重构风险。

验收：

- import 不循环。
- `AUNClient()` 和 `AUNClient(aid)` 构造行为不变。
- `test_client_without_identity_starts_no_identity`、`test_client_construct_with_aid_enters_standby` 通过。

### 第 2 步：抽 IdentityRuntimeManager

执行点：

- 把 `_rebuild_runtime_for_identity` 移到 `identity.py`。
- 把 `load_identity` 主逻辑移到 `IdentityRuntimeManager.load_identity`。
- `AUNClient.load_identity` 保留，委托到组件。
- `AUNClient._rebuild_runtime_for_identity` 保留，委托到组件。

注意：

- `_dispatcher._log`、`_transport.set_meta_observer`、`_agent_md_manager` 重建顺序必须保持。
- `token_store.close()` 和 `net.close()` 的异常吞掉行为保持。
- debug flag 来源保持现状，不顺手改日志策略。

验收：

- `test_client_load_identity_only_accepts_private_aid`
- `test_close_clears_identity_and_allows_reload`
- `test_client_rejects_legacy_config_constructor`

### 第 3 步：抽 PeerDirectory

执行点：

- 把 peer cache 字段访问集中到 `PeerDirectory`。
- 移动 `cache_peer` / `get_peer` / `lookup_peer` / `peers`。
- 移动 gateway discovery cache 相关方法。
- `AUNClient` 保留同名公开方法和私有转发方法。

注意：

- `_discover_gateway_for_aid` 是 `authenticate()` 依赖点，迁移后 lifecycle 也要通过 peer directory 调用。
- `_resolve_peer_aid` 是 agent.md manager 的 peer resolver 依赖点，runtime manager 重建时要指向新组件。

验收：

- `test_client_peer_cache_methods_use_public_aid_objects`
- `test_client_authenticate_rejects_external_gateway_option`
- `test_client_connect_rejects_external_gateway_option`
- agent.md 相关单测。

### 第 4 步：抽 LifecycleController 第一段

执行点：

- 移动 `authenticate`。
- 移动 `_normalize_connect_params`、`_build_session_options`、`_resolve_gateway`、`_resolve_gateways`。
- `AUNClient.authenticate`、`AUNClient._normalize_connect_params` 等保留转发。

注意：

- `authenticate()` 禁止外部传 gateway 的规则不变。
- 状态从 `standby` 到 `authenticated` 的变化不变。
- `access_token` 写入 `_identity` 的字段名不变。

验收：

- `test_authenticate_moves_standby_to_authenticated`
- strict API 中 external gateway 相关测试。

### 第 5 步：抽 LifecycleController 第二段

执行点：

- 移动 `connect`。
- 移动 `_connect_once`。
- 移动 `disconnect` / `close`。
- `AUNClient.connect` 等保留公开委托。
- `AUNClient._connect_once` 保留私有 shim，兼容现有 monkeypatch 测试。

注意：

- `connect()` 从 `standby` 自动 `authenticate()` 的流程不变。
- 取消旧 reconnect task 的行为不变。
- `_connect_once()` 中 restore seq 必须仍发生在 `transport.connect()` reader 启动前。
- connect 成功后的 V2 初始化和 gap fill 可以先通过原 client 私有方法调用，暂不移动。

验收：

- `test_connect_from_standby_authenticates_then_ready`
- `test_connect_normalizes_empty_slot_id_to_default`
- `test_disconnect_returns_to_standby_and_keeps_identity`
- `test_close_clears_identity_and_allows_reload`

### 第 6 步：抽后台任务与重连

执行点：

- 移动 `_start_background_tasks`、`_stop_background_tasks`。
- 移动 `_heartbeat_loop`、`_apply_server_heartbeat_interval`。
- 移动 `_token_refresh_loop`。
- 移动 `_handle_transport_disconnect`、`_reconnect_loop`、`_reconnect_sleep`、`_invoke_reconnect_connect_once`、`_should_retry_reconnect`。

注意：

- `on_disconnect` 回调仍要能触发新 lifecycle。
- token refresh 不能在自身 task 内递归 cancel 自己。
- server kicked 和 no-reconnect close code 的状态事件 payload 不变。

验收：

- `test_reconnect_loop_moves_through_backoff_and_reconnecting`
- `test_reconnect_loop_records_connection_failed_when_attempts_exhausted`
- `test_token_refresh_loop_runs_in_ready_state_using_session_gateway`
- `python/tests/unit/test_reconnect.py`

### 第 7 步：抽 RpcPipeline 的前置处理

执行点：

- 新增 `RpcPipeline`，先迁移 `AUNClient.call` 的前半段。
- 移动 protected headers 合并。
- 移动 outbound message normalize / validate。
- 移动 group_id canonical normalize。
- 移动 device/slot 注入。
- `AUNClient.call` 委托 pipeline preflight，后续 V2 路由、签名、pull gate 和 transport call 暂留原类。

注意：

- 先不移动 V2 加密分支，可在 pipeline 中继续调用 `client._send_encrypted_v2`。
- `AUNClient._merge_instance_protected_headers` 等保留转发。
- 关键 method 名称集合保持在原文件或迁移后 re-export，避免测试找不到。
- TS/JS/Go 已按同一切片并行完成：`client/rpc-pipeline.ts` / `client_rpc_pipeline.go` 承接 preflight，主类保留 shim。

验收：

- `test_client_instance_protected_headers_merge_only_for_message_methods`
- `test_client_protected_headers.py`
- `test_connection_kind.py`

### 第 8 步：抽 RpcPipeline 的签名与 pull gate

执行点：

- 移动 `_SIGNED_METHODS` 或封装为 `SignedMethodPolicy`。
- 移动 `_sign_client_operation`。
- 移动 echo trace skip 判断。
- 移动 pull gate。
- 为 V2 coordinator 提供 `raw_call(method, params, *, timeout=None, trace=None)`。

注意：

- 签名失败必须继续抛 `ClientSignatureError`，不能静默发送。
- pull gate stale 时间、等待策略、key 生成规则不变。
- 内部 raw call 不绕过签名，除非调用方明确说明已签名或是 internal-only 初始化阶段。
- TS/JS 迁移时保留旧私有 shim，`call()`、`_callRawV2Rpc()`、pull gate shim 委托 `RpcPipeline`，避免破坏现有测试 spy 和私有访问点。
- Go 同包拆分可直接访问未导出字段，但 `signClientOperation` 需要返回 error，签名失败统一转换为 `ClientSignatureError`。
- TS/JS 的 V2 pull 分页 auto-ack 要与 Python 一致在页内 `await`；payload push ack 和纯通知 auto-pull 要保持调用方可等待，避免浏览器/Node 微任务边界导致分页 ack 或应用事件晚于调用返回。

验收：

- `test_client_signature.py`
- `TestSignatureFailureRaises`
- pull gate / p0 common gaps 相关测试。

### 第 9 步：抽 RpcPipeline 的结果后处理

执行点：

- 把 `message.pull` / `group.pull` 的 seq tracker 后处理迁到 delivery。
- 把 `thought.get` 解密结果后处理委托给 e2ee。
- 把 `message.v2.bootstrap` / `group.v2.bootstrap` material observe 委托给 e2ee。
- 把 group membership 成功后的自动 propose hook 委托给 group_state。

注意：

- 此步只改路由，不改实际处理逻辑。
- 每个后处理函数都应拿到 method、params、result 三元组，便于跨 SDK 对齐。

验收：

- `test_p0_common_gaps.py`
- thought 相关单测。
- group state 相关单测。

### 第 10 步：抽 MessageDeliveryEngine 第一段

执行点：

- 移动 `_publish_app_event`。
- 移动 ordered publish、pending ordered、pushed seq 去重。
- 移动 instance context 注入。
- 移动 message debug helpers。

注意：

- dispatcher 仍为唯一应用层事件出口。
- agent.md etag 注入仍发生在 publish 前。
- echo receive trace 行为不变。

验收：

- `test_off_*` 事件测试。
- message received / ordered publish 相关测试。

### 第 11 步：抽 MessageDeliveryEngine 第二段

执行点：

- 移动 P2P push handler。
- 移动 P2P gap fill。
- 移动 auto-ack / ack clamp。
- 移动 seq tracker restore/save/persist。

注意：

- namespace lock 语义不变。
- push 先更新 max_seen，再决定是否 pull 的顺序不变。
- 异常路径仍发布 `message.undecryptable`，不泄漏密文 payload。

验收：

- `test_p0_common_gaps.py`
- `test_gateway_disconnect_detail.py`
- P2P pull/ack 相关单测。

### 第 12 步：抽 MessageDeliveryEngine 第三段

执行点：

- 移动 group push handler。
- 移动 group V2 push notification 到 delivery 外层，再委托 e2ee 解密。
- 移动 group event gap fill。
- 移动 online unread hint。

注意：

- group message push 不带 payload 时仍触发 pull。
- group ack clamp 使用 group namespace 的 max_seen。
- `group.changed` 事件透传兼容逻辑不变。

验收：

- group pull/ack/event gap 相关单测。
- group event ack 测试。

### 第 13 步：抽 V2E2EECoordinator 第一段

执行点：

- 移动 `_init_v2_session`。
- 移动 group SPK registration / rotation 调度。
- 移动 bootstrap cache 字段。
- `LifecycleController._connect_once` connect 成功后调用 `e2ee.on_connected()`。
- TS/JS/Go 可拆成两个小片：先迁 V2 session 初始化与 connect 后 hook，再迁 group SPK 调度和 bootstrap cache 字段。

注意：

- `V2Session.ensure_registered(self.call)` 改为受控 internal call，避免重入公开加密路径。
- 本地 AID 私钥仍只从 `current_aid` 读取，不从 keystore 解密。
- TS/JS 保留短连接延迟初始化现有语义；Go 保留 connect 后初始化 V2 session 的现有语义。
- `on_connected(background_sync)` 中的 pending proposal auto-confirm 只在 `background_sync` 开启且 V2 session 存在时触发。
- TS/JS 可保留 `_v2BootstrapCache` 物理字段在主类上，访问出口统一由 `V2E2EECoordinator` 承接；Go 可保留底层 `bootstrapCache/groupBootstrapCache` 在 `v2P2PState` 中，锁与访问由 coordinator 管理。

验收：

- V2 session 初始化相关单测。
- token gateway reuse 相关测试。
- group SPK registration/rotation、bootstrap cache 命中/失效相关目标单测。

### 第 14 步：抽 V2E2EECoordinator 第二段

执行点：

- 移动 P2P V2 send / pull / ack。
- 移动 P2P envelope build。
- 移动 peer target 构造和 sender IK pending。

注意：

- `message.send` 默认 encrypt=True 的行为不变。
- speculative send 使用缓存失败后刷新 bootstrap 重试一次的行为不变。
- self-sync recipient 构造不变。
- TS/JS/Go 主类保留 `send/pull/ack` 与 sender IK pending 私有/内部 shim，主体实现迁入 `V2E2EECoordinator`；Go 的公开 `SendV2WithOpts` 也保留 AUNClient 兼容门面。

验收：

- P2P E2EE 单测。
- `client-v2-only-parity` 类测试。
- 跨 SDK P2P E2EE 用例。

### 第 15 步：抽 V2E2EECoordinator 第三段

执行点：

- 移动 group V2 send / pull / ack。
- 移动 group envelope build。
- 移动 thought put/get 加解密。
- 移动 encrypted push 解密和 undecryptable 降级。

注意：

- `group.send` 默认 encrypt=True 的行为不变。
- `group.thought.put` 强制加密的语义不变。
- group pull 返回前的 decrypt / publish / ack 顺序不变。
- group envelope build 迁入 coordinator 后，TS/JS 主类保留 `_buildV2GroupEnvelope` shim 兼容既有私有测试点；Go 的无引用 thought envelope 构造门面已在第 17 步清理。

验收：

- group E2EE 单测。
- thought 相关单测。
- 浏览器 JS parity 用例可在 TS/JS 迁移时复用。

### 第 16 步：抽 GroupStateCoordinator

执行点：

- 先移动 group membership RPC 后处理 hook。
- 再移动 state proposal / confirm / retry event handler。
- 最后移动 state signature、fork check、security level。

注意：

- auto propose per-group 串行化不变。
- lazy propose 去重窗口不变。
- `group.state_committed` 验证失败时的日志和事件行为不变。

验收：

- `python/tests/unit/test_group_state.py`
- group state proposal / committed 相关测试。

### 第 17 步：清理 AUNClient

执行点：

- 删除只被新组件内部使用的旧私有方法。
- 保留以下 shim 至少一个版本周期：
  - `_connect_once`
  - `_sign_client_operation`
  - `_merge_instance_protected_headers`
  - `_resolve_peer_aid`
  - `_fetch_peer_cert`
  - `_publish_app_event`
  - `_fill_p2p_gap`
- 对 tests 中直接访问私有字段的用例逐步改成组件级测试或公开行为测试。

注意：

- 不要一次性删除所有私有 shim。
- 每删除一个 shim，先 `rg` 确认 SDK、CLI、测试和 federation helper 无引用。

验收：

- Python 全量 unit 通过。
- CLI adapter 相关测试通过。

### 第 18 步：沉淀组件级测试

执行点：

- 为 `RpcPipeline` 增加纯 fake transport 测试。
- 为 `MessageDeliveryEngine` 增加 fake dispatcher + fake seq tracker 测试。
- 为 `LifecycleController` 增加 fake auth / transport / discovery 测试。
- 为 `V2E2EECoordinator` 增加 bootstrap cache、raw call、undecryptable 降级测试。

注意：

- 组件测试只验证内部边界，端到端行为仍由现有 `AUNClient` 测试覆盖。
- 避免为测试新增公开 API。

验收：

- 组件测试覆盖每个迁移后的组件。
- 原 `test_client.py` 可逐步瘦身，但不要先删覆盖。

### 第 19 步：迁移 Go / TypeScript / JavaScript

执行点：

- 按 Python 稳定后的边界同步迁移。
- Go 使用未导出 struct 和方法：`clientRuntime`、`lifecycleController`、`rpcPipeline`、`messageDeliveryEngine`、`v2E2EECoordinator`、`groupStateCoordinator`。
- TS/JS 使用内部文件：`client/runtime.ts`、`client/lifecycle.ts`、`client/rpc-pipeline.ts`、`client/delivery.ts`、`client/v2-e2ee.ts`、`client/group-state.ts`。

注意：

- TS、JS、Go 按同一切片并行推进；TS 和 JS 目前各有一份实现，必须各自独立落地，不要把 JS 改成依赖 TS 源码。
- Go 已有 `v2P2PState` 等拆分，迁移时优先利用现有文件，避免重复状态结构。
- TS/JS 的 `AUNClient` 大量字段声明为 `private`，跨文件组件不能像 Go 同包文件一样直接静态访问字段。第一轮迁移允许内部组件以 `unknown as any` 持有 client 引用并只搬低风险职责，避免为了拆分一次性把大量字段改成 public/protected。后续稳定后再把字段访问收敛为明确的 runtime accessor。
- JS 浏览器版与 TS Node 版存在运行时差异：JS 使用 IndexedDB token store、`fetch`/浏览器传输、异步 `AuthFlow.loadIdentityOrNone()`；TS 使用本地文件 token store、`DnsResilientNet`、同步 token store 读取。因此 JS 不能机械复制 TS 组件，必须保留浏览器版的异步边界。
- Go 在同一切片内可以更直接：Go 同属 `aun` package，新增文件可以访问未导出字段；TS/JS 先做门面委托，再逐步提取 `connect`/`disconnect`/`close`。

第一轮低风险切片：

1. 三端新增内部组件骨架：`ClientRuntime` / `IdentityRuntimeManager` / `PeerDirectory` / `LifecycleController`。
2. 迁移身份加载：`loadIdentity` / `LoadIdentity` 只保留公开门面，实际逻辑进入 identity 组件。
3. 迁移 peer 目录：`cachePeer` / `getPeer` / `lookupPeer` / `peers` 和 Go 的 `publicAIDFromCert` 进入 peer 组件。
4. 迁移认证：`authenticate` / `Authenticate` 进入 lifecycle 组件；`connect` 暂时继续调用公开认证入口。
5. 每端迁移后立即跑编译和单测；不碰 V2 E2EE、seq/gap fill、消息投递和重连循环。

第二轮切片：

1. TS/JS：迁移 `connect` 参数规范化和 connect 主流程，但仍调用 client 私有 `_connectOnce` / `_startBackgroundTasks`。
2. Go：迁移 `Connect`、`connectWithLoadedIdentity`、`connectWithParams` 到 lifecycle 组件，保留 `connectOnce` 作为 AUNClient 私有 shim。
3. 验证连接状态机、long/short connection、token gateway reuse 和 reconnect 相关单测。

第三轮切片：

1. 迁移 `RpcPipeline` 前置处理、签名、pull gate 和 raw call。
   - 已完成：TS/JS/Go 的 preflight，包括 internal-only 拦截、protected headers 合并、outbound normalize/validate、group_id normalize、device/slot 注入；Go 同步迁移 ack clamp shim。
   - 已完成：TS/JS/Go 的签名策略、client signature、echo trace skip、pull gate、raw call 接入主类；TS/JS 保留旧私有 shim，Go 签名失败返回 `ClientSignatureError`。
   - 已完成：TS/JS/Go 的 `RpcPipeline` 结果后处理接入主类，覆盖 thought.get 解密、普通 pull 结果 seq/retention-floor 后处理、membership 后 V2 state hook。
2. 已完成：TS/JS 新增 `client/delivery.ts`，Go 收敛 `client_delivery.go` shim，覆盖应用层事件发布、instance context 注入、message debug（TS/Go）、ordered publish、pending ordered、pushed seq 去重和 gap-fill publish 入口。
3. 已完成：TS/JS/Go 的 P2P raw push handler、P2P publish task、P2P gap fill、seq tracker persist、ack clamp 统一出口、group push / group gap fill、group event gap fill、group.changed event_seq push path、V2 P2P/group push notification 外层、online unread hint 队列进入 `MessageDeliveryEngine`；Go 的 `lazySyncGroup`、`fillGroupGap`、`fillGroupEventGap`、`clampAckSeq`、V2 push、seq tracker restore/migrate/save 主类入口已收敛为 delivery shim。
4. online unread hint parity 已按 Python 语义补齐：按 group 去重排队，初始延迟 750ms、队列间隔 50ms；`background_sync=false` 时跳过；drain payload 带 `_online_hint_drained` 重新进入 group V2 push pull 路径。
5. 已完成：TS/JS 新增 `client/v2-e2ee.ts`，Go 新增 `client_v2_e2ee.go`；V2 session 初始化、connect 后 `onConnected` hook、group SPK registration/rotation 调度和 bootstrap cache 访问出口已进入 `V2E2EECoordinator`，主类保留兼容 shim。
6. 已完成：第 14 步 P2P V2 最小切片，TS/JS/Go 的 P2P V2 send/pull/ack、P2P envelope build、peer target 构造调用链和 sender IK pending 队列已进入 `V2E2EECoordinator`。
7. 已完成：第 15 步第一小片，TS/JS/Go 的 group V2 send/pull/ack、group bootstrap 缓存调用链已进入 `V2E2EECoordinator`；TS/JS 的 group envelope build 独立迁入 coordinator，Go 的 `v2GroupSendOnce` 发送编排 receiver 已迁入 coordinator，后续第二小片补齐可复用 envelope build helper 迁移。
8. 已完成：第 15 步第二小片，TS/JS/Go 的 thought put/get 加解密已迁入 `V2E2EECoordinator`；TS/JS 保留主类私有 shim 以兼容测试 monkey-patch，Go 的 `buildV2P2PEnvelope` / `buildV2GroupEnvelope` receiver 同步迁入 coordinator，后续第 17 步已清理无引用 AUNClient 同名门面。
9. 已完成：第 15 步第三小片，TS/JS/Go 的 encrypted push 解密、header-only undecryptable 降级、push envelope 识别和 push payload 解密发布 helper 已进入 `V2E2EECoordinator`；主类保留同名 shim，TS/JS delivery 通过 `_decryptV2PushMessage` 进入组件，Go 保留包级 `isEncryptedPushMessage` 测试入口。

验收：

- 四语言单测通过。
- 单域 SDK 集成测试通过。
- 双域 federation 测试按是否改动服务模块决定是否 rebuild Docker。

## 每步提交建议

推荐拆成小提交：

1. `python: add client internal component skeleton`
2. `python: move identity runtime rebuild into client component`
3. `python: move peer directory and gateway discovery helpers`
4. `python: move lifecycle authenticate/connect`
5. `python: move reconnect and background tasks`
6. `python: move rpc pipeline preflight`
7. `python: move rpc signing and pull gate`
8. `python: move message delivery ordered publish`
9. `python: move p2p delivery gap fill`
10. `python: move group delivery gap fill`
11. `python: move v2 session lifecycle`
12. `python: move v2 p2p e2ee coordinator`
13. `python: move v2 group e2ee coordinator`
14. `python: move group state coordinator`
15. `python: remove unused client shims`

每个提交都应能独立通过对应最小测试集。

## 风险点

### 递归 call 风险

V2 send 内部会再次调用 `message.send encrypt=False`。迁移到 `RpcPipeline` 后必须明确区分：

- 公开 `call()`：执行完整路由。
- 内部 raw call：只做签名、超时、transport，不再触发加密路由。

### 状态字段漂移

多个组件同时读写 `_state`、`_identity`、`_session_params` 时容易出现状态不一致。应通过 `ClientRuntime` 提供少量状态写入方法，例如：

- `set_state(state, event_payload=None)`
- `set_identity(identity)`
- `set_session(params, options)`
- `record_error(error, code)`
- `clear_retry_state()`

### 事件订阅重复

构造和 `load_identity()` 重建 runtime 时不要重复注册内部事件。内部订阅应只注册一次，组件重建时只更新依赖引用。

### 私有测试点

现有测试会直接 patch 私有方法。迁移早期保留 shim，后续再把测试迁成组件级 fake。不要在同一步既移动逻辑又大量改测试。

### 跨语言偏差

Python 迁移过程中应维护一份跨 SDK 行为清单，至少覆盖：

- 构造和身份加载状态。
- connect 选项。
- message/group 默认加密。
- protected headers。
- client signature。
- pull gate。
- seq / ack / gap fill。
- reconnect 状态事件。
- gateway.disconnect detail。

## 验收矩阵

Python 每个阶段最小测试：

- `python/tests/unit/test_client_state_machine.py`
- `python/tests/unit/test_client_strict_api.py`
- `python/tests/unit/test_client_protected_headers.py`
- `python/tests/unit/test_client_signature.py`
- `python/tests/unit/test_connection_kind.py`
- `python/tests/unit/test_p0_common_gaps.py`
- `python/tests/unit/test_group_state.py`

Python 全量阶段测试：

- `python -m pytest python/tests/unit`
- `python -m pytest python/tests`，仅在需要覆盖集成/e2e 时运行。

多语言阶段测试：

- Python / Go / TS / JS 各自单测。
- 单域 SDK 集成测试。
- 双域 federation 测试。

Docker 注意：

- 只改 SDK 代码时，按 SDK 测试环境运行。
- 如果改到 `D:\modelunion\kite\extensions\services` 服务模块，集成测试和 E2E 前需要重新 build 和重启 Docker 镜像。

## 当前进度与下一切片

已完成：

1. Python 已形成参考实现：`AUNClient` 通过 `_client` 下的 runtime、identity、peers、lifecycle、rpc pipeline、delivery、V2 E2EE 和 group state 组件承接主体逻辑，旧私有 shim 仍作为兼容门面保留。
2. TS/JS/Go 的 `ClientRuntime`、`IdentityRuntimeManager`、`PeerDirectory`、`LifecycleController.authenticate/connect`。
3. TS/JS/Go 的 `RpcPipeline` preflight、签名策略、client signature、echo trace skip、pull gate、raw call 和结果后处理已接入主类。
4. TS/JS 已新增 `MessageDeliveryEngine` 基础组件并保留主类私有 shim；Go 的 pushed seq、pending ordered、ordered/pulled publish、gap-fill publish 入口已收敛为 delivery shim。
5. TS/JS/Go 的 P2P raw push handler、P2P publish task、P2P gap fill、seq tracker persist、ack clamp 统一出口、group push / group gap fill、group event gap fill、group.changed event_seq push path、V2 P2P/group push notification 外层、online unread hint 队列已迁入 `MessageDeliveryEngine`；Go 的 `lazySyncGroup`、`fillGroupGap`、`fillGroupEventGap`、`clampAckSeq`、V2 push、seq tracker restore/migrate/save 主类入口已收敛为 delivery shim。
6. TS/JS/Go 已完成 online unread hint parity：按 Python 语义延迟 drain、按 group 合并排队、`background_sync=false` 跳过，并增加三端目标单测覆盖。
7. TS/JS/Go 已完成 `V2E2EECoordinator` 第 13 步：V2 session 初始化、connect 后 `onConnected` hook、group SPK registration/rotation 调度、bootstrap cache 访问出口均已进入组件；主类 `_initV2Session` / `initV2Session` 与 group SPK/cache 私有 shim 保留兼容。
8. TS/JS/Go 已完成 `V2E2EECoordinator` 第 14 步 P2P V2 最小切片：P2P V2 send/pull/ack、P2P envelope build、peer target 构造调用链、sender IK pending 队列已迁入 coordinator；主类保留同名 shim，不进入 group/thought/undecryptable 主体迁移。
9. TS/JS/Go 已完成 `V2E2EECoordinator` 第 15 步第一小片：group V2 send/pull/ack、group bootstrap 缓存调用链已迁入 coordinator；TS/JS 的 group envelope build 独立迁入 coordinator，Go 的 `v2GroupSendOnce` 发送编排 receiver 已迁入 coordinator，后续第二小片补齐可复用 envelope build helper 迁移；主类保留同名 shim。
10. TS/JS/Go 已完成 `V2E2EECoordinator` 第 15 步第二小片：thought put/get 加解密已迁入 coordinator；TS/JS 通过主类 shim 调用 envelope 构造和 thought 解密以保留 monkey-patch 兼容，Go 的 `buildV2P2PEnvelope` / `buildV2GroupEnvelope` receiver 同步迁入 coordinator。
11. TS/JS/Go 已完成 `V2E2EECoordinator` 第 15 步第三小片：encrypted push 解密和 undecryptable 降级已迁入 coordinator；TS/JS 主类保留 `_isEncryptedPushMessage`、`_publishEncryptedPushMessage`、`_decryptV2PushMessage` 等 shim，Go 主类保留 `decryptEncryptedPushPayload` / `publishEncryptedPushMessage` 门面。
12. TS/JS/Go 已完成 `GroupStateCoordinator` 第 16 步第一小片：group membership RPC 后处理 hook、`group.changed` 中 V2 membership/cache/SPK/auto-propose 副作用、`state_proposed` / `state_retry_needed` / `state_confirmed` handler 已迁入组件；TS/JS/Go 均补齐 `group.create` / `group.use_invite_code` 后 group SPK registration 的 Python 语义，主类保留事件 handler shim。
13. TS/JS/Go 已完成 `GroupStateCoordinator` 第 16 步第二小片：state signature 验证、fork check、group security level 发布、lazy pending propose trigger 已迁入组件；签名缓存 key 同步为 Python 的 `sha256(length_prefixed(actor,payload)+signature)` 语义，Go 验签缓存 TTL 同步为 3600 秒。
14. TS/JS/Go 已完成 `GroupStateCoordinator` 第 16 步第三小片：`group.state_committed` handler、auto propose 串行入口、leader delay、committed state base 校验、pending proposal 校验/confirm、auto confirm pending proposals 主体已迁入组件；主类保留旧私有/同包门面以兼容测试 spy 和既有调用点。
15. TS/JS 构建通过；TS 目标单测 4 个文件 186 个用例通过，JS 目标单测 5 个文件 174 个用例通过；Go `go test ./...` 通过。
16. 第 17 步前置清理第一小片已完成：TS/JS 主类删除迁移后无引用的 state hash / wrap capabilities 旧 helper 与无用 import；Go 删除无引用的 `v2AutoProposeStateLocked` 同包门面；仍被 SPK 校验、测试 spy 或同包调用依赖的 helper/shim 暂保留。
17. 第 17 步前置清理第二小片已完成：TS/JS 主类继续删除无引用 import、内部接口、迁移后重复 helper 和旧工具函数；Go 删除无引用的 `v2CheckMembershipTamper`、`v2VerifyCommittedStateBase`、`v2VerifyPendingProposalAgainstBase` 同包门面。`SIGNED_METHODS` 与 JS `PEER_PREKEYS_CACHE_TTL` 虽运行时已迁移/未使用，但仍作为源码审计测试契约保留。
18. 第 17 步前置清理第三小片已完成：TS 删除仅赋值无读取的 `_connectCapabilities` 存储，并清理 TS/JS 主类重复的 V2 retry / pull-gate 静态常量；Go 删除无引用的 P2P/group send-once 与 sender-IK 相关 AUNClient 同包门面。仍被 TS/JS 组件 runtime 访问的 `_pullGates`、`_v2BootstrapCache`、online unread hint、auto-propose、JS `_gapFillActive` / `_v2PullInflight` 等字段继续保留。
19. 第 17 步前置清理第四小片已完成：TS/JS 删除无调用的命名群旧高层 helper `createNamedGroup` / `bindGroupAid`，保留 `AUNClient.call('group.create', ...)` / `AUNClient.call('group.bind_aid', ...)` 的 RPC 透传语义。
20. 第 17 步前置清理第五小片已完成：TS/JS 删除无引用的 group identity 旧存储 helper `_saveGroupIdentityToV2` 及其 keystore 辅助入口，并清理无引用的 sender-IK key/fetch 主类门面 `_v2PendingSenderIKMessageKey`、`_v2PendingSenderIKFetchKey`、`_scheduleV2SenderIKFetch`；仍被组件或测试访问的 `_cacheV2PeerIKFromDevice`、`_scheduleV2SenderIKPending`、`_resolveV2SenderIKPending`、`_v2BuildTargetFromDevice` 继续保留。
21. 第 17 步前置清理第六小片已完成：Go 同步删除无引用的命名群旧高层 helper `createNamedGroup` / `bindGroupAid` 及其内部 `saveGroupIdentityToV2`；Go 命名群相关能力保留在 `AUNClient.Call("group.create", ...)` / `AUNClient.Call("group.bind_aid", ...)` 透传路径，`group.create` / `group.use_invite_code` 后的 V2 state/SPK 副作用仍由 RPC 后处理组件承接。
22. 第 17 步前置清理第七小片已完成：Go 删除无引用的 thought envelope 构造/单 envelope 解密 AUNClient 门面 `buildV2P2PEnvelope`、`buildV2GroupEnvelope`、`decryptV2EnvelopeForThought`；仍由 `Call` / RPC pipeline 使用的 `putMessageThoughtEncryptedV2`、`putGroupThoughtEncryptedV2`、`decryptV2ThoughtGetResult` 保留。
23. 第 17 步前置清理第八小片已完成：JS/Go 删除无引用的 sender cert cache/getVerified 旧门面 `_ensureSenderCertCached` / `_getVerifiedPeerCert` 与 `ensureSenderCertCached` / `getVerifiedPeerCert`；实际仍使用的 `_fetchPeerCert` / `fetchPeerCert`、PKI 验证缓存和组件取证书路径保留。
24. 第 17 步前置清理第九小片已完成：TS/JS/Go 删除迁移后无引用的主类签名跳过门面 `_shouldSkipClientSignature` / `shouldSkipClientSignature`，签名跳过逻辑仅保留在 RPC pipeline；同步删除无引用的 `_currentMessageDeliveryMode` / `currentMessageDeliveryMode` 主类门面；并修复 Go `AIDStore` AgentMD 指纹证书缓存的编译问题，按现有 `LocalTokenStore.SaveCertVersion` 保存版本化证书。本轮验证：TS build、JS build、Go `go test ./...`、TS 目标单测 186 个用例、JS 目标单测 174 个用例均通过。
25. 第 17 步前置清理第十小片已完成：继续清理 TS/JS 主类中仅直转到 `MessageDeliveryEngine` / `V2E2EECoordinator` / `RpcPipeline` 且无引用的旧 shim，包括自动群 pull、有序队列、发布 payload 规范化、seq state 迁移、encrypted push 细粒度 helper、outbound payload normalize 等；TS 同步删除旧 pull follow-up 二阶 helper、V2 capability 常量门面和无引用 `_pullGroupV2Internal`；JS 删除无引用 pull-gate 旧门面；Go 删除无引用 `trustRoots` 同包门面。清理后 TS/JS/Go “只有定义的主类方法”扫描为空；本轮验证：TS build、JS build、Go `go test ./...`、TS 目标单测 186 个用例、JS 目标单测 174 个用例均通过。
26. 第 17 步前置清理第十一小片已完成：字段层面补扫后，TS/JS private 字段未发现只有声明项；Go 删除 `AUNClient` 结构体中只有声明的旧 `v2PullInflight` / `v2PullPending` 字段，对应 V2 pull 串行化已由 `v2PushPullInflight` 与 pull gate 路径承接。清理后 Go `AUNClient` struct 字段“只有声明”扫描为空，Go `go test ./...` 通过。
27. 第 17 步前置清理第十二小片已完成：import/type 层面补扫后，TS/JS 主类删除因第十小片清理后变成无用的 `Message` type import；`SIGNED_METHODS` 与 JS `PEER_PREKEYS_CACHE_TTL` 仍按源码审计测试契约保留。TS build、JS build 通过。
28. 第 18 步组件级测试第一小片已完成：TS/JS 新增 `tests/unit/rpc-pipeline.test.ts`，用 fake `ClientRuntime` / fake client host 直接覆盖 `RpcPipeline` 边界，包括未连接与 internal-only 拦截、protected_headers 合并、outbound payload normalize、message cursor 实例注入与跨实例拒绝、group_id / group cursor 归一化、echo 明文 send 跳过 client_signature 与普通关键方法签名调用。验证：TS/JS 新组件测试各 5 个用例通过；TS build、JS build 通过；TS 目标单测 5 个文件 191 个用例通过；JS 目标单测 6 个文件 179 个用例通过。
29. 第 18 步组件级测试第二小片已完成：TS/JS 新增 `tests/unit/delivery-engine.test.ts`，用 fake host 直接覆盖 `MessageDeliveryEngine` 边界，包括 `publishAppEvent` 注入 `device_id` / `slot_id` 与 `_agent_md`、`messageTargetsCurrentInstance` 按 device/slot 过滤、`publishOrderedMessage` 对空洞消息入队并在 contiguous seq 前进后按顺序发布。验证：TS/JS 新组件测试各 3 个用例通过；TS build、JS build 通过；TS 目标单测 6 个文件 194 个用例通过；JS 目标单测 7 个文件 182 个用例通过。
30. 第 18 步组件级测试第三小片已完成：TS/JS 新增 `tests/unit/lifecycle-controller.test.ts`，用 fake auth / transport / discovery 覆盖 `LifecycleController` 边界；`authenticate` 明确拒绝外部 `gateway` / `gateways`，gateway 必须由 SDK 通过缓存或 discovery 自动解析；connect 覆盖 auth 结果 token/gateway 复用、authenticated 状态缓存 token 复用、短连接参数透传、retry_backoff 手动 connect 打断以及普通连接失败回到 standby/disconnected。Go 同步新增公开 options 反射契约测试，确保 `ConnectionOptions` / `ConnectOptions` 不暴露 gateway/token 字段。验证：TS/JS 新组件测试各 6 个用例通过；TS build、JS build 通过；TS 目标单测 7 个文件 200 个用例通过；JS 目标单测 8 个文件 188 个用例通过；Go `go test ./...` 复跑通过。
31. 第 18 步组件级测试第四小片已完成：TS/JS 新增 `tests/unit/v2-e2ee-coordinator.test.ts`，用 fake host 直接覆盖 `V2E2EECoordinator` 边界，包括 bootstrap cache set/get/delete/clear/prune、`message.thought.put` V2 raw call 及 `client_signature` 注入、retryable V2 error `-33011` 时清理 peer bootstrap cache 并禁用缓存重试、encrypted push 解密失败时只发布 header-only `message.undecryptable` 且透传 `_decrypt_stage`、`_envelope_type`、`payload_type`、`protected_headers`、`agent_md`。Go 既有 `v2_python_parity_test.go` / `integration_undecryptable_test.go` 已覆盖 raw encrypted push、undecryptable 与 group cache 场景，未新增重复测试。验证：TS/JS 新组件测试各 4 个用例通过；TS build、JS build 通过；TS 目标单测 8 个文件 204 个用例通过；JS 目标单测 9 个文件 192 个用例通过；Go `go test ./...` 通过。
32. 第 18 步组件级测试第五小片已完成：TS/JS 新增 `tests/unit/group-state-coordinator.test.ts`，用 fake host 直接覆盖 `GroupStateCoordinator` 边界，包括 `verifyStateSignature` 命中签名缓存时不重复拉证书且继续执行 member tamper 检查、leader delay 只让在线 owner/admin 设备参与选举、`confirmPendingProposal` 先校验 committed base 与 proposal hash 后才确认、proposal hash 不匹配时不确认、`autoConfirmPendingProposals` 只处理 owner/admin 且未确认时触发 propose。Go 既有 `v2_python_parity_test.go` 已覆盖 state signature、leader delay、pending proposal confirm 等同类边界，未新增重复测试。验证：TS/JS 新组件测试各 5 个用例通过；TS build、JS build 通过；TS 目标单测 9 个文件 209 个用例通过；JS 目标单测 10 个文件 197 个用例通过；Go `go test ./...` 通过。
33. 第 18 步组件级测试第六小片已完成：TS/JS 新增 `tests/unit/identity-peer-components.test.ts`，Go 新增 `client_identity_peers_test.go`，覆盖 `IdentityRuntimeManager` 只接受有效私钥 AID、加载身份后重置运行态、`PeerDirectory` 的身份状态校验、证书有效性校验、cache/get/lookup 命中、空 lookup 拒绝和 peers 排序。同步修正 JS `loadIdentity` 遗漏的 `_lastError` / `_lastErrorCode` / `_retryAttempt` / `_nextRetryAt` 复位，以及 Go `loadIdentity` 遗漏的 `authenticated=false` / `nextRetryAt` 清理，避免加载新身份后公开状态仍映射为 authenticated。验证：TS/JS 新组件测试各 4 个用例通过；Go 新组件测试 4 个用例通过；TS build、JS build 通过；TS 目标单测 10 个文件 213 个用例通过；JS 目标单测 11 个文件 201 个用例通过；Go `go test ./...` 通过。
34. 第 18 步组件级测试第七小片已完成：TS/JS `GroupStateCoordinator` 组件测试补齐 membership RPC 后处理、`group.changed` V2 membership/cache/SPK/auto-propose 副作用、`group.v2.state_proposed` / `group.v2.state_retry_needed` / `group.v2.state_confirmed` 事件转发与缓存清理、group security level 仅变更时发布；Go `client_identity_peers_test.go` 同步补齐 group security level 变更发布和 `state_confirmed` 清缓存/snapshot 的同步边界。同步修复 TS `_validateAndCachePeerCert` 迁移后遗漏的 `x509Cert` 局部变量声明，以及 JS `publicKeyFingerprint` WebCrypto `BufferSource` 类型收窄问题。验证：TS build、JS build 通过；TS 目标单测 10 个文件 218 个用例通过；JS 目标单测 11 个文件 206 个用例通过；Go `go test ./...` 通过。
35. 第 18 步组件级测试第八小片已完成：TS/JS `MessageDeliveryEngine` 组件测试从基础有序投递扩展到 pulled 批内部空洞发布与去重 guard、ack clamp、seq tracker group namespace 迁移、按 namespace 持久化和恢复；Go `client_identity_peers_test.go` 同步补齐 delivery 组件的 ack clamp、pulled 去重、seq tracker 迁移/保存/恢复边界，直接调用 `c.delivery()` 而不新增公开 API。验证：TS/JS `delivery-engine.test.ts` 各 8 个用例通过；Go 组件目标测试通过；TS build、JS build 通过；TS 目标单测 10 个文件 223 个用例通过；JS 目标单测 11 个文件 211 个用例通过；Go `go test ./...` 通过。
36. 第 18 步组件级测试第九小片已完成：TS/JS `MessageDeliveryEngine` 组件测试继续下沉旧主类 V2 push 白盒点，覆盖 P2P V2 payload push 遇空洞时只排队并触发 pull、push seq 已被 contiguous 覆盖时幂等忽略、group V2 纯通知 push 修复过大的 contiguous 后按修复值 pull、online unread hint 延迟 drain 以及 `background_sync=false` 跳过。Go 此类 V2 push 自动 pull 路径仍含 goroutine 调度，已由主类/集成 parity 回归覆盖，本轮不新增不稳定组件测试。验证：TS/JS `delivery-engine.test.ts` 各 12 个用例通过；TS build、JS build 通过；Go `go test ./...` 通过；TS 目标单测 10 个文件 227 个用例通过；JS 目标单测 11 个文件 215 个用例通过。
37. 第 18 步组件级测试第十小片已完成：TS/JS `MessageDeliveryEngine` 组件测试继续下沉 group event gap fill 白盒点，覆盖 `fillGroupEventGap` 拉取群事件后标记 `_from_gap_fill`、跳过 `group.message_created` 事件、按最终 contiguous seq 发送 `group.ack_events`、空页 retention/cursor floor 只推进 tracker 不 ack、`has_more=true` 时按最大 `event_seq` 翻页，以及 `handleGroupChangedEventSeq` 遇 `_from_gap_fill` 不递归触发补洞。同步修复 TS 组件迁移遗漏：`fillGroupEventGap` 现在按 JS/Go 语义调用 `SeqTracker.onPullResult` 并支持 `has_more` 翻页。TS `group-event-ack.test.ts` 与 JS `client-p2-fixes.test.ts` 中旧源码审计已从主类 shim 改为审计 `client/delivery.ts` 组件实现；主类 shim 行为回归继续保留。Go 的 group event gap fill ack 使用 goroutine，已由既有主类/集成回归覆盖，本轮不新增不稳定组件测试。验证：TS/JS `delivery-engine.test.ts` 各 16 个用例通过；TS build、JS build 通过；Go `go test ./...` 通过；TS 目标单测 11 个文件 239 个用例通过；JS 目标单测 13 个文件 257 个用例通过。
38. 第 18 步最终收口扫描已完成：剩余 TS/JS 直接触达旧私有方法的测试已分类为兼容 shim 行为回归、transport/e2e 回归、源码审计或带异步调度的旧主类回归；可稳定下沉的 delivery 白盒点已补入 `delivery-engine.test.ts`，源码审计点已改为检查 `MessageDeliveryEngine` 组件实现。同步复核外部 gateway/token 禁止传入：TS/JS 公开 `ConnectionOptions` 不暴露 `gateway` / `token` / `access_token`，`LifecycleController.authenticate/connect` 拒绝外部 gateway/token 字段，Go options 反射测试已覆盖；源码中 `ConnectParams.gateway/access_token` 仅为 SDK 自动发现和认证后的内部连接参数。验证：TS 目标单测 11 个文件 239 个用例通过；JS 目标单测 13 个文件 257 个用例通过；本轮前置 TS build、JS build、Go `go test ./...` 均通过。
39. 发布前本地验收第一轮已完成：补跑 Python/TS/JS/Go 不依赖服务环境的全量本地测试并修复验收阻塞点。修复项包括 Python `AIDStore` agent.md peer resolver 在带 `cert_fingerprint` 时保留本地 PEM 原始换行并优先匹配本地证书、TS/JS agent.md peer resolver 在带指纹时优先读取本地版本化/活跃证书再按自动发现 gateway 拉取 PKI 证书、Python peer cache 单测改为 mock `_fetch_peer_cert` 避免误打真实网关、TS agent.md peer resolver 断言同步新增的指纹参数。验证结果：Python `python -m pytest tests/unit` 665 passed / 20 warnings；Python `python -m pytest tests/conformance` 205 passed；TS `npm run test:unit` 35 files / 476 passed / 7 skipped；JS `npm run test:unit` 38 files / 488 passed；Go `go test ./...` 全通过；TS `npm run build --if-present`、JS `npm run build --if-present` 均通过。
40. Claude Code 审计报告复核与缺陷修复已完成：确认并修复 TS/JS `authenticate()` 在认证 RPC 已成功后重新加载 identity 抛错会把已消耗 token 路径误判为认证失败的问题，改为用认证结果回填内存 identity；JS `authenticate()` / `loadIdentity()` / connect 失败和 transport 断线后的内部未连接态同步为 `standby`，继续保留旧 `disconnected -> standby` 公开状态映射兼容；TS/JS `_applyAidRuntimeContext` 在重建 transport 前 best-effort 关闭旧 transport，避免 AID runtime 切换时旧 WebSocket / pending RPC 泄漏；JS `V2E2EECoordinator` 的 sender public key 指纹校验改为显式 `pubDer.slice().buffer`，并新增非零 `byteOffset` 子视图测试；TS/JS `V2E2EECoordinator` 复用 `runtime.ts` 导出的 `ClientHost` 类型，删除本地重复定义。复核结论：TS 版 v2 指纹不存在 `ArrayBuffer` 切片 bug，使用 `Buffer.from(pubDer)`；JS 原实现按 `byteOffset + byteLength` 截取并非报告描述的越界错误，本轮改为更直观的显式复制并加测试；TS/JS/Go 的 P2P gap fill 均已存在（TS/JS `MessageDeliveryEngine.fillP2pGap`，Go `messageDeliveryEngine.fillP2pGap`），报告中的缺失项不成立。验证：TS 目标组件单测 3 个文件 16 个用例通过；JS 目标组件单测 3 个文件 17 个用例通过；JS 受状态语义影响单测 5 个文件 160 个用例通过；TS 相关单测 3 个文件 177 个用例通过；TS `npm run build --if-present`、JS `npm run build --if-present` 均通过。

集成/E2E 边界：

- Python `tests/integration_test_*.py` / `tests/e2e_test_*.py`、TS `tests/integration` / `tests/e2e`、JS `tests/integration` / `tests/e2e-browser` 均依赖运行中的单域 Gateway/Group/Message 等服务环境和 `agentid.pub` / `gateway.agentid.pub` 解析；不能当成本地无服务单测直接跑。
- TS federation、Go federation 以及 `docker-deploy/federation-test` 相关用例依赖双域 federation Docker 环境和 `aid.com` / `aid.net` / `gateway.*` 解析。
- Go 集成测试使用 `//go:build integration`，默认 `go test ./...` 不包含这些服务依赖用例；需要显式加 build tag 并准备单域/双域服务环境。
- JS reconnect 集成测试会调用 `docker compose restart/stop/start` 模拟断线；此类测试属于服务环境操作，不在本地验收自动执行范围内。

下一切片：

1. SDK 拆分重构主体已收口，本地无服务验收已通过；后续不再新增组件拆分切片，除非单域/双域回归暴露新的 parity 缺口。
2. 下一步如要继续发布前验收，应在用户确认单域 Docker 服务环境已启动后跑 Python/TS/JS/Go 单域集成/E2E；双域 federation 需确认 `docker-deploy/federation-test` 已启动后单独跑。
3. 旧主类 shim 可按版本节奏继续保留；若后续清理 shim，需要先把对应兼容测试改成公开行为或组件测试，不新增公开 API。


