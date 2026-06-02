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

- 新增 `RpcPipeline.call`，先复制 `AUNClient.call` 的前半段。
- 移动 protected headers 合并。
- 移动 outbound message normalize / validate。
- 移动 group_id canonical normalize。
- 移动 device/slot 注入。
- `AUNClient.call` 委托 pipeline。

注意：

- 先不移动 V2 加密分支，可在 pipeline 中继续调用 `client._send_encrypted_v2`。
- `AUNClient._merge_instance_protected_headers` 等保留转发。
- 关键 method 名称集合保持在原文件或迁移后 re-export，避免测试找不到。

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

注意：

- `V2Session.ensure_registered(self.call)` 改为受控 internal call，避免重入公开加密路径。
- 本地 AID 私钥仍只从 `current_aid` 读取，不从 keystore 解密。

验收：

- V2 session 初始化相关单测。
- token gateway reuse 相关测试。

### 第 14 步：抽 V2E2EECoordinator 第二段

执行点：

- 移动 P2P V2 send / pull / ack。
- 移动 P2P envelope build。
- 移动 peer target 构造和 sender IK pending。

注意：

- `message.send` 默认 encrypt=True 的行为不变。
- speculative send 使用缓存失败后刷新 bootstrap 重试一次的行为不变。
- self-sync recipient 构造不变。

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

- TS 和 JS 目前各有一份实现，先迁 TS，再用相同结构迁 JS；不要把 JS 改成依赖 TS 源码。
- Go 已有 `v2P2PState` 等拆分，迁移时优先利用现有文件，避免重复状态结构。

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

## 推荐先做的最小切片

第一轮只做 Python 的 3 个低风险切片：

1. `IdentityRuntimeManager`
2. `PeerDirectory`
3. `LifecycleController.authenticate + connect 参数规范化`

这三步能明显降低 `AUNClient` 构造和身份/发现复杂度，又不会碰 V2 E2EE、seq gap fill 和消息投递这些高风险路径。完成后再评估是否进入 `RpcPipeline`。
