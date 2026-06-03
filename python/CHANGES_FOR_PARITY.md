# Python SDK 变更清单（v0.3.3 → v0.4.9）— 跨 SDK 对齐参考

本文档供 Go / TypeScript / JavaScript / C++ SDK 进行功能对齐时使用，详尽列出各版本 Python SDK 的实际变更，定位到具体类、函数与代码行。

CHANGELOG（接口级摘要）：见 `python/CHANGELOG.md`。本文档为**实现级别详尽清单**。

涉及提交：`5a962885` (v0.3.7) → `4b1364d2` (v0.4.0) → `009438db` (v0.4.2) → `2d1bce76` (v0.4.3a) → `dc380c86` (v0.4.3b) → `5144a71d` (v0.4.5) → `d50456d7` (v0.4.6) → `748e1be1` (v0.4.7) → `471675be` (v0.4.8) → 工作区 (v0.4.9)。

---

## v0.4.9 — 相对于 v0.4.8 的变更

### `_client/runtime.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| — | 重写 | `ClientRuntime` | 从占位类扩展为完整运行时入口，持有 7 个分区子对象：`identity`、`lifecycle`、`rpc`、`delivery`、`v2`、`group_state`、`services` |
| +98 | 新增 | `ClientRuntime.coerce(runtime_or_client)` | 类方法工厂：传入 `ClientRuntime` 直接返回，传入含 `_client_runtime` 属性的客户端则提取，否则新建；供所有子组件构造函数统一调用 |
| +107 | 新增 | `class _RuntimeSection` | 所有分区基类，持有 `runtime` 引用，通过 `self.client` property 间接访问客户端 |
| +116 | 新增 | `class RuntimeIdentityState` | 身份分区：`set_loaded_identity`、`set_identity`、`set_aid`、`set_instance_context`、`clear`、`apply_runtime_context`；`apply_runtime_context` 原子更新客户端的 `_config_model/_device_id/_slot_id/_log/_net/_discovery/_token_store/_auth/_transport` 等全部运行时字段 |
| +209 | 新增 | `class RuntimeLifecycleState` | 生命周期分区：`set_state`、`set_closing`、`set_gateway_url`、`set_loop`、`set_session`、`set_error`/`clear_error`、`set_connected_at`、`set_retry_backoff`、`set/clear_reconnect_task`、`set_heartbeat/token_refresh_task`、`increment_token_refresh_failures`、`set_connection_failed`、`reset_for_disconnect`、`reset_for_close` 等完整状态机 setter |
| +334 | 新增 | `class RuntimeRpcState` | RPC 分区：`protected_headers` 读写 property；`pull_gates` lazy 初始化 property |
| +355 | 新增 | `class RuntimeDeliveryState` | 消息投递分区：`seq_tracker`、`pending_ordered`、`pending_p2p_pull_upper`（均 lazy 初始化 property）；`set_online_unread_hint_task`、`set_gap_fill_active`；`reset_seq_tracking_state(*, next_context, reset_context)` 统一两个清状态路径 |
| +411 | 新增 | `class RuntimeV2State` | V2 E2EE 分区：`session` 读写 property；`bootstrap_cache` lazy property；`reset_for_identity`；`group_spk_registration_inflight`、`group_spk_rotation_inflight`、`group_spk_peer_fallback_registered`（均 lazy set property） |
| +461 | 新增 | `class RuntimeGroupState` | 群状态分区：`state_chains`、`security_levels`（均 lazy dict property） |
| +479 | 新增 | `class RuntimeServices` | 服务分区：通过 `__getattr__` 代理以 `_name` 命名的客户端属性；`set_agent_md_manager` |

### `_client/delivery.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +9 | 新增 import | `ClientRuntime` | — |
| +22 | 修改 | `MessageDeliveryEngine.__init__` 参数 | `client: Any` → `runtime: Any`；构造时调用 `ClientRuntime.coerce(runtime)`，`self.client` 改为 `self.runtime.client` |
| +28 | 修改 | `pending_ordered()` | 删除 `getattr` + 懒初始化逻辑，改为 `return self.runtime.delivery.pending_ordered` |
| +43 | 修改 | `_schedule_online_unread_hint_if_needed()` | `client._online_unread_hint_task = ...` → `self.runtime.delivery.set_online_unread_hint_task(...)` |
| +52 | 修改 | `drain_online_unread_hints()` finally 块 | `client._online_unread_hint_task = None` → `self.runtime.delivery.set_online_unread_hint_task(None)` |
| +62 | 修改 | `fill_p2p_gap()` | `client._gap_fill_active = True/False` → `self.runtime.delivery.set_gap_fill_active(True/False)` |
| +82 | 修改 | `record_pending_p2p_pull()` | `getattr(client, "_pending_p2p_pull_upper", None)` 懒初始化 → `self.runtime.delivery.pending_p2p_pull_upper` |
| +88 | 修改 | `reset_seq_tracking_state()` | 删除 15 行内联清理逻辑，改为 `self.runtime.delivery.reset_seq_tracking_state(reset_context=True)` |
| +108 | 修改 | `refresh_seq_tracking_context()` | 删除 15 行内联清理 + 上下文切换逻辑，改为 `self.runtime.delivery.reset_seq_tracking_state(next_context=next_context)` |

### `_client/group_state.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +7 | 新增 import | `ClientRuntime` | — |
| +11 | 修改 | `GroupStateCoordinator.__init__` 参数 | `client: Any` → `runtime: Any`；调用 `ClientRuntime.coerce` |

### `_client/identity.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +13 | 新增 import | `ClientRuntime` | — |
| +21 | 修改 | `IdentityRuntimeManager.__init__` 参数 | `client: Any` → `runtime: Any`；调用 `ClientRuntime.coerce` |
| +28 | 修改 | `load_identity()` | 删除 8 行直接赋值客户端字段（`_current_aid`、`_aid`、`_state`、`_closing` 等），改为调用 `self.runtime.identity.set_loaded_identity`、`self.runtime.lifecycle.set_state/set_closing/clear_retry_state` |
| +80 | 修改 | `rebuild_runtime_for_identity()` | 删除 30 行逐字段赋值（`client._config_model`、`client._log`、`client._net` 等），改为先构造 `log/net/discovery/token_store/auth/transport` 局部变量，再一次性调用 `self.runtime.identity.apply_runtime_context(...)` |
| +122 | 修改 | `rebuild_runtime_for_identity()` 末尾 | `client._agent_md_manager = ...` → `self.runtime.services.set_agent_md_manager(...)` |

### `_client/lifecycle.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +17 | 新增 import | `ClientRuntime` | — |
| +22 | 修改 | `LifecycleController.__init__` 参数 | `client: Any` → `runtime: Any`；调用 `ClientRuntime.coerce` |
| — | 修改 | `authenticate()` | `client._gateway_url = ...` → `self.runtime.lifecycle.set_gateway_url`；`client._aid = ...` → `self.runtime.identity.set_aid`；`client._identity = ...` → `self.runtime.identity.set_identity`；`client._state = ...` → `self.runtime.lifecycle.set_state`；error 字段 → `set_error/clear_error` |
| — | 修改 | `connect()` | 所有直接状态赋值全部改为对应 runtime 分区 setter；`set_session` 原子设置 `_session_params` + `_session_options` |
| — | 修改 | `disconnect()` | `client._reconnect_task = None` → `clear_reconnect_task`；多处状态重置 → `reset_for_disconnect(next_state)` |
| — | 修改 | `close()` | `client._closing = True` → `set_closing(True)`；重复的 15 字段清零逻辑 × 2 → `reset_for_close()`；`client._reconnect_task = None` → `clear_reconnect_task` |
| — | 修改 | `_connect_once()` | `client._slot_id = ...` + `client._auth.set_instance_context` → `self.runtime.identity.set_instance_context`；其余状态赋值改为 runtime setter |
| — | 删除 | `_cancel_background_tasks` 中 `_cache_cleanup_task` | 停止清理已删除的 prekey 缓存清理任务 |
| — | 修改 | `start_heartbeat_task/start_token_refresh_task` | `client._heartbeat_task/token_refresh_task = ...` → runtime lifecycle setter |
| — | 修改 | `token_refresh_loop` | `client._identity = ...` → `self.runtime.identity.set_identity`；`client._token_refresh_failures` 计数 → `increment_token_refresh_failures/set_token_refresh_failures` |
| — | 修改 | `handle_server_disconnect` | `client._server_kicked = True` → `set_server_kicked`；`client._last_disconnect_info = ...` → `set_last_disconnect_info`；`reset_for_disconnect` + `set_connection_failed` 替代内联多字段赋值 |
| — | 修改 | `reconnect_loop` | 所有 `client._retry_attempt`、`client._next_retry_at`、`client._reconnect_task`、`client._state` 赋值全部改为对应 runtime setter；新增 `set_retry_backoff` 原子方法 |

### `_client/peers.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +10 | 新增 import | `ClientRuntime` | — |
| +25 | 修改 | `PeerDirectory.__init__` 参数 | `client: Any` → `runtime: Any`；调用 `ClientRuntime.coerce` |
| +58 | 修改 | `discover_gateway_for_aid()` 两处 | `client._gateway_url = ...` → `self.runtime.lifecycle.set_gateway_url(...)` |

### `_client/rpc_pipeline.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +17 | 新增 import | `ClientRuntime` | — |
| +22 | 修改 | `RpcPipeline.__init__` 参数 | `client: Any` → `runtime: Any`；调用 `ClientRuntime.coerce` |
| +61 | 修改 | `call()` 末尾 | `client._call_after_pipeline(...)` → `self.call_after_pipeline(...)` |
| +63 | 新增 | `RpcPipeline.call_after_pipeline()` | 将原 `AUNClient._call_after_pipeline` 整体迁入 RpcPipeline，含 pull gate 串行化、加密路由、签名注入、transport 调用等完整逻辑（约 170 行） |
| +376 | 修改 | `try_acquire_pull_gate()` | `getattr(client, "_pull_gates", None)` 懒初始化 → `self.runtime.rpc.pull_gates` |
| +386 | 修改 | `release_pull_gate()` | `client._pull_gates.get(key)` → `self.runtime.rpc.pull_gates.get(key)` |

### `_client/v2_e2ee.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +11 | 新增 import | `ClientRuntime` | — |
| +21 | 修改 | `V2E2EECoordinator.__init__` 参数 | `client: Any` → `runtime: Any`；调用 `ClientRuntime.coerce` |
| +53 | 修改 | `on_connected()` | `client._v2_session = V2Session(...)` → `self.runtime.v2.session = V2Session(...)`；`client._v2_bootstrap_cache = {}` → `self.runtime.v2.bootstrap_cache.clear()` |
| +73 | 修改 | `ensure_group_spk_registered()` | `getattr(client, "_group_spk_registration_inflight", ...)` 懒初始化 → `self.runtime.v2.group_spk_registration_inflight` |
| +105 | 修改 | `ensure_group_spk_rotated()` | 同上，改用 `self.runtime.v2.group_spk_rotation_inflight` |
| +133 | 修改 | `schedule_group_spk_registration_after_peer_fallback()` | 改用 `self.runtime.v2.group_spk_peer_fallback_registered` |
| +587 | **新增** | `pull_v2_p2p` 明文路径（P2P） | 构造 `v1_msg` 后调用 `self.attach_gateway_proximity(v1_msg, msg)`，将 gateway 注入的 `proximity` 字段写入消息事件 payload |
| +1853 | **新增** | `pull_v2_group` 明文路径（群组） | 同上，群组明文消息投递前补充 `attach_gateway_proximity` 调用 |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +644 | 修改 | `AUNClient.__init__` 子组件初始化 | 7 个子组件从传入 `self` 改为传入 `self._client_runtime`，确保均通过 `ClientRuntime` 获取客户端引用 |
| +859 | 新增 | `AUNClient._runtime()` | lazy 获取/构建 `ClientRuntime` 的访问器（init 时已建，此处为 fallback 兼容路径） |
| +704 | 修改 | `_lifecycle/rpc/delivery/_v2_e2ee_coordinator/_group_state` lazy getter | fallback 新建时由 `LifecycleController(self)` 改为 `LifecycleController(self._runtime())` 等 |
| — | 删除 | `_require_peer_management_state` | 代理方法移除，调用方直接用 `_peer_directory.require_peer_management_state()` |
| — | 删除 | `_rebuild_runtime_for_identity` | 同上 |
| — | 删除 | `_issuer_domain_for_aid`、`_discover_gateway_url`、`_load_cached_gateway_url`、`_persist_gateway_url` | 代理方法移除，内部通过 `_peer_directory` 调用 |
| — | 删除 | `_public_aid_from_cert` | 代理方法移除 |
| — | 删除 | `_pull_gate_key_for_call`、`_run_pull_serialized` | 已内聚到 `RpcPipeline.call_after_pipeline` |
| — | 删除 | `_call_after_pipeline` | 整体迁入 `RpcPipeline.call_after_pipeline` |
| — | 删除 | `_debug_json_default` 静态方法代理 | `MessageDeliveryEngine.debug_json_default` 直接使用 |
| — | 删除 | `_is_echo_message_params`、`_current_message_delivery_mode` | 代理方法移除 |
| — | 删除 | `_lazy_sync_group`、`_join_mode_allows_member_epoch_rotation` 等群状态辅助方法 | 已迁入 `GroupStateCoordinator` |
| — | 删除 | `_list_contains_token`、`_client_uses_v2_p2p/group` | 静态辅助方法移除 |
| — | 删除 | `_ensure_sender_cert_cached`（兼容别名） | 移除不再需要的旧调用点别名 |
| — | 删除 | `_extract_consumed_prekey_id` | 静态方法移除 |
| — | 删除 | `_attach_rotation_id`、`_rotation_expected_members_stale`、`_rotation_retry_delay_s` | 群轮换辅助函数移除 |
| — | 删除 | `_cache_cleanup_loop` | prekey 列表缓存（`_peer_prekeys_cache`）整体删除，连带清理任务一并移除 |
| — | 删除 | `_GROUP_ROTATION_*` 常量、`_KEY_WAIT_*` 常量 | 随 `_cache_cleanup_loop` 一并清理 |
| — | 删除 | `_peer_prekeys_cache`、`_cache_cleanup_task` 字段 | init 中移除初始化 |
| — | 删除 | `_PEER_PREKEYS_CACHE_TTL` | 常量移除 |
| — | 删除 | `_decrypt_thought_get_result`、`_metadata_without_auth`、`_v2_envelope_payload_type` 代理方法 | 直接使用 `V2E2EECoordinator` 类方法 |
| — | 删除 | `_attach_group_dispatch_mode_to_payload` | 静态方法移除 |
| — | 删除 | `_group_secret_matches_committed_rotation` | 静态方法移除 |

### `version.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +1 | 修改 | `__version__` | `"0.4.8"` → `"0.4.9"` |

---

## v0.4.8 — 相对于 v0.4.7 的变更

### `_cert_utils.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| — | 删除 | `_AGENT_MD_FINGERPRINT_RE` | 删除严格 sha256: 前缀正则，由 `normalize_fingerprint_hex` 替代 |
| +23 | 新增 | `_FINGERPRINT_HEX_RE` | 纯 hex 字符校验正则（取代原正则） |
| +26 | 新增 | `def normalize_fingerprint_hex(value)` | 将 `sha256:xxx`、`xx:xx:xx`（冒号分隔）、裸 hex 统一为小写 hex，支持 16/64 位 |
| +34 | 新增 | `def cert_fingerprint_hexes(cert)` | 同时返回证书指纹 hex 和 SPKI（公钥 DER）指纹 hex |
| +39 | 新增 | `def cert_matches_fingerprint(cert, fingerprint)` | 将证书指纹（cert/SPKI）与 fingerprint 比对，支持 16 位短前缀匹配 |
| +47 | 新增 | `def public_key_matches_fingerprint(cert, fingerprint)` | 仅比对 SPKI 指纹，支持短前缀 |
| +87 | 修改 | `parse_agent_md_tail_signature()` | 使用 `normalize_fingerprint_hex` 校验 `cert_fingerprint`；新增 `public_key_fingerprint` 字段可选校验 |
| +115 | 修改 | `def build_agent_md_signature_block(...)` | 新增可选参数 `public_key_fingerprint: str = ""`，若非空则在签名块中写入该字段 |
| +182 | 新增 | `def public_key_fingerprint(cert)` | 返回 `sha256:` + SPKI DER SHA-256 hex |

### `aid.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +14 | 新增 import | `cert_matches_fingerprint` | 引入新的指纹比对函数 |
| +18 | 新增 import | `public_key_fingerprint`, `public_key_matches_fingerprint` | 引入公钥指纹函数 |
| +145 | 修改 | `AID.sign_agent_md()` | 签名块中新增 `public_key_fingerprint` 字段 |
| +171 | 修改 | `AID.verify_agent_md()` | cert_fingerprint 比对改用 `cert_matches_fingerprint()`（支持多格式/短前缀） |
| +180 | 新增 | `AID.verify_agent_md()` | 新增对 `public_key_fingerprint` 字段的可选校验（`public_key_matches_fingerprint`） |
| +205 | 修改 | `AID.verify_agent_md()` 返回值 | 验证结果中新增 `public_key_fingerprint` 字段 |

### `aid_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| — | 删除 import | `normalize_device_id` | 改用 `get_device_id` |
| +106 | 删除 | `AIDStore.__init__` 参数 `device_id` | 移除外部传入 device_id 的能力，改为始终调用 `get_device_id(aun_path)` |
| +114 | 修改 | `AIDStore.__init__` | `self.device_id` 赋值从 `normalize_device_id(device_id, ...)` 改为 `get_device_id(self.aun_path)` |
| +149 | 修改 | `resolve_peer()` 闭包签名 | 新增参数 `cert_fingerprint: str \| None = None` |
| +152 | 修改 | `resolve_peer()` 闭包实现 | 重写：先查本地 keystore 证书，若指纹匹配则直接构造公钥 AID；否则按指纹走 PKI HTTP 接口或 `fetch_peer_cert` |

### `agent_md.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +18 | 新增 import | `cert_matches_fingerprint`, `parse_agent_md_tail_signature` | 引入指纹比对与签名块解析 |
| +302 | 修改 | `AgentMdManager._resolve_peer()` 签名 | 新增参数 `cert_fingerprint: str \| None = None` |
| +305 | 修改 | `AgentMdManager._resolve_peer()` | 当前 AID 匹配时，额外校验 `cert_fingerprint`；调用 `_peer_resolver` 时透传 fingerprint，并用 `try/except TypeError` 兼容旧签名 |
| +525 | 修改 | `AgentMdManager.download_and_verify()` | 下载后先解析签名块提取 `cert_fingerprint`/`public_key_fingerprint`，再将其传入 `_resolve_peer()` 做锁定解析 |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +9 | 新增 import | `_client` 模块中的 8 个子类 | `ClientRuntime`, `GroupStateCoordinator`, `IdentityRuntimeManager`, `LifecycleController`, `MessageDeliveryEngine`, `PeerDirectory`, `RpcPipeline`, `V2E2EECoordinator` |
| +21 | 修改 import | `cert_matches_fingerprint`, `normalize_fingerprint_hex` | 替换原 `cert_common_name`, `cert_time_error` |
| +368 | 修改 | `resolve_peer()` 闭包签名 | 新增 `cert_fingerprint` 参数，透传给 `_resolve_peer_aid` |
| +468 | 修改 | `AUNClient.__init__` | `raw_config` 初始化时额外传入 `verify_ssl`、`debug`、`root_ca_path`（来自 initial_aid_obj） |
| +651 | 新增 | `AUNClient.__init__` | 初始化 8 个子组件实例（`_client_runtime`、`_identity_runtime`、`_peer_directory` 等） |
| +374 | 新增 | `AUNClient._lifecycle()` | lazy 获取 `LifecycleController` 的访问器 |
| +381 | 新增 | `AUNClient._rpc()` | lazy 获取 `RpcPipeline` |
| +388 | 新增 | `AUNClient._delivery()` | lazy 获取 `MessageDeliveryEngine` |
| +395 | 新增 | `AUNClient._v2_e2ee_coordinator()` | lazy 获取 `V2E2EECoordinator` |
| +402 | 新增 | `AUNClient._group_state()` | lazy 获取 `GroupStateCoordinator` |
| +409 | 修改 | `AUNClient.authenticate()` / `connect()` / `disconnect()` / `close()` | 实现委托给 `_lifecycle()` 对应方法 |
| +699~977 | 修改 | RPC/ACK 相关方法群 | `_sign_client_operation`, `_pull_gate_key_for_call`, `_try_acquire_pull_gate`, `_release_pull_gate`, `_run_pull_serialized`, `call`, `_merge_instance_protected_headers`, `_fire_ack`, `_await_ack`, `_clamp_ack_params` 均委托给 `_rpc()` / `_delivery()` |
| +793 | 新增 | `AUNClient._call_after_pipeline()` | pull gate 锁定检测 + 结果后处理的新入口（由 `RpcPipeline.call` 回调） |
| +795 | 修改 | `AUNClient.load_identity()` | 委托给 `_identity_runtime.load_identity(aid)` |
| +100~134 | 修改 | peer 管理方法群 | `_require_peer_management_state`, `cache_peer`, `get_peer`, `lookup_peer`, `peers`, `_rebuild_runtime_for_identity` 均委托给 `_peer_directory` / `_identity_runtime` |
| +224~338 | 修改 | gateway 发现/持久化方法群 | `_discover_gateway_for_aid`, `_issuer_domain_for_aid`, `_discover_gateway_for_peer_aid`, `_discover_gateway_url`, `_load_cached_gateway_url`, `_persist_gateway_url`, `_resolve_peer_aid`, `_public_aid_from_cert` 均委托给 `_peer_directory` |

### `config.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +78 | 修改 | `get_device_id()` | `mkdir` 移入 try 块内；文件不可写时 fallback 从静默返回旧 device_id 改为返回 `"default"` |

### `version.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +1 | 修改 | `__version__` | `"0.4.7"` → `"0.4.8"` |

---

## v0.4.7 — 相对于 v0.4.6 的变更

### `aid_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L22 | 新增 import | `AuthFlow` | 新增对 `AuthFlow` 的导入 |
| L29 | 修改 import | `errors` | 新增导入 `ClientSignatureError`, `StateError` |
| L31 | 新增 import | `LocalTokenStore` | 新增对 `LocalTokenStore` 的导入 |
| L56–L62 | 新增 | `class UploadAgentMdResult` | upload_agent_md 的返回类型定义（TypedDict，含 aid/etag/last_modified/agent_md_url） |
| L128–L131 | 新增 | `AIDStore.__init__` 中 `_token_store` | 初始化 `LocalTokenStore` 实例 |
| L179 | 新增 | `AIDStore.close()` | 关闭时同步调用 `self._token_store.close()` |
| L434–L439 | 新增 | `AIDStore._auth_identity_from_aid()` | 从 AID 对象构造 auth identity dict 的私有辅助方法 |
| L441–L458 | 新增 | `AIDStore._upload_agent_md_token()` | 通过 AuthFlow 获取上传 agent.md 所需 token 的私有异步方法 |
| L460–L510 | 新增 | `AIDStore.upload_agent_md()` | 公开异步方法，签名并上传指定 AID 的 agent.md，返回 `Result[UploadAgentMdResult]` |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1062 | 删除 | `AUNClient.upload_agent_md()` | 从 AUNClient 移除该方法（职责迁移到 AIDStore） |

### `keystore/sqlite_db.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L308–L313 | 修改 | `AIDDatabase._migrate_schema()` v1→v2 分支 | 用 `_add_column_if_missing` 替代直接 `ALTER TABLE`，防止重复迁移报错 |
| L321–L322 | 新增 | `AIDDatabase._migrate_schema()` 末尾 | 补充幂等的 `slot_id_full` 列添加，修复 pending 升级场景 |
| L384–L390 | 新增 | `AIDDatabase._add_column_if_missing()` | 静态方法，检查列是否存在后再执行 ADD COLUMN，实现幂等迁移 |

### `version.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1 | 修改 | `__version__` | `"0.4.6"` → `"0.4.7"` |

## v0.4.6 — 相对于 v0.4.5 的变更

### `agent_md.py`（新文件，相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L24 | 新增 | `class AgentMdManager` | agent.md 本地持久化、远端同步、观察元数据管理器，从 AUNClient/AIDStore 中拆出，通过回调注入能力 |
| L27 | 新增 | `AgentMdManager.__init__` | 构造器接收 aun_path + 一组可选回调（owner_aid_getter, gateway_resolver, peer_resolver, token_provider, authenticator 等） |
| L70 | 新增 | `AgentMdManager.content_etag` | 静态方法，计算内容 SHA-256 ETag |
| L77 | 新增 | `AgentMdManager.root` | property，返回 AIDs 根目录 Path |
| L83 | 新增 | `AgentMdManager.safe_aid` | 静态方法，校验 AID 不含路径分隔符 |
| L88 | 新增 | `AgentMdManager.file_path` / `meta_path` | 返回 agent.md 内容文件 / agentmd.json 元数据文件路径 |
| L104 | 新增 | `AgentMdManager._record_lock` | contextmanager，跨进程文件锁（msvcrt / fcntl 双平台） |
| L132 | 新增 | `AgentMdManager._atomic_write_text` | 原子写文本文件（tmp → replace + fsync） |
| L154 | 新增 | `AgentMdManager._write_record_unlocked` / `_normalize_record` / `_read_record_unlocked` | 元数据 JSON 读写内部方法 |
| — | 新增 | `download` / `upload` / `check` / `observe_rpc_meta` / `observe_envelope` / `event_snapshot` | 对外公开的核心业务方法（下载/上传/检查/观察/etag 快照） |

### `aid_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L21 | 修改 import | `AuthFlow` → `AgentMdManager` | 删除 `from .auth import AuthFlow`，改为 `from .agent_md import AgentMdManager` |
| L28 | 修改 import | `FileKeyStore` → `LocalIdentityStore` | 新增 `AUNError`, `NotFoundError` |
| L38 | 修改 | `FetchAgentMdResult` → `DownloadAgentMdResult` | TypedDict 重命名 |
| L44 | 删除 | `HeadAgentMdResult` | TypedDict 整体删除 |
| L112 | 删除 | `AIDStore._agent_md_cache` | 内存 cache dict 删除，移入 AgentMdManager |
| L115 | 修改 | `AIDStore.__init__` | `FileKeyStore` → `LocalIdentityStore` |
| L129 | 修改 | `AIDStore.__init__` | 删除 `self._auth = AuthFlow(...)`，改为直接创建 `self._register_flow = RegisterFlow(...)` |
| L155 | 新增 | `AIDStore.__init__` | 初始化 `self._agent_md_manager = AgentMdManager(...)` 并注入 peer_resolver / http 回调 |
| L293 | 修改 | `AIDStore.register` | `self._auth._validate_aid_name` → `self._register_flow.validate_aid_name`；注册成功后调用 `_persist_gateway_url` |
| L355 | 修改 | `AIDStore.resolve` | `fetch_peer_cert` 改用 register_flow；resolve 后增加 `_persist_gateway_url`；`fetch_agent_md` → `download_agent_md` |
| L389 | 修改 | `fetch_agent_md` → `download_agent_md` | 方法重命名；委托给 `self._agent_md_manager.download()`，删除内联 HTTP + 验签逻辑 |
| L418 | 修改 | `head_agent_md` → `check_agent_md` | 重命名；委托给 `self._agent_md_manager.check()`；旧 check_agent_md 逻辑并入 |
| L501 | 修改 | `AIDStore.renew_cert` / `rekey` / `_begin_aid_operation` | `_validate_aid_name` / `_short_rpc` / `_verify_phase1_response` / `generate_identity` 全部改用 register_flow 公开方法 |
| L775 | 修改 | `import_trust_roots` / `update_issuer_root_cert` | `self._auth.reload_trusted_roots()` → `self._register_flow.reload_trusted_roots()` |
| L1104 | 修改 | `_load_cached_gateway_url` / `_persist_gateway_url` | 内联 db.get/set_metadata 改用 `_keystore.get/set_metadata_value`；新增 `_has_local_aid_material` 前置校验 |
| L1123 | 新增 | `AIDStore._has_local_aid_material` | 判断本地是否存有证书或密钥对（防止向无身份的 peer 写元数据） |
| L1133 | 删除 | `AIDStore._agent_md_url` | URL 拼接逻辑移入 AgentMdManager |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L29 | 修改 import | `AIDStore` → `AgentMdManager` | 删除 `from .aid_store import AIDStore`，改为 `from .agent_md import AgentMdManager` |
| L38 | 修改 import | `FileKeyStore` → `LocalTokenStore` | — |
| L342 | 新增 | `_build_client_runtime_manager(client)` | 模块级工厂函数，构造绑定 AUNClient 回调的 AgentMdManager 实例 |
| L524 | 修改 | `AUNClient.__init__` | 删除 `_agent_md_path` / `_local_agent_md_etag` / `_remote_agent_md_etag` / `_agent_md_cache` 字段；改为 `self._agent_md_manager = _build_client_runtime_manager(self)`；`FileKeyStore` → `LocalTokenStore` |
| L867 | 修改 | `AUNClient._reconnect_setup` | `FileKeyStore` → `LocalTokenStore`；重建 `_agent_md_manager` |
| L174 | 修改 | `AUNClient._discover_gateway_for_aid` | 删除 `_make_aid_store` 调用；改为先查 `_load_cached_gateway_url`，再调 `_discover_gateway_url`，并持久化 |
| L369 | 新增 | `AUNClient._discover_gateway_url` | 抽出 gateway 发现逻辑（DNS .well-known 双 URL fallback） |
| L423 | 新增 | `AUNClient._load_cached_gateway_url` | 从 LocalTokenStore 读取持久化 gateway_url |
| L460 | 新增 | `AUNClient._persist_gateway_url` | 写 gateway_url 到 LocalTokenStore |
| L486 | 新增 | `AUNClient._resolve_peer_aid` | 替代 `_get_peer` 内的 AIDStore.resolve；先查本地缓存 cert，再 fetch，构造只含公钥的 AID 对象 |
| L719 | 新增 | `AUNClient._public_aid_from_cert` | 从 cert PEM 构造公钥 AID 对象（校验时效 / CN 一致性） |
| L854 | 修改 | `AUNClient.upload_agent_md` | 重写为委托 `self._agent_md_manager.upload(content)` |
| L880 | 修改 | `AUNClient._observe_rpc_meta` | 内联逻辑 → `self._agent_md_manager.observe_rpc_meta(meta, ...)` |
| L2981 | 修改 | `AUNClient._inject_agent_md_etag` | 内联 local/remote etag 注入 → `self._agent_md_manager.event_snapshot()` |
| L4395 | 修改 | `_validate_slot_id`（message.pull/ack） | `slot_id != self._slot_id` → `slot_isolation_key(...)` 比较 |
| L6280 / L6443 / L7418 | 修改 | V2 解密路径 × 3 | `_observe_agent_md_from_envelope` → `self._agent_md_manager.observe_envelope` |
| — | 删除 | agent.md 内联方法群 | `_agent_md_content_etag` / `_agent_md_owner_aid` / `_agent_md_root` / `_make_aid_store` / `_agent_md_url` / `_agent_md_safe_aid` / `_agent_md_file_path` / `_agent_md_meta_path` / `_agent_md_record_lock` / `_atomic_write_text` / `_write_agent_md_record_unlocked` / `_normalize_agent_md_record` / `_read_agent_md_record_unlocked` / `_read_agent_md_content` / `_write_agent_md_content` / `_load_agent_md_record` / `_save_agent_md_record` / `_agent_md_has_local_content` / `_agent_md_checked_at_fresh` / `_schedule_agent_md_fetch_if_missing` / `_observe_agent_md_meta` / `_observe_agent_md_etag` / `_observe_agent_md_from_envelope` / `_check_agent_md` / `publish_agent_md` 全部移入 AgentMdManager 或合并 |

### `register_flow.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L17 | 新增 import | `GatewayCertificateVerifier` | — |
| L20 | 修改 import | `FileKeyStore` → `KeyStore` | 抽象基类 |
| L29 | 修改 | `RegisterFlow.__init__` | keystore 类型 `FileKeyStore` → `KeyStore`；新增 `root_ca_path` 参数；初始化 `self._certs = GatewayCertificateVerifier(...)` |
| L43~61 | 新增 | 公开代理方法群 | `validate_aid_name` / `fetch_peer_cert` / `short_rpc` / `generate_identity` / `new_client_nonce` / `verify_phase1_response` / `reload_trusted_roots` |

### `keystore/local_identity_store.py`（新文件，相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L35 | 新增 | `class LocalIdentityStore` | 原 FileKeyStore "含私钥"部分的独立实现，持有 encryption_seed，供 AIDStore 使用 |
| L78~150 | 新增 | 身份/私钥/证书/元数据读写 | `load_identity` / `save_identity` / `list_identities` / `load_any_identity` / `load_key_pair` / `save_key_pair` / `load_cert` / `save_cert` / `get_metadata_value` / `set_metadata_value` |
| L170 | 新增 | 信任根管理 | `trust_root_dir` / `trust_root_bundle_path` / `save_trust_roots` / `save_issuer_root_cert` |
| L212 | 新增 | pending 目录原子注册全流程 | `pending_identity_dir` / `list_pending_identity_dirs` / `save_pending_key_pair` / `load_pending_key_pair` / `save_pending_cert` / `promote_pending_identity` / `discard_pending_identity` / `cleanup_pending_dirs` |
| L268 | 新增 | `change_seed` / `ChangeSeed` | seed 迁移（委托 seed_migration 模块） |

### `keystore/local_token_store.py`（新文件，相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L28 | 新增 | `class LocalTokenStore` | 原 FileKeyStore "无私钥"部分的独立实现，供 AuthFlow / AUNClient 使用 |
| L80 | 新增 | `load_cert` / `save_cert` | 证书读写（含 fingerprint 版本化存储） |
| L116 | 新增 | `load_metadata` / `get_metadata_value` / `set_metadata_value` | 元数据读写 |
| L154 | 新增 | prekey 存取 | `load_e2ee_prekeys` / `load_e2ee_prekey_by_id` / `save_e2ee_prekey` |

## v0.4.5 — 相对于 v0.4.3 的变更

### `keystore/base.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L7 | 新增 | `class TokenStore` | 新增不含私钥操作的存储接口，AuthFlow/AUNClient 持有此类型 |
| L93 | 修改 | `class KeyStore` | 移除 load/save_key_pair、load/save_identity、list_identities，改为纯私钥接口；新增 pending 目录相关方法群 |
| L122~134 | 新增 | KeyStore pending 协议方法 | `pending_identity_dir` / `list_pending_identity_dirs` / `save_pending_key_pair` / `load_pending_key_pair` / `save_pending_cert` / `promote_pending_identity` / `discard_pending_identity` |
| L127 | 新增 | `class FullKeyStore` | 组合协议类，物理 keystore 同时实现 TokenStore + KeyStore |

### `register_flow.py`（新文件，相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L4 | 新增 | `class RegisterFlow` | 独立注册流模块，持有 FileKeyStore（含私钥操作），从 auth.py 剥离 |
| L20 | 新增 | `async def register_aid()` | 注册主流程，返回含私钥字段的 dict（私钥由 AIDStore 写入）；新增 pending 目录原子注册 |
| L122 | 新增 | `def _persist_identity()` | 只持久化 cert，私钥由 pending promote 或 AIDStore 管理 |
| L131 | 新增 | `async def _try_recover_pending_registration()` | pending 残留崩溃恢复逻辑 |
| L182 | 新增 | `async def _download_registered_cert()` | HTTP GET /pki/cert/{aid} 查服务端已注册证书 |
| L204~258 | 新增 | 注册辅助方法群 | `_create_aid` / `_short_rpc` / `_connect` / `_gateway_http_url` / `_validate_aid_name` |

### `auth.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L12 | 修改 import | — | 移除 `IdentityConflictError`、`FileKeyStore`；改导入 `TokenStore` |
| L21 | 修改 | `AuthFlow.__init__` 参数 | `keystore: FileKeyStore` → `token_store: TokenStore`（`_keystore` 重命名 `_token_store`） |
| L48 | 新增 | `AuthFlow._mem_identity` | 内存 identity 字段，存放 AUNClient 注入的明文私钥 |
| L50 | 新增 | `def set_identity()` | 由 AUNClient.load_identity 调用，注入内存私钥，不再走 token_store 解密 |
| L77 | 删除 | `async def register_aid()`（原实现） | 完整注册逻辑迁移至 RegisterFlow |
| L221 | 修改 | `_assert_cert_matches_local_keypair()` | 行为弱化：cert 或 pub_b64 任一缺失则直接 return，不再 raise |
| L233 | 新增 | `async def register_aid()`（stub） | 保留方法但直接 raise StateError，提示用 AIDStore.register |
| L1278 | 修改 | `_load_identity_or_raise()` | 移除 keystore 读取路径；优先从 `_mem_identity` 读取 |
| L1318 | 修改 | `_persist_identity()`（token_store 分支） | 只写 cert，不再写私钥字段 |

### `aid_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L20 | 新增 import | `RegisterFlow` | 引入新的注册流模块 |
| L141 | 修改 | `AIDStore._auth` 构造 | `keystore=` 参数改名为 `token_store=` |
| L148 | 新增 | `AIDStore._register_flow` | 新增 RegisterFlow 实例，由 AIDStore 独占持有（含私钥 keystore） |
| L285 | 修改 | `AIDStore.register()` 实现 | 从 `self._auth.register_aid()` 改为 `self._register_flow.register_aid()`；cert 和 key_pair 由 AIDStore 写入 keystore |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L356 | 修改 | `AUNClient._keystore` | 重命名为 `_token_store`（20+ 处引用同步替换） |
| L375 | 新增 | `AUNClient.__init__` identity 注入 | 若传入 `initial_aid_obj`，立即构建内存 identity dict 并调用 `_auth.set_identity()` |
| L391 | 修改 | `AUNClient.load_identity()` | `self._identity = None` 改为构建完整内存 identity dict 并调用 `_auth.set_identity()` |
| L431 | 修改 | `_post_authenticate()` | identity 改为直接用 `self._identity`；新增持久化 `refresh_token`、`access_token_expires_at` |
| L621 | 修改 | `_sync_identity_after_connect()` | 不再调用 `_auth.load_identity_or_none()` / `_persist_identity()`；直接操作 `_identity` dict 并通过 `_token_store.update_instance_state()` 持久化 access_token |
| L655 / L4708 | 修改 | `_invoke_reconnect_connect_once()` / `_token_refresh_loop()` | fresh_identity 改为直接读 `self._identity` |
| L4522~4542 | 修改 | 调试事件名 | `ensure_sender_cert_keystore_*` → `ensure_sender_cert_token_store_*` |

## v0.4.3 — 相对于 v0.4.2 的变更

> 0.4.3 含两次提交：`2d1bce76`（slot_id 校验与隔离键，标记 0.4.3a）与 `dc380c86`（AID 持明文私钥 + pending 原子注册，标记 0.4.3b）。

### 0.4.3a（`2d1bce76`）— slot_id 隔离键 + ConnectionOptions 扩展

#### `config.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L13 | 新增 | `_SLOT_ID_PATTERN` | slot_id 正则，允许 `/` `:` 空格作分隔符（但不得出现在首字符） |
| L57 | 修改 | `normalize_slot_id()` | 重写：不再复用 `normalize_instance_id`，改用 `_SLOT_ID_PATTERN` 校验，非法字符抛 `ValueError` |
| L67 | 新增 | `slot_isolation_key()` | 提取 slot_id 第一个分隔符之前的部分作为隔离键 |

#### `client.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L27 | 修改 import | — | 新增导入 `slot_isolation_key` |
| L1625~1633 | 新增 | `_build_connect_params()` 内 | 透传 `connection_kind` / `short_ttl_ms` / `extra_info` / `delivery_mode` / `background_sync` |
| L3452 | 修改 | `_is_message_for_me()` | slot_id 比较改用 `slot_isolation_key()` 对比隔离键，不再全字符串匹配 |

#### `types.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L69~73 | 新增 | `ConnectionOptions` 新字段 | `connection_kind`（'long'/'short'）、`short_ttl_ms`、`extra_info`、`delivery_mode`、`background_sync`（默认 True） |

#### `keystore/sqlite_db.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L26 | 修改 | `_SCHEMA_VERSION` | `1` → `2` |
| L132 / L140 | 新增 | `instance_state.slot_id_full` / `seq_tracker.slot_id_full` | 表新增列，存储完整 slot_id（原 slot_id 列改存隔离键） |
| L370 | 修改 | `AIDDatabase._init_schema()` | 新增 schema 版本检测分支，旧版本调用 `_migrate_schema()` 升级 |
| L380 | 新增 | `AIDDatabase._migrate_schema()` | 静态方法：v1→v2 为两张表各 ALTER ADD COLUMN slot_id_full |
| L1380~1413 | 修改 | `save_instance_state()` / `load_instance_state()` / `save_seq()` | slot 存储/查询键改用 `slot_isolation_key()`，写入时同时保存 `slot_id_full` 原始值 |

### 0.4.3b（`dc380c86`）— AID 持明文私钥 + pending 原子注册

#### `aid.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L41 | 新增 | `AID.private_key_pem: str` | 新增字段，AIDStore 加载时注入明文私钥 PEM |
| L61 | 新增 | `AID._create(private_key_pem)` | `_create` 工厂方法新增 `private_key_pem` 参数，构造时写入实例 |

#### `aid_store.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L234 | 新增 | `AIDStore.load`（内部构造 AID） | 调用 `AID._create` 时传入 `private_key_pem`，将 key_pair 明文私钥注入 AID 对象 |

#### `auth.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1422 | 新增 | `AuthFlow._persist_identity` | 持久化前过滤 `private_key_pem`、`public_key_der_b64`、`curve`，防止私钥写入 key.json |

#### `client.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L228 | 新增 | `_PUBLIC_CONNECTION_OPTION_KEYS` | 模块级常量，列出 connect() opts 允许的公开字段白名单 |
| L504 / L837 | 删除 | `connect` / `reconnect`（内部） | 构造 `FileKeyStore` 时移除 `encryption_seed` 参数 |
| L1617 | 修改 | `connect` opts 校验 | 改为白名单校验：传入非公开字段抛 `ValidationError` |
| L1847 / L1873 | 修改 | `_sign_client_operation` | 私钥来源从 `_identity` dict 改为 `_current_aid.private_key_pem`；cert 改为 `current_aid.cert_pem` |
| L2038 | 修改 | `_route_call`（group.ack_messages） | V2 ack 路由前增加 `_group_cursor_targets_current_instance` 检查 |
| L2363 | 新增 | `AUNClient._await_ack` | 异步方法，await ack RPC 完成（替代 fire-and-forget，用于 pull 返回前收敛游标） |
| L4874 | 新增 | `_group_cursor_targets_current_instance` | 判断 params 中 device_id/slot_id 是否指向当前实例 |
| L5492 | 修改 | `_init_v2_session` | 移除 identity 缓存自愈逻辑，直接从 `_current_aid.private_key_pem` 读私钥 |
| L5885 | 修改 | `_pull_v2_p2p`（auto-ack） | `_fire_ack` → `await _await_ack`；ack 触发增加 `has_page_server_ack and contig > page_server_ack` 分支 |
| L6991~7163 | 修改 | `_pull_v2_group` | 新增 `has_explicit_after_seq` 标志；pull/ack 携带 device_id/slot_id/device_name/device_type 支持外部 cursor；`owns_cursor` 判断；补充 `has_more` 字段计算 |
| L7572 | 修改 | `_auto_propose_v2_group_state` | 签名私钥来源改为 `_current_aid.private_key_pem` |

## v0.4.2 — 相对于 v0.4.0 的变更

### `__init__.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L7 / L43 | 新增 | `ConnectionOptions` | 从 `.types` 导入并加入 `__all__` 导出列表 |

### `aid.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L39~41 | 新增 | `AID.verify_ssl` / `root_ca_path` / `debug` | 新增三个连接配置字段（默认 True / None / False） |
| L56 | 修改 | `AID._create()` | 新增 `verify_ssl`、`root_ca_path`、`debug` 三个参数 |

### `aid_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L37~91 | 新增 | 9 个 TypedDict 返回类型 | `FetchAgentMdResult` / `HeadAgentMdResult` / `CheckAgentMdResult` / `DiagnoseResult` / `RenewCertResult` / `RekeyResult` / `ChangeSeedResult` / `ResolveResult` / `ListResult` |
| L107 | 删除 | `AIDStore.__init__` 参数 `discovery_port` | 移除 `discovery_port: int \| None` 参数 |
| L190 / L228 | 修改 | `AIDStore.load()` / `register()` | `_create` 调用时透传 `verify_ssl`、`root_ca_path`、`debug` |
| L233~633 | 修改 | 各方法返回类型收窄 | `list` / `change_seed` / `resolve` / `fetch_agent_md` / `head_agent_md` / `check_agent_md` / `diagnose` / `renew_cert` / `rekey` 均收窄为对应 `Result[XxxResult]`；`resolve` 新增 `timeout`/`timeoutMs`，`fetch_agent_md` 新增 `timeout_s` 并删除 signature/certPem/status 等冗余返回字段 |
| L974 / L1175 / L1226 | 修改 | `_pki_authority()` / `_resolve_gateway_url()` / `_agent_md_url()` | 移除 `discovery_port` 端口拼接逻辑 |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L403 | 修改 | `AUNClient.__init__()` | 删除参数 `debug: bool`、`protected_headers`；`debug` 改为从 `aid.debug` 读取；删除 `set_protected_headers()` 调用 |
| L889 | 修改 | `AUNClient._make_aid_store()` | 移除 `discovery_port` 传参 |
| L1594 | 修改 | `AUNClient.connect()` | 参数由 `options: dict` 改为 `opts: ConnectionOptions \| None`；移除 `access_token` 外部传入；`slot_id` 改从 AID 对象读取；`NO_IDENTITY` 状态直接 raise |
| L1733~5216 | 修改 | 多处事件名 | `connection.state` → `state_change`（`disconnect` / `close` / `_on_auth_complete` / `_on_disconnected` / `_reconnect_loop`） |

### `types.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L59 | 新增 | `class ConnectionOptions(TypedDict, total=False)` | 新增连接选项类型，含 7 个可选字段：`auto_reconnect`、`connect_timeout`、`retry_initial_delay`、`retry_max_delay`、`retry_max_attempts`、`heartbeat_interval`、`call_timeout` |

---

## v0.4.0 — 相对于 v0.3.7 的变更

### `aid.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L37 / L38 | 新增 | `AID.device_id` / `AID.slot_id` | 新增字段，默认 `""` / `"default"` |
| L51 | 修改 | `AID._create()` | 签名新增 `device_id` 和 `slot_id` 参数，构造时赋值（`slot_id` 空值归一化为 `"default"`） |

### `aid_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L128 / L163 | 修改 | `_load_cert_only()` / `_load_full()` | 调用 `AID._create()` 时透传 `device_id` / `slot_id` |

### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L10 | 新增 import | `re` | 用于 key 校验 |
| L418 / L499 / L804 | 修改 | `__init__()` / `switch_aid()` | `_device_id` 优先用 `initial_aid_obj.device_id`，回退 `get_device_id()`；`_slot_id` 优先用 `aid.slot_id`，回退 `normalize_slot_id(None)` |
| L444 | 修改 | `__init__()` | `_instance_protected_headers` 初始化改为先置 `None` 再调 `set_protected_headers()` |
| L857 | 修改 | `set_protected_headers()` | 新增 key 合规校验：限 `[a-z0-9_-]`，过滤 `_auth` 保留键，非法 key 静默跳过，值强转 `str` |

### `__init__.py` / `version.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L31 | 修改 | `__version__` | 从硬编码字符串改为从 `version.py` 导入；版本号升至 `"0.4.0"` |

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
| 304 处理 | 按非 2xx 错误返回；不复用缓存、不重试 |

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
