# Python SDK V2-Only 改动清单

基线：`d8b79f44` (v0.2.20 之后，master_1.0.0 分支)
日期：2026-05-20

## 一、源码改动（`python/src/aun_core/`）

### 1. client.py：8588 行 → 4502 行（净删 4086 行）

#### 删除的 V1 E2EE 代码（共 ~95 个方法）

**V1 P2P 加密：**
- `_send_encrypted`, `_build_self_sync_copies`, `_build_recipient_device_copies`
- `_encrypt_copy_payload`, `_ensure_encrypt_result`, `_resolve_self_copy_peer_cert`
- `_log_e2ee_error`

**V1 群组加密：**
- `_send_group_encrypted`, `_put_group_thought_encrypted`, `_put_message_thought_encrypted`
- `_call_group_encrypted_rpc`, `_prepare_group_encrypted_rpc_params`

**V1 Epoch 管理：**
- `_recover_group_epoch_key`, `_do_recover_group_epoch_key`, `_try_recover_epoch_key_from_server`
- `_recover_initial_group_epoch_if_needed`, `_request_group_key_from_candidates`
- `_request_group_key_from_online`, `_request_group_key_from`
- `_group_epoch_secret_ready_for_recovery`, `_pending_group_secret_still_current`
- `_ensure_group_epoch_ready`, `_wait_for_group_membership_epoch_floor`
- `_committed_group_epoch`, `_committed_group_epoch_state`
- `_ensure_committed_group_secret_for_send`, `_committed_rotation_membership_gap`

**V1 密钥控制面：**
- `_try_handle_group_key_message`, `_verify_active_group_rotation_distribution`
- `_verify_group_key_response_epoch`, `_discard_group_distribution_if_stale`
- `_ack_group_rotation_key`

**V1 Epoch 轮换：**
- `_build_rotation_signature`, `_attach_rotation_id`, `_build_epoch_encrypted_keys`
- `_distribute_group_epoch_key`, `_heartbeat_group_rotation`, `_abort_group_rotation`
- `_schedule_group_rotation_retry`, `_sync_epoch_to_server`
- `_maybe_lead_rotate_group_epoch`, `_ranked_group_rotation_candidates`, `_rotate_group_epoch`
- `_delayed_rotate_after_join`, `_maybe_backfill_key_to_joined_member`
- `_distribute_key_to_new_member`, `_start_group_epoch_tasks`
- `_is_rotation_leader`, `_group_epoch_rotate_loop`, `_group_epoch_cleanup_loop`

**V1 解密：**
- `_decrypt_messages`, `_decrypt_single_message`
- `_decrypt_group_message`, `_decrypt_group_messages`
- `_decrypt_group_thoughts`, `_decrypt_message_thoughts`

**V1 Pending queue：**
- `_enqueue_pending_decrypt`, `_schedule_retry_pending_decrypt_msgs`
- `_retry_pending_decrypt_msgs`, `_schedule_recovery_timeout`, `_cleanup_group_state`

**V1 Prekey：**
- `_upload_prekey`, `_prekey_refresh_loop`, `_start_prekey_refresh_task`
- `_schedule_prekey_replenish_if_consumed`, `_invalidate_peer_prekey_cache`
- `_fetch_peer_prekeys`, `_fetch_peer_prekey`, `_normalize_peer_prekeys`
- `_refresh_peer_prekeys`, `_clear_peer_cert_cache`

**V1 错误辅助：**
- `_is_group_epoch_too_old_error`, `_is_group_epoch_rotation_pending_error`
- `_is_group_epoch_changed_during_send_error`, `_is_recoverable_group_epoch_error`
- `_is_expected_group_rotation_skip_error`

**V1 成员轮换辅助：**
- `_membership_rotation_trigger_id`, `_membership_rotation_changed`
- `_membership_rotation_expected_epoch`, `_extract_group_id_from_result`
- `_get_group_member_aids`, `_local_group_members_match`, `_extract_group_join_mode`
- `_group_allows_member_epoch_rotation`, `_group_key_recovery_candidates`
- `_joined_member_aids_from_payload`

**V1 群组推送处理：**
- `_process_and_publish_group_message`, `_auto_pull_group_messages`, `_fill_group_gap`

**V1 公开 API：**
- `e2ee` property, `group_e2ee` property
- `send_v2`, `pull_v2`, `ack_v2`, `send_group_v2`, `pull_group_v2`, `ack_group_v2`
  （独立方法合并进 `call()` 路由）

#### 删除的 V1 实例变量

- `self._e2ee` (E2EEManager)
- `self._group_e2ee` (GroupE2EEManager)
- `self._pending_decrypt_msgs`
- `self._recovery_timeout_scheduled`
- `self._group_epoch_rotation_inflight`
- `self._group_epoch_rotation_retry_tasks`
- `self._group_epoch_recovery_inflight`
- `self._group_membership_rotation_done`
- `self._group_member_key_backfill_done`

#### 新增/修改的逻辑

- `_on_raw_group_message_created`：简化为明文消息透传 + seq 跟踪（不再做 V1 解密）
- `_process_and_publish_message`：移除 V1 解密调用，明文直接透传
- `_on_raw_group_changed`：移除 V1 epoch 轮换编排，保留 V2 `_v2_auto_propose_state` + event gap 检测
- `call()` 中 `message.pull` / `group.pull` 后处理：移除 V1 解密，保留 seq 跟踪 + auto-ack
- `_stop_background_tasks`：移除 V1 epoch 任务清理
- `_start_background_tasks`：移除 `_start_group_epoch_tasks()` 调用
- V2 解密元数据：`e2ee` 字段增加 `encryption_mode` 和 `forward_secrecy`
- V2 group pull：移除返回值去重（pull 始终返回所有解密成功的消息）

### 2. seq_tracker.py：+14 行

- `on_pull_result` 新增 `after_seq` 参数
- gap fill 场景（`after_seq == contiguous_seq`）：直接把 pull 到的最大 seq 作为新 `contiguous_seq`，跳过服务端永久空洞

### 3. `__init__.py`：无变化（`ProtectedHeaders` 保留）

### 4. `e2ee.py`：不动（3544 行保留作为参考）

### 5. 保留的 e2ee.py 引用（非 E2EE 加解密）

- `from .e2ee import ProtectedHeaders` — 纯数据类，V2 也用
- `from .e2ee import compute_state_hash` (2处) — 群组 state hash 验证工具函数

## 二、测试改动（`python/tests/`）

### 删除的测试文件（纯 V1 E2EE）

- `e2e_test_epoch_key_server.py` — V1 epoch key 服务端托管
- `integration_test_e2ee.py` — V1 P2P E2EE 集成
- `integration_test_multi_device_e2ee.py` — V1 多设备 E2EE
- `unit/test_client_group_e2ee.py` — V1 群组 E2EE 单元测试（93 个用例）

### 删除的测试用例（从现有文件中移除）

- `test_client.py`：24 个 V1 测试（prekey、send_encrypted V1、decrypt_group 等）
- `test_py_issues.py`：`TestPY004PrekeyRefreshLoop`
- `test_py_issues_batch2.py`：`TestPY001DecryptFailStillAutoAck`、`TestPY002KeyRecoveryRetry`、`TestPY003DissolveCleanup`、`TestPY005RotateLoopLeaderElection`
- `test_py_issues_batch3.py`：`TestPY002PushedSeqsLimit`、`TestPY005EpochWait`

### 修改的测试

- `test_client.py`：`test_e2ee_property` 改为断言 `e2ee` 属性不存在
- `integration_test_storage.py`：自定义 redirect handler 支持 PUT 302 重定向

## 三、服务端改动（`extensions/services/`）

| 文件 | 改动 |
|------|------|
| `gateway/entry.py` | kernel event 订阅补全 V2 事件（fallback）；`_handle_event_notification` 路由补全 V2 事件 |
| `gateway/ws_server.py` | `_dispatch_event_from_service` 白名单补全 `group.state_committed` |
| `gateway/relay.py` | `_should_forward_event` 补全 `group.state_committed`；`_V2_ONLY_GROUP_METHODS` 补全 `propose_state/confirm_state/get_proposal` |
| `message/entry.py` | `AUN_DIRECT_EVENT_MESSAGE` 默认改为 True；V2 send 返回 status 对齐 V1 语义（`delivered`/`sent`） |
| `group/entry.py` | `AUN_DIRECT_EVENT_GROUP` 默认改为 True；`_targets_for_group_event` / `is_client_event` 补全 `group.state_committed`；`_rpc_v2_pull` / `_rpc_v2_ack` 补全成员权限检查 |

## 四、Bug 修复（需要其它 SDK 对齐）

### BUG-1: gap fill 时 contiguous_seq 卡死

**根因：** `on_pull_result` 从 `contiguous_seq` 开始 pull，如果服务端返回的消息跳过了某些 seq（永久空洞：竞态跳跃/未持久化/过期清理），`_try_advance` 逐个检查时会卡在第一个缺失的 seq 上，永远无法推进。新消息被阻塞在 SDK 内部有序队列中，上层收不到。

**修复：** `on_pull_result` 新增 `after_seq` 参数。当 `after_seq == contiguous_seq`（gap fill 场景）时，直接把 pull 到的最大 seq 作为新的 `contiguous_seq`。

**影响范围：** P2P pull、group pull、event pull 三条路径。

### BUG-2: V2 group pull 返回值去重导致手动 pull 拿不到已 push 的消息

**根因：** `_pull_group_v2_internal` 中 `_is_published_seq` 去重导致已通过 push 自动 pull 消费的消息在手动 pull 时被跳过，返回空列表。

**修复：** pull 返回值不再做 `_is_published_seq` 去重。`_publish_ordered_message` 内部仍做事件投递去重（防止重复触发应用层回调），但 pull 的返回值始终包含所有解密成功的消息。

### BUG-3: V2 message.send 返回 status 不对齐 V1 语义

**根因：** V2 send 返回 `"status": "accepted"`，但 SDK 和应用层已按 V1 语义（`sent`/`delivered`）实现。

**修复：** 服务端 `delivered_count > 0` 时返回 `delivered`，否则返回 `sent`。

### BUG-4: V2 解密元数据缺少 encryption_mode

**根因：** V2 解密后 `e2ee` 字段只有 `version` + `suite`，缺少 `encryption_mode` 和 `forward_secrecy`，导致依赖这些字段的测试/应用层判断失败。

**修复：** 补全 `encryption_mode: "v2_{suite}"` 和 `forward_secrecy: True`。

## 五、验证结果

| 测试 | 结果 |
|------|------|
| 单元测试 | 501 passed |
| V2 P2P E2EE | 12/12 |
| V2 Group E2EE | 8/8 |
| V2 Multi-device | 6/6 |
| Echo | 5/5 |
| Message Ack | 4/4 |
| Storage | 4/4 |
| 双域明文 | PASS |
| 双域加密 | PASS |
| 双域离线 | PASS |
| 双域群组 | 2/2 |
