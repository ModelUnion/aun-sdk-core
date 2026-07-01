# Python SDK 变更清单（v0.3.3 → v0.5.1）— 跨 SDK 对齐参考

本文档供 Go / TypeScript / JavaScript SDK 进行功能对齐时使用，详尽列出各版本 Python SDK 的实际变更，定位到具体类、函数与代码行。

CHANGELOG（接口级摘要）：见 `python/CHANGELOG.md`。本文档为**实现级别详尽清单**。

涉及提交：`5a962885` (v0.3.7) → ... → `1a92fbf6` (v0.5.0，对外发布基线；tag object 为 `b0328ef2`) → `42e1694b` (perf-quick-wins) → `3f3fa167` (storage 对齐) + 工作区 (v0.5.1)。

---


## v0.5.1 — 相对于对外发布 v0.5.0 的变更

> 基线：`v0.5.0^{}` = `1a92fbf6`（对外发布的 v0.5.0 commit；`v0.5.0` 本身是 annotated tag，tag object 为 `b0328ef2`）vs 当前工作区（目标版本 v0.5.1，`pyproject.toml` / `version.py` 已标 0.5.1）。
>
> 提交范围：`42e1694b`（gateway/group/message 性能优化 + storage VFS/group-resources 四语言对齐）→ `3f3fa167`（storage 与 group.fs SDK/服务端对齐）+ 工作区未提交改动。
>
> 行号说明：本节所有 `Lx` / `Lx~Ly` 均指**当前工作区文件行号**，用于 Go / TypeScript / JavaScript SDK 对齐实现时快速定位。相对路径默认以 `python/` 为基准。
>
> 七大变更块：**① `group_id` → `group_aid` 目标态与校验层**、**② V1 E2EE 移除与 V2-only/keystore 简化**、**③ group_aid 身份生命周期与签名集合**、**④ Storage VFS / group.fs 增量**、**⑤ V2 消息、seq_tracker、push/gap-fill 性能与可靠性**、**⑥ transport/logger/errors/CLI bench**、**⑦ 测试覆盖与对齐优先级**。

### 版本与基线

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `pyproject.toml` | L7 | 修改 | `version = "0.5.1"` | Python 包目标版本号 |
| `src/aun_core/version.py` | L1 | 修改 | `__version__ = "0.5.1"` | SDK 运行时版本号 |
| git tag | - | 基线 | `v0.5.0^{}` = `1a92fbf6` | 上次公开发布版本；注意 `v0.5.0` 是 annotated tag，直接 `rev-parse v0.5.0` 得到 tag object `b0328ef2` |

### 块① `group_id` → `group_aid` 目标态与校验层

> 0.5.1 的核心目标态是：协议字段仍兼容 `group_id`，但 SDK 内部 namespace、seq、state、keystore、签名与 V2 envelope 统一按 `group_aid = {base}.{issuer}` 归一。旧 `group.{issuer}/{base}`、`{base}@{issuer}`、短 group name 都必须兼容转换。

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/group_id.py` | L16~53 | 新增/重写 | `convert_to_group_aid()` | 将旧 `group.{issuer}/{base}`、`{base}@{issuer}`、目标 `{base}.{issuer}`、短格式统一转换为 `{base}.{issuer}`；跨 SDK 必须复刻同一解析优先级 |
| `src/aun_core/group_id.py` | L56~63 | 修改 | `normalize_group_aid()` / `normalize_group_id()` | `normalize_group_id()` 保留旧函数名但返回 group_aid，不能再返回 legacy group id |
| `src/aun_core/group_id.py` | L66~78 | 修改 | `split_group_id()` / `build_discovery_host()` | `split_group_id()` 返回 `(base, issuer)`；`build_discovery_host()` 只返回 issuer 域，不再拼 `{base}.{domain}` |
| `src/aun_core/validators.py` | L31~91 | 新增 | `validate_aid_format()` | AID 格式校验独立成公共实现；message/group/thought 入参都应复用相同规则 |
| `src/aun_core/validators.py` | L96~127 | 新增 | `_validate_group_aid_parts()` | 校验 group_aid 的 base/issuer 片段，约束长度、字符集、域名片段 |
| `src/aun_core/validators.py` | L130~155 | 新增 | `validate_group_aid_format()` | 目标格式校验入口，返回规范化 group_aid |
| `src/aun_core/validators.py` | L158~192 | 修改 | `validate_group_id_format()` | 兼容旧命名但直接转向 `validate_group_aid_format()`；SDK 对齐时不应保留旧 legacy-only 校验 |
| `src/aun_core/_client/rpc_pipeline.py` | L56~83 | 修改 | `call()` | RPC 调用进入前先调用 `normalize_group_call_identifier()`，再做 outbound 参数校验 |
| `src/aun_core/_client/rpc_pipeline.py` | L301~348 | 修改 | `validate_outbound_call()` | 覆盖 `message.send.to`、`group.send.group_id`、thought 的 AID/group_id 校验；错误应在 SDK 侧提前抛出 |
| `src/aun_core/_client/rpc_pipeline.py` | L444~454 | 修改 | `pull_gate_key_for_call()` | pull gating key 优先使用 `group_aid`，生成 `group:{group_aid}` / `group_event:{group_aid}` |
| `src/aun_core/_client/rpc_pipeline.py` | L546~578 | 新增 | `normalize_group_call_identifier()` | 接受 `group_aid` / `groupAid` / `group_id` / `groupId`；写回 `group_aid`，同时保留 wire 兼容字段 `group_id` |
| `src/aun_core/_client/delivery.py` | L96~123 | 修改 | `_postprocess_group_pull()` | group pull 后处理使用 group_aid 作为 seq namespace，避免 legacy id 与目标 id 混用 |
| `src/aun_core/_client/delivery.py` | L178~215 | 修改 | `handle_group_changed_event()` | `group.changed` 先 normalize group id；`group.online_unread_hint` 只触发 gap fill，不发布给业务层 |
| `src/aun_core/_client/delivery.py` | L938~981 | 修改 | `clamp_ack_params()` | group ack namespace 统一按 group_aid 计算，ack 参数保持兼容 |
| `src/aun_core/_client/delivery.py` | L1782~1829 | 新增 | `migrate_seq_state_group_ids()` | 启动时迁移 `group:` / `group_event:` / `group_msg:` 的 legacy namespace；冲突时取 max 并落盘 |
| `src/aun_core/_client/v2_e2ee.py` | L17~26 | 新增 | `_group_identifier_pair()` | 从 `group_aid` / legacy `group_id` 得到 `(wire_group_id, group_aid)`，所有 group V2 路径复用 |
| `src/aun_core/_client/v2_e2ee.py` | L1377~1614 | 修改 | `send_group_encrypted_v2()` | `group.v2.send` 增加 `group_aid`，同时保留 `group_id` wire 字段 |
| `src/aun_core/_client/v2_e2ee.py` | L2365~2618 | 修改 | `pull_group_v2_internal()` / `ack_group_v2_internal()` | 内部 ns 使用 group_aid，RPC 参数同时带 `group_id` 与 `group_aid`，ack 也双字段兼容 |
| `src/aun_core/keystore/sqlite_db.py` | L120~150 | 新增 | `_group_lookup_candidates()` / `_canonical_group_key()` | SQLite group state 读取兼容 legacy 候选，写入使用 canonical group_aid |
| `src/aun_core/keystore/sqlite_db.py` | L470~516 | 修改 | `save_group_state()` / `load_group_state()` | group_state 存 canonical group_aid；读取时多候选兼容并在返回值补 `group_aid` |
| `src/aun_core/keystore/local_token_store.py` | L28~32 | 新增 | `_issuer_from_aid()` | 本地 JSON token store 通过 issuer 做 legacy group state 查询兼容 |
| `src/aun_core/keystore/local_token_store.py` | L177~225 | 修改 | `save_group_state()` / `load_group_state()` / `save_seqs()` | group state 兼容读取；新增批量 seq 保存入口 |
| `src/aun_core/v2/keystore.py` | L34~35 | 修改 | `_group_key()` | V2 keystore 内部 group key 统一 normalize 为 group_aid |
| `src/aun_core/v2/keystore.py` | L77~84 | 新增迁移 | schema migration | 迁移旧 group key 到 normalize 后的 canonical key |
| `src/aun_core/v2/session.py` | L76~77 | 修改 | `_group_key()` | V2 session group cache key 统一 normalize |
| `src/aun_core/v2/state/commitment.py` | L33~61 | 修改 | `compute_state_commitment()` | state commitment 输入 group_id 先 normalize，再进入 canonical commitment |

**对齐要点**：其他语言 SDK 需要把“字段兼容”和“内部目标态”分离：RPC wire 可以继续传 `group_id`，但本地缓存、seq namespace、V2 group SPK、state commitment、keystore key 必须以 group_aid 为准。

---

### 块② V1 E2EE 移除与 V2-only/keystore 简化

> 0.5.1 不再保留 Python V1 E2EE 本地实现。`e2ee.py` 只保留协议仍需的轻量结构与 hash helper；V2 路径集中在 `_client/v2_e2ee.py`、`v2/session.py`、`v2/keystore.py`。

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/e2ee.py` | L12~46 | 保留 | `ProtectedHeaders` | 保留 V2 envelope/header 仍需要的 protected header 数据结构 |
| `src/aun_core/e2ee.py` | L49~78 | 保留 | `compute_state_hash()` | 保留 state hash helper；旧 `E2EEManager` / `GroupE2EEManager` / epoch key / metadata auth helper 已移除 |
| `src/aun_core/__init__.py` | L5~50 | 修改导出 | top-level exports | 顶层仅导出 `ProtectedHeaders` 等当前 API，不再导出旧 V1 E2EE manager |
| `src/aun_core/keystore/base.py` | L7~49 | 简化 | `TokenStore` protocol | 删除 prekeys、group secrets、e2ee sessions 等 V1 协议面，只保留 token/group_state/seq 等当前存储能力 |
| `src/aun_core/keystore/local_token_store.py` | L177~225 | 简化 | `LocalTokenStore` | 删除 V1 prekeys/group secrets 方法；保留 group_state 与 seq 持久化 |
| `src/aun_core/keystore/sqlite_db.py` | L470~579 | 简化 | `AUNSQLiteDB` group/seq methods | DDL 不再保留 `prekeys`、`group_current`、`group_old_epochs`、`e2ee_sessions`；保留 `tokens` / `group_state` / `instance_state` / `v2_device_keys` |
| `src/aun_core/auth.py` | L44~46 | 修改能力声明 | capabilities | SDK 仍声明 `group_e2ee=True`，但 `supported_group_e2ee` 只保留 `group_e2ee_v2` |
| `src/aun_core/config.py` | L127~156 | 修改配置语义 | `group_e2ee` | group E2EE 是必备能力，不再允许通过配置关闭到 V1/非 V2 语义 |

| 删除测试/旧入口 | 类型 | 说明 |
|----------------|------|------|
| `tests/e2e_test_group_e2ee.py` | 删除 | 旧 V1 group E2EE E2E 覆盖移除 |
| `tests/e2e_test_v2_group_e2ee.py` | 删除 | 旧命名/旧流程 V2 group E2E 覆盖移除，改由当前 V2/group SPK/group pull 测试覆盖 |
| `tests/unit/test_e2ee.py` | 删除 | 旧 `E2EEManager`/`GroupE2EEManager` 单测移除 |
| `tests/unit/test_ecies_epoch_key.py` | 删除 | 旧 epoch/prekey crypto 单测移除 |
| `tests/unit/test_py_issues.py` / `test_py_issues_batch2.py` / `test_py_issues_batch3.py` | 删除 | 旧问题回归集合移除或迁移到当前 test_client/test_validators 等文件 |
| `tests/unit/test_sqlite_storage_interop.py` | 删除 | 旧 SQLite storage interop 覆盖移除 |

**对齐要点**：Go/TS/JS 不应再补旧 V1 manager API；保留兼容文档中的旧名字时，也应标记为废弃或移除，不要让 SDK 对外面重新暴露 V1 本地加密接口。

---

### 块③ group_aid 身份生命周期与签名集合

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/client.py` | L208~235 | 修改 | `_NON_IDEMPOTENT_METHODS` | 新增 `group.renew_group_aid`、`group.fs.set_acl`、`group.fs.remove_acl`；移除旧 group e2ee rotation/update_name/avatar 等写侧方法 |
| `src/aun_core/client.py` | L1003~1048 | 修改 | `_SIGNED_METHODS` | 新增 `group.renew_group_aid`、`group.fs.set_acl/remove_acl`；移除 `group.e2ee.*` 签名集合 |
| `src/aun_core/client.py` | L1066~1083 | 新增 | `call()` / `_maybe_handle_half_open_rpc_failure()` | READY 状态下 `ConnectionError` / `TimeoutError` 自动触发重连，修复半开连接后业务 RPC 长时间失败 |
| `src/aun_core/client.py` | L1085~1138 | 修改 | `create_group()` | 命名群创建时本地生成 group_aid 身份并导入证书；匿名群路径仍兼容透传 |
| `src/aun_core/client.py` | L1140~1279 | 重写 | `bind_group_aid()` | 匿名群绑定 group_aid 支持 pending key、崩溃恢复、证书公钥校验、import 后清理 pending |
| `src/aun_core/client.py` | L1281~1400 | 新增 | `renew_group_aid()` | 用旧 group_aid 私钥签 canonical `aun-group-aid-renew-v1|...`，调用 `group.renew_group_aid`，校验证书公钥后覆盖本地身份 |
| `src/aun_core/client.py` | L1402~1461 | 修改 | `start_group_transfer()` | 群转让发起端改用 `group.get_info` 获取 group_aid，并以 group_aid 身份签 transfer auth |
| `src/aun_core/client.py` | L1463~1562 | 修改 | `complete_group_transfer()` | 新群主完成 rekey 后校验证书公钥并 import 新 group_aid 身份 |
| `src/aun_core/client.py` | L1762~1784 | 修改 | `_on_raw_group_changed()` | 事件入口接受 `group_aid` 或 `group_id`，再交给 delivery 统一 normalize |
| `src/aun_core/client.py` | L1786~1812 | 修改 | `_cleanup_dissolved_group()` | 解散群时清理 bootstrap target cache、seq_tracker、pending ordered 等本地状态 |
| `src/aun_core/keystore/local_identity_store.py` | L112~126 | 修改 | `save_identity()` | 保存 identity 时 skip 集合只跳过密钥/证书原材料字段，不再跳旧 e2ee 字段 |
| `src/aun_core/keystore/local_identity_store.py` | L341~412 | 新增 | `save_pending_group_bind()` / `load_pending_group_bind()` / `clear_pending_group_bind()` | group_aid bind 崩溃恢复所需 pending key slot |
| `src/aun_core/facades.py` | L70~71 | 新增 | `GroupFacade.renew_group_aid()` | group 门面暴露 renew 能力 |
| `src/aun_core/facades.py` | L163~174 | 修改 | `GroupFacade.send()` / `GroupFacade.pull()` | 门面侧先校验 group_id/group_aid，避免低层 RPC 才报错 |
| `src/aun_core/facades.py` | L186~350 | 新增 | group settings helpers | `get/update_announcement`、`get/update_rules`、`get/update_join_requirements` 统一封装 settings map |

**对齐要点**：group_aid 私钥只在 SDK 本地生成和保存，服务端只返回证书。bind/renew/transfer 都必须验证服务端证书中的公钥与本地生成的公钥一致，不能只信任返回字段。

---

### 块④ Storage VFS / group.fs 增量

#### Storage VFS 与 LowLevel

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/storage/lowlevel.py` | L792~814 | 新增 | `StorageLowLevel.fs_touch()` | 映射 `storage.fs.touch`，用于 CLI `fs touch` 与 VFS `touch()` |
| `src/aun_core/storage/lowlevel.py` | L993~1021 | 修改 | `StorageLowLevel.fs_invalidate_membership()` | 接受 `group_id` 或 `group_aid`，要求 `group_owner_aid`，RPC 同时传 `group_id` / `group_aid` 兼容字段 |
| `src/aun_core/storage/vfs.py` | L545~566 | 新增 | `StorageVFS.touch()` | 高级 VFS touch API，统一走 `storage.fs.touch` |
| `src/aun_core/storage/vfs.py` | L737~777 | 新增 | `StorageVFS.du()` | 基于 `find()` 聚合 size、file/dir/symlink 计数，不依赖新的服务端 du RPC |
| `src/aun_cli/commands/fs.py` | L188~194 | 新增 | `_human_size()` | `fs quota` / `fs du` 输出复用的人类可读 size helper |
| `src/aun_cli/commands/fs.py` | L265~267 | 修改 | `fs_lstat._run()` | lstat 输出补齐 readlink 相关展示 |
| `src/aun_cli/commands/fs.py` | L539~558 | 新增 | `fs_touch()` | CLI 暴露 `aun fs touch` |
| `src/aun_cli/commands/fs.py` | L601~603 | 修改 | `fs_quota._run()` | quota 输出使用 `_human_size()` |
| `src/aun_cli/commands/fs.py` | L777~791 | 新增 | `fs_du()` | CLI 暴露 `aun fs du`，对应 VFS 聚合实现 |

#### group.fs ACL、token 与 group_aid 参数

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/group_fs.py` | L96~109 | 修改 | `_bearer_headers()` | HTTP 数据面 access token 从 `client.access_token`、`_identity.access_token`、`_session_params.access_token` 逐级 fallback |
| `src/aun_core/group_fs.py` | L126~157 | 新增 | `set_acl()` / `remove_acl()` / `get_acl()` / `list_acl()` | group.fs ACL 门面；写侧方法进入 `_SIGNED_METHODS` |
| `src/aun_core/group_fs.py` | L166~242 | 修改 | `cp()` | 支持 `group_aid` / `src_group_aid` / `dst_group_aid`，兼容旧 `group_id`；local↔group 分支传 group_aid |
| `src/aun_core/group_fs.py` | L244~275 | 修改 | `mv()` | 支持 group_aid 参数，并拒绝本地路径 move |
| `src/aun_cli/commands/group.py` | L605~633 | 新增 | `group_fs_setfacl()` | CLI 暴露 group.fs set ACL，支持 `--sign-as` |
| `src/aun_cli/commands/group.py` | L635~645 | 新增 | `group_fs_getfacl()` | CLI 暴露 group.fs get/list ACL |
| `src/aun_cli/commands/group.py` | L753~773 | 修改 | `group_bind._run()` | bind 输出/保存 active group 时使用 group_aid |
| `src/aun_cli/commands/group.py` | L1090~1096 | 修改 | `group_set_role._run()` | group role 命令对 active group/group_aid 做兼容处理 |
| `src/aun_cli/commands/group.py` | L1200~1205 | 修改 | `group_info._run()` | group info 展示服务端返回的 group_aid/核心字段 |

**对齐要点**：Storage `touch/du` 是 SDK/VFS 层能力；`du` 当前不需要新增服务端 RPC。group.fs 写操作要保留 `sign_as` 本地签名身份选择，但不能把 `sign_as` 作为业务参数透传给服务端。

---

### 块⑤ V2 消息、seq_tracker、push/gap-fill 性能与可靠性

#### delivery 与 seq_tracker

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/_client/delivery.py` | L25~32 | 新增 | `_coerce_positive_seq()` | push/pull seq 接受数字与数字字符串；非法/非正值返回 0 |
| `src/aun_core/_client/delivery.py` | L671~699 | 修改 | `log_message_debug()` | debug 未启用或 NullLogger 时直接返回，避免高频 JSON 序列化开销 |
| `src/aun_core/_client/delivery.py` | L701~720 | 新增 | `record_push_processing()` / `record_p2p_gap_fill()` / `record_auto_ack()` | 增加 push/gap/ack 统计计数，供 bench/e2e 与诊断输出读取 |
| `src/aun_core/_client/delivery.py` | L759~783 | 修改 | `drain_ordered_messages()` | ordered drain 后保存 seq_tracker，避免重启后重复发布 |
| `src/aun_core/_client/delivery.py` | L785~857 | 修改 | `publish_ordered_message()` | 增加 `_ordered_gap_block_stats`，按阈值 WARN gap block，发布后持久化 seq |
| `src/aun_core/_client/delivery.py` | L908~996 | 修改 | `fire_ack()` / `safe_ack()` | ack scheduled/ok/failed 统计，ack 参数先 clamp 到 canonical namespace |
| `src/aun_core/_client/delivery.py` | L1492~1575 | 修改 | `fill_p2p_gap()` / `fill_p2p_gap_inner()` | READY 状态允许 gap fill；统计 raw/published/empty/failed |
| `src/aun_core/_client/delivery.py` | L1577~1695 | 修改 | `fill_group_event_gap()` / `fill_group_event_gap_inner()` | READY 状态允许 group event gap fill，group_id 先 normalize |
| `src/aun_core/_client/delivery.py` | L1697~1751 | 修改 | pending P2P follow-up | 记录 upper bound，仅 READY 时调度 follow-up pull |
| `src/aun_core/_client/delivery.py` | L1842~1959 | 新增 | seq flush helpers | `_seq_tracker_flush_loop()`、`_write_seq_tracker_values()`、`_flush_seq_tracker_pending()`、`_merge_seq_tracker_pending()`、`_schedule_seq_tracker_flush()` 支持延迟批量落盘 |
| `src/aun_core/_client/delivery.py` | L1996~2076 | 修改 | `persist_seq()` / `persist_repaired_seq()` / `repair_push_contiguous_bound()` / `save_seq_tracker_state()` | seq 持久化默认 0.2s 批量写；修复 push contiguous bound 与强制保存路径 |
| `src/aun_core/keystore/sqlite_db.py` | L555~579 | 新增 | `save_seq()` / `save_seqs()` | `save_seq()` 转调 `save_seqs()`；SQLite 使用 `executemany` 批量 upsert |

#### V2 E2EE/pull/send 性能

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/_client/v2_e2ee.py` | L102~128 | 新增 | `_target_cache*()` / `clear_*_bootstrap_cache()` | P2P/group bootstrap target cache，发送失败或群解散时清理 |
| `src/aun_core/_client/v2_e2ee.py` | L505~700 | 修改 | `send_encrypted_v2()` | P2P 目标集合使用 target cache，支持 self-sync/audit recipients；失败清 cache 重试 |
| `src/aun_core/_client/v2_e2ee.py` | L702~899 | 修改 | `pull_v2_internal()` | P2P 分页 pull、stale row 过滤、force contiguous、并行解密多消息页、ack 逻辑重写 |
| `src/aun_core/_client/v2_e2ee.py` | L901~1060 | 新增 | `_can_parallel_decrypt_*()` / `_decrypt_*_page_parallel()` | 判断页面是否可并行解密，并执行 P2P/group 页面并行解密 |
| `src/aun_core/_client/v2_e2ee.py` | L1061~1241 | 新增 | `_apply_p2p_decrypt_result()` / `_apply_group_decrypt_result()` | 并行解密结果统一转业务消息、统计、过滤 stale |
| `src/aun_core/_client/v2_e2ee.py` | L1243~1763 | 修改 | `build_v2_p2p_envelope()` / `build_v2_group_envelope()` | 构建 envelope 时复用 target cache，group 路径使用 group_aid |
| `src/aun_core/_client/v2_e2ee.py` | L2226~2274 | 修改 | `publish_encrypted_push_as_undecryptable()` / `publish_encrypted_push_message()` | push 统计增加 decrypt_fail/undecryptable_published/decrypt_ok/app_published |
| `src/aun_core/_client/v2_e2ee.py` | L2365~2586 | 修改 | `pull_group_v2_internal()` | group 分页、stale 过滤、并行解密、group_aid namespace、ack 重写 |
| `src/aun_core/v2/crypto/ecdh.py` | L28~85 | 修改 | `_cache_get()` / `_cache_put()` / `ecdh_compute_shared()` | ECDH 私钥/公钥对象缓存，减少热路径 DER/scalar 解析 |
| `src/aun_core/v2/crypto/ecdsa.py` | L29~116 | 修改 | `_private_key_from_scalar()` / `_public_key_from_der()` / `ecdsa_sign_raw()` / `ecdsa_verify_raw()` | ECDSA key 解析路径统一并缓存化 |
| `src/aun_core/v2/session.py` | L66~70 | 新增字段 | group SPK cache | V2 session 新增 group SPK 缓存，避免与 P2P SPK 记录冲突 |
| `src/aun_core/v2/session.py` | L184~247 | 修改 | `ensure_group_spk()` / `get_group_decrypt_keys()` / `ensure_group_registered()` / `rotate_group_spk()` / `is_last_uploaded_group_spk()` | group SPK 生命周期与上传标记按 group_aid 隔离 |

**对齐要点**：并行解密只适用于满足页面条件的批次；其他语言 SDK 不能为了性能跳过 stale row、contiguous seq、ack floor 与 undecryptable 事件语义。

---

### 块⑥ transport/logger/errors/CLI bench

| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `src/aun_core/logger.py` | L99~100 | 新增 | `AUNLogger.is_debug_enabled()` | 高频路径可在构造 debug payload 前判断 |
| `src/aun_core/logger.py` | L160~178 | 新增 | `NullLogger.is_null_logger()` / `is_debug_enabled()` | NullLogger 明确返回 debug disabled，配合 delivery/transport 降低热路径开销 |
| `src/aun_core/transport.py` | L94~105 | 新增 | `_debug_enabled()` | transport 层统一判断 debug 是否启用 |
| `src/aun_core/transport.py` | L306~342 | 修改 | `RPCTransport.__init__()` | 新增 `_foreground_waiters` / `_admission_cond`，背景 RPC 在前台调用前让路 |
| `src/aun_core/transport.py` | L482~524 | 修改 | `RPCTransport.call()` | 后台双信号量 + `_wait_background_turn()`；队列超时抛 `TimeoutError(retryable=True)` |
| `src/aun_core/transport.py` | L553~702 | 修改 | `_call_inner()` | full request/response debug 仅 debug enabled 时构造；timeout 诊断增强 |
| `src/aun_core/transport.py` | L714~759 | 修改 | `_reader_loop()` | 记录 websocket close code/reason，并 fail pending |
| `src/aun_core/transport.py` | L761~790 | 新增/修改 | `_not_connected_error()` / `_send_failure_error()` | 断线错误包含 last close code/reason；send failure 从 websocket closed 提取细节 |
| `src/aun_core/transport.py` | L791~856 | 修改 | `_route_message()` | 全量事件/通知 debug 输出受 debug enabled gating 控制 |
| `src/aun_core/errors.py` | L125~170 | 修改 | `map_remote_error()` | `-32004` 且 message 以 `rpc handler timeout` 开头映射 `TimeoutError`；`-32429` 映射 RateLimit；`gateway service degraded` / `certificate not loaded` 标记 retryable |
| `src/aun_cli/adapter.py` | L123~170 | 修改 | `resolve_profile_config()` | CLI profile/config 解析调整，影响 bench/e2e 与 group/fs 命令默认身份 |
| `src/aun_cli/commands/bench.py` | L126~181 | 修改 | `_bench_trace_off()` / `_run_benchmark()` | bench 默认关闭 trace 并统一运行包装 |
| `src/aun_cli/commands/bench.py` | L185~235 | 修改 | `bench_send()` | 新增 `--no-persist` 与 payload 参数，便于吞吐/延迟压测 |
| `src/aun_cli/commands/bench_e2e.py` | L51~103 | 新增 | `E2EConfig` / `AutoscaleConfig` | e2e/autoscale 配置对象 |
| `src/aun_cli/commands/bench_e2e.py` | L177~416 | 新增 | `E2ERecorder` / `BenchMatchTrace` | 记录发送、投递、ack、trace 与匹配状态 |
| `src/aun_cli/commands/bench_e2e.py` | L985~1175 | 新增 | `run_e2e_scenario()` / `_run_*_scenario()` | connect、receiver drain、message 等 e2e 场景 |
| `src/aun_cli/commands/bench_e2e.py` | L1302~1403 | 新增 | `_run_offline_pull_scenario()` / `_pull_until_seen()` / `_settle_receivers_after_send()` | 离线 pull 与发送后 settle 逻辑 |
| `src/aun_cli/commands/bench_e2e.py` | L1684~1769 | 新增 | `_run_storage_vfs_scenario()` / `_run_group_fs_scenario()` / `_run_collab_scenario()` / `_run_notify_scenario()` | 非消息类 happy path 纳入 e2e bench |
| `src/aun_cli/commands/bench_e2e.py` | L1816~2048 | 新增 | `_send_one()` / handler helpers | 单条发送与 receiver handler 安装/提取 |
| `src/aun_cli/commands/bench_e2e.py` | L2059~2148 | 新增 | `_summarize_e2e()` | e2e 输出 delivery/ack/gap/backpressure 摘要 |
| `src/aun_cli/commands/bench_e2e.py` | L2344~2880 | 新增 | `run_autoscale()` / autoscale helpers | autoscale 阶段执行、hard/soft stop、summary、backpressure 统计 |
| `src/aun_cli/commands/bench_e2e.py` | L3204~3815 | 新增命令 | `e2e_*` / `autoscale_*` | 暴露 connect/drain/send/group/offline/storage/group_fs/collab/notify/all 与 autoscale send/group |

**对齐要点**：transport 的前后台公平性与 debug gating 是性能语义的一部分；CLI bench 不是 SDK core API，但它定义了跨语言压测/验收口径。

---

### 块⑦ 测试覆盖与跨 SDK 对齐优先级

#### 新增/重点测试入口

| 文件 | 行号 | 类型 | 说明 |
|------|------|------|------|
| `tests/unit/test_group_id.py` | L14~47 | 新增 | 覆盖 group_aid 多格式转换、legacy 函数名、discovery host、非法输入 |
| `tests/unit/test_validators.py` | L11~231 | 修改/新增 | AID/group_aid/group_id 校验与 send 方法入参校验 |
| `tests/unit/test_group_aid_bind_renew.py` | L64~209 | 新增 | bind 幂等/崩溃恢复清理、renew 旧 key 签名、本地身份缺失错误 |
| `tests/unit/test_storage_vfs_p4.py` | L28~182 | 新增/修改 | VFS ACL/token/read range/touch/du 合约 |
| `tests/unit/test_cli_fs_p4.py` | L94~207 | 新增/修改 | CLI chmod/setfacl/token/cat/lstat/readlink/touch/quota/du |
| `tests/unit/test_cli_group_fs.py` | L118~326 | 新增/修改 | active group 裸路径、local↔group cp、Windows 盘符、本地路径拒绝、ACL、mount/umount |
| `tests/e2e_test_group_fs_sdk.py` | L64~136 | 新增 | group.fs SDK facade roundtrip 与 admin ACL grant/revoke |
| `tests/unit/test_v2_group_spk.py` | L26~267 | 新增/修改 | group SPK 与 P2P SPK 隔离、legacy composite id 兼容、上传标记恢复 |
| `tests/unit/test_client.py` | L1123 | 新增/修改 | group call 接受 `group_aid` / `groupAid` / `groupId` aliases |
| `tests/unit/test_client.py` | L1963 | 新增/修改 | group pull 使用 group_aid namespace，同时保留 legacy wire `group_id` |
| `tests/unit/test_client.py` | L2185 / L2372 | 新增/修改 | P2P/group 多消息页并行解密 |
| `tests/unit/test_client.py` | L2909 / L2952 / L2981 | 新增/修改 | push gap 与 READY 状态 gap fill |
| `tests/unit/test_client.py` | L3719 / L3753 | 新增/修改 | `group.online_unread_hint` 背景同步行为 |
| `tests/unit/test_client.py` | L4268 | 新增/修改 | `group.changed` 只带 group_aid 时仍走 canonical group namespace |
| `tests/unit/test_client.py` | L5392 / L5417 / L5708 | 新增/修改 | ordered gap block 统计、debug short-circuit、push processing stats |
| `tests/unit/test_client.py` | L5968 | 新增/修改 | READY client RPC timeout 触发 half-open reconnect |
| `tests/unit/test_errors.py` | L10~45 | 修改 | timeout、legacy permission、rate limit、certificate-not-loaded retryable 映射 |
| `tests/unit/test_cli_bench_e2e.py` | L9~1591 | 新增/修改 | e2e recorder、send/drain/offline/autoscale、backpressure、summary、happy path 场景 |
| `tests/unit/test_sdk_facades.py` | L22~127 | 修改 | 门面参数剔除 None、group send/pull 预校验、namespace facade 缓存 |
| `tests/unit/test_cli_group.py` | L542 | 修改 | group fs 写命令使用 `--as-aid` / `--sign-as` session 与签名身份 |

#### 对齐优先级建议

| 优先级 | 范围 | 必须对齐的 file:func:line |
|--------|------|---------------------------|
| P0 | group_aid canonical 化 | `src/aun_core/group_id.py:convert_to_group_aid:L16`、`validators.py:validate_group_aid_format:L130`、`_client/rpc_pipeline.py:normalize_group_call_identifier:L546`、`_client/delivery.py:migrate_seq_state_group_ids:L1782` |
| P0 | V2 group 消息正确性 | `_client/v2_e2ee.py:_group_identifier_pair:L17`、`send_group_encrypted_v2:L1377`、`pull_group_v2_internal:L2365`、`ack_group_v2_internal:L2588`、`v2/session.py:ensure_group_spk:L184` |
| P0 | V1 E2EE 移除 | `e2ee.py:ProtectedHeaders:L12`、`e2ee.py:compute_state_hash:L49`、`keystore/base.py:TokenStore:L7`、`__init__.py:exports:L5` |
| P1 | group_aid 生命周期 | `client.py:bind_group_aid:L1140`、`renew_group_aid:L1281`、`complete_group_transfer:L1463`、`local_identity_store.py:save_pending_group_bind:L347` |
| P1 | Storage/group.fs 增量 | `storage/lowlevel.py:fs_touch:L792`、`storage/vfs.py:touch:L545`、`storage/vfs.py:du:L737`、`group_fs.py:set_acl:L126`、`group_fs.py:cp:L166` |
| P1 | seq/push/gap 性能可靠性 | `delivery.py:publish_ordered_message:L785`、`fill_p2p_gap:L1492`、`fill_group_event_gap:L1577`、`persist_seq:L1996`、`sqlite_db.py:save_seqs:L558` |
| P2 | transport 与 bench 口径 | `transport.py:call:L482`、`errors.py:map_remote_error:L125`、`bench_e2e.py:run_e2e_scenario:L985`、`bench_e2e.py:run_autoscale:L2344` |

---



## v0.5.0 — 相对于对外发布 v0.4.13 的变更

> 基线：`0d418563`（对外发布的 v0.4.13）vs v0.5.0 发布整理时的目标工作区（`pyproject.toml` / `version.py` 当时已标 0.5.0）。本节保留为历史对齐清单。
>
> 行号说明：本节所有 `Lx` / `Lx~Ly` 保留 v0.5.0 整理时的实现定位，用于 Go / TypeScript / JavaScript / C++ SDK 对齐实现时快速定位。相对路径默认以 `python/src/aun_core/` 或 `python/src/aun_cli/` 为基准。
>
> 六大变更块：**① 公开门面与导出面升级**、**② Storage VFS / LowLevel 子协议**、**③ `group.fs` POSIX 群文件系统（替代 `group.resources`）**、**④ Collab 协作编辑 RPC 门面与 CLI**、**⑤ Transport / 后台 RPC 公平性与关闭清理**、**⑥ CLI 与测试对齐**。

### 块① 公开门面与导出面升级

#### `client.py`（相对 `python/src/aun_core/`）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L609 | 新增字段 | `AUNClient._background_rpc_depth` | SDK 内部后台 RPC 深度计数；进入后台任务时置位，避免把 `_rpc_background` 泄漏为业务参数 |
| L682~686 | 新增字段 | `_storage_vfs` / `_message_facade` / `_group_facade` / `_stream_facade` / `_collab_facade` | AUNClient 懒加载门面缓存 |
| L707~712 | 新增属性 | `AUNClient.storage` | 懒加载并返回 `StorageVFS(self)`；这是属性，不是方法 |
| L715~720 | 新增属性 | `AUNClient.collab` | 懒加载并返回 `CollabClient(self)` |
| L723~728 | 新增属性 | `AUNClient.message` | 懒加载并返回 `MessageFacade(self)` |
| L731~736 | 新增属性 | `AUNClient.group` | 懒加载并返回 `GroupFacade(self)`；`GroupFacade.__init__` 内挂载 `group.fs` |
| L739~744 | 新增属性 | `AUNClient.stream` | 懒加载并返回 `StreamFacade(self)` |
| L1056~1109 | 新增 | `async create_group(params=None, *, aid_store=None, **kwargs)` | `group_name` 为空时保持原 `group.create` 透传；命名群路径本地生成 group_aid 密钥、把 `public_key` / `curve` 注入 `group.create`，服务端返回 `aid_cert` 后调用 `AIDStore.import_group_identity()` 落盘私钥 + 证书 |
| L1111~1157 | 新增 | `async bind_group_aid(params=None, *, aid_store=None, **kwargs)` | 为匿名群补齐 group_aid：本地生成密钥，调用 `group.bind_group_aid`，再导入群身份 |
| L1159~1218 | 新增 | `async start_group_transfer(params=None, *, aid_store=None, **kwargs)` | 群主转让发起端：加载旧 `group_aid` 私钥，构造 canonical `aun-group-owner-transfer-v1|...`，签名后把 `transfer_auth` 注入 `group.transfer_owner` |
| L1220~1308 | 新增 | `async complete_group_transfer(params=None, *, aid_store=None, **kwargs)` | 新群主完成 rekey：本地生成新 group_aid 密钥，用当前 AID 私钥签 `transfer_accept`，调用 `group.complete_transfer` 后导入新的 group_aid 身份 |
| L206~236 | 修改 | `_NON_IDEMPOTENT_METHODS` | 新增 `storage.fs.*`、`storage.volume.*`、`group.fs.*`、`collab.*` 写侧方法；影响非幂等 RPC 超时策略 |
| L990~1040 | 修改 | `_SIGNED_METHODS` | 同步新增 `storage.*` / `storage.fs.*` / `group.fs.*` / `collab.*` 写侧方法，确保 `client_signature` 注入覆盖新增写操作 |

#### `aid_store.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L88~90 | 新增类型 | `ImportGroupIdentityResult` | `{"imported": bool}` 返回结构 |
| L744~793 | 新增 | `AIDStore.import_group_identity(aid, *, private_key_pem, public_key_der_b64, curve, cert_pem)` | 校验证书 AID 与公钥匹配（L768~773），保存身份材料（L774~780），再通过 `load()` 做私钥/证书自检（L781~787）；供 `create_group` / `bind_group_aid` / `complete_group_transfer` 落盘 group_aid |

#### `facades.py`（新文件）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L6~22 | 新增 | `_RpcFacade` | 通用 RPC 门面基类；`_params()` 合并 dict + kwargs 并剔除 None，`_call()` 拼接 `<prefix>.<method>` |
| L25~30 | 新增 | `ThoughtFacade.put()` / `get()` | 封装 `message.thought.*` 与 `group.thought.*` |
| L33~51 | 新增 | `MessageFacade` | 封装 `message.send` / `pull` / `ack` / `recall` / `query_online`，并挂载 `message.thought` |
| L54~207 | 新增 | `GroupFacade` | 封装 group 管理、成员、邀请、消息、事件、公告、规则、在线成员等 RPC；L57~59 创建 `GroupFSVFS` 并挂到 `self.fs` |
| L210~224 | 新增 | `StreamFacade` | 封装 `stream.create` / `close` / `get_info` / `list_active` |

#### `__init__.py` / `storage/__init__.py` / `collab/__init__.py`
| 文件 | 行号 | 类型 | 说明 |
|------|------|------|------|
| `__init__.py` | L8~11 | 新增导入 | 导出 `GroupFacade` / `MessageFacade` / `StreamFacade` / `ThoughtFacade`、`GroupFSVFS`、`StorageLowLevel` / `StorageVFS`、`CollabClient` / `CollabError` / `CollabConflictError` |
| `__init__.py` | L49~58 | 修改 `__all__` | 将上述新增门面列入顶层公开 API |
| `storage/__init__.py` | L1~40 | 新增 | 导出 storage 错误类型、`StorageLowLevel`、`StorageVFS`、`NodeView` / `ObjectView` / `DownloadResult` / `RemoveResult` / `UsageView` 与路径 helper |
| `collab/__init__.py` | L1~9 | 新增 | 导出 `CollabClient`、`TagClient`、`CollabError`、`CollabConflictError` |

**对齐要点**：四语言需保持 `client.storage` / `client.group.fs` / `client.collab` 这种“门面入口”语义一致。Python 当前是属性；TS/JS/Go 可按本语言惯例暴露，但不要把 storage 门面误做成低级 `StorageLowLevel`，Python 的 `client.storage` 返回的是 `StorageVFS`。

---

### 块② Storage VFS / LowLevel 子协议

#### `storage/lowlevel.py`（新文件）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L12~22 | 新增 | `_AllMethodRedirectHandler.redirect_request()` | 允许 PUT/POST/DELETE/PATCH 在 301/302/303/307/308 时保持原 method 与 body 继续跳转 |
| L25~34 | 新增 | `_build_opener(verify_ssl)` | 基于 `urllib.request` 构造 HTTP/HTTPS opener，`verify_ssl=False` 时关闭证书校验 |
| L37~1058 | 新增类 | `StorageLowLevel` | Storage RPC + HTTP 数据面低级封装 |
| L45~50 | 新增 | `_call(method, params=None, *, path="")` | 统一调用 `client.call()`，异常经 `map_storage_error()` 映射为 storage 错误 |
| L53~59 | 新增 | `_params(owner=None, bucket="default", **kwargs)` | 统一把 `owner` 映射为 `owner_aid`，补 `bucket`，剔除 None |
| L61~80 | 新增 | `get_limits()` / `get_quota()` / `check_upload()` | 上传限制、配额、上传预检 RPC |
| L82~185 | 新增 | `put_object()` / `get_object()` / `create_upload_session()` / `complete_upload()` | 对象上传下载核心 RPC；`put_object()` 对 bytes 做 base64，`complete_upload()` 支持 `skip_blob` / `overwrite` |
| L187~241 | 新增 | `create_download_ticket()` / `create_share_link()` / `list_share_links()` / `revoke_share_link()` / `get_by_share()` | 下载票据、分享链接与分享访问 |
| L243~293 | 新增 | `http_put()` / `http_get()` | HTTP 数据面上传/下载；支持 headers 与进度回调 |
| L295~344 | 新增 | `head_object()` / `list_objects()` / `list_prefixes()` / `delete_object()` | 对象元信息、分页列表、前缀列表、删除 |
| L346~396 | 新增 | `set_object_meta()` / `append_object()` | 元数据更新与追加写 |
| L398~455 | 新增 | `batch_delete()` / `move_object()` / `copy_object()` | 批量删除、移动、复制 |
| L457~544 | 新增 | `create_folder()` / `get_folder()` / `list_children()` / `move_folder()` / `delete_folder()` | 目录树低级 RPC |
| L546~611 | 新增 | `create_symlink()` / `readlink()` / `atomic_repoint()` / `rename_symlink()` / `delete_symlink()` | 软链创建、读取、CAS 改指向、改名、删除 |
| L613~731 | 新增 | `set_acl()` / `remove_acl()` / `list_acl()` / `set_visibility()` / `check_access()` / `issue_token()` / `revoke_token()` / `list_tokens()` | ACL、可见性、访问检查与访问 token |
| L733~991 | 新增 | `fs_list()` / `fs_stat()` / `fs_lstat()` / `fs_mkdir()` / `fs_remove()` / `fs_rename()` / `fs_copy()` / `fs_find()` / `fs_df()` / `fs_mount()` / `fs_approve()` / `fs_reject()` / `fs_unmount()` / `fs_invalidate_membership()` | `storage.fs.*` POSIX 层低级 RPC |
| L993~1043 | 新增 | `volume_create()` / `volume_renew()` / `volume_expire_due()` | storage volume 生命周期 RPC |
| L1045~1058 | 新增 | `resolve_path()` | 路径解析 RPC；支持 `expected_type` / `follow_symlinks` |

#### `storage/vfs.py`（新文件）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L17~42 | 新增 helper | `normalize_path()` / `path_to_key()` / `key_to_path()` / `split_parent_name()` | POSIX 路径规范化，统一 `/` 与 object key 的转换 |
| L49~66 | 新增 helper | `_is_remote_ref()` / `_split_remote_ref()` | 识别 `AID:/path` 远程引用；排除 Windows 盘符和 HTTP URL |
| L69~977 | 新增类 | `StorageVFS` | 高级虚拟文件系统门面，默认走 `storage.fs.*` 权威 RPC，可通过 `use_fs_rpc=False` 回退旧对象/目录 RPC |
| L83~234 | 新增 | `upload_file()` / `write_bytes()` / `_upload_bytes()` | 文件/bytes 上传；先 `check_upload`，命中 dedup/instant 时走 `complete_upload(skip_blob=True)`，否则创建 upload session + HTTP PUT |
| L236~318 | 新增 | `download_file()` / `read_bytes()` | 下载文件或读取 bytes；输出文件默认拒绝覆盖，`overwrite=True` 时用临时文件原子替换 |
| L320~392 | 新增 | `list()` / `_list_recursive()` | 默认调用 `storage.fs.list`，递归模式 breadth-first 展开 |
| L394~448 | 新增 | `stat()` / `lstat()` / `_stat()` | `stat` 跟随软链，`lstat` 不跟随；回退路径用 `resolve_path` + `head_object/get_folder/readlink` |
| L450~527 | 新增 | `symlink()` / `readlink()` / `repoint()` / `rename_symlink()` | 软链高级 API；CAS 冲突时映射为 `ConflictError` |
| L529~580 | 新增 | `mkdir()` / `remove()` | 创建目录、删除文件/目录/软链；`remove(recursive=True)` 回退用 `batch_delete` |
| L582~682 | 新增 | `rename()` / `copy()` | 文件、目录、软链统一移动/复制；fs RPC 不可用时按对象/目录回退 |
| L684~719 | 新增 | `find()` / `df()` | 查找节点与用量视图 |
| L721~860 | 新增 | `mount()` / `mount_volume()` / `approve_mount()` / `reject_mount()` / `unmount()` | mount 支持源 `AID:/path` 与 volume_id 两条路径；approve/reject 支持 mount_path/mount_id/request_id |
| L862~977 | 新增 | `set_acl()` / `remove_acl()` / `list_acl()` / `set_visibility()` / `check_access()` / `issue_token()` / `revoke_token()` / `list_tokens()` / `get_usage()` | ACL、可见性、访问检查、访问 token、用量高级 API |

#### `storage/types.py` / `storage/errors.py`
| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `storage/types.py` | L26~37 | 新增 | `normalize_display_path()` / `name_from_path()` | 展示路径归一与 basename 提取 |
| `storage/types.py` | L40~120 | 新增 dataclass | `NodeView` | 统一 file/dir/symlink/mount 视图；`from_object()` L60~76、`from_folder()` L79~92、`from_any()` L95~117 |
| `storage/types.py` | L123~135 | 新增 dataclass | `ObjectView` | `NodeView` 扩展 `sha256` / `etag` |
| `storage/types.py` | L138~156 | 新增 dataclass | `DownloadResult` / `RemoveResult` | 下载与删除结果视图 |
| `storage/types.py` | L159~180 | 新增 dataclass | `UsageView` | 配额/用量视图；兼容 `quota_total_bytes` / `quota_used_bytes` |
| `storage/types.py` | L183~192 | 新增 | `to_plain(value)` | dataclass/list/tuple/dict 递归转 plain dict/list，供 CLI JSON 输出 |
| `storage/errors.py` | L10~55 | 新增错误类型 | `StorageError` 及 `NotFoundError` / `ExistsError` / `AccessDeniedError` / `ConflictError` / `QuotaError` / `SessionExpiredError` / `LoopError` / `DanglingSymlinkError` 等 | Storage 专用异常体系 |
| `storage/errors.py` | L58~91 | 新增 | `map_storage_error(exc, *, path="")` | 远端 `AUNError.code` / 消息文本映射到 POSIX 风格错误码：`ENOENT`、`EEXIST`、`EACCES`、`ECONFLICT`、`ELOOP`、`EDANGLING`、`EQUOTA` 等 |

**对齐要点**：Storage 对齐必须分两层实现：低级 `StorageLowLevel` 逐个 RPC 映射，高级 `StorageVFS` 负责路径归一、dedup 上传流程、软链/mount/ACL 语义与错误映射。`storage.fs.*` 是 0.5.0 的权威 POSIX 接口；旧对象/目录 RPC 仅作为兼容回退。

---

### 块③ `group.fs` POSIX 群文件系统（替代 `group.resources`）

> 0.5.0 整理时已移除 `group.resources.*` 方向的 SDK 文档/测试入口，`rg "group.resources"` 在运行时代码中无命中；面向 SDK 的群文件能力统一收敛为 `group.fs.*`。

#### `group_fs.py`（新文件，相对 `python/src/aun_core/`）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L20~45 | 新增 helper | `_is_explicit_local_path()` / `_strip_local_path_prefix()` / `_is_group_remote_copy_path()` / `is_group_remote_path()` | 区分本地路径、`local:` 显式本地路径、`group:`/`AID:/path` 远程路径；Windows 盘符不被误判为远程 |
| L48~334 | 新增类 | `GroupFSVFS` | `client.group.fs` 的 POSIX 群文件系统门面 |
| L53~61 | 新增 | `_params(params=None, **kwargs)` | 合并参数、调用 `_apply_signing_identity()`、剔除 None |
| L63~88 | 新增 | `_apply_signing_identity(params)` | 支持 `sign_as` / `aid_store`：当写操作需用 group_aid 私钥签名时，从 `AIDStore.load(sign_as)` 取 AID 对象并注入内部 `_client_signature_identity` |
| L90~98 | 新增 | `_call()` / `_bearer_headers()` | RPC 异常映射为 storage 错误；下载票据 HTTP GET 自动带当前 access token |
| L100~120 | 新增 | `ls()` / `find()` / `stat()` / `lstat()` / `mkdir()` / `rm()` | POSIX 读写基础方法，对应 `group.fs.ls/find/stat/lstat/mkdir/rm` |
| L122~184 | 新增 | `cp(src, dst, *, force=False, recursive=False, parents=True, ...)` | 三分支：远程→远程走 `group.fs.cp`；本地→远程走 `_upload_local_file()`；远程→本地走 `_download_remote_file()`；本地→本地抛 `StorageError(EINVAL)` |
| L186~205 | 新增 | `mv(src, dst, *, force=False, **options)` | 仅支持 group remote path，调用 `group.fs.mv` |
| L207~217 | 新增 | `df()` / `mount()` / `umount()` | 对应 `group.fs.df/mount/umount` |
| L219~276 | 新增 | `_upload_local_file()` | 本地文件上传：读文件、算 sha256、`group.fs.check_upload`，命中 instant/dedup/skip_upload 则 `complete_upload(skip_blob=True)`，否则创建 upload session + HTTP PUT + complete |
| L278~334 | 新增 | `_download_remote_file()` | 创建 `group.fs.create_download_ticket`，HTTP GET 下载，校验 sha256，写本地文件；`force=True` 时临时文件原子替换 |

#### `client.py` / `aid_store.py`
| 文件 | 行号 | 类型 | 说明 |
|------|------|------|------|
| `client.py` | L1028~1035 | 修改 `_SIGNED_METHODS` | 将 `group.fs.mkdir/rm/cp/mv/mount/umount/check_upload/create_upload_session/complete_upload/create_download_ticket` 纳入签名集合 |
| `client.py` | L1056~1308 | 新增 group_aid 生命周期 | `create_group` / `bind_group_aid` / `start_group_transfer` / `complete_group_transfer` 为 group.fs 提供可签名 group_aid 身份与群主转让 rekey 流程 |
| `aid_store.py` | L744~793 | 新增 `import_group_identity()` | group_aid 私钥由 SDK 本地生成，服务端只签证书；落盘后通过 `load()` 自检 |

#### `aun_cli/commands/group.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L126~199 | 新增 helper | `_normalize_group_fs_bare_path()` / `_is_local_group_fs_path()` / `_classify_group_fs_cp_path()` / `_output_group_fs_nodes()` 等 | 裸路径默认绑定当前 active group；支持 `local:` 前缀和 Windows 盘符本地判定 |
| L296~320 | 新增命令 | `group_fs_ls()` | `aun group fs ls`，裸路径用 active group，输出节点表 |
| L324~355 | 新增命令 | `group_fs_find()` | `aun group fs find`，支持 name/type/size/mtime 过滤 |
| L359~397 | 新增命令 | `group_fs_stat()` / `group_fs_lstat()` | stat/lstat |
| L401~448 | 新增命令 | `group_fs_mkdir()` / `group_fs_rm()` | mkdir/rm；写侧支持 `--sign-as` 注入 group_aid 签名身份 |
| L452~522 | 新增命令 | `group_fs_cp()` | 支持本地↔group、group↔group copy，处理 `--force` / `--recursive` / `--sign-as` |
| L526~568 | 新增命令 | `group_fs_mv()` | group remote path move；拒绝本地路径 |
| L572~633 | 新增命令 | `group_fs_df()` / `group_fs_mount()` / `group_fs_umount()` | 用量、挂载、卸载 |
| L637~676 | 修改命令 | `group_create()` | 新增 `--group-name`；命名群路径调用 `client.create_group(..., aid_store=store)` |
| L681~720 | 新增命令 | `group_bind()` / `bind-aid` | 匿名群补 group_aid |
| L724~762 | 新增命令 | `group_transfer()` | 发起群主转让，旧群主用 group_aid 私钥签 `transfer_auth` |
| L767~794 | 新增命令 | `group_transfer_complete()` | 新群主完成 rekey 并导入新的 group_aid 身份 |

**对齐要点**：`group.fs.cp` 必须支持三种路径组合；`sign_as` 是 SDK 内部签名身份选择，不应透传给服务端。服务端收到的是普通 `client_signature`，签名者可能是当前 AID，也可能是本地 AIDStore 中的 group_aid。

---

### 块④ Collab 协作编辑 RPC 门面与 CLI

#### `collab/client.py`（新文件）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L8~9 | 新增 helper | `_drop_none(params)` | tag prune 等可选参数剔除 None |
| L12~53 | 新增类 | `TagClient` | 封装 `collab.tag.create/list/show/diff/restore/rm/prune` |
| L58~61 | 新增 | `CollabClient.__init__()` | 保存底层 client 并创建 `self.tag = TagClient(self)` |
| L63~70 | 新增 | `CollabClient._call()` | 调用 `client.call()`，异常经 `map_collab_error()` 转换；仅 `-32009` 映射为 `CollabConflictError` |
| L72~127 | 新增 | `ls_files()` / `create()` / `show()` / `commit()` / `merge()` / `log()` / `diff()` / `clone()` / `prune()` / `gc()` / `reflog()` / `revert()` / `ls_remote()` / `unregister()` | 逐个映射 `collab.*` RPC；Python SDK 不在本地实现 diff3，只转发 RPC |

#### `collab/errors.py` / `collab/types.py`
| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `collab/errors.py` | L8~9 | 新增 | `CollabError(AUNError)` | Collab 错误基类 |
| `collab/errors.py` | L12~27 | 新增 | `CollabConflictError` | 保存 `current_version` / `current_target` / `hint` / `data` / `trace_id` |
| `collab/errors.py` | L30~47 | 新增 | `map_collab_error(exc)` | `code == -32009` 时从 `exc.data` 抽取冲突字段并返回 `CollabConflictError` |
| `collab/types.py` | L1~7 | 新增 | `CollabResult` / `CollabList` | 类型别名 |

#### `errors.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L157~194 | 修改 | `map_remote_error(error)` | `code in {4290, 429, -32029, -32429}` 映射为 `RateLimitError`（L177），并保持 `retryable=True` 判定（L192）；覆盖 gateway backpressure 新错误码 |

#### `aun_cli/commands/collab.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L24~85 | 新增 helper | `_set_json()` / `_is_aid_path()` / `_source_value()` / `_decode_content()` / `_print_result()` / `_run_collab()` / `_is_collab_user_error()` | 本地文件内容转 base64；远程 AID:path 保持原样；冲突退出码 2，用户错误退出码 3 |
| L91~177 | 新增命令 | `ls-files` / `create` / `show` / `commit` / `merge` | 基础文档读写；`show/merge` 可 `--output` 写文件 |
| L180~259 | 新增命令 | `log` / `diff` / `clone` / `prune` / `revert` / `gc` | 版本历史、差异、克隆、清理、回退 |
| L262~297 | 新增命令 | `reflog` / `ls-remote` / `unregister` | 维护与远程查询 |
| L300~374 | 新增 tag 命令 | `tag create/list/show/diff/restore/rm/prune` | 目录级标签命令树 |

**对齐要点**：Collab SDK 侧只做 RPC 门面、错误映射和 CLI 输入输出转换；不要在 SDK 内部实现 diff3 或快照算法。`CollabConflictError` 的 `hint/current_version/current_target` 需要从服务端 error data 透传。

---

### 块⑤ Transport / 后台 RPC 公平性与关闭清理

#### `transport.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L292~300 | 新增字段 | `_pending_meta` / `_send_lock` / `_last_reader_closed_at` / `_last_reader_error` / `_foreground_waiters` / `_admission_cond` | 记录 pending RPC 诊断、串行化 websocket send、记录 reader 关闭原因，并实现前台优先 admission |
| L351~368 | 修改 | `RPCTransport.close()` | close 时调用 `_fail_pending(ConnectionError("transport closed"))`，避免 pending RPC 永久挂起 |
| L370~382 | 新增 | `cancel_event_tasks()` | 关闭时取消 transport 派生的事件发布 task |
| L384~399 | 新增 | `_schedule_event_publish(event, params)` | 事件 publish 统一建 task 并登记 `_event_tasks`，完成后回收并吞掉 task 异常 |
| L401~426 | 新增 | `_pending_snapshot()` / `_fail_pending(exc, *, context)` | 超时/断连日志携带 pending 快照；断连时批量置异常并清 `_pending_meta` |
| L428~446 | 新增 | `_mark_foreground_waiter()` / `_unmark_foreground_waiter()` / `_wait_background_turn()` | 后台 RPC 在有前台等待者时让路；防止后台同步淹没前台调用 |
| L448~490 | 修改 | `call(..., background=False)` | 后台 RPC 先取后台信号量再等 admission；前台 RPC 标记 waiter；队列超时释放已取信号量并抛 retryable `TimeoutError` |
| L492~517 | 修改 | `notify()` | 发送 JSON-RPC notification 时使用 `_send_lock` 串行化 websocket send |
| L523~560 | 修改 | `_call_inner()` | 写入 `_pending_meta[rpc_id]`，websocket send 使用 `_send_lock`，send 成功记录 `sent_at` |
| L572~576 | 修改 | `_call_inner()` 超时/取消 | CancelledError 与 TimeoutError 都清理 `_pending` / `_pending_meta` |
| L704~713 | 修改 | `_reader_loop()` finally | 记录 reader 关闭时间/错误；若仍有 pending RPC，按断连原因 `_fail_pending()` |
| L723~773 | 修改 | `_route_message()` | 收到 response 时清 `_pending_meta`；收到 `event/*` 时用 `_schedule_event_publish()` 替代裸 `asyncio.create_task()` |

#### `_client/rpc_pipeline.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L80~85 | 新增 | `call_after_pipeline()` 读取 `_rpc_background` | 弹出内部 `_rpc_background`，或从 `client._background_rpc_depth` 推断后台 RPC |
| L87~103 | 修改 | pull gate 重入参数 | pull gate 递归调用时透传 `_skip_send_result_envelope` 与 `_rpc_background` |
| L158~181 | 修改 | V2 pull/ack 路由 | `message.pull` / `message.ack` / `group.pull` / `group.ack_messages` 进入 V2 内部方法前透传 `_rpc_background` |
| L224~230 | 修改 | transport call kwargs | 后台 RPC 设置 `background=True`，交给 `RPCTransport.call()` 走前台优先队列 |
| L458~495 | 修改 | `raw_call(..., background=False)` | 内部裸 RPC 也支持 `background`；关闭中后台 RPC 直接抛 `ConnectionError("client is closing")` |

#### `_client/delivery.py` / `_client/group_state.py` / `_client/v2_e2ee.py` / `_client/lifecycle.py`
| 文件 | 行号 | 类型 | 说明 |
|------|------|------|------|
| `_client/delivery.py` | L907~925 | 新增 | `transport_call_background()` 与 `run_background_rpc()`：后台 ack 与补洞统一使用 transport background 通道，并用 `_background_rpc_depth` 标记嵌套 RPC |
| `_client/delivery.py` | L198~213 | 修复 | `handle_group_changed_event()` 对重复/已覆盖的 group.changed push 也发送 `group.ack_events`，避免服务端 cursor 停滞 |
| `_client/delivery.py` | L1202~1214 / L1314~1335 | 修改 | V2 群 push 触发的自动 pull 用 `run_background_rpc()`，不抢占前台 RPC |
| `_client/delivery.py` | L1414~1469 / L1491~1503 | 修改 | P2P gap fill 与 group event gap fill 调 `client.call(..., "_rpc_background": True)` |
| `_client/group_state.py` | L332~362 | 修改 | 自动 propose / 自动 confirm 调度包装进 `run_background_rpc()` |
| `_client/group_state.py` | L724~730 / L747~764 | 修改 | pending proposal confirm/propose 与 state 事件响应均走后台 RPC |
| `_client/v2_e2ee.py` | L403 / L583~611 / L764~783 / L1891~1945 / L2097~2121 | 修改 | V2 P2P / Group pull 和 ack 内部方法识别 `_rpc_background`，raw pull/ack 透传 `background=True` 或重注入 `_rpc_background` |
| `_client/lifecycle.py` | L420~471 | 修改 | 停止后台任务时先取消 transport event tasks，再取消 heartbeat/token/online hint/auto state task，并等待 `_background_ack_tasks` 最多 1 秒后取消残留 |

#### `service_proxy/client.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L69~82 | 新增 | `_SendLockedWebSocket` | 包装后端 websocket，所有 `send()` 通过实例级 lock 串行化，避免并发 send 竞态 |
| L898~932 | 新增/调整 | `register_services_with_proxy_server()` / `_auth_and_register()` | 数据面 tunnel 连接后先 `service_proxy_auth`，再发送 `register_services` |
| L1676~1704 | 新增 | `_send_tunnel_message()` / `_is_websocket_connection_closed()` / `_ws_error_message()` | WS relay 关闭/错误处理辅助 |
| L1706~1764 | 新增 | `create_admin_app(admin_token=...)` | holder 侧本地 admin API：`/health`、`/services` GET/POST/DELETE |

**对齐要点**：后台 RPC 公平性是 0.5.0 的关键稳定性变更。所有 SDK 都需要区分前台业务 RPC 与 SDK 自动补洞/ack/propose 等后台 RPC；后台 RPC 不应长期占满全局 inflight，也不应在 client closing 后继续发起。

---

### 块⑥ CLI 增强与命令入口

#### `aun_cli/commands/fs.py`（新文件）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L22~185 | 新增 helper | `_json_ready()` / `_remote_or_exit()` / `_remote_or_default()` / `_parse_acl_spec()` / `_match_size()` / `_match_mtime()` / `_filter_find_nodes()` / `_print_node_table()` 等 | 远程路径解析、输出转换、find 本地过滤、表格输出 |
| L189~300 | 新增命令 | `fs_ls()` / `fs_stat()` / `fs_cat()` | list/stat/cat；`cat` 支持 token、文本/二进制识别 |
| L304~417 | 新增命令 | `fs_cp()` / `fs_mv()` / `fs_rm()` | 本地/远程 copy、move、remove |
| L421~500 | 新增命令 | `fs_ln()` / `fs_mkdir()` / `fs_df()` | 软链、目录、用量 |
| L504~620 | 新增命令 | `fs_mount()` / `fs_approve()` / `fs_reject()` / `fs_umount()` | mount / approve / reject / unmount |
| L624~662 | 新增命令 | `fs_find()` | name/type/size/mtime 过滤 |
| L666~840 | 新增命令 | `fs_chmod()` / `fs_setfacl()` / `fs_getfacl()` / `fs_token_issue()` / `fs_token_revoke()` / `fs_token_ls()` | 可见性、ACL、访问 token 管理 |

#### `aun_cli/commands/storage.py` / `aun_cli/storage_core.py`
| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `commands/storage.py` | L29~30 | 新增 | `_normalize_object_key()` | 统一 `\` → `/`，去掉前导 `/` |
| `commands/storage.py` | L33~81 | 新增命令 | `storage_list()` / alias `ls` | 列对象与直接子前缀，表格输出 |
| `commands/storage.py` | L84~103 | 新增命令 | `storage_info()` | 调 `storage.head_object` 查看对象元信息 |
| `commands/storage.py` | L106~142 | 修改命令 | `storage_upload()` | 新增 `--force`，透传 `overwrite=force` |
| `commands/storage.py` | L145~185 | 修改命令 | `storage_download()` | 新增 `--force`，默认拒绝覆盖本地文件 |
| `storage_core.py` | L66~117 | 修改 | `upload_object(..., overwrite=False)` | 先 `storage.check_upload`，处理超限/目标已存在/dedup/skip_upload；inline 时 `put_object(overwrite=overwrite)`，大文件 session/complete 均透传 overwrite |

#### `aun_cli/adapter.py` / `aun_cli/fs_utils.py` / `aun_cli/main.py`
| 文件 | 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|------|
| `adapter.py` | L119~122 | 新增 | `_print_debug()` | debug 输出固定写 stderr，避免污染 CLI stdout/JSON |
| `adapter.py` | L222 | 修改 | `CLISession.__aenter__()` | 用 AIDStore 加载身份后把 store 绑定到 `client._aid_store`，供 group.fs `sign_as` 与 group_aid 生命周期使用 |
| `fs_utils.py` | L9~46 | 新增 | `is_remote()` / `normalize_path()` / `parse_remote()` / `format_remote()` | CLI 远程路径工具；排除 Windows 盘符和 HTTP URL |
| `main.py` | L85~92 | 修改 | Typer app 注册 | 注册新增 `fs_app` 与 `collab_app` |

---

### 版本号

| 文件 | 行号 | 类型 | 说明 |
|------|------|------|------|
| `pyproject.toml` | L7 | 修改 | `version = "0.4.13"` → `"0.5.0"` |
| `src/aun_core/version.py` | L1 | 修改 | `__version__ = "0.4.13"` → `"0.5.0"` |

---

### 文档与生成物同步

| 路径 | 类型 | 说明 |
|------|------|------|
| `CHANGELOG.md` | 修改 | 对外接口级摘要同步到 0.5.0；本文件继续作为 func/line 级实现清单 |
| `src/aun_core/docs/skill/methods/group.fs.*.md` | 新增 | 新增 `group.fs` RPC 方法文档，替代已删除的 `group.resources.*` 方法文档 |
| `src/aun_core/docs/skill/methods/storage.*.md` / `storage.fs.*.md` / `storage.volume.*.md` | 新增/修改 | Storage P1~P6、POSIX fs、ACL/token、volume 方法文档同步 |
| `src/aun_core/docs/skill/rpc-manual/*/04-RPC-Manual.md` / `sdk-core/09-*-rpc-manual.md` | 新增/修改 | Collab/Group/Message/Proxy/Storage/Stream RPC 手册同步；这些文件是 SDK 文档生成物，不改变 Python 运行时代码路径 |

### 测试新增/修改（按当前文件行号）

| 文件 | 用例/行号 | 覆盖点 |
|------|-----------|--------|
| `tests/unit/test_storage_vfs_p1.py` | `test_upload_inline_dedup_skips_http_put` L35；`test_upload_large_uses_session_and_complete` L71；`test_upload_refuses_existing_remote_target_unless_overwrite` L107 | Storage VFS 上传预检、dedup、大文件 session、overwrite |
| `tests/unit/test_storage_vfs_p2.py` | `test_vfs_symlink_and_readlink_call_lowlevel` L31；`test_vfs_repoint_cas_mismatch_maps_conflict` L78；`test_vfs_maps_loop_and_dangling_errors` L171 | 软链、CAS 冲突、ELOOP/EDANGLING 映射 |
| `tests/unit/test_storage_vfs_p3.py` | `test_vfs_defaults_to_fs_list_and_preserves_authoritative_mode` L38；`test_vfs_can_fallback_to_p1_p2_paths_when_flag_disabled` L131 | `storage.fs.*` 权威路径与回退路径 |
| `tests/unit/test_storage_vfs_p4.py` | `test_vfs_acl_and_token_methods_call_p4_rpc_contracts` L28；`test_vfs_read_methods_forward_token_to_read_rpc_paths` L68 | ACL/token/read token 透传 |
| `tests/unit/test_storage_vfs_p6.py` | `test_lowlevel_fs_mount_unmount_rpc_contracts` L24；`test_vfs_mount_volume_uses_volume_id_branch` L221；`test_lowlevel_volume_lifecycle_and_membership_invalidation_rpc_contracts` L252 | mount/unmount、volume、membership invalidate |
| `tests/unit/test_group_fs_contract.py` | `test_group_facade_exposes_posix_group_fs_namespace` L39；`test_group_fs_posix_methods_call_group_fs_rpc` L51；`test_group_fs_does_not_map_memberdata_to_storage_root_in_sdk` L90 | `client.group.fs` POSIX 合同与 memberdata 路由不在 SDK 改写 |
| `tests/unit/test_group_fs_vfs.py` | `test_cp_local_to_group_uses_upload_control_plane` L60；`test_cp_group_to_local_sends_bearer_for_scoped_download_ticket` L236；`test_cp_group_to_group_uses_single_rpc` L296 | group.fs cp 三路径、Bearer 下载、远程单 RPC |
| `tests/unit/test_cli_group_fs.py` | `test_cli_group_fs_write_can_sign_as_group_aid` L157；`test_cli_group_fs_cp_windows_drive_is_local` L180；`test_cli_group_fs_mount_and_umount_use_active_group` L295 | CLI group.fs active group、sign-as、Windows 路径 |
| `tests/unit/test_cli_group_fs_contract.py` | `test_cli_group_fs_help_exposes_only_posix_commands` L34；`test_cli_group_help_recommends_fs_not_compat_resources` L47 | CLI 帮助不再推荐/暴露 `resources` |
| `tests/unit/test_group_identity.py` | `test_import_group_identity_persists_and_loads` L34；`test_create_named_group_generates_key_and_persists` L149；`test_bind_group_aid_generates_key_and_persists_without_group_name` L200；`test_complete_group_transfer_generates_key_and_persists` L242 | group_aid 证书/私钥落盘、命名群、匿名群补绑、群主转让 rekey |
| `tests/unit/test_collab_client.py` | `test_collab_methods_match_server_rpc_contract` L41；`test_python_sdk_does_not_implement_diff3` L118；`test_collab_conflict_error_preserves_server_fields` L137 | Collab RPC 门面、无本地 diff3、冲突错误字段透传 |
| `tests/unit/test_collab_cli.py` | `test_collab_create_converts_local_file_to_base64` L115；`test_collab_commit_conflict_exit_code_and_hint` L181；`test_collab_tag_and_ls_remote_commands` L236 | Collab CLI 输入转换、退出码、tag 命令 |
| `tests/unit/test_cli_collab_exit_codes.py` | `test_collab_no_change_is_user_error` L7；`test_collab_conflict_is_user_error` L14；`test_collab_internal_error_is_not_user_error` L32 | Collab CLI 用户错误/内部错误退出码分类 |
| `tests/unit/test_collab_commit_message.py` | `test_commit_with_message` L7；`test_commit_without_message_defaults_empty` L42；`test_log_returns_message` L69 | Collab commit/log message 字段语义 |
| `tests/unit/test_collab_create_transaction.py` | `test_create_delegates_transaction_to_collab_rpc` L18；`test_tag_create_delegates_transaction_to_collab_rpc` L38 | Collab create/tag create transaction 参数透传 |
| `tests/unit/test_collab_gc.py` | `test_gc_defaults_to_dry_run` L24；`test_gc_can_request_cleanup` L37 | Collab GC dry-run 默认语义 |
| `tests/unit/test_collab_revert.py` | `test_revert_calls_collab_revert_with_exact_params` L23；`test_revert_not_found_error_is_propagated` L44 | Collab revert 参数与错误透传 |
| `tests/unit/test_cli_fs_p1.py` | `test_cli_fs_cp_upload_and_download` L100；`test_cli_fs_bare_paths_default_to_profile_aid` L212；`test_cli_debug_output_does_not_pollute_stdout` L297 | 全局 `aun fs` P1 路径分类、裸路径默认 AID、debug stderr |
| `tests/unit/test_cli_fs_p2.py` | `test_cli_fs_ln_s_calls_vfs_symlink` L86；`test_cli_fs_ln_force_calls_vfs_repoint` L108；`test_cli_fs_stat_symlink_includes_target` L150 | `aun fs` 软链/repoint/stat 展示 |
| `tests/unit/test_cli_fs_p4.py` | `test_cli_fs_chmod_calls_set_visibility` L74；`test_cli_fs_setfacl_getfacl_and_remove` L111；`test_cli_fs_token_commands` L131；`test_cli_fs_cat_forwards_token` L152 | `aun fs` visibility、ACL、token、cat token |
| `tests/unit/test_cli_fs_p5.py` | `test_cli_fs_find_filters_name_type_and_size` L77；`test_cli_fs_find_filters_mtime_and_symlink` L93 | `aun fs find` 本地过滤语义 |
| `tests/unit/test_cli_fs_p6.py` | `test_cli_fs_mount_source_calls_vfs_mount` L68；`test_cli_fs_mount_volume_calls_vfs_mount_volume` L119；`test_cli_fs_approve_reject_pass_request_id` L181 | `aun fs` mount/volume/approve/reject |
| `tests/unit/test_cli_storage.py` | `test_upload_force_passes_overwrite_true` L100；`test_download_refuses_existing_file_without_force` L144；`test_list_calls_object_and_prefix_listing` L179；`test_info_calls_head_object` L204 | storage CLI force/list/info 行为 |
| `tests/unit/test_sdk_facades.py` | `test_facades_accept_dict_and_omit_none` L21；`test_aun_client_exposes_cached_namespace_facades` L101；`test_low_level_group_rpcs_remain_accessible_through_call` L113 | 新门面参数合并、懒加载缓存、低级 RPC 兼容 |
| `tests/unit/test_client_signature.py` | `test_storage_mutation_method_is_non_idempotent` L199；`test_group_fs_method_is_non_idempotent` L205；`test_collab_mutation_method_is_non_idempotent` L211 | 非幂等集合覆盖新增 storage/group.fs/collab 写操作 |
| `tests/unit/test_client.py` | `test_background_rpc_depth_marks_public_calls_background` L3161；`test_background_rpc_does_not_call_transport_when_client_is_closing` L3260；`test_group_changed_covered_event_reconciles_server_cursor_without_fill` L3609 | 后台 RPC 标记、关闭中拒发、group.changed covered ack |
| `tests/unit/test_errors.py` | `test_gateway_backpressure_32429_maps_to_rate_limit_error` L32 | `-32429` 映射为 retryable `RateLimitError` |
| `tests/unit/test_service_proxy_send_lock.py` | `test_send_locked_websocket_serializes_concurrent_sends` L22 | service proxy websocket send 串行化 |
| `tests/unit/test_service_proxy_tunnel_messages.py` | `test_service_proxy_client_registers_with_gateway_and_proxy_server_in_order` L181；`test_service_proxy_client_serve_once_dispatches_ws_connect` L466；`test_service_proxy_client_serve_once_demuxes_concurrent_ws_connections` L508 | proxy server auth/register 顺序与 WS tunnel demux |
| `tests/unit/test_service_proxy_ws_backend_caller.py` | `test_service_proxy_client_ws_backend_relay_text_binary_and_close` L112；`test_service_proxy_client_ws_backend_normalizes_unsendable_close_code` L250 | WS 后端转发与 close code 归一 |
| `tests/integration_test_fs_p1.py` | `test_roundtrip_small_and_large` L94；`test_list_stat_rm_df` L118 | Storage VFS P1 集成路径 |
| `tests/integration_test_fs_p2.py` | `test_symlink_basic` L83；`test_repoint_and_remove` L100；`test_dangling_and_loop` L135 | Storage symlink/repoint/loop 集成路径 |
| `tests/integration_test_fs_p3.py` | `test_authoritative_nodes` L93；`test_mutations` L113 | `storage.fs.*` 权威节点与 mutation 集成路径 |
| `tests/integration_test_fs_p4.py` | `test_acl_and_visibility` L101；`test_token_reads` L122 | ACL/visibility/token 集成路径 |
| `tests/e2e_test_fs_p1.py` / `p2.py` / `p3.py` / `p4.py` / `p6.py` | `test_cli_fs_p1_e2e` L198；`test_cli_fs_p2_e2e` L198；`test_cli_fs_p3_e2e` L197；`test_cli_fs_p4_e2e` L219；`test_cli_fs_p6_e2e` L232 | `aun fs` P1/P2/P3/P4/P6 CLI E2E |
| `tests/e2e_test_group_fs_cli.py` | `test_cli_group_fs_e2e` L234 | `aun group fs` CLI E2E |
| `tests/e2e_test_collab_docker.py` | `test_collab_create_show_commit_log_get_diff` L93；`test_collab_submit_conflict_hint_and_merge_modes` L135；`test_collab_group_discover_unregister_and_wrong_namespace` L241 | Collab Docker E2E 主流程、冲突提示、group discover/unregister |
| `tests/integration/test_collab_gc_e2e.py` / `tests/integration_test_collab_group_acl.py` | `test_gc_basic_dry_run` L60；`test_gc_cleans_orphans` L76；`test_collab_read_non_member_with_acl` L129；`test_collab_read_non_member_without_acl` L141 | Collab GC 与 group ACL 集成路径 |

### 跨 SDK 对齐优先级

1. **P0**：`storage.fs.*` / `group.fs.*` RPC 方法名、签名集合、非幂等集合、错误映射必须一致；`group.resources.*` 不再作为 0.5.0 SDK 对齐目标。
2. **P0**：后台 RPC 标记与 transport 前台优先 admission 必须对齐，否则补洞/ack/auto-propose 可能挤占业务 RPC。
3. **P1**：`client.storage` / `client.group.fs` / `client.collab` 门面语义、Collab `-32009` 冲突错误映射、group_aid 本地私钥落盘流程需对齐。
4. **P1**：CLI 行为可按语言生态调整命令框架，但路径分类、overwrite 默认拒绝、`local:` 前缀、Windows 盘符判定、JSON/stdout/stderr 分离语义需保持一致。

---

## v0.4.13 — 相对于 v0.4.12 的变更

> 基线：`d85a6f62`（git HEAD，即 v0.4.12 提交）vs 工作区未提交改动。
>
> 四大变更块：**① 发送结果回填 envelope（send 回执带信封）**、**② refresh_token 失效自愈（清缓存 + token.refresh_exhausted 触发重登）**、**③ protected_headers 类型归一（ProtectedHeaders 对象转 dict）**、**④ app_message_envelope 字段收窄 + RPC 日志 token 脱敏**。四块均为四语言对齐项；另有服务端配套改动见块末「服务端协同」。

### 块① 发送结果回填 envelope

> 动机：接收端事件已带 `envelope`（v0.4.12 块①），但发送方调用 `message.send`/`group.send`/`message.thought.put`/`group.thought.put` 拿到的回执只有 `message_id`/`seq`，没有与接收端一致的信封元数据。本块为四个发送方法的返回结果统一回填规范化 `envelope`，并把原始 `payload`/`content` 一并回填。明文路径在 rpc-pipeline postprocess 后自动附加；V2 加密路径用内部标志跳过明文附加、由加密协调器在密文构造后自行补挂，避免重复封装。

#### `_client/delivery.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L36 | 新增常量 | `_APP_SEND_ENVELOPE_METHODS` | 四个发送方法集合：`message.send`/`group.send`/`message.thought.put`/`group.thought.put` |
| L349 | 新增 | `send_result_envelope(method, params, result, *, encrypted)` | 仅当 method ∈ 集合时构造发送结果信封：从 params/result 归一 `from`/`to`/`group_id`/`type`/`kind`/`version`/`timestamp`/`encrypted`/`context`/`protected_headers`/`payload_type`，回填原始 `payload`/`content` |
| L400 | 新增 | `attach_send_result_envelope(method, params, result, *, encrypted)` | method 命中且 result 为 dict 时，浅拷贝后写入 `result["envelope"]`；否则原样返回 |

#### `_client/rpc_pipeline.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L79 | 新增 | `call_after_pipeline()` 入口 | `skip_send_result_envelope = bool(params.pop("_skip_send_result_envelope", False))`：弹出内部标志，V2 加密路径置 True 以跳过明文自动附加 |
| L85 | 修改 | pull-gate 二次进入透传 | 锁定 params 时透传 `locked_params["_skip_send_result_envelope"] = True`，避免 gate 重入丢标志 |
| L229 | 修改 | postprocess 后附加 | `postprocess_result` 之后，若未跳过则 `result = client._delivery().attach_send_result_envelope(method, params, result, encrypted=False)`（L231） |

#### `_client/v2_e2ee.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L543 | 新增 | 内层调用置标志 | V2 加密发送内层 `_attempt()` 的 params 写 `"_skip_send_result_envelope": True`，阻止明文路径重复附加 |
| L558 | 修改 | `message.send` 加密路径 | 加密发送拿到 result 后改为 `return client._delivery().attach_send_result_envelope("message.send", params, result, encrypted=True)`（原直接 return） |
| L1093 | 修改 | `group.send` 加密路径 | 同上，`attach_send_result_envelope("group.send", ..., encrypted=True)` |
| L1305 | 修改 | `message.thought.put` 加密路径 | 同上 |
| L1379 | 修改 | `group.thought.put` 加密路径 | 同上 |

**对齐要点**：Go 见 `client_delivery.go`（`appSendEnvelopeMethods`:42 / `sendResultEnvelope`:146 / `attachSendResultEnvelope`:190）、`client_rpc_pipeline.go`（skip 标志读取/透传:123/129、附加:268）、`client_v2_e2ee.go`（加密回填:849/859、内层置标志:957）、`v2_group.go`:75/84、`v2_thought.go`:307/323/417/433。TS 见 `client/delivery.ts`（`APP_SEND_ENVELOPE_METHODS`:16 / `sendResultEnvelope`:220 / `attachSendResultEnvelope`:258）、`client/rpc-pipeline.ts`:134/144/282、`client/v2-e2ee.ts`（内层标志:659、各加密路径附加:666/680/927/942/1330/1343/1403/1416）。JS 见 `client/delivery.ts`:16/208/246、`client/rpc-pipeline.ts`:130/200/263、`client/v2-e2ee.ts`:571/577/591/792/815/1030/1043/1103/1116。**四语言内部标志键统一为字符串 `_skip_send_result_envelope`**（TS/JS 用局部变量 `skipSendResultEnvelope` 接收，键名一致）；明文路径自动附加（encrypted=False），加密路径由 V2 协调器手动附加（encrypted=True），二者互斥不重复。

---

### 块② refresh_token 失效自愈（清缓存 + 强制重登）

> 动机：refresh_token 过期或被服务端判定不可用时，客户端原本会无限循环刷新失败、卡死无法自愈。本块新增「失败是否需重新登录」的判定，命中时清空本地缓存的所有 token 并持久化；后台 token 刷新循环捕获到需重登错误时发布 `token.refresh_exhausted` 事件、关闭 transport 触发重连，下次 `connect_session` 因无可用 token 自动走两阶段登录。同时 `auth.refresh_token` RPC 补传诊断/路由参数，并通过 `AuthError(data=result)` 把服务端结构化响应透传给判定逻辑。

#### `auth.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1231 | 新增（静态） | `_refresh_failure_requires_relogin(exc)` | 判定刷新失败是否需重登：非 `AuthError` 返回 False；`exc.data` 含 `relogin_required is True` → True；否则取 `data["error"]` 或 `str(exc)` 命中 {`missing refresh_token`,`invalid_or_expired_refresh_token`,`refresh not supported`} → True |
| L1247 | 新增 | `_clear_cached_tokens(identity, *, reason)` | 清空 identity 的 `access_token`/`refresh_token`/`kite_token`/`token` 与 `access_token_expires_at=0` 并 `_persist_identity`；无 token 且无过期时间则提前返回；持久化失败仅 WARN 不抛 |
| L634 | 修改签名 | `_refresh_access_token(gateway_url, refresh_token, identity=None)` | 新增 `identity` 入参：从中提取 `aid`/`device_id`/`slot_id`/`access_token`/`access_token_expires_at` 补入 RPC params，并固定加 `sdk_lang`/`sdk_version`；服务端 `success=False` 时 `raise AuthError(str(error), data=result)`（携带完整响应供 relogin 判定） |
| L345 | 修改 | `refresh_cached_tokens()` | 缺 refresh_token 分支调 `_clear_cached_tokens(identity, reason="missing refresh_token")` 后再抛；`_refresh_access_token` 调用补传 `identity` |
| L356 | 修改 | `refresh_cached_tokens()` except | 捕获异常时 `if self._refresh_failure_requires_relogin(exc): self._clear_cached_tokens(...)` 再重抛 |
| L515 | 修改 | `connect_session()` except | refresh 预登录失败分支同样判定 + 清缓存 |
| L711 | 修改 | `_pre_auth_rpc()` | `success is False` 改为 `raise AuthError(..., data=result)`（原无 data） |

#### `_client/lifecycle.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L564 | 修改 | `token_refresh_loop()` 成功分支 | 刷新成功 `set_token_refresh_failures(0)` 重置计数 |
| L566 | 新增分支 | `token_refresh_loop()` 需重登分支 | 捕获 `AuthError` 且 `client._auth._refresh_failure_requires_relogin(exc)` 为真时：发布 `token.refresh_exhausted` 事件（payload 带 `relogin_required: True`，L572~576）、`set_token_refresh_failures(0)`、关闭 transport 触发重连 |
| L584 | 修改 | `token_refresh_loop()` 普通失败分支 | 非重登错误走原 `increment_token_refresh_failures()` 计数路径，达上限同样发 `token.refresh_exhausted`（L591，不带 relogin_required） |

**对齐要点**：Go 见 `auth.go`（包级函数 `authRefreshFailureRequiresRelogin`:2032 读 `relogin_required`:2041、方法 `clearCachedTokens`:1813、调用点 429/436/558、判定点 435/557、refresh RPC `auth.refresh_token`:849）、`client.go`（刷新循环判定:2173、发布 `token.refresh_exhausted`:2175/2190、payload `relogin_required:true`:2179）。TS 见 `auth.ts`（`_refreshFailureRequiresRelogin`:2032、读 relogin_required:2036、`_clearCachedTokens`:2044、清缓存调用 563/575/740）、`client.ts`（发布事件:3068/3081、payload:3072、判定:395）。JS 见 `auth.ts`（`_refreshFailureRequiresRelogin`:1652、`_clearCachedTokens`:1664、清缓存 849/889/899）、`client.ts`（发布事件:2149/2162、payload:2153、判定:529）。**判定的三个错误字符串与 `relogin_required` 字段语义四语言必须一致**；`token.refresh_exhausted` 事件名与 `relogin_required` payload 字段对齐。
>
> **语言特有**：TS/JS 额外修复重连状态位 `_reconnectActive`（TS `client.ts`:703 字段 + 3181/3190/3210… 置位复位；JS `client.ts`:744 字段 + 2227/2253/2283… ），断连分支补齐复位避免重连标志残留；Go 无此字段。JS 另修正日志拼写（`client.ts`:2161，原 `token refreshconsecutivefailed` → 规范文案）。

---

### 块③ protected_headers 类型归一

> 动机：V2 发送方法构造 envelope 元数据时，原先仅当 protected_headers 为 dict 才接受；当应用层传入 `ProtectedHeaders` 对象（非 dict）时会被丢弃。修复：统一识别并转为 dict。

#### `_client/v2_e2ee.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L22 | 新增（静态） | `_protected_headers_dict(value)` | 对支持 `to_dict()` 的 `ProtectedHeaders` 对象统一转 dict；已是 dict 则原样返回 |
| L395 | 修改 | `message.send` 加密路径取值 | `protected_headers = self._protected_headers_dict(client._protected_headers_from_params(params))` |
| L930 | 修改 | `group.send` 加密路径取值 | 同上 |
| L1253 | 修改 | `message.thought.put` 加密路径取值 | 同上 |
| L1327 | 修改 | `group.thought.put` 加密路径取值 | 同上 |

**对齐要点**：Go 见 `client_delivery.go`:260/262 与 `client_rpc_pipeline.go`:504/506 的类型 switch（`case *ProtectedHeaders` / `case ProtectedHeaders` → `ToMap()`）。TS 见 `client/delivery.ts`:149/150（探测 `toObject` 并归一）；JS 见 `client/delivery.ts`:138/139（同 TS）。**Go 用 `ToMap()`、TS/JS 用 `toObject()`、Python 用 `to_dict()`**，均归一为对象/字典；归一后剔除 `_auth`。

---

### 块④ app_message_envelope 字段收窄 + RPC 日志 token 脱敏

> 动机一（字段收窄）：v0.4.12 的消息信封键集合包含 `message_id`/`seq`/`device_id`/`slot_id`/`status`/`delivery_mode` 等本地与传输层字段，会向应用层泄漏内部状态。收窄为只保留跨端可转发的语义元数据。
> 动机二（日志脱敏）：短 RPC 的请求/响应全量 debug 日志会把明文 token 落盘，新增递归脱敏。

#### `_client/delivery.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L23 | 修改常量 | `_APP_MESSAGE_ENVELOPE_KEYS` | 收窄为 18 键：`module_id`/`message_type`/`type`/`kind`/`version`/`from`/`from_aid`/`sender_aid`/`to`/`to_aid`/`group_id`/`timestamp`/`created_at`/`encrypted`/`context`/`protected_headers`/`headers`/`payload_type`。**移除**：`message_id`/`id`/`seq`/`msg_seq`/`t_server`/`status`/`delivery_mode`/`dispatch_mode`/`dispatch`/`device_id`/`slot_id`；**新增**：`context`/`protected_headers`/`headers`/`payload_type`（群事件键 `_APP_GROUP_EVENT_ENVELOPE_KEYS` 不变） |
| L280 | 新增（静态） | `envelope_metadata(value)` | 从信封 dict 过滤掉 `_auth` 字段后返回 |
| L290 | 修改（classmethod） | `app_message_envelope(payload)` | 由静态方法改为类方法并重写：用 `first_value`/`set_if_present` 从顶层与 `payload` body 多来源归一上述键，提取 `context`/`protected_headers`/`payload_type` |

#### `auth.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L29 | 新增常量 | `_SENSITIVE_RPC_LOG_KEYS` | 敏感键集合：`access_token`/`refresh_token`/`kite_token`/`token` |
| L50 | 新增 | `_redact_rpc_log_payload(value, *, key, depth)` | 递归脱敏：命中敏感键或 `_token` 结尾时替换为 `<redacted len=.. sha256=..>`（sha256 取前 12 位）；限深 6 层（超出返回 `<max-depth>`）；dict/list 递归 |
| L694 | 修改 | `_short_rpc()` 请求日志 | `json.dumps(_redact_rpc_log_payload(request_envelope), ...)` |
| L704 | 修改 | `_short_rpc()` 响应日志 | `json.dumps(_redact_rpc_log_payload(message), ...)` |

**对齐要点**：收窄后 18 键三语言完全一致。Go 见 `client_delivery.go`（`appMessageEnvelopeKeys`:35、按白名单过滤:311/416）、`auth.go`（`authRedactRPCLogPayload`:2060、日志脱敏:664/685）。TS 见 `client/delivery.ts`（`APP_MESSAGE_ENVELOPE_KEYS`:10、过滤:297/346）、`auth.ts`（`SENSITIVE_RPC_LOG_KEYS`:49、`_redactRpcLogPayload`:56、调用:859/865）。JS 见 `client/delivery.ts`:10/285/334、`auth.ts`（`SENSITIVE_RPC_LOG_KEYS`:14、`redactRpcLogPayload`:21、调用:994/1000）。**JS 浏览器环境受 crypto 限制，脱敏只输出 `<redacted len=N>` 不含 sha256**，Go/TS 含 sha256（与 Python 一致）。

---

### 服务端协同（本版本配套，影响 SDK 行为）

> 仅列与 SDK 契约直接相关的服务端变化；实现细节见服务端代码。涉及 `extensions/services/{auth,gateway,message}/`。

| 主题 | 说明 |
|------|------|
| `auth.refresh_token` 响应结构化 | 新增 `relogin_required`/`retryable`/`diagnostic`/`aid`/`refresh_count` 字段；SDK 块② 据 `relogin_required` 判定是否清缓存重登，不再按 `error` 字符串硬匹配。失败分支统一走 `_refresh_failure_response`（auth/entry.py） |
| refresh_token 按 token_hash 分锁 | 服务端 `_refresh_token_lock(token_hash)` 替代全局单锁，不同 token 刷新不再互相阻塞 |
| JWT 老 SDK 兼容 | `AUN_JWT_LEGACY_ACCESS_TOKEN_COMPAT`（默认开）：合法 JWT access_token 直接放行，避免 refresh_token 迁移期老客户端重连风暴；gateway `_verify_jwt_local` 绕过 60s 信任时长限制 |
| JWT jti 即时吊销 | `auth.token.revoked` 事件新增 `jti`/`expires_at`；gateway 按真实 TTL 调 `revoke_token_jti`，吊销即时生效 |
| V2 P2P 写入幂等 | `v2_write_peer_message`/`v2_write_peer_wrap`（message/db.py）捕获唯一键冲突逐字段比对：重发相同 message_id 幂等返回原 seq、不再分配新序号产生空洞；自发自收（from==to）跳过重复 self-sync 推送（message/entry.py） |

### 测试新增/修改

| 文件 | 用例 | 说明 |
|------|------|------|
| `tests/unit/test_auth.py` | `test_refresh_failure_clears_cached_tokens` | 验证刷新失败后本地 token 被清空并持久化 |
| `tests/unit/test_auth.py` | `test_connect_session_relogins_after_refresh_failure` | 验证刷新失败后 `connect_session` 自动走重新登录、token 被清理 |
| `tests/unit/test_client_components.py` | `test_message_delivery_envelope_keeps_only_forwardable_metadata` | 验证只保留可转发元数据且 `context`/`headers` 中 `_auth` 被剔除 |
| `tests/unit/test_client.py` | `test_published_message_events_fallback_current_instance_context`（改写） | envelope 断言改为收窄字段集（不含 message_id/seq/device_id/slot_id/message_type/sender_aid） |
| `tests/unit/test_client_components.py` | 撤回墓碑事件断言（改写） | envelope 断言改为收窄字段集 |

**对齐要点**：Go 见 `token_gateway_reuse_test.go`（`TestTokenGatewayReuse_RefreshFailureClearsCachedTokens`:227 / `TestTokenGatewayReuse_ReloginRequiredRefreshError`）、`client_test.go`（`TestAppMessageEnvelopeKeepsForwardableMetadata` 新增 + 撤回/fallback 用例改写）。TS/JS 见 `auth.test.ts`（`refresh 业务失败且要求重登时应清掉本地 token 缓存` / `connectSession 在 refresh 失败后应继续走两步登录`）、`delivery-engine.test.ts`（`应用层消息 envelope 只保留可转发字段并归一化 headers` + `publishAppEvent`/群撤回用例改写）。

### `version.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1 | 修改 | `__version__` | `"0.4.12"` → `"0.4.13"` |

### `pyproject.toml`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L7 | 修改 | `version` | `"0.4.12"` → `"0.4.13"` |

---

## v0.4.12 — 相对于 v0.4.11 的变更

> 基线：`67d35b06`（git HEAD，即 v0.4.11 提交）vs 工作区未提交改动。
>
> 五大变更块：**① 应用层事件信封（envelope）**、**② 撤回事件补全 message_id 与信封**、**③ 入群首个事件 seq 基线对齐（self-join baseline）**、**④ 过期 token 重连清空（避免 4001 死循环）**、**⑤ Service Proxy 持久隧道指数退避 + auth 重认证**，外加配额语义注释修正。所有变更块均为四语言对齐项。

### 块① 应用层事件信封（envelope）

> 动机：应用层回调收到的 message/group 事件中，元数据字段（message_id、seq、from、to、group_id、action 等）散落在 payload 顶层，难以与业务 payload 区分。新增 `envelope` 聚合字段，统一承载这些元数据；顶层别名在兼容期保留，计划 `0.5.*` 移除。

#### `_client/delivery.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L23 | 新增常量 | `_APP_MESSAGE_ENVELOPE_KEYS` | 26 个消息信封键：`module_id`/`message_id`/`id`/`seq`/`msg_seq`/`message_type`/`type`/`kind`/`version`/`from`/`from_aid`/`sender_aid`/`to`/`to_aid`/`group_id`/`timestamp`/`created_at`/`t_server`/`encrypted`/`status`/`delivery_mode`/`dispatch_mode`/`dispatch`/`device_id`/`slot_id` |
| L30 | 新增常量 | `_APP_GROUP_EVENT_ENVELOPE_KEYS` | 18 个群事件信封键：`module_id`/`event_id`/`event_seq`/`seq`/`event_type`/`action`/`group_id`/`actor_aid`/`sender_aid`/`member_aid`/`target_aid`/`operator_aid`/`created_at`/`timestamp`/`t_server`/`status`/`device_id`/`slot_id` |
| L261 | 重构 | `normalize_published_message_payload()` | 原仅处理实例级消息事件（非则原样返回）。新增分支：实例级事件 → `strip_internal_sender_device_fields(attach_current_instance_context(payload))` 后再 `attach_app_message_envelope`；`is_group_scoped_event` 为真（`group.changed`）→ `attach_current_instance_context` 后 `attach_app_group_event_envelope` |
| L273 | 新增（静态） | `app_message_envelope(payload)` | 从 payload 抽取 `_APP_MESSAGE_ENVELOPE_KEYS` 中存在的键，返回信封 dict |
| L279 | 新增（静态） | `is_group_scoped_event(event)` | 判断是否群作用域事件（当前仅 `group.changed`） |
| L283 | 新增（静态） | `app_group_event_envelope(payload)` | 从 payload 抽取 `_APP_GROUP_EVENT_ENVELOPE_KEYS` 中存在的键 |
| L289 | 新增（classmethod） | `attach_app_message_envelope(payload)` | 浅拷贝 payload 后写入 `result["envelope"] = app_message_envelope(result)`；注释标注顶层别名 0.5.* 移除 |
| L298 | 新增（classmethod） | `attach_app_group_event_envelope(payload)` | 同上，写入群事件 envelope |

**对齐要点**：Go 见 `client_delivery.go`（`appMessageEnvelopeKeys`/`appGroupEventEnvelopeKeys` 变量、`attachAppMessageEnvelope`/`attachAppGroupEventEnvelope`/`isGroupScopedEvent` 函数）；TS/JS 见 `src/client/delivery.ts`（`APP_MESSAGE_ENVELOPE_KEYS`/`APP_GROUP_EVENT_ENVELOPE_KEYS` 常量、`attachAppMessageEnvelope`/`attachAppGroupEventEnvelope`/`isGroupScopedEvent` 方法）。四语言键列表、顺序与 envelope 注入位置必须一致；`group.changed` 是唯一群作用域事件。

---

### 块② 撤回事件补全 message_id 与自身信封

> 动机：`message.recalled` / `group.message_recalled` 通知原本只带 `tombstone_message_id`，应用层难以直接拿到被撤回消息的 `message_id` 与上下文。现补全 `message_id` 并继承原消息的信封键。

#### `_client/delivery.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L316 | 修改 | `recall_event_from_message()` | 构造 event 后遍历 `_APP_MESSAGE_ENVELOPE_KEYS`，原消息中存在而 event 缺失的键补入（L325 起）；`message_id` 改为**始终覆盖** `event["message_id"] = message["message_id"]`（原仅 setdefault tombstone），同时保留 `tombstone_message_id` setdefault（L349） |
| L365 | 修改 | `recall_event_from_group_message()` | 同上：信封键补全（L382 起）+ `message_id` 始终覆盖（L405） |

**对齐要点**：Go 见 `client_delivery.go`（`recallEventFromMessage`/`recallEventFromGroupMessage`，遍历 `appMessageEnvelopeKeys` + `event["message_id"] = mid`）；TS/JS 见 `src/client/delivery.ts`（同名方法，`for...of APP_MESSAGE_ENVELOPE_KEYS` + `event.message_id = msg.message_id`）。`message_id` 必须始终写入（不再用 setdefault），`tombstone_message_id` 仍保持「缺失才补」语义。

---

### 块③ 入群首个事件 seq 基线对齐（self-join baseline）

> 动机：自己刚入群时，服务端推送的首个 `group.changed` 事件 `event_seq` 可能 > 1（入群前已有其它成员事件累积），而本地 `group_event` tracker 基线为 0，导致首个可见事件被当作「有空洞」卡住或反复补拉入群前不可见的事件。修复：识别 self-join 时把本地 contiguous 基线直接对齐到 `event_seq-1`。

#### `_client/delivery.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L159 | 修改 | `handle_group_changed_event()` | 取 `ns = group_event:{group_id}` 后、contiguous 判断前插入：若 `is_self_join_group_changed(data)` 且 `contig == 0 and max_seen == 0 and event_seq > 1`，调 `_seq_tracker.force_contiguous_seq(ns, event_seq - 1)` 建立基线（约 L176~L188） |
| L225 | 新增 | `is_self_join_group_changed(data)` | 判定自己入群：`action` ∈ {`member_added`,`joined`,`join_approved`,`invite_code_used`}；取 `joined_aid`/`member_aid`/`aid` 与 `self._aid` 比对；或 `joined_aid` 为空且 action ∈ {`joined`,`invite_code_used`} 且 `actor_aid == self_aid` |

**对齐要点**：Go 见 `client_delivery.go`（`isSelfJoinGroupChanged` + `handleGroupChangedEventSeq` 中 `ForceContiguousSeq(ns, es-1)`）；TS/JS 见 `src/client/delivery.ts`（`isSelfJoinGroupChanged` + `forceContiguousSeq(ns, eventSeq-1)`）。判定的 action 集合、aid 字段优先级（joined_aid→member_aid→aid）、`actor_aid` 兜底分支四语言必须一致；仅在 `contig==0 && maxSeen==0 && seq>1` 时建立基线。

---

### 块④ 过期 token 重连清空（避免 4001 死循环）

> 动机：重连时若 sessionParams 仍携带已过期的 `access_token`，gateway 会反复返回 4001，且 4001 在 `_NO_RECONNECT_CODES` 内本应不重连——但单连接重连路径会拿旧 token 反复尝试。修复：重连前若缓存身份无有效 token，清空 `access_token` 强制走两阶段登录。

#### `_client/lifecycle.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L821 | 修改 | `_invoke_reconnect_connect_once()` | 缓存 identity 无有效 access_token 分支：日志补充「clearing stale token to trigger re-login」，并新增 `client._session_params["access_token"] = ""` 清空过期 token |

**对齐要点**：Go 见 `client_lifecycle.go`（`reconnectLoop` 中读取 `c.identity`，用 `auth.GetAccessTokenExpiry` 判断有效期，有效则 `params["access_token"]=cachedToken` 否则清空）；TS/JS 见 `src/client.ts`（重连循环内同逻辑，`getAccessTokenExpiry` + 过期/缺失清空）。注意：**Go/TS/JS 在重连入口同时做了「有效则回填、过期则清空」双向同步**，Python 此处仅清空（回填由 `_invoke_reconnect_connect_once` 上文 L814 的 refresh 分支处理），语义等价。过期判定阈值为 `now + 30s`。

---

### 块⑤ Service Proxy 持久隧道指数退避 + auth 重认证

> 动机：持久模式（persistent）隧道断开后原本固定延迟重连，且不区分 auth 失败；access_token 过期时会无意义地反复重连。修复：引入指数退避（上限 60s，成功后重置），auth 类错误先重新获取 token 再退避重连。

#### `service_proxy/client.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L466 | 新增局部 | `_proxy_reconnect_max_delay = 60.0` | 退避上限 |
| L468 | 新增局部 | `_delay = reconnect_delay_seconds` | persistent 循环退避初值 |
| L483 | 修改 | `serve_forever()` 成功分支 | 连接成功后 `_delay = reconnect_delay_seconds` 重置退避 |
| L486 | 新增分支 | `except AuthError as exc` | auth 失败：WARN「re-authenticating」→ `await self._authenticate_for_access_token()`（失败再 WARN）→ `_sleep_or_stop(_delay)` → `_delay = min(_delay*2, 60)` |
| L497 | 修改 | `except Exception` 分支 | 延迟从固定 `reconnect_delay_seconds` 改为 `_delay`，退避后 `_delay = min(_delay*2, 60)` |

**对齐要点**：Go 见 `service_proxy.go`（`ServeForever` 中 `maxReconnectDelay = 60*time.Second`、`handlePersistentTunnelError`（`errors.As(&authErr)` → `ensureAccessToken`）、`minDuration` 退避、成功后 `delay = opts.ReconnectDelay` 重置）；TS/JS 见 `src/service-proxy.ts`（`maxReconnectDelay = 60_000`、`exc instanceof AuthError` → `_authenticateForAccessToken`、`_delay = Math.min(_delay*2, maxReconnectDelay)`、成功后重置）。三语言均：成功重置、auth 错误先重认证、退避封顶 60s。

---

### 块⑥ 配额语义注释修正

#### `client.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L2148 | 修改（注释） | `_NO_RECONNECT_CODES` 上方注释 | 4015 说明移除不存在的 `device_aids` 踢出场景，改为「`aid_device_slot` / `aid_devices`」。集合值不变 |

**对齐要点**：对应服务端 gateway 配额逻辑——`device → aid 数`（`device_aids`）不再触发踢出，仅 `aid_device_slot` / `aid_devices` 会。集成测试 `integration_test_gateway_quota.py` 的 `test_device_aids_quota` 已改名为 `test_device_aids_not_quota_limited`。

---

### 测试新增/修改

| 文件 | 用例 | 说明 |
|------|------|------|
| `tests/unit/test_reconnect.py` | `TestReconnectTokenRefresh.test_stale_token_cleared_before_reconnect_connect_once` | 验证过期 token 在重连前被清空 |
| `tests/unit/test_reconnect.py` | `TestReconnectTokenRefresh.test_valid_cached_token_used_in_reconnect` | 验证有效缓存 token 被复用 |
| `tests/unit/test_client.py` | `test_group_changed_self_join_sets_visible_event_baseline` | 验证入群首个 event_seq>1 时建立可见基线 |
| `tests/unit/test_client.py` | `test_group_changed_gap_fill_skips_permanent_hole_and_publishes_ordered` | 验证永久空洞不阻塞已就绪群事件发布 |
| `tests/unit/test_service_proxy_serve_forever.py`（新文件） | `test_backoff_increases_on_repeated_failure` | 退避随重复失败递增 |
| `tests/unit/test_service_proxy_serve_forever.py` | `test_backoff_resets_after_successful_connection` | 成功连接后退避重置 |
| `tests/unit/test_service_proxy_serve_forever.py` | `test_auth_error_triggers_reauthentication` | AuthError 触发重新认证 |
| `tests/unit/test_service_proxy_serve_forever.py` | `test_non_auth_error_does_not_trigger_reauthentication` | 非 auth 错误不触发重认证 |
| `tests/integration_test_gateway_quota.py` | `test_device_aids_not_quota_limited`（原 `test_device_aids_quota`） | 验证 `device_aids` 不再限流（语义修正） |
| `tests/integration_test_replay_guard.py` | 用例隔离改进 | 每个用例独立 AID/目录（`replay-{label}-...`），消除串扰 |
| `tests/integration_test_signature.py` / `integration_test_storage.py` / `integration_test_service_proxy.py` | 断言补强 | 配合上述改动调整 |

### `version.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1 | 修改 | `__version__` | `"0.4.11"` → `"0.4.12"` |

### `pyproject.toml`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L7 | 修改 | `version` | `"0.4.11"` → `"0.4.12"` |

---

## v0.4.11 — 相对于 v0.4.10 的变更

> 基线：`0dbe71b4`（git HEAD，即 v0.4.10 提交）vs 工作区未提交改动。
>
> 四大变更块：**① Storage 目录树与扩展操作**、**② group.resources 树形资源系统**、**③ group.changed 事件保序去重重构**、**④ V2 E2EE 并发与容量保护**，外加若干独立修复（errors.py、SPK lifecycle、_pushed_seqs 防护）。

### 块① Storage / group.resources 签名与非幂等方法扩展

#### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +208 | 修改 | `_NON_IDEMPOTENT_METHODS` | 新增 15 个 `storage.*` 方法：`storage.put_object`、`storage.get_by_share`、`storage.create_share_link`、`storage.revoke_share_link`、`storage.create_folder`、`storage.rename_folder`、`storage.move_folder`、`storage.delete_folder`、`storage.move_object`、`storage.copy_object`、`storage.batch_delete`、`storage.set_object_meta`、`storage.append_object`（原有 `storage.create_upload_session`/`storage.complete_upload`/`storage.delete_object` 保留） |
| +208 | 修改 | `_NON_IDEMPOTENT_METHODS` | 新增 16 个 `group.resources.*` 方法：`create_folder`/`rename`/`move`/`mount_object`/`update`/`delete`/`cleanup_by_storage_ref`/`request_add`/`request_mount_object`/`direct_add`/`approve_request`/`reject_request`/`unmount`/`get_access`/`resolve_access_ticket`（在原有 `put` 基础上补全） |
| +943 | 修改 | `_SIGNED_METHODS`（frozenset） | 与 `_NON_IDEMPOTENT_METHODS` 同步扩展：所有上述 `storage.*` 和 `group.resources.*` 方法均加入签名集合 |
| +1069 | 修复 | `_cert_sha256_fingerprint` | 静态方法补 `self` 参数（原本缺失导致调用报错） |

**对齐要点**：`_NON_IDEMPOTENT_METHODS` 控制非幂等 RPC 超时（35 秒 vs 默认 15 秒）；`_SIGNED_METHODS` 控制 `client_signature` 注入。Go 见 `client.go:nonIdempotentMethods` / `client.go:signedMethods`；TS/JS 见 `src/client/rpc-pipeline.ts`。所有 16 个 `group.resources.*` 和 15 个 `storage.*` 方法必须在四语言同步存在于这两个集合。

---

### 块② group.changed 事件保序去重重构

> 原实现：`_on_raw_group_changed` 中直接 `dispatcher.publish("group.changed", data)`，event_seq 仅做空洞检测，不做有序缓冲和去重。新实现：将 group.changed 分发逻辑整体下沉到 `MessageDeliveryEngine`，通过 `group_event:{group_id}` namespace 做 SDK 内部保序消费，应用层回调不再影响 SDK 内部 cursor。

#### `_client/delivery.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +92 | 修复 | `mark_published_seq()` / `is_published_seq()` | 改用 `getattr(client, "_pushed_seqs", None)` 防护，避免连接初期 `_pushed_seqs` 未初始化时 `AttributeError` |
| +121 | 新增 | `is_group_event_namespace(ns)` (静态) | 判断 ns 是否为 `group_event:` 前缀 |
| +128 | 新增 | `async publish_ordered_queue_item(ns, event, seq, payload, *, source)` | 有序队列项发布路由：`group.changed` + `group_event:` namespace 走 `publish_ordered_group_changed`，其余走 `_publish_app_event` |
| +135 | 新增 | `async publish_ordered_group_changed(payload, *, source)` | group.changed 统一发布入口：①调 `handle_group_changed_v2_membership` SDK 内部消费；②`action == "dissolved"` 时调 `_cleanup_dissolved_group`；③发布给应用层 |
| +145 | 新增 | `async handle_group_changed_event(data, group_id)` | 按 `group_event:{group_id}` 保序去重的完整实现：解析 `event_seq`（失败走 legacy 直发）→ 跳过 ≤ contiguous 或已发布的 seq → 入有序队列 → `on_message_seq` → drain → contiguous 推进后 `_persist_seq` + `_fire_ack(group.ack_events, ...)` → gap 检测触发补拉 |
| +503 | 修改 | `publish_ordered_message()` 内 drain 路径 | 原 `_publish_app_event(event, payload)` 改为 `publish_ordered_queue_item(ns, event, seq, payload)`，使 group.changed drain 也走统一路由 |
| +516 | 修改 | `publish_ordered_message()` 无 seq 分支 | 同上，改用 `publish_ordered_queue_item` |
| +656 | 修改 | `_clamp_ack_params()` group.ack_events 分支 | ns 从 `group:{group_id}` 改为 `group_event:{group_id}`，防止与群消息 cursor 串用 |
| +1271 | 修改 | `fill_group_event_gap_inner()` 补洞事件处理 | 原 `dispatcher.publish("group.changed", evt)` 改为：若 `es > 0` 且未发布则 `_enqueue_ordered_message`，之后统一 `drain_ordered_messages` 发布；`action == "dissolved"` 不持久化 seq（群已解散）|

**对齐要点**：Go `handleGroupChangedEvent`（delivery.go）、TS/JS `handleGroupChangedEventSeq`（client/delivery.ts）需与此保持一致：1) 无 event_seq 时走 legacy 直发；2) ≤ contiguous 或已发布 seq 直接丢弃；3) 入有序队列后 drain；4) ack 使用 `group_event:` namespace；5) 补洞事件不触发二次补拉（`_from_gap_fill` 标记）；6) 解散事件不持久化 cursor。

#### `client.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +1201 | 修改 | `_on_raw_group_changed()` | 有 group_id + dict 时改为 `await self._delivery().handle_group_changed_event(data, group_id)`；否则 `publish_ordered_group_changed(data, source="legacy")` |
| +1393 | 新增 | `_cleanup_dissolved_group(group_id)` | 群解散后清理本地运行态：从 `_v2_bootstrap_cache` 移除 `group:{group_id}`、`_v2_group_security_levels` 移除 `group_id`、`_seq_tracker` 移除 `group:{group_id}` 和 `group_event:{group_id}`、`save_seq_tracker_state()`、清理 `_gap_fill_done`/`_pushed_seqs`/`_pending_ordered()` 中与 group_id 相关条目 |

**对齐要点**：Go 见 `client.go:cleanupDissolvedGroup`；TS/JS 见 `client.ts:_cleanupDissolvedGroup`。解散清理必须同时清 `group:` 和 `group_event:` 两个 namespace。

---

### 块③ V2 E2EE 并发与容量保护

#### `v2/session.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +24 | 新增常量 | `_PEER_IK_CACHE_MAX = 200` | 对端 IK 公钥缓存 LRU 容量上限 |
| +23 | 新增常量 | `_VERIFIED_SPKS_MAX = 500` | 已验证 SPK 签名缓存上限 |
| +60 | 修改 | `V2Session.__init__` | `_peer_ik_cache` 改为 `OrderedDict`（支持 LRU）；新增 `_group_register_lock = asyncio.Lock()` |
| +204 | 修改 | `ensure_group_registered()` | 整体加 `async with self._group_register_lock`，防止并发注册产生重复 group SPK 上传 |
| +348 | 修改 | `cache_peer_ik()` | 改为 LRU 逻辑：命中时 `move_to_end`，超 `_PEER_IK_CACHE_MAX` 时 `popitem(last=False)` 淘汰最旧 |
| +374 | 修改 | `mark_peer_spk_verified()` | 超 `_VERIFIED_SPKS_MAX` 时 `_verified_spks.clear()` 重建，避免无限增长 |
| +284 | 修改 | `_auto_destroy_spks()` 异常处理 | 三处 `except Exception: pass` 改为 `except Exception as e: _logger.warning(...)` |

**对齐要点**：Go 见 `v2/session.go`（`groupRegisterMu sync.Mutex` / `peerIKCache` LRU 实现）；TS/JS 见 `v2/session/session.ts`（`_registeringPromise` 并发保护 / `_peerIKCache` Map + LRU）。`_group_register_lock` 须在注册期间全程持有（含 `ensure_keys` + `load_latest_uploaded` + `publish_group_spk`）。

#### `v2/keystore.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +154 | 新增 | `V2KeyStore.delete_group_spk(device_id, group_id, spk_id)` | DELETE 单条群 SPK（`v2_device_keys` 表，key_type=group_spk）；供上传失败回滚用 |

**对齐要点**：Go 见 `v2/keystore/sqlite.go:DeleteGroupSPK`；TS/JS 见 `v2/session/keystore.ts:deleteGroupSpk`。

#### `v2/e2ee/spk_lifecycle.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +144 | 修改 | `SpkLifecycleManager._rotate_spk()` | 旧逻辑：先标记旧 SPK `pending_drain` → 写新 SPK → 回调上传。新逻辑：**先写新 SPK 入 store → 先上传（回调） → 上传成功后才标记旧 SPK `pending_drain`**，避免回调抛异常时旧 SPK 已被标记但新 SPK 未上传 |

**对齐要点**：Go 见 `v2/e2ee/spk_lifecycle.go`（`rotateSPK`）；TS/JS 见 `v2/session/session.ts`（`_rotateGroupSpk`）。"先上传后 pending_drain" 是四语言一致的顺序要求。

#### `_client/v2_e2ee.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +114 | 修改 | `_schedule_group_spk_rotation()` | 捕获 `rotate_group_spk` 异常后做回滚：若本地新 SPK（`session._store.load_current_group_spk`）与旧 SPK id 不同，则调 `session._store.delete_group_spk` 删除新 SPK，防止本地/服务端 spk_id 不一致 |
| +193 | 修改 | `_retry_v2_sender_ik_pending()` | 仍未能解密的消息从原 `pop + 丢弃` 改为**保留队列继续重试**；同时发射 `message.undecryptable` / `group.message_undecryptable` 事件通知应用层；新增 `_V2_SENDER_IK_PENDING_MAX = 1000` 上限，超限淘汰最旧并 WARN |

**对齐要点**：Go `scheduleGroupSpkRotation` 捕获局部变量 session 的 goroutine 逻辑（见 `client_v2_e2ee.go`）；TS/JS `_scheduleGroupSpkRotation` 捕获 session + rollback 逻辑。IK pending 保留+事件通知是四语言一致行为：不可静默丢弃；Go/TS/JS 需同步。

---

### 块④ 独立修复

#### `errors.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +164 | 修复 | `map_remote_error()` | 在 `-32004 → PermissionError` 判断前插入特判：`code == -32004 and message.lower().startswith("rpc handler timeout")` 时映射为 `TimeoutError` |
| +189 | 修改 | `map_remote_error()` retryable 计算 | `cls is RateLimitError` → `cls in {RateLimitError, TimeoutError}`，使 handler timeout 可重试 |

**对齐要点**：Go 见 `errors.go:mapRemoteError`；TS/JS 见 `src/errors.ts:mapRemoteError`。-32004 的双分支映射需四语言完全一致：前缀匹配 `"rpc handler timeout"` → `TimeoutError`（retryable=true），其余 → `PermissionError`（retryable=false）。

---

### 测试新增

| 文件 | 新增用例 | 说明 |
|------|----------|------|
| `tests/unit/test_client.py` | `test_group_changed_push_persists_and_acks_contiguous_event_seq` | 连续 push 推进 group_event tracker、持久化并 ack |
| `tests/unit/test_client.py` | `test_group_changed_gap_fill_publishes_ordered_and_deduped_to_app` | 高序号先到时补洞后保序去重，SDK 内部消费与应用层回调分离 |
| `tests/unit/test_client.py` | `test_group_pull_events_acks_once_after_event_publish_final_contiguous` | ack_seq 断言从 4 改为 3（SDK 内部 contiguous_seq，不含 drain 中的应用层 seq） |
| `tests/unit/test_client_signature.py` | `test_storage_mutation_method_is_non_idempotent`（参数化） | 16 个 storage 方法均在 `_NON_IDEMPOTENT_METHODS` |
| `tests/unit/test_client_signature.py` | `test_group_resource_method_is_non_idempotent`（参数化） | 16 个 group.resources 方法均在 `_NON_IDEMPOTENT_METHODS` |
| `tests/unit/test_trace.py` | `test_trace_event_observer_can_filter_after_background_rpc` | 后台 RPC trace 与目标事件 trace 混合时，observer 可按 type/event 筛选 |
| `tests/integration_test_storage.py` | `test_storage_directory_tree_rename_move_delete` | 目录树 RPC 完整流程（权限/同名冲突/递归 path 更新/dry_run） |
| `tests/integration_test_storage.py` | `test_storage_object_move_copy_batch_and_meta_edges` | move/copy/batch_delete/set_object_meta 边界（冲突策略/ID 稳定/dry_run 不删） |
| `tests/integration_test_group_resources.py` | `test_group_resources_tree_folder_mount_rename_move_delete` | 群资源树操作完整流程（权限/create_folder/mount_object/rename/move/递归删除） |
| `tests/integration_test_group_resources.py` | `test_group_resources_request_mount_cleanup_and_unmount_edges` | request_mount_object/approve/cleanup_by_storage_ref/unmount 边界 |
| `tests/integration_test_group_resources.py` | `test_group_resources_storage_delete_marks_resource_missing` | storage 删除后群资源 status 自动标记 missing |
| `tests/integration_test_group_resources.py` | `test_group_resources_mount_object_conflict_policy` | mount_object 冲突策略（reject/replace/keep_both） |
| `tests/e2e_test_trace.py` | trace E2E 整体改进 | 新增 `_rpc_traces`/`_event_traces` 过滤辅助函数；`test_event_trace_propagation` 改用 `asyncio.Event` 等待目标消息，消除 sleep 竞态 |
| `tests/e2e_test_group_e2ee.py` | `_ensure_connected` 重试 | 捕获 `TimeoutError`/`OSError` |

### `version.py`
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +1 | 修改 | `__version__` | `"0.4.10"` → `"0.4.11"` |

---

## v0.4.10 — 相对于 v0.4.9 的变更

> 对齐基准为 git 中首个 v0.4.9 提交 `1d64d186`。v0.4.10 = `b45b9f15`（Service Proxy + notify() + Storage 逻辑下载 URL，版本仍标 0.4.9）+ 工作区未提交改动（群撤回端到端 + ChangeSeed 健壮性 + 版本号升 0.4.10）。
>
> 三大变更块：**① Service Proxy 服务代理（新模块）**、**② notify() 单向通知（新公开 API）**、**③ 群消息撤回 `group.message_recalled` 端到端打通（修复）**，外加 **④ ChangeSeed 健壮性增强**。Storage 逻辑下载 URL 主要为服务端 + 文档改动，SDK 侧仅 `_NON_IDEMPOTENT_METHODS` 方法名同步。

### 块① Service Proxy 服务代理（新模块 `service_proxy/`）

#### `service_proxy/__init__.py`（新文件，相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L1~9 | 新增 | 模块导出 | 导出 `ServiceProxyClient`、`EmbeddedServiceRegistry`、`EndpointPolicy`、`ServiceRecord` |

#### `service_proxy/registry.py`（新文件，172 行）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L83 | 新增 | `class ServiceRecord` | 服务注册记录（service_name/endpoint/service_type/visibility/metadata）；`summary()`→dict |
| L100 | 新增 | `class EndpointPolicy` | 后端 endpoint 白名单策略；`is_allowed(endpoint)` 校验目标 host |
| L123 | 新增 | `class EmbeddedServiceRegistry` | 内嵌服务注册表：`register()` / `unregister()` / `get()` / `list_records()` / `list_summaries()` |

#### `service_proxy/protocol_detection.py`（新文件，237 行）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L23 | 新增 | `class ProtocolDetection` | 协议探测结果（stream_mode/protocol/service_type）；`summary()`→dict |
| L125 | 新增 | `def detect_request_protocol(message, record)` | 从请求头/路径/body 探测 HTTP/JSON-RPC/SSE/WS 流模式 |
| L217 | 新增 | `def is_stream_response_headers(headers)` | 判断响应头是否为流式（SSE/chunked） |
| L230 | 新增 | `def stream_type_from_response(headers, fallback)` | 从响应头推断流类型 |

#### `service_proxy/client.py`（新文件，1716 行）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| L58 | 新增 | `class ServiceProxyClient` | 服务代理客户端核心 |
| L160 | 新增 | `register_service()` / `unregister_service()` / `list_service_summaries()` | 本地服务登记（控制面） |
| L191 | 新增 | `register_services_with_gateway()` | RPC `proxy.register_services` 向 gateway 注册服务 |
| L207 | 新增 | `unregister_services_from_gateway()` | RPC `proxy.unregister_services` |
| L220 | 新增 | `list_gateway_services()` | RPC `proxy.list_services` |
| L360 | 新增 | `discover_proxy_server()` / `discover_proxy_ws_url()` | 发现 proxy 数据面 WS 地址 |
| L381 | 新增 | `connect_once()` / `serve_once()` / `serve_forever()` | 数据面隧道：建链、单次/持续处理反代请求 |
| L936 | 新增 | `handle_request_message()` / `iter_request_messages()` / `stream_request_message()` | 隧道请求→本地后端 HTTP 转发（含流式分块） |
| L1378 | 新增 | `handle_ws_connect_message()` | WS 反代隧道 |
| L1658 | 新增 | `create_admin_app()` | holder 侧本地 admin HTTP（带 admin_token） |

#### `service_proxy/tools/`（新文件）
| 文件 | 说明 |
|------|------|
| `tools/common.py`（199 行） | holder/visitor 公共工具 |
| `tools/test_service_holder.py`（465 行） | holder 端测试工具（暴露本地服务到 proxy） |
| `tools/visitor_client.py`（307 行） | visitor 端测试工具（经 proxy 访问远端服务） |

**对齐要点**：四语言 service_proxy 客户端 API 一致。Go 见 `go/service_proxy.go`（`NewServiceProxyClient` + `RegisterService`/`ServeForever` 等，含 `cmd/service-proxy-holder`、`cmd/service-proxy-visitor`）；TS 见 `ts/src/service-proxy.ts` + `tools/service-proxy-{holder,visitor}.mjs`；JS 见 `js/src/service-proxy.ts` + `tools/service-proxy-{holder-boundary,visitor}.mjs`。控制面方法名固定为 `proxy.register_services`/`proxy.unregister_services`/`proxy.list_services`。

### 块② notify() 单向通知（新公开 API）

#### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +99 | 新增常量 | `_MAX_NOTIFY_PAYLOAD_SIZE = 64 * 1024` | notify payload 上限 64KB |
| +967 | 新增 | `AUNClient._notify_params_size_ok(params)` | 校验序列化后字节数 ≤ 上限 |
| +974 | 新增 | `AUNClient._validate_notify_event_method(method)` | 路由型 notify 的 method 必须为 `event/app.*`，否则抛 `ValidationError` |
| +981 | 新增 | `AUNClient._normalize_notify_ttl(ttl_ms)` | 校验 ttl_ms 为 0~60000 整数 |
| +992 | 新增 | `async AUNClient.notify(method, params, *, to, group_id, device_id, slot_id, ttl_ms)` | 三种目标分支：① `to`（AID 单播，可带 device_id/slot_id）→ `notification/route`；② `group_id`（群广播）→ `notification/group.route`；③ 无目标（直发 `notification/*`）。互斥校验：`to` 与 `group_id` 不可同设；`slot_id` 须配 `device_id` |

#### `transport.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +400 | 新增 | `async RPCTransport.notify(method, params)` | 发送无 `id` 的 JSON-RPC 2.0 Notification（method 须以 `notification/` 或 `event/` 开头）；不分配 seq、不等 ack、超 `MAX_WS_PAYLOAD_SIZE` 抛错；未连接抛 `ConnectionError` |
| +655 | 新增 | `_handle_event()` 内 `app.*` 分支 | 收到 `event/app.*` 事件直接 `publish(sdk_event, params)`（应用层事件，不走 `_raw.` 前缀分发） |

**对齐要点**：所有 SDK 的 `notify()` 三分支语义与互斥校验必须一致。Go：`AUNClient.Notify(ctx, method, params, opts...)` + `type NotifyOptions`（client.go:1176/397），`RPCTransport.Notify`（transport.go:620），辅助函数 `notifyParamsSizeOK`/`validateNotifyEventMethod`/`normalizeNotifyTTL`（client.go:1155~1168）。TS：`notify(method, params?, options)` + `interface NotifyOptions`（client.ts:1140/174）。JS：同 TS（client.ts:1204/146）。

### 块③ 群消息撤回 `group.message_recalled` 端到端打通（修复）

> 服务端发两条 tombstone（pull 路径的占位 tombstone 用原 seq + 通知 tombstone 用新 notice_seq），外加在线 push 通道。SDK 三条通道都归一化为 `group.message_recalled` 事件并按 `(group_id, message_ids)` 去重，确保应用层只回调一次；push/pull 都要正确推进 seq/ack，避免 contiguous 序列留洞导致重复拉取。

#### `_client/delivery.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +18 | 新增常量 | `_GROUP_RECALL_SEEN_LIMIT = 10000` | 去重表上限 |
| +124 | 新增 | `_handled_app_event_types` 集合补 `group.message_recalled` | 标记为已处理事件类型 |
| +201 | 新增 | `MessageDeliveryEngine.recall_event_from_group_message(message)` (静态) | 把 pull/push 收到的撤回 tombstone 归一化为 `group.message_recalled` payload；识别 `type`/`kind` 或 `payload.type/kind == "group.message_recalled"`；提取 `message_ids`（兼容 `recalled_message_id`/`target_message_id`/`original_message_id`） |
| +243 | 新增 | `MessageDeliveryEngine.group_recall_dedup_key(group_id, payload)` (静态) | 去重键 = `group_id + sorted(message_ids)`；**不含 `recalled_at`**（三通道时间戳来源不同，纳入会使去重失效） |
| +258 | 新增 | `async MessageDeliveryEngine.publish_group_recall_tombstone(group_id, seq, message)` | 归一化 + 按去重键发布一次 `group.message_recalled`；维护 `client._group_recall_seen` dict 并按上限 LRU 淘汰；返回是否实际发布 |
| +738 | 新增 | `async MessageDeliveryEngine.on_raw_group_message_recalled(data)` | 处理在线 push：包装 data 为可识别形状，进 ns lock 后调 `_apply_group_recall_push` |
| +772 | 新增 | `async MessageDeliveryEngine._apply_group_recall_push(group_id, seq, wrapped)` | 在 ns lock 内推进 notice_seq 的 seq/ack（与普通群消息 push 对齐）：`update_max_seen` → contiguous 判断 → `on_message_seq` + `persist_seq` → 发布撤回 → `mark_published_seq` → `group.ack_messages` auto-ack；已覆盖/已发布的 seq 走去重兜底不重复推进 |

#### `_client/v2_e2ee.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +1848 | 新增 | `pull_v2_group` 明文路径撤回识别 | pull 到的消息若被 `recall_event_from_group_message` 识别为撤回 tombstone，则 `publish_group_recall_tombstone` + `mark_published_seq` 后 `continue`，绝不当普通消息投递给应用层 |

#### `client.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +208 | 修改 | `_NON_IDEMPOTENT_METHODS` | storage 方法名同步：`storage.upload`/`storage.delete` → `storage.create_upload_session`/`storage.delete_object`（配合块④ Storage 改动） |
| +632 | 新增 | `__init__` 订阅 | `dispatcher.subscribe("_raw.group.message_recalled", self._on_raw_group_message_recalled)` |
| +926 | 新增 | RPC 白名单 | `"group.recall"` 加入允许调用的 RPC 方法集 |
| +1151 | 新增 | `async AUNClient._on_raw_group_message_recalled(data)` | 委托 `_delivery().on_raw_group_message_recalled(data)` |

#### `transport.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +28 | 新增 | `EVENT_NAME_MAP` 补项 | `"group.message_recalled": "group.message_recalled"` |

**对齐要点**：Go 见 `client_delivery.go`（`recallEventFromGroupMessage`:170 / `groupRecallDedupKey`:252 / `publishGroupRecallTombstone`:268 / `onRawGroupMessageRecalled`:315，去重表 `groupRecallSeen`+`groupRecallSeenMu` client.go:554，常量 `groupRecallSeenLimit`:70），订阅 client.go:744，RPC 白名单 client.go:1291，V2 pull 路径 v2_routing.go:201（含 legacy V1 tombstone 归一化）。TS 见 `client/delivery.ts`（`recallEventFromGroupMessage`:142 / `groupRecallDedupKey`:174 / `publishGroupRecallTombstone`:189 / `onRawGroupMessageRecalled`:213，常量 `GROUP_RECALL_SEEN_LIMIT`:9），订阅 client.ts:803。JS 见 `client/delivery.ts`（同名符号 138/170/183/207），订阅 client.ts:850。**去重键统一不含 `recalled_at`** 是四语言一致的关键修复点。

### 块④ ChangeSeed 健壮性增强（优化）

> 原 ChangeSeed 用单一 `.bak` 备份，重复迁移会因 `.bak` 已存在而跳过备份；改为递增版本备份 `.vN`（每次都新建），迁移失败可从对应版本回滚，成功后保留备份供审计。`LocalIdentityStore` 覆盖 key.json 前同样做版本备份。

#### `keystore/_utils.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +63 | 新增 | `def next_versioned_backup_path(path)` | 返回下一个可用的 `path.v1`/`path.v2`… 路径 |

#### `keystore/seed_migration.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +264 | 修改 | `_change_seed_bytes()` 阶段2 | `written` 列表元素从 `_PrivateKeyMigration` 改为 `(migration, bak_path)` 元组；失败时从 `.vN` 备份回滚 |
| +279 | 删除 | 阶段3 `_cleanup_key_json_backups()` 调用 | 成功后保留版本备份供审计（不再删除） |
| +402 | 修改 | `_rewrite_key_json()` | 返回值由 `None` 改为 `Path`（备份路径）；备份改用 `_next_versioned_backup_path()`（每次新建，不再复用 `.bak`） |
| +444 | 新增 | `def _next_versioned_backup_path(path)` | 同 `_utils` 版本（模块内私有） |
| +454 | 修改 | `_rollback_key_json_from_backups(written, ...)` | 参数改为 `(migration, bak_path)` 元组列表；从版本备份恢复 |

#### `keystore/local_identity_store.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +23 | 修改 import | 增 `next_versioned_backup_path` | 从 `_utils` 引入 |
| +359 | 新增 | `_save_key_pair_at_path()` 备份逻辑 | 覆盖已有 key.json 前先 `next_versioned_backup_path` 备份（失败仅 WARN，非致命），再 `write_key_json_atomic` |

**对齐要点**：Go 见 `keystore/seed_migration.go`（`nextVersionedBackupPath`:176 / `writeFileAtomic`:186，`rewriteKeyJSONPrivateKey`:144 覆盖前备份）、`keystore/local_identity_store.go`（`saveKeyPairAtPath`:215 覆盖前 `nextVersionedBackupPath` 备份 + 改用带时间戳的 tmp 文件名）。TS 见 `secret-store/file-store.ts`（`nextVersionedBackupPath`:115 / `writeKeyJsonAtomic`:122，`changeSeedBytes` 覆盖前备份:209）、`keystore/local-identity-store.ts`（覆盖前 `.vN` 备份:171）。JS（浏览器 IndexedDB 后端）无文件级 seed 迁移，**不适用本块**。

#### `version.py`（相对 python/src/aun_core/）
| 行号 | 类型 | 符号 | 说明 |
|------|------|------|------|
| +1 | 修改 | `__version__` | `"0.4.9"` → `"0.4.10"` |

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
