# 重启全量拉取问题优化设计

日期：2026-04-17
范围：aun-sdk-core/python（客户端） + extensions/services/group（服务端）

## 背景

用户反馈：客户端每次重启感觉全量拉取了所有 P2P 消息 / 群消息 / 群事件，即使 SeqTracker 已持久化。

## 根因

三层叠加导致"全量拉"表象：

1. **启动期竞态（客户端）**：
   - `transport.connect()` 在 `client.py:1824` 启动 reader task
   - `_restore_seq_tracker_state()` 在 `client.py:1859` 才执行
   - auth 完成（1852）→ restore 完成（1859）之间，server 推送的积压事件进入 handler 时 tracker 为空
   - SeqTracker S2 不变量：首条 seq>1 的消息会创建 `[1, seq-1]` 历史 gap
   - `need_pull = True` → 触发 `_fill_*_gap(after_seq=0)`

2. **`group.changed` 无条件补拉（客户端）**：
   - `_on_raw_group_changed` 在 `client.py:949-952` 不检查 `on_message_seq` 返回值
   - 每条 event push 都无条件 `create_task(_fill_group_event_gap(group_id))`
   - 正常运行期也会产生冗余拉取

3. **服务端信任显式零值（服务端）**：
   - `group/service.py:1626-1631`（multi-device msg）、`:1648-1650`（single-device msg）、`:4301-4305`（multi-device event）、`:4325`（single-device event）
   - 客户端传 `after_* = 0` 时服务端按字面值执行 `WHERE seq > 0`
   - 即使服务端存有 ack cursor（`group_members.last_ack_seq` 或 `device_cursors.last_ack_*`），也会从头分页
   - SQL 本身有 LIMIT 不会一次返回全部，但后续分页会把历史全部拉完

## 目标

消除启动期误触发 + 正常运行期 `group.changed` 冗余拉取 + 服务端对客户端误传的兜底保护。保持推送消息的 publish 流程不变（应用层实时性不退化）。

## 非目标

- 不修改 SeqTracker 不变量
- 不改变客户端/服务端 RPC 接口契约
- 不清理历史持久化数据

## 三项优化

### 客户端 1：SeqTracker 恢复前置

**变更位置**：`python/src/aun_core/client.py::_connect_once`

**当前顺序**（1820-1861）：
```
_transport.connect(url)      # reader 启动
_auth.connect_session(...)   # auth 完成
_refresh_seq_tracking_context()
_restore_seq_tracker_state()
_start_background_tasks()
```

**新顺序**：
```
_auth.set_instance_context(...)
_refresh_seq_tracking_context()     # 前置
_restore_seq_tracker_state()        # 前置
_transport.connect(url)
_auth.connect_session(...)
# auth 后 aid 可能被 identity 覆盖，做 context diff 兜底：
if self._seq_tracker_context != self._current_seq_tracker_context():
    self._refresh_seq_tracking_context()
    self._restore_seq_tracker_state()
_start_background_tasks()
```

**保障**：
- `_restore_seq_tracker_state` 只依赖 `self._aid` + `self._keystore`，无 transport 依赖
- 首次 restore 在任何 reader push 进入 handler 之前完成
- auth 阶段 aid 变更的罕见路径，通过 context diff 二次 restore
- restore 是本地 keystore 读取（毫秒级），阻塞 connect 链路可忽略

**推送路径行为**：保持不变。`_process_and_publish_message` / `_process_and_publish_group_message` / `_on_raw_group_changed` 继续走解密 → `_publish_event` → 应用层回调。

### 客户端 2：`group.changed` 基于 gap 检测门控

**变更位置**：`python/src/aun_core/client.py::_on_raw_group_changed`（约 924-959）

**当前行为**：
```python
if event_seq is not None:
    self._seq_tracker.on_message_seq(f"group_event:{group_id}", es)  # 返回值丢弃
loop.create_task(self._fill_group_event_gap(group_id))               # 无条件触发
```

**新行为**：
```python
need_pull = False
if event_seq is not None:
    need_pull = self._seq_tracker.on_message_seq(f"group_event:{group_id}", es)
if need_pull:
    loop.create_task(self._fill_group_event_gap(group_id))
```

**与 P2P / group.message 路径对齐**：这两处已经是基于 `need_pull` 返回值门控，本次改动使 event 路径行为一致。

**兼容性**：server 当前实现在 `group/service.py` 内所有 event 发送路径都带 `event_seq`（见仓库中 `_broadcast_*` 系列），不存在缺失 `event_seq` 的兼容风险。

### 服务端：cursor 静默兜底

**变更位置**：
- `extensions/services/group/service.py::pull_messages`（约 1608-1697）
- `extensions/services/group/service.py::pull_events`（约 4284-4368）

**cursor 数据源差异**：

| 路径 | 单设备（无 device_id） | 多设备（有 device_id） |
|------|--------------------|---------------------|
| `pull_messages` | `group_members.last_ack_seq`（由 `ack_messages` 更新） | `device_cursors.last_ack_msg_seq` |
| `pull_events` | **无**（单设备 event ack 不落盘） | `device_cursors.last_ack_event_seq` |

因此兜底方案分 4 种情况：

#### pull_messages 多设备（当前 1626-1631）

```python
after_msg_seq_raw = params.get("after_message_seq")
if after_msg_seq_raw is not None:
    after_msg_seq = int(after_msg_seq_raw)
    if after_msg_seq < cursor.last_ack_msg_seq:
        after_msg_seq = cursor.last_ack_msg_seq   # 静默抬升
else:
    after_msg_seq = cursor.last_ack_msg_seq
```

#### pull_messages 单设备（当前 1648-1650）

```python
# 原：after_msg_seq = max(0, int(params.get("after_message_seq", 0) or 0))
member_cursor = await self._message_store.get_member_cursor(
    group_id=group_id, aid=aid
)
last_ack = int(member_cursor["last_ack_seq"])

after_msg_seq_raw = params.get("after_message_seq")
if after_msg_seq_raw is not None:
    after_msg_seq = max(0, int(after_msg_seq_raw))
    if after_msg_seq < last_ack:
        after_msg_seq = last_ack                  # 静默抬升
else:
    after_msg_seq = last_ack
```

#### pull_events 多设备（当前 4301-4305）

对称处理，floor 使用 `cursor.last_ack_event_seq`。

#### pull_events 单设备（当前 4325）

**无法兜底**：`group_members` 表无 `last_ack_event_seq` 字段，`ack_events` handler 也只更新 `device_cursors`。

单设备 event 启动期风险完全依赖客户端优化 1（restore 前置）解决。保留原行为：
```python
after_event_seq = max(0, int(params.get("after_event_seq", 0) or 0))
```

**语义**：
- 客户端显式传小于 cursor 的值：静默抬升（不报错，向前兼容）
- 客户端不传：沿用原 cursor 回退
- 响应中已有 `cursor` 字段回传真实 cursor，client 下次对齐

## 预期效果

- **重启场景**：restore 完成后 SeqTracker 含历史 contiguous_seq，首条推送的 `on_message_seq` 返回 `need_pull=False`，不触发 fill
- **运行期 group event**：只在真实 event gap 时拉
- **多设备误传**：服务端兜底避免分页回溯全部历史

## 测试策略

### 客户端单元测试

`python/tests/unit/test_client.py` 新增：

1. **`test_restore_before_transport_connect`**：
   mock `_transport.connect`、`_auth.connect_session`；断言 `_restore_seq_tracker_state` 在 `_transport.connect` 被调用前执行。
2. **`test_restore_after_aid_change_during_auth`**：
   模拟 auth 覆盖 `self._aid`；断言发生二次 `_restore_seq_tracker_state`。
3. **`test_group_changed_skips_fill_when_no_gap`**：
   预置 tracker contiguous `group_event:G = 5`，推送 `event_seq=6`；断言 `_fill_group_event_gap` 未被调度。
4. **`test_group_changed_triggers_fill_when_gap`**：
   预置 tracker contiguous `group_event:G = 5`，推送 `event_seq=10`；断言 `_fill_group_event_gap` 被调度。

### 服务端单元测试

`extensions/services/codex-unit/group/test_group_*.py`（按现有约定目录）新增：

1. **`test_pull_messages_multidevice_floors_after_to_cursor`**：
   device_cursor.last_ack_msg_seq=50，请求 `after_message_seq=0 device_id="d1"`；断言实际查询起点为 50。
2. **`test_pull_messages_multidevice_respects_above_cursor`**：
   cursor=50，请求 `after_message_seq=80`；断言使用 80。
3. **`test_pull_messages_singledevice_floors_to_member_last_ack`**：
   `group_members.last_ack_seq=30`，请求 `after_message_seq=0`（无 device_id）；断言实际查询起点为 30。
4. **`test_pull_messages_singledevice_respects_above_last_ack`**：
   `last_ack_seq=30`，请求 `after_message_seq=60`；断言使用 60。
5. **`test_pull_events_multidevice_floors_after_to_cursor`**：
   `cursor.last_ack_event_seq=25`，请求 `after_event_seq=0 device_id="d1"`；断言起点 25。
6. **`test_pull_events_singledevice_unchanged`**：
   无 device_id，请求 `after_event_seq=0`；断言仍使用 0（无 cursor 源可兜底）。

## 风险与缓解

| 风险 | 缓解 |
|------|------|
| restore 前置后 `self._aid` 在 auth 阶段被 identity 覆盖 | context diff 检测后二次 restore |
| keystore 读取在极端情况下阻塞过久 | restore 已有 try/except，失败降级为空 tracker（与当前行为一致） |
| 服务端兜底掩盖 client bug | 响应中 `cursor` 字段回传真实位置；未来可加 warn 日志 |
| group.changed 路径依赖 `event_seq` 总是携带 | 仓库内已确认 server 所有 event 路径都带，无缺失风险 |

## 不做的事

- 不引入 `asyncio.Event` 门控 handler
- 不添加 buffer queue
- 不推迟 reader 启动
- 不改变 `message.pull` / `message.ack` 已有行为
- 不对服务端 P2P `message.pull` 做 cursor 兜底（P2P 的 `server_ack_seq` retention floor 已提供保护）
