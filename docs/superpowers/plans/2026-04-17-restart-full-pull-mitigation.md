# 重启全量拉取问题优化 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 消除客户端重启时 P2P/群消息/群事件的全量拉取误触发，同时为服务端 group pull 路径提供 cursor 静默兜底保护。

**Architecture:** 三项独立优化叠加——(1) 客户端 SeqTracker 恢复前置到 transport.connect 之前；(2) `group.changed` 事件处理改用 `on_message_seq` 返回值门控补拉；(3) 服务端 `pull_messages` / `pull_events` 对客户端显式 `after_* < cursor` 静默抬升到 cursor。各项优化在独立任务中实现，保持推送 publish 流程不变。

**Tech Stack:** Python 3.11+，pytest，asyncio，aiomysql，无新增依赖。

---

## 文件结构

### 客户端改动

- Modify: `python/src/aun_core/client.py`
  - `_connect_once`（1816-1871）：restore 前置、aid 变更二次 restore
  - `_on_raw_group_changed`（924-959）：need_pull 门控 `_fill_group_event_gap`
- Test: `python/tests/unit/test_client.py`（追加测试）

### 服务端改动

- Modify: `extensions/services/group/service.py`
  - `pull_messages`（1608-1697）：多设备 + 单设备 cursor 兜底
  - `pull_events`（4284-4368）：多设备 cursor 兜底（单设备不做）
- Test: `extensions/services/codex-unit/group/test_group_pull_cursor_floor.py`（新建）

---

## Task 1：客户端 - `_on_raw_group_changed` 基于 gap 门控

**Files:**
- Modify: `python/src/aun_core/client.py:924-959`
- Test: `python/tests/unit/test_client.py`

- [ ] **Step 1：写失败测试 - 无 gap 时不调度 fill**

在 `python/tests/unit/test_client.py` 末尾追加：

```python
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_group_changed_skips_fill_when_no_gap():
    """gap 检测：连续 event_seq 无需触发 _fill_group_event_gap。"""
    from aun_core.client import Client
    client = Client.__new__(Client)
    # 最小化手工装配
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._seq_tracker = __import__(
        "aun_core.seq_tracker", fromlist=["SeqTracker"]
    ).SeqTracker()
    # 预置 contiguous = 5
    client._seq_tracker.restore_state({"group_event:G1": 5})
    client._loop = asyncio.get_running_loop()
    client._verify_event_signature = AsyncMock(return_value=True)
    fill_calls = []
    async def fake_fill(gid):
        fill_calls.append(gid)
    client._fill_group_event_gap = fake_fill
    client._rotate_group_epoch = AsyncMock()

    data = {"group_id": "G1", "event_seq": 6, "action": "foo"}
    await client._on_raw_group_changed(data)
    # 给 create_task 机会运行
    await asyncio.sleep(0)
    assert fill_calls == []


@pytest.mark.asyncio
async def test_group_changed_triggers_fill_when_gap():
    """gap 检测：event_seq 跳跃触发 _fill_group_event_gap。"""
    from aun_core.client import Client
    client = Client.__new__(Client)
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._seq_tracker = __import__(
        "aun_core.seq_tracker", fromlist=["SeqTracker"]
    ).SeqTracker()
    client._seq_tracker.restore_state({"group_event:G1": 5})
    client._loop = asyncio.get_running_loop()
    client._verify_event_signature = AsyncMock(return_value=True)
    fill_calls = []
    async def fake_fill(gid):
        fill_calls.append(gid)
    client._fill_group_event_gap = fake_fill
    client._rotate_group_epoch = AsyncMock()

    data = {"group_id": "G1", "event_seq": 10, "action": "foo"}
    await client._on_raw_group_changed(data)
    await asyncio.sleep(0)
    assert fill_calls == ["G1"]
```

- [ ] **Step 2：运行测试验证失败**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/test_client.py::test_group_changed_skips_fill_when_no_gap tests/unit/test_client.py::test_group_changed_triggers_fill_when_gap -v
```

Expected：`test_group_changed_skips_fill_when_no_gap` FAIL（当前无条件触发 fill，`fill_calls == ["G1"]` 而期望 `[]`）。`test_group_changed_triggers_fill_when_gap` 可能 PASS。

- [ ] **Step 3：修改 `_on_raw_group_changed` 用 `need_pull` 门控**

`python/src/aun_core/client.py:924-959` 替换为：

```python
    async def _on_raw_group_changed(self, data: Any) -> None:
        """处理群组变更事件：验签 → 透传给用户 → 基于 gap 检测补齐 → epoch 轮换。

        验签策略：有 client_signature 就验，没有默认安全（兼容旧版）。
        """
        if isinstance(data, dict):
            # 验签：有签名就验证操作者身份
            cs = data.get("client_signature")
            if cs and isinstance(cs, dict):
                data["_verified"] = await self._verify_event_signature(data, cs)
            # 发布给用户（publish 流程保持不变）
            await self._dispatcher.publish("group.changed", data)

            group_id = data.get("group_id", "")

            # event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq
            # 用 on_message_seq 返回值决定是否补拉，与 P2P / group.message 路径对齐
            need_pull = False
            raw_event_seq = data.get("event_seq")
            if raw_event_seq is not None and group_id:
                try:
                    es = int(raw_event_seq)
                    ns = f"group_event:{group_id}"
                    need_pull = self._seq_tracker.on_message_seq(ns, es)
                except (ValueError, TypeError):
                    pass

            # 仅真实存在 gap 时才补拉（补洞回来的事件不再触发新补洞）
            if need_pull and group_id and not data.get("_from_gap_fill"):
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._fill_group_event_gap(group_id))

            # 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
            if data.get("action") in ("member_left", "member_removed") and group_id:
                loop = getattr(self, "_loop", None) or asyncio.get_running_loop()
                loop.create_task(self._rotate_group_epoch(group_id))
        else:
            await self._dispatcher.publish("group.changed", data)
```

- [ ] **Step 4：运行测试验证通过**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/test_client.py::test_group_changed_skips_fill_when_no_gap tests/unit/test_client.py::test_group_changed_triggers_fill_when_gap -v
```

Expected：两个测试都 PASS。

- [ ] **Step 5：全量客户端单元测试回归**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/ -v --tb=short
```

Expected：全部通过（允许 kite_console 路径问题的 1 个已知无关失败）。

- [ ] **Step 6：提交**

```bash
cd D:/modelunion/kite/aun-sdk-core
git add python/src/aun_core/client.py python/tests/unit/test_client.py
git commit -m "fix(sdk): group.changed 仅在真实 event gap 时才触发补拉

原 _on_raw_group_changed 无条件 create_task(_fill_group_event_gap)，
每条 event push 都产生一次冗余拉取。改用 on_message_seq 返回值
门控，与 P2P / group.message 路径对齐。"
```

---

## Task 2：客户端 - SeqTracker 恢复前置到 transport.connect 之前

**Files:**
- Modify: `python/src/aun_core/client.py:1816-1871`（`_connect_once`）
- Test: `python/tests/unit/test_client.py`

- [ ] **Step 1：写失败测试 - restore 在 transport.connect 之前执行**

在 `python/tests/unit/test_client.py` 追加：

```python
@pytest.mark.asyncio
async def test_restore_before_transport_connect(monkeypatch):
    """restore_seq_tracker_state 必须在 transport.connect 之前被调用。"""
    from aun_core.client import Client
    client = Client.__new__(Client)

    # 装配最小依赖
    from aun_core.seq_tracker import SeqTracker
    client._seq_tracker = SeqTracker()
    client._seq_tracker_context = None
    client._gap_fill_done = set()
    client._gap_fill_active = False
    client._pushed_seqs = {}
    client._aid = "alice.aid.com"
    client._device_id = "dev1"
    client._slot_id = "s1"
    client._identity = {"aid": "alice.aid.com"}
    client._logger = None
    client._session_params = None
    client._connect_delivery_mode = {}
    client._state = "idle"
    client._gateway_url = None
    client._loop = asyncio.get_running_loop()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._keystore = MagicMock()
    client._keystore.load_all_seqs = MagicMock(return_value={})
    client._auth = MagicMock()
    client._auth.set_instance_context = MagicMock()
    client._auth.connect_session = AsyncMock(return_value={
        "identity": {"aid": "alice.aid.com"}, "token": "t"
    })
    client._transport = MagicMock()
    client._transport.connect = AsyncMock(return_value={"challenge": "x"})
    client._start_background_tasks = MagicMock()
    client._upload_prekey = AsyncMock()
    client._resolve_gateway = lambda p: "wss://gw"
    client._sync_identity_after_connect = MagicMock()

    # 记录调用次序
    call_order = []
    original_restore = Client._restore_seq_tracker_state.__get__(client, Client)

    def traced_restore():
        call_order.append("restore")
        original_restore()

    original_connect = client._transport.connect

    async def traced_connect(url):
        call_order.append("transport.connect")
        return await original_connect(url)

    client._restore_seq_tracker_state = traced_restore
    client._transport.connect = traced_connect

    await client._connect_once(
        {"gateway": "wss://gw", "access_token": "t"}, allow_reauth=True
    )

    restore_idx = call_order.index("restore")
    connect_idx = call_order.index("transport.connect")
    assert restore_idx < connect_idx, f"call order: {call_order}"


@pytest.mark.asyncio
async def test_restore_after_aid_change_during_auth(monkeypatch):
    """auth 阶段 aid 发生变化时，二次 restore 被触发。"""
    from aun_core.client import Client
    from aun_core.seq_tracker import SeqTracker
    client = Client.__new__(Client)
    client._seq_tracker = SeqTracker()
    client._seq_tracker_context = None
    client._gap_fill_done = set()
    client._gap_fill_active = False
    client._pushed_seqs = {}
    client._aid = "alice.aid.com"        # 初始 aid
    client._device_id = "dev1"
    client._slot_id = "s1"
    client._identity = {"aid": "alice.aid.com"}
    client._logger = None
    client._session_params = {"access_token": "t"}
    client._connect_delivery_mode = {}
    client._state = "idle"
    client._gateway_url = None
    client._loop = asyncio.get_running_loop()
    client._dispatcher = MagicMock()
    client._dispatcher.publish = AsyncMock()
    client._keystore = MagicMock()
    client._keystore.load_all_seqs = MagicMock(return_value={})
    client._auth = MagicMock()
    client._auth.set_instance_context = MagicMock()

    # auth 返回不同 aid，模拟身份覆盖
    async def fake_connect_session(transport, challenge, url, **kwargs):
        client._aid = "bob.aid.com"   # 模拟 1839 行 identity 覆盖
        return {"identity": {"aid": "bob.aid.com"}, "token": "t"}

    client._auth.connect_session = fake_connect_session
    client._transport = MagicMock()
    client._transport.connect = AsyncMock(return_value={"challenge": "x"})
    client._start_background_tasks = MagicMock()
    client._upload_prekey = AsyncMock()
    client._resolve_gateway = lambda p: "wss://gw"
    client._sync_identity_after_connect = MagicMock()

    restore_count = {"n": 0}
    original_restore = Client._restore_seq_tracker_state.__get__(client, Client)

    def traced_restore():
        restore_count["n"] += 1
        original_restore()

    client._restore_seq_tracker_state = traced_restore

    await client._connect_once(
        {"gateway": "wss://gw", "access_token": "t"}, allow_reauth=True
    )

    assert restore_count["n"] == 2, f"expected 2 restores, got {restore_count['n']}"
```

- [ ] **Step 2：运行测试验证失败**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/test_client.py::test_restore_before_transport_connect tests/unit/test_client.py::test_restore_after_aid_change_during_auth -v
```

Expected：两个测试都 FAIL（当前代码 restore 在 transport.connect 之后；aid 变更也只有一次 restore）。

- [ ] **Step 3：修改 `_connect_once` 把 restore 前置**

`python/src/aun_core/client.py:1816-1871` 的 `_connect_once` 方法体中，按以下顺序调整。

找到当前代码（约 1820-1861）：

```python
        self._slot_id = str(params.get("slot_id") or "")
        self._connect_delivery_mode = dict(params.get("delivery_mode") or self._connect_delivery_mode)
        self._auth.set_instance_context(device_id=self._device_id, slot_id=self._slot_id)
        self._state = "connecting"
        challenge = await self._transport.connect(gateway_url)
```

在 `self._state = "connecting"` 之后、`challenge = await self._transport.connect(...)` 之前插入前置 restore：

```python
        self._slot_id = str(params.get("slot_id") or "")
        self._connect_delivery_mode = dict(params.get("delivery_mode") or self._connect_delivery_mode)
        self._auth.set_instance_context(device_id=self._device_id, slot_id=self._slot_id)
        self._state = "connecting"

        # ── 前置 restore：在 transport.connect 启动 reader 之前完成
        # 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉
        self._refresh_seq_tracking_context()
        self._restore_seq_tracker_state()

        challenge = await self._transport.connect(gateway_url)
```

然后在原位置（约 1857-1859）移除重复的 refresh + restore，替换成 **context diff 兜底**：

原代码（约 1854-1861）：
```python
        self._state = "connected"
        await self._dispatcher.publish("connection.state", {"state": self._state, "gateway": gateway_url})

        self._refresh_seq_tracking_context()
        # 从 keystore 恢复 SeqTracker 状态
        self._restore_seq_tracker_state()

        self._start_background_tasks()
```

改为：
```python
        self._state = "connected"
        await self._dispatcher.publish("connection.state", {"state": self._state, "gateway": gateway_url})

        # auth 阶段 aid 可能被 identity 覆盖（上方 1839 行路径）；
        # 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致
        if self._seq_tracker_context != self._current_seq_tracker_context():
            self._refresh_seq_tracking_context()
            self._restore_seq_tracker_state()

        self._start_background_tasks()
```

- [ ] **Step 4：运行测试验证通过**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/test_client.py::test_restore_before_transport_connect tests/unit/test_client.py::test_restore_after_aid_change_during_auth -v
```

Expected：两个测试都 PASS。

- [ ] **Step 5：全量客户端单元测试回归**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/ -v --tb=short
```

Expected：与基线一致（除已知 kite_console 无关失败外全部通过）。

- [ ] **Step 6：提交**

```bash
cd D:/modelunion/kite/aun-sdk-core
git add python/src/aun_core/client.py python/tests/unit/test_client.py
git commit -m "fix(sdk): SeqTracker 恢复前置到 transport.connect 之前

启动期 reader 先启动、restore 后执行的竞态会让 handler 用空 tracker
处理积压 push，触发 S2 历史 gap 假检测 → 全量补拉。把 restore 前置
到 transport.connect 之前，并在 auth 后通过 context diff 做兜底。"
```

---

## Task 3：服务端 - `pull_messages` 多设备 cursor 兜底

**Files:**
- Modify: `extensions/services/group/service.py:1608-1697`（`pull_messages` 多设备分支）
- Test: `extensions/services/codex-unit/group/test_group_pull_cursor_floor.py`（新建）

- [ ] **Step 1：检查测试目录约定**

```bash
ls D:/modelunion/kite/extensions/services/codex-unit/group/ 2>/dev/null || \
  ls D:/modelunion/kite/extensions/services/group/ | grep test_
```

Expected：确认 group 测试文件放哪。若 `codex-unit/group/` 存在用它，否则放 `extensions/services/group/`。以下代码假设路径为 `extensions/services/codex-unit/group/test_group_pull_cursor_floor.py`；若实际不同请同步调整。

- [ ] **Step 2：写失败测试 - 多设备 pull_messages cursor 抬升**

创建 `extensions/services/codex-unit/group/test_group_pull_cursor_floor.py`：

```python
"""服务端 group.pull / pull_events cursor 静默兜底单元测试。"""
import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def fake_service():
    """构造一个仅装配 pull 路径依赖的 GroupService 最小桩。"""
    from extensions.services.group.service import GroupService
    svc = GroupService.__new__(GroupService)
    svc._config = {"pull_max_limit": 100, "pull_max_response_bytes": 1 << 20}
    svc._require_actor_aid = lambda p: p["aid"]
    svc._require_group_id = lambda p: p["group_id"]

    group_stub = MagicMock()
    group_stub.group_id = "G1"
    group_stub.owner_aid = "alice"
    group_stub.message_seq = 100
    group_stub.event_seq = 50
    svc._require_group = AsyncMock(return_value=group_stub)

    member_stub = MagicMock()
    member_stub.join_msg_seq = 0
    member_stub.join_event_seq = 0
    svc._require_member = AsyncMock(return_value=member_stub)

    svc._decorate_message_view = AsyncMock(side_effect=lambda a, o, m: m)

    svc._repo = MagicMock()
    svc._repo.get_epoch_for_seq = AsyncMock(return_value=None)
    svc._repo.get_epoch_range = AsyncMock(return_value=None)
    svc._repo.update_device_cursor = AsyncMock()

    svc._message_store = MagicMock()
    svc._message_store.pull = AsyncMock(return_value={
        "messages": [], "events": [],
        "latest_message_seq": 100, "latest_event_seq": 50,
    })
    svc._message_store.touch_pull = AsyncMock()
    svc._message_store.get_member_cursor = AsyncMock(return_value={
        "last_ack_seq": 0, "last_pull_at": 0,
        "latest_message_seq": 100, "latest_event_seq": 50,
    })

    return svc


@pytest.mark.asyncio
async def test_pull_messages_multidevice_floors_after_to_cursor(fake_service):
    svc = fake_service
    cursor = MagicMock()
    cursor.last_ack_msg_seq = 50
    cursor.last_ack_event_seq = 0
    cursor.join_msg_seq = 0
    cursor.join_event_seq = 0
    svc._get_or_create_device_cursor = AsyncMock(return_value=cursor)

    await svc.pull_messages({
        "aid": "alice",
        "group_id": "G1",
        "device_id": "d1",
        "after_message_seq": 0,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_message_seq"] == 50, (
        "多设备误传 0 应抬升到 cursor.last_ack_msg_seq=50"
    )


@pytest.mark.asyncio
async def test_pull_messages_multidevice_respects_above_cursor(fake_service):
    svc = fake_service
    cursor = MagicMock()
    cursor.last_ack_msg_seq = 50
    cursor.last_ack_event_seq = 0
    cursor.join_msg_seq = 0
    cursor.join_event_seq = 0
    svc._get_or_create_device_cursor = AsyncMock(return_value=cursor)

    await svc.pull_messages({
        "aid": "alice",
        "group_id": "G1",
        "device_id": "d1",
        "after_message_seq": 80,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_message_seq"] == 80, "高于 cursor 的值保持不变"
```

- [ ] **Step 3：运行测试验证失败**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py::test_pull_messages_multidevice_floors_after_to_cursor -v
```

Expected：FAIL，`after_message_seq == 0` 而期望 50。

- [ ] **Step 4：修改 `pull_messages` 多设备分支**

`extensions/services/group/service.py:1626-1631` 替换：

```python
            after_msg_seq = params.get("after_message_seq")
            if after_msg_seq is not None:
                after_msg_seq = int(after_msg_seq)
            else:
                after_msg_seq = cursor.last_ack_msg_seq
```

改为：

```python
            after_msg_seq_raw = params.get("after_message_seq")
            if after_msg_seq_raw is not None:
                after_msg_seq = int(after_msg_seq_raw)
                # 静默兜底：客户端显式传值小于 cursor 时抬升，避免误触发全量回溯
                if after_msg_seq < cursor.last_ack_msg_seq:
                    after_msg_seq = cursor.last_ack_msg_seq
            else:
                after_msg_seq = cursor.last_ack_msg_seq
```

- [ ] **Step 5：运行测试验证通过**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py::test_pull_messages_multidevice_floors_after_to_cursor extensions/services/codex-unit/group/test_group_pull_cursor_floor.py::test_pull_messages_multidevice_respects_above_cursor -v
```

Expected：两个测试都 PASS。

- [ ] **Step 6：提交**

```bash
cd D:/modelunion/kite
git add extensions/services/group/service.py extensions/services/codex-unit/group/test_group_pull_cursor_floor.py
git commit -m "fix(group): pull_messages 多设备对 after<cursor 静默抬升

多设备模式下客户端误传 after_message_seq=0 会导致分页回溯整个历史。
在已有 device cursor 的情况下，对显式小于 cursor.last_ack_msg_seq
的值静默抬升到 cursor，保持向前兼容不报错。"
```

---

## Task 4：服务端 - `pull_messages` 单设备 cursor 兜底

**Files:**
- Modify: `extensions/services/group/service.py:1648-1650`（`pull_messages` 单设备分支）
- Test: `extensions/services/codex-unit/group/test_group_pull_cursor_floor.py`（追加）

- [ ] **Step 1：写失败测试 - 单设备 pull_messages 用 member.last_ack_seq 兜底**

追加到测试文件：

```python
@pytest.mark.asyncio
async def test_pull_messages_singledevice_floors_to_member_last_ack(fake_service):
    svc = fake_service
    svc._message_store.get_member_cursor = AsyncMock(return_value={
        "last_ack_seq": 30, "last_pull_at": 0,
        "latest_message_seq": 100, "latest_event_seq": 50,
    })

    await svc.pull_messages({
        "aid": "alice",
        "group_id": "G1",
        "after_message_seq": 0,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_message_seq"] == 30, (
        "单设备误传 0 应抬升到 group_members.last_ack_seq=30"
    )


@pytest.mark.asyncio
async def test_pull_messages_singledevice_respects_above_last_ack(fake_service):
    svc = fake_service
    svc._message_store.get_member_cursor = AsyncMock(return_value={
        "last_ack_seq": 30, "last_pull_at": 0,
        "latest_message_seq": 100, "latest_event_seq": 50,
    })

    await svc.pull_messages({
        "aid": "alice",
        "group_id": "G1",
        "after_message_seq": 60,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_message_seq"] == 60, "高于 last_ack_seq 的值保持不变"


@pytest.mark.asyncio
async def test_pull_messages_singledevice_no_after_uses_last_ack(fake_service):
    svc = fake_service
    svc._message_store.get_member_cursor = AsyncMock(return_value={
        "last_ack_seq": 30, "last_pull_at": 0,
        "latest_message_seq": 100, "latest_event_seq": 50,
    })

    await svc.pull_messages({"aid": "alice", "group_id": "G1"})

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_message_seq"] == 30, "缺省时用 last_ack_seq"
```

- [ ] **Step 2：运行测试验证失败**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py::test_pull_messages_singledevice_floors_to_member_last_ack -v
```

Expected：FAIL，`after_message_seq == 0` 而期望 30。

- [ ] **Step 3：修改 `pull_messages` 单设备分支**

`extensions/services/group/service.py:1648-1650` 替换：

```python
        else:
            # ── 单设备模式：简单游标 ──
            after_msg_seq = max(0, int(params.get("after_message_seq", 0) or 0))
```

改为：

```python
        else:
            # ── 单设备模式：用 group_members.last_ack_seq 作为 cursor floor ──
            member_cursor = await self._message_store.get_member_cursor(
                group_id=group_id, aid=aid,
            )
            last_ack = int(member_cursor.get("last_ack_seq") or 0)
            after_msg_seq_raw = params.get("after_message_seq")
            if after_msg_seq_raw is not None:
                after_msg_seq = max(0, int(after_msg_seq_raw))
                if after_msg_seq < last_ack:
                    after_msg_seq = last_ack  # 静默兜底
            else:
                after_msg_seq = last_ack
```

- [ ] **Step 4：运行测试验证通过**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py -v
```

Expected：所有已添加的测试 PASS。

- [ ] **Step 5：提交**

```bash
cd D:/modelunion/kite
git add extensions/services/group/service.py extensions/services/codex-unit/group/test_group_pull_cursor_floor.py
git commit -m "fix(group): pull_messages 单设备对 after<last_ack_seq 静默抬升

单设备模式原本完全信任客户端传值。现读取 group_members.last_ack_seq
作为 floor，对显式小于该值的请求静默抬升，语义与多设备路径对称。"
```

---

## Task 5：服务端 - `pull_events` 多设备 cursor 兜底

**Files:**
- Modify: `extensions/services/group/service.py:4284-4368`（`pull_events` 多设备分支）
- Test: `extensions/services/codex-unit/group/test_group_pull_cursor_floor.py`（追加）

- [ ] **Step 1：写失败测试 - 多设备 pull_events cursor 抬升**

追加到测试文件：

```python
@pytest.mark.asyncio
async def test_pull_events_multidevice_floors_after_to_cursor(fake_service):
    svc = fake_service
    cursor = MagicMock()
    cursor.last_ack_msg_seq = 0
    cursor.last_ack_event_seq = 25
    cursor.join_msg_seq = 0
    cursor.join_event_seq = 0
    svc._get_or_create_device_cursor = AsyncMock(return_value=cursor)
    # pull_events 用了 _normalize_group_id；补齐
    svc._normalize_group_id = lambda gid: gid

    await svc.pull_events({
        "aid": "alice",
        "group_id": "G1",
        "device_id": "d1",
        "after_event_seq": 0,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_event_seq"] == 25, (
        "多设备 event 误传 0 应抬升到 cursor.last_ack_event_seq=25"
    )


@pytest.mark.asyncio
async def test_pull_events_multidevice_respects_above_cursor(fake_service):
    svc = fake_service
    cursor = MagicMock()
    cursor.last_ack_msg_seq = 0
    cursor.last_ack_event_seq = 25
    cursor.join_msg_seq = 0
    cursor.join_event_seq = 0
    svc._get_or_create_device_cursor = AsyncMock(return_value=cursor)
    svc._normalize_group_id = lambda gid: gid

    await svc.pull_events({
        "aid": "alice",
        "group_id": "G1",
        "device_id": "d1",
        "after_event_seq": 40,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_event_seq"] == 40
```

- [ ] **Step 2：运行测试验证失败**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py::test_pull_events_multidevice_floors_after_to_cursor -v
```

Expected：FAIL。

- [ ] **Step 3：修改 `pull_events` 多设备分支**

`extensions/services/group/service.py:4301-4305` 替换：

```python
            after_event_seq = params.get("after_event_seq")
            if after_event_seq is not None:
                after_event_seq = int(after_event_seq)
            else:
                after_event_seq = cursor.last_ack_event_seq
```

改为：

```python
            after_event_seq_raw = params.get("after_event_seq")
            if after_event_seq_raw is not None:
                after_event_seq = int(after_event_seq_raw)
                # 静默兜底：客户端显式传值小于 cursor 时抬升
                if after_event_seq < cursor.last_ack_event_seq:
                    after_event_seq = cursor.last_ack_event_seq
            else:
                after_event_seq = cursor.last_ack_event_seq
```

- [ ] **Step 4：运行测试验证通过**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py -v
```

Expected：全部 PASS。

- [ ] **Step 5：单设备 event 行为不变性断言**

追加测试：

```python
@pytest.mark.asyncio
async def test_pull_events_singledevice_unchanged(fake_service):
    """单设备 event 无 cursor 源可兜底，行为保持原样。"""
    svc = fake_service
    svc._normalize_group_id = lambda gid: gid

    await svc.pull_events({
        "aid": "alice",
        "group_id": "G1",
        "after_event_seq": 0,
    })

    call = svc._message_store.pull.await_args
    assert call.kwargs["after_event_seq"] == 0, (
        "单设备 event 无兜底源，显式 0 应按字面值执行"
    )
```

运行：

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/test_group_pull_cursor_floor.py::test_pull_events_singledevice_unchanged -v
```

Expected：PASS（行为未修改，直接通过）。

- [ ] **Step 6：提交**

```bash
cd D:/modelunion/kite
git add extensions/services/group/service.py extensions/services/codex-unit/group/test_group_pull_cursor_floor.py
git commit -m "fix(group): pull_events 多设备对 after<cursor 静默抬升

对称补全 event 路径的多设备 cursor 兜底。单设备 event 因
group_members 表无 last_ack_event_seq 字段无法兜底，保留原行为。"
```

---

## Task 6：回归测试 + 集成验证

**Files:** 无代码改动。

- [ ] **Step 1：SDK 全量单元测试**

```bash
cd D:/modelunion/kite/aun-sdk-core/python
python -X utf8 -m pytest tests/unit/ -v --tb=short
```

Expected：通过率与基线一致，无新失败。

- [ ] **Step 2：服务端 group 相关测试**

```bash
cd D:/modelunion/kite
python -X utf8 -m pytest extensions/services/codex-unit/group/ -v --tb=short
```

Expected：本次新增的测试全部 PASS；已有测试保持。

- [ ] **Step 3：docker 环境重建提示（交由用户执行）**

由于 `extensions/services/group/service.py` 的服务端代码打包在 docker 镜像中，单域 / 双域集成测试前需要重新 build。**不要自动执行**，列入交付清单供用户决定时机：

```bash
# 用户手动执行：
cd D:/modelunion/kite/docker-deploy
docker compose -f docker-compose.build.yml build kite sdk-tester
docker compose up -d kite
```

- [ ] **Step 4：最终 git 状态检查**

```bash
cd D:/modelunion/kite
git status
git log --oneline -5
```

Expected：工作树干净；最近 4-5 条提交覆盖本次五个代码 task。

---

## 不做的事（对齐 spec 非目标）

- 不引入 `asyncio.Event` / buffer queue 延迟 publish 路径
- 不推迟 reader 启动
- 不改 `message.pull` / `message.ack` 已有行为
- 不对服务端 P2P `message.pull` 做 cursor 兜底（P2P 已有 `server_ack_seq` retention floor 保护）
- 不触碰 Kernel / Launcher / Watchdog / 核心模块代码
- 不自动执行 docker rebuild 或集成/E2E 测试（用户手动触发）
