#!/usr/bin/env python3
"""Message.ack cursor 推进与幂等语义测试。

测试场景：
  1. A 发消息给 B，B ack
  2. ack_seq 已推进
  3. 重复 ack 保持幂等

使用方法：
  docker exec kite-sdk-tester python /tests/integration_test_message_ack.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT 指向 Docker 挂载的持久化数据目录
"""
import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_message_ack"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

# ---------------------------------------------------------------------------
# 计数
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str):
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} — {reason}")


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _build_test_slot_id(tag: str) -> str:
    return f"message-ack-{tag}-{uuid.uuid4().hex[:12]}"


def _make_client(tag: str = "client") -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    client._test_slot_id = _build_test_slot_id(tag)
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            connect_params = dict(auth)
            slot_id = str(getattr(client, "_test_slot_id", "") or "")
            if slot_id:
                connect_params["slot_id"] = slot_id
            connect_params["auto_reconnect"] = False
            await client.connect(connect_params)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


def _seq_of(msg: dict) -> int:
    return int(msg.get("seq") or 0)


async def _sdk_send(client: AUNClient, to_aid: str, payload: str):
    """发送加密消息"""
    return await client.call("message.send", {
        "to": to_aid,
        "payload": {"type": "text", "text": payload},
        "encrypt": True
    })


def _subscribe_push_after(client: AUNClient, from_aid: str, *, after_seq: int = 0):
    inbox = []
    event = asyncio.Event()

    def handler(data):
        if not isinstance(data, dict):
            return
        if data.get("from") != from_aid:
            return
        if _seq_of(data) <= after_seq:
            return
        inbox.append(data)
        event.set()

    sub = client.on("message.received", handler)
    return inbox, event, sub


async def _wait_for_messages_after(
    client: AUNClient,
    from_aid: str,
    *,
    after_seq: int = 0,
    min_count: int = 1,
    timeout: float = 5.0,
    inbox: list[dict] | None = None,
    event: asyncio.Event | None = None,
):
    """等待已订阅的推送消息，数量不足时再主动拉取兜底。"""
    own_sub = None
    if inbox is None or event is None:
        inbox, event, own_sub = _subscribe_push_after(client, from_aid, after_seq=after_seq)

    deadline = asyncio.get_running_loop().time() + timeout
    while len(inbox) < min_count:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        event.clear()
        if len(inbox) >= min_count:
            break
        try:
            await asyncio.wait_for(event.wait(), timeout=remaining)
        except asyncio.TimeoutError:
            break

    if own_sub is not None:
        own_sub.unsubscribe()

    all_msgs = list(inbox)
    if len(all_msgs) < min_count:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": 50})
        all_msgs.extend(m for m in result.get("messages", []) if m.get("from") == from_aid)

    by_seq = {}
    for msg in all_msgs:
        seq = _seq_of(msg)
        if seq > after_seq:
            by_seq[seq] = msg
    return [by_seq[seq] for seq in sorted(by_seq)]


async def _sdk_recv_push_after(client: AUNClient, from_aid: str, *, after_seq: int = 0, timeout: float = 5.0):
    """等待推送或主动拉取"""
    return await _wait_for_messages_after(
        client, from_aid, after_seq=after_seq, min_count=1, timeout=timeout,
    )


async def _current_max_seq(client: AUNClient, *, limit: int = 200) -> int:
    """获取当前最大 seq，用于建立 baseline。

    V2 pull 的翻页依据是 raw 行元数据，不是解密后的 messages 数量。
    """
    after_seq = 0
    max_seq = 0
    for _ in range(100):
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": limit})
        latest_seq = int(result.get("latest_seq") or 0)
        server_ack_seq = int(result.get("server_ack_seq") or 0)
        raw_count = int(result.get("raw_count") or 0)
        max_seq = max(max_seq, server_ack_seq, latest_seq)
        msgs = result.get("messages", [])
        for msg in msgs:
            max_seq = max(max_seq, _seq_of(msg))
        next_after = max(max_seq, after_seq)
        if raw_count <= 0 or next_after <= after_seq:
            return max_seq
        after_seq = next_after
    return max_seq


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def test_message_ack_basic():
    """测试基本 ack 功能"""
    alice = _make_client("basic-alice")
    bob = _make_client("basic-bob")

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq，避免拉取历史消息
        baseline = await _current_max_seq(bob)
        inbox, event, sub = _subscribe_push_after(bob, _ALICE_AID, after_seq=baseline)

        # 1. Alice 发送消息给 Bob
        try:
            await _sdk_send(alice, _BOB_AID, "test_ack_message")
            msgs = await _wait_for_messages_after(
                bob, _ALICE_AID, after_seq=baseline, timeout=3.0, inbox=inbox, event=event,
            )
        finally:
            sub.unsubscribe()
        if not msgs:
            _fail("message_ack_basic", "Bob 未收到消息")
            return

        msg_seq = _seq_of(msgs[0])
        print(f"  [INFO] Bob 收到消息 seq={msg_seq}")

        # 3. Bob ack 消息
        ack_result = await bob.call("message.ack", {"seq": msg_seq})

        # 4. 验证 ack 结果（ack_seq 是累积值，可能 >= msg_seq）
        if not ack_result.get("success"):
            _fail("message_ack_basic", f"ack 失败: {ack_result}")
            return

        if not (ack_result.get("ack_seq") >= msg_seq):
            _fail("message_ack_basic", f"ack_seq 不匹配: 期望 >= {msg_seq}, 实际 {ack_result.get('ack_seq')}")
            return

        _ok("message_ack_basic")

    finally:
        await alice.close()
        await bob.close()


async def test_message_ack_idempotent():
    """测试重复 ack 的幂等返回语义"""
    alice = _make_client("idempotent-alice")
    bob = _make_client("idempotent-bob")

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq
        baseline = await _current_max_seq(bob)
        inbox, event, sub = _subscribe_push_after(bob, _ALICE_AID, after_seq=baseline)

        # 1. Alice 发送消息给 Bob
        try:
            await _sdk_send(alice, _BOB_AID, "test_partial_success")
            msgs = await _wait_for_messages_after(
                bob, _ALICE_AID, after_seq=baseline, timeout=3.0, inbox=inbox, event=event,
            )
        finally:
            sub.unsubscribe()
        if not msgs:
            _fail("message_ack_idempotent", "Bob 未收到消息")
            return

        msg_seq = _seq_of(msgs[0])
        print(f"  [INFO] Bob 收到消息 seq={msg_seq}")

        # 3. Bob ack 消息
        ack_result = await bob.call("message.ack", {"seq": msg_seq})
        print(f"  [INFO] ack 结果: {ack_result}")

        # 4. 验证 ack 结果包含必要字段
        if not ack_result.get("success"):
            _fail("message_ack_idempotent", f"ack 失败: {ack_result}")
            return

        if "ack_seq" not in ack_result:
            _fail("message_ack_idempotent", "ack 结果缺少 ack_seq 字段")
            return

        # 5. 再次 ack 同一 seq，验证幂等性（ack_seq 是累积值，可能 >= msg_seq）
        ack_result2 = await bob.call("message.ack", {"seq": msg_seq})
        if not ack_result2.get("success"):
            _fail("message_ack_idempotent", f"重复 ack 失败: {ack_result2}")
            return

        if not (ack_result2.get("ack_seq") >= msg_seq):
            _fail("message_ack_idempotent", f"重复 ack 的 ack_seq 不匹配: 期望 >= {msg_seq}, 实际 {ack_result2.get('ack_seq')}")
            return

        _ok("message_ack_idempotent")

    finally:
        await alice.close()
        await bob.close()


async def test_message_ack_sequence():
    """测试 ack 序列推进"""
    alice = _make_client("sequence-alice")
    bob = _make_client("sequence-bob")

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 0. 获取 baseline seq
        baseline = await _current_max_seq(bob)
        inbox, event, sub = _subscribe_push_after(bob, _ALICE_AID, after_seq=baseline)

        # 1. Alice 发送 3 条消息给 Bob
        try:
            await _sdk_send(alice, _BOB_AID, "msg1")
            await asyncio.sleep(0.2)
            await _sdk_send(alice, _BOB_AID, "msg2")
            await asyncio.sleep(0.2)
            await _sdk_send(alice, _BOB_AID, "msg3")
            msgs = await _wait_for_messages_after(
                bob,
                _ALICE_AID,
                after_seq=baseline,
                min_count=3,
                timeout=5.0,
                inbox=inbox,
                event=event,
            )
        finally:
            sub.unsubscribe()
        if len(msgs) < 3:
            _fail("message_ack_sequence", f"Bob 未收到足够消息: 期望 3 条, 实际 {len(msgs)} 条")
            return

        seqs = [_seq_of(m) for m in msgs[:3]]
        print(f"  [INFO] Bob 收到消息 seqs={seqs}")

        # 3. Bob 按顺序 ack（ack_seq 是累积值，可能 >= 当前 seq）
        for seq in seqs:
            ack_result = await bob.call("message.ack", {"seq": seq})
            if not ack_result.get("success"):
                _fail("message_ack_sequence", f"ack seq={seq} 失败: {ack_result}")
                return
            if not (ack_result.get("ack_seq") >= seq):
                _fail("message_ack_sequence", f"ack_seq 不匹配: 期望 >= {seq}, 实际 {ack_result.get('ack_seq')}")
                return

        # 4. 验证最终 ack_seq >= 最后一条消息的 seq
        final_ack = await bob.call("message.ack", {"seq": seqs[-1]})
        if not (final_ack.get("ack_seq") >= seqs[-1]):
            _fail("message_ack_sequence", f"最终 ack_seq 不匹配: 期望 >= {seqs[-1]}, 实际 {final_ack.get('ack_seq')}")
            return

        _ok("message_ack_sequence")

    finally:
        await alice.close()
        await bob.close()


async def main():
    print("=" * 60)
    print("Message.ack cursor 推进与幂等语义测试")
    print("=" * 60)

    await test_message_ack_basic()
    await test_message_ack_idempotent()
    await test_message_ack_sequence()

    print()
    print(f"通过: {_passed}, 失败: {_failed}")
    if _errors:
        print("\n失败详情:")
        for err in _errors:
            print(f"  - {err}")

    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
