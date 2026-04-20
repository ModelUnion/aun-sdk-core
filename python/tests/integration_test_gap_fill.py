#!/usr/bin/env python3
"""Payload gap 真实补洞测试 — 对应 P1-7 修复。

测试场景：
  1. P2P：B 错过 seq=3/4，服务端 push seq=5（带 payload），SDK 自动 fill gap
  2. Group：同理，群消息带 payload 的 push 触发 group gap fill
  3. 最终 B 拿到完整消息序列，顺序正确

使用方法：
  docker exec kite-sdk-tester python /tests/integration_test_gap_fill.py

前置条件：
  - Docker 单域环境运行中
  - AUN_DATA_ROOT 指向 Docker 挂载的持久化数据目录
"""
import asyncio
import os
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_gap_fill"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CAROL_AID = os.environ.get("AUN_TEST_CAROL_AID", f"carol.{_ISSUER}").strip()

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

def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return aid


def _seq_of(msg: dict) -> int:
    return int(msg.get("seq") or 0)


async def _sdk_send(client: AUNClient, to_aid: str, payload: str):
    """发送加密消息"""
    return await client.call("message.send", {
        "to": to_aid,
        "payload": payload,
        "encrypt": True
    })


async def _sdk_recv_push_after(client: AUNClient, from_aid: str, *, after_seq: int = 0, timeout: float = 5.0):
    """等待推送或主动拉取"""
    inbox = []
    event = asyncio.Event()

    def handler(data):
        if data.get("from") != from_aid:
            return
        if _seq_of(data) <= after_seq:
            return
        inbox.append(data)
        event.set()

    sub = client.on("message.received", handler)
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    sub.unsubscribe()

    if not inbox:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": 50})
        inbox.extend(m for m in result.get("messages", []) if m.get("from") == from_aid)

    return sorted(inbox, key=_seq_of)


async def _current_max_seq(client: AUNClient, *, limit: int = 200) -> int:
    """获取当前最大 seq"""
    after_seq = 0
    max_seq = 0
    while True:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": limit})
        msgs = result.get("messages", [])
        if not msgs:
            return max_seq
        for msg in msgs:
            max_seq = max(max_seq, _seq_of(msg))
        if len(msgs) < limit:
            return max_seq
        after_seq = max_seq


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def test_p2p_payload_gap_fill():
    """测试 P2P 消息 payload gap 自动补洞"""
    alice = _make_client()
    bob = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)

        # 获取基线 seq，避免历史消息干扰
        baseline_seq = await _current_max_seq(bob)
        print(f"  [INFO] 基线 seq={baseline_seq}")

        # 1. Alice 发送 5 条消息给 Bob
        await _sdk_send(alice, _BOB_AID, "msg1")
        await asyncio.sleep(0.3)
        await _sdk_send(alice, _BOB_AID, "msg2")
        await asyncio.sleep(0.3)
        await _sdk_send(alice, _BOB_AID, "msg3")
        await asyncio.sleep(0.3)
        await _sdk_send(alice, _BOB_AID, "msg4")
        await asyncio.sleep(0.3)
        await _sdk_send(alice, _BOB_AID, "msg5")

        # 2. 等待服务端处理
        await asyncio.sleep(2.0)

        # 3. Bob 拉取基线之后的所有消息
        all_msgs = await _sdk_recv_push_after(bob, _ALICE_AID, after_seq=baseline_seq, timeout=3.0)

        # 4. 验证：应该收到 5 条消息，seq 连续
        if len(all_msgs) < 5:
            _fail("p2p_payload_gap_fill", f"期望至少 5 条消息，实际 {len(all_msgs)} 条")
            return

        # 取最后 5 条（本次发送的）
        recent_msgs = all_msgs[-5:]
        seqs = [_seq_of(m) for m in recent_msgs]
        first_seq = seqs[0]
        expected_seqs = list(range(first_seq, first_seq + 5))
        if seqs != expected_seqs:
            _fail("p2p_payload_gap_fill", f"seq 不连续：期望 {expected_seqs}，实际 {seqs}")
            return

        payloads = [m.get("payload") for m in recent_msgs]
        expected_payloads = ["msg1", "msg2", "msg3", "msg4", "msg5"]
        if payloads != expected_payloads:
            _fail("p2p_payload_gap_fill", f"payload 不匹配：期望 {expected_payloads}，实际 {payloads}")
            return

        _ok("p2p_payload_gap_fill")

    finally:
        await alice.close()
        await bob.close()


async def test_group_payload_gap_fill():
    """测试群消息 payload gap 自动补洞"""
    alice = _make_client()
    bob = _make_client()
    carol = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)
        await _ensure_connected(carol, _CAROL_AID)

        # 1. Alice 创建群组并添加成员
        group_result = await alice.call("group.create", {
            "name": "Gap Fill Test Group",
        })
        group_id = (group_result.get("group", {}) or {}).get("group_id") or group_result.get("group_id")
        print(f"  [INFO] 创建群组 {group_id}")

        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOB_AID})
        await alice.call("group.add_member", {"group_id": group_id, "aid": _CAROL_AID})

        await asyncio.sleep(2.0)  # 等待成员同步 + E2EE 密钥分发

        # 2. Alice 发送 5 条群消息（不加密，避免 E2EE epoch 分发延迟问题）
        for i in range(1, 6):
            await alice.call("group.send", {
                "group_id": group_id,
                "payload": f"group_msg{i}",
                "encrypt": False
            })
            await asyncio.sleep(0.3)

        # 3. 等待服务端处理
        await asyncio.sleep(2.0)

        # 4. Bob 拉取所有群消息（直接用 transport 绕过 E2EE 过滤）
        all_group_msgs = await bob._transport.call("group.pull", {"group_id": group_id, "after_seq": 0, "limit": 50})
        all_msgs = all_group_msgs.get("messages", [])

        # 5. 验证：应该收到至少 5 条消息
        if len(all_msgs) < 5:
            _fail("group_payload_gap_fill", f"期望至少 5 条消息，实际 {len(all_msgs)} 条")
            return

        # 过滤出 Alice 发送的消息（群消息用 sender_aid 字段）
        alice_msgs = [m for m in all_msgs if m.get("sender_aid") == _ALICE_AID or m.get("from") == _ALICE_AID]
        if len(alice_msgs) < 5:
            _fail("group_payload_gap_fill", f"期望 Alice 至少 5 条消息，实际 {len(alice_msgs)} 条")
            return

        # 取最后 5 条
        recent_msgs = alice_msgs[-5:]
        seqs = [_seq_of(m) for m in recent_msgs]
        first_seq = seqs[0]
        expected_seqs = list(range(first_seq, first_seq + 5))
        if seqs != expected_seqs:
            _fail("group_payload_gap_fill", f"seq 不连续：期望 {expected_seqs}，实际 {seqs}")
            return

        payloads = [m.get("payload") for m in recent_msgs]
        expected_payloads = ["group_msg1", "group_msg2", "group_msg3", "group_msg4", "group_msg5"]
        if payloads != expected_payloads:
            _fail("group_payload_gap_fill", f"payload 不匹配：期望 {expected_payloads}，实际 {payloads}")
            return

        _ok("group_payload_gap_fill")

    finally:
        await alice.close()
        await bob.close()
        await carol.close()


async def main():
    print("=" * 60)
    print("Payload Gap 真实补洞测试")
    print("=" * 60)

    await test_p2p_payload_gap_fill()
    await test_group_payload_gap_fill()

    print()
    print(f"通过: {_passed}, 失败: {_failed}")
    if _errors:
        print("\n失败详情:")
        for err in _errors:
            print(f"  - {err}")

    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
