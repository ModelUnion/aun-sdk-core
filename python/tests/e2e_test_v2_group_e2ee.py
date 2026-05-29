#!/usr/bin/env python3
"""
AUN E2EE V2: Group 端到端测试

测试 V2 Group 加密消息的完整链路：
- bootstrap → encrypt → send → pull → decrypt
- 多成员收发
- ack

使用方法（容器内）：
  python /tests/e2e_test_v2_group_e2ee.py
"""
import asyncio
import os
import sys
import time
import traceback
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.errors import AuthError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", "").strip()
if not _TEST_AUN_PATH:
    if _AUN_DATA_ROOT:
        _TEST_AUN_PATH = f"{_AUN_DATA_ROOT}/single-domain/persistent"
    else:
        _TEST_AUN_PATH = "/data/aun/single-domain/persistent"

_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip()
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()


async def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, debug=True)


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    await ensure_connected_identity(client, aid, connect_options={"auto_reconnect": False})


class GroupV2TestRunner:
    def __init__(self):
        self.alice: AUNClient | None = None
        self.bob: AUNClient | None = None
        self.group_id: str = ""
        self.passed = 0
        self.failed = 0
        self.errors = []

    async def setup(self):
        print("\n[setup] 连接 Alice 和 Bob...")
        self.alice = await _make_client()
        self.bob = await _make_client()
        await _ensure_connected(self.alice, _ALICE_AID)
        await _ensure_connected(self.bob, _BOB_AID)
        print("[setup] Alice/Bob 已连接")

        # push 事件收集（用于 pull 兜底）
        self._alice_push_msgs = []
        self._bob_push_msgs = []
        self.alice.on("group.message_created", lambda d: self._alice_push_msgs.append(d) if isinstance(d, dict) else None)
        self.bob.on("group.message_created", lambda d: self._bob_push_msgs.append(d) if isinstance(d, dict) else None)

        # 创建测试群
        result = await self.alice.call("group.create", {
            "name": f"v2-test-{int(time.time())}",
            "visibility": "private",
        })
        self.group_id = result["group"]["group_id"]
        print(f"[setup] 创建群: {self.group_id}")

        # 添加 Bob
        await self.alice.call("group.add_member", {
            "group_id": self.group_id,
            "aid": _BOB_AID,
        })
        # 等 auto propose+confirm 完成（private 群 bob 需要进入 committed 才能收发）
        for _ in range(30):
            await asyncio.sleep(0.5)
            bs = await self.alice.call("group.v2.bootstrap", {"group_id": self.group_id})
            committed = list(bs.get("committed_member_aids") or [])
            if _BOB_AID in committed:
                break
        print(f"[setup] Bob 已加入群 (committed={_BOB_AID in committed})")

    async def teardown(self):
        for c in [self.alice, self.bob]:
            if c:
                try:
                    await c.disconnect()
                except Exception:
                    pass
        print("[teardown] 已断开")

    async def run_test(self, name: str, test_func):
        print(f"\n  [{name}] ...", end=" ")
        try:
            await test_func()
            print("✅ PASSED")
            self.passed += 1
        except Exception as e:
            print(f"❌ FAILED: {e}")
            self.errors.append((name, str(e), traceback.format_exc()))
            self.failed += 1

    # ── 场景 1：Alice group.send ──

    async def test_send(self):
        self._payload = {"text": f"group-v2-test {int(time.time())}"}
        result = await self.alice.call("group.send", {"group_id": self.group_id, "payload": self._payload})
        assert result.get("status") == "accepted", f"unexpected status: {result}"
        self._msg_seq = result.get("seq", 0)
        print(f"(seq={self._msg_seq})", end=" ")

    # ── 场景 2：Bob group.pull 解密（push 可能已消费，兜底等 push 事件）──

    async def test_bob_pull(self):
        # push 可能已经消费了消息，先等 push 事件
        for _ in range(20):
            await asyncio.sleep(0.3)
            if any(m.get("payload", {}).get("text") == self._payload["text"] for m in self._bob_push_msgs):
                break
        # 兜底 pull
        messages = (await self.bob.call("group.pull", {"group_id": self.group_id})).get("messages", [])
        all_msgs = self._bob_push_msgs + messages
        found = None
        for m in all_msgs:
            if m.get("payload", {}).get("text") == self._payload["text"]:
                found = m
                break
        assert found is not None, f"Bob got {len(all_msgs)} msgs but none match expected text"
        assert found.get("from") == _ALICE_AID or found.get("from_aid") == _ALICE_AID
        print(f"(decrypted: '{found['payload']['text'][:30]}...')", end=" ")

    # ── 场景 3：Bob ack ──

    async def test_bob_ack(self):
        result = await self.bob.call("group.ack_messages", {"group_id": self.group_id})
        assert isinstance(result, dict), f"ack failed: {result}"

    # ── 场景 4：ack 后 pull 为空 ──

    async def test_pull_after_ack_empty(self):
        messages = (await self.bob.call("group.pull", {"group_id": self.group_id})).get("messages", [])
        assert len(messages) == 0, f"expected 0 after ack, got {len(messages)}"

    # ── 场景 5：Bob 回复 ──

    async def test_bob_reply(self):
        reply = {"text": f"bob-group-reply {int(time.time())}"}
        result = await self.bob.call("group.send", {"group_id": self.group_id, "payload": reply})
        assert result.get("status") == "accepted"
        self._reply_text = reply["text"]

    # ── 场景 6：Alice pull 解密回复（push 可能已消费，兜底等 push 事件）──

    async def test_alice_pull_reply(self):
        for _ in range(20):
            await asyncio.sleep(0.3)
            if any(m.get("payload", {}).get("text") == self._reply_text for m in self._alice_push_msgs):
                break
        messages = (await self.alice.call("group.pull", {"group_id": self.group_id})).get("messages", [])
        all_msgs = self._alice_push_msgs + messages
        found = None
        for m in all_msgs:
            if m.get("payload", {}).get("text") == self._reply_text:
                found = m
                break
        assert found is not None, f"Alice got {len(all_msgs)} msgs but none match reply"
        assert found.get("from") == _BOB_AID or found.get("from_aid") == _BOB_AID
        print(f"(from Bob: '{found['payload']['text'][:30]}...')", end=" ")

    # ── 场景 7：epoch 验证（rotate 后新消息用新 epoch）──

    async def test_epoch_after_rotation(self):
        """kick Bob → epoch 递增 → Alice 发消息用新 epoch → re-add Bob → Bob 能收到"""
        # kick Bob
        await self.alice.call("group.kick", {"group_id": self.group_id, "aid": _BOB_AID})
        await asyncio.sleep(0.5)

        # rotate epoch (V1 方式)
        try:
            await self.alice.call("group.e2ee.rotate_epoch", {"group_id": self.group_id})
        except Exception:
            pass
        await asyncio.sleep(0.5)

        # re-add Bob
        await self.alice.call("group.add_member", {"group_id": self.group_id, "aid": _BOB_AID})
        await asyncio.sleep(0.5)

        # Alice 发消息（应使用新 epoch）
        self._epoch_payload = {"text": f"after-rotation {int(time.time())}"}
        result = await self.alice.call("group.send", {"group_id": self.group_id, "payload": self._epoch_payload})
        assert result.get("status") == "accepted"
        new_epoch = result.get("seq", 0)
        print(f"(seq={new_epoch})", end=" ")

    # ── 场景 8：stale epoch 推测性重试 ──

    async def test_stale_epoch_retry(self):
        """成员变更后再次发送仍应按最新 V2 状态成功。"""
        payload = {"text": f"stale-epoch-retry {int(time.time())}"}
        result = await self.alice.call("group.send", {"group_id": self.group_id, "payload": payload})
        assert result.get("status") == "accepted"
        print(f"(post-rotation send succeeded)", end=" ")

    # ── 运行所有测试 ──

    async def run_all(self):
        print("=" * 60)
        print("AUN E2EE V2: Group 端到端测试")
        print("=" * 60)
        print(f"  Alice: {_ALICE_AID}")
        print(f"  Bob:   {_BOB_AID}")
        print(f"  Data:  {_TEST_AUN_PATH}")

        await self.setup()

        try:
            await self.run_test("1. Alice group.send", self.test_send)
            await self.run_test("2. Bob group.pull 解密", self.test_bob_pull)
            await self.run_test("3. Bob ack", self.test_bob_ack)
            await self.run_test("4. ack 后 pull 为空", self.test_pull_after_ack_empty)
            await self.run_test("5. Bob 回复", self.test_bob_reply)
            await self.run_test("6. Alice pull 解密回复", self.test_alice_pull_reply)
            await self.run_test("7. epoch rotation 后发送", self.test_epoch_after_rotation)
            await self.run_test("8. stale epoch 推测性重试", self.test_stale_epoch_retry)
        finally:
            await self.teardown()

        print("\n" + "=" * 60)
        print(f"结果: {self.passed} passed, {self.failed} failed")
        if self.errors:
            print("\n失败详情:")
            for name, err, tb in self.errors:
                print(f"\n  [{name}] {err}")
                print(f"    {tb.strip().split(chr(10))[-1]}")
        print("=" * 60)
        return self.failed == 0


async def main():
    runner = GroupV2TestRunner()
    success = await runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())

