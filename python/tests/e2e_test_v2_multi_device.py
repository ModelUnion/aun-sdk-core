#!/usr/bin/env python3
"""
AUN E2EE V2: 多设备 + Self-Sync Docker E2E 测试

参照 V1 integration_test_e2ee.py 的多设备模式：
- 每个"设备"使用独立的 aun_path 目录（含独立 .device_id）
- 通过 _copy_identity_tree 复制身份到隔离目录

使用方法（容器内）：
  python /tests/e2e_test_v2_multi_device.py
"""
import asyncio
import os
import re
import shutil
import sys
import time
import traceback
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.config import get_device_id
from aun_core.errors import AuthError, RateLimitError


# ── 环境配置 ──────────────────────────────────────────────────

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


# ── 多设备辅助（参照 V1 integration_test_e2ee.py） ──────────────

def _single_domain_device_root(tag: str) -> Path:
    base = Path(_TEST_AUN_PATH)
    parent = base.parent if base.name else base
    root = parent / "v2-multi-device" / tag
    root.mkdir(parents=True, exist_ok=True)
    return root


def _copy_identity_tree(source_root: Path, target_root: Path, aid: str) -> None:
    source_identity = source_root / "AIDs" / aid
    if not source_identity.exists():
        raise RuntimeError(f"identity source missing: {source_identity}")
    source_seed = source_root / ".seed"
    target_root.mkdir(parents=True, exist_ok=True)
    if source_seed.exists():
        shutil.copy2(source_seed, target_root / ".seed")
    (target_root / "AIDs").mkdir(parents=True, exist_ok=True)
    _skip_suffixes = {".db-shm", ".db-wal"}
    shutil.copytree(
        source_identity, target_root / "AIDs" / aid, dirs_exist_ok=True,
        ignore=lambda d, files: [f for f in files if any(f.endswith(s) for s in _skip_suffixes)],
    )


def _ensure_unique_device_id(tag: str) -> str:
    root = _single_domain_device_root(tag)
    device_id_path = root / ".device_id"
    # 每次测试生成新的 device_id，确保隔离
    new_id = f"v2md-{tag}-{uuid.uuid4().hex[:8]}"
    device_id_path.write_text(new_id, encoding="utf-8")
    return new_id


def _prepare_isolated_identity(tag: str, aid: str) -> Path:
    target_root = _single_domain_device_root(tag)
    _copy_identity_tree(Path(_TEST_AUN_PATH), target_root, aid)
    _ensure_unique_device_id(tag)
    return target_root


def _make_isolated_client(tag: str) -> AUNClient:
    root = _single_domain_device_root(tag)
    client = AUNClient({"aun_path": str(root)}, debug=True)
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    """认证 + 连接"""
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            connect_params = dict(auth)
            connect_params["auto_reconnect"] = False
            await client.connect(connect_params)
            return
        except Exception as exc:
            last_error = exc
            if attempt >= 3:
                break
            if "invalid_token" in str(exc):
                import sqlite3
                db_path = str(Path(client.config["aun_path"]) / "AIDs" / aid / "aun.db")
                try:
                    conn = sqlite3.connect(db_path)
                    conn.execute("DELETE FROM instance_state")
                    conn.execute("DELETE FROM tokens")
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


# ── 测试场景 ──────────────────────────────────────────────────

class MultiDeviceTestRunner:
    """多设备 + Self-Sync E2E 测试"""

    def __init__(self):
        self.alice_main: AUNClient | None = None
        self.alice_sync: AUNClient | None = None
        self.bob_phone: AUNClient | None = None
        self.passed = 0
        self.failed = 0
        self.errors = []

    async def setup(self):
        print("\n[setup] 准备隔离身份目录...")
        _prepare_isolated_identity("alice-main", _ALICE_AID)
        _prepare_isolated_identity("alice-sync", _ALICE_AID)
        _prepare_isolated_identity("bob-phone", _BOB_AID)

        self.alice_main = _make_isolated_client("alice-main")
        self.alice_sync = _make_isolated_client("alice-sync")
        self.bob_phone = _make_isolated_client("bob-phone")

        print("[setup] 连接 Alice(main), Alice(sync), Bob(phone)...")
        await _ensure_connected(self.alice_main, _ALICE_AID)
        await _ensure_connected(self.alice_sync, _ALICE_AID)
        await _ensure_connected(self.bob_phone, _BOB_AID)

        am_dev = self.alice_main._device_id
        as_dev = self.alice_sync._device_id
        bp_dev = self.bob_phone._device_id
        print(f"[setup] Alice main: device={am_dev}, V2={self.alice_main._v2_session is not None}")
        print(f"[setup] Alice sync: device={as_dev}, V2={self.alice_sync._v2_session is not None}")
        print(f"[setup] Bob phone:  device={bp_dev}, V2={self.bob_phone._v2_session is not None}")
        assert am_dev != as_dev, "Alice devices should have different IDs"

        # 清空旧 inbox 并重置 SeqTracker
        # 注：isolated identity 是从 alice/bob 主目录拷贝的，包含 seq_tracker 持久化数据，
        # 新 device 启动时会恢复到旧 device 的 contiguous_seq，导致 push 触发的 pull 用错误的 after_seq
        for client, name in [
            (self.alice_main, "alice-main"),
            (self.alice_sync, "alice-sync"),
            (self.bob_phone, "bob-phone"),
        ]:
            try:
                # 重置 SeqTracker（隔离设备从 0 开始）
                aid = client._aid
                if aid:
                    ns = f"p2p:{aid}"
                    client._seq_tracker = type(client._seq_tracker)()
                    client._seq_tracker.restore_state({ns: 0})
                # 清空 V2 inbox 中本设备的旧消息
                result = await client.call("message.v2.pull", {"after_seq": 0, "limit": 200})
                msgs = result.get("messages", [])
                if msgs:
                    max_seq = max(m["seq"] for m in msgs)
                    await client.call("message.v2.ack", {"up_to_seq": max_seq})
                    print(f"  [setup] {name}: acked {len(msgs)} old V2 messages (up_to_seq={max_seq})")
            except Exception as e:
                print(f"  [setup] {name}: cleanup ok: {e}")

        # 收集 push 自动接收的消息
        self._main_msgs = []
        self._sync_msgs = []
        self._bob_msgs = []
        self.alice_main.on("message.received", lambda d: self._main_msgs.append(d))
        self.alice_sync.on("message.received", lambda d: self._sync_msgs.append(d))
        self.bob_phone.on("message.received", lambda d: self._bob_msgs.append(d))

    async def teardown(self):
        for c in [self.alice_main, self.alice_sync, self.bob_phone]:
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

    # ── 场景 1：两个设备各自注册独立 V2 session ──

    async def test_independent_sessions(self):
        """两个设备共享 AID 身份（IK 相同），但 SPK 必须独立"""
        s1 = self.alice_main._v2_session
        s2 = self.alice_sync._v2_session
        assert s1 is not None and s2 is not None
        # IK = AID 身份密钥，多设备共享 AID 必然相同
        assert s1._ik_pub_der == s2._ik_pub_der, "IK should be shared across devices of the same AID"
        # SPK 是每设备独立生成的 Signed Pre-Key
        assert s1._spk_id != s2._spk_id, "SPK should differ per device"

    # ── 场景 2：Alice(main) 发给 Bob，Bob 能解密 ──

    async def test_send_to_bob(self):
        """Alice(main) send_v2 给 Bob"""
        # 清空收集器，确保下面的 push 是当前消息的
        self._bob_msgs.clear()
        self._sync_msgs.clear()
        self._payload = {"text": f"multi-dev-v2 {int(time.time())}"}
        # 诊断：确认 bootstrap 能看到 Bob 的设备
        bs = await self.alice_main.call("message.v2.bootstrap", {"peer_aid": _BOB_AID})
        print(f"\n    [diag] bootstrap Bob: {len(bs.get('peer_devices', []))} devices", end="")
        for d in bs.get("peer_devices", []):
            print(f"\n      device_id={d.get('owner_device_id', d.get('device_id', '?'))}", end="")
        result = await self.alice_main.call("message.send", {"to": _BOB_AID, "payload": self._payload})
        assert result.get("status") == "accepted" or result.get("message_id")
        print(f"\n    (msg_id={result.get('message_id', '')[:12]}...)", end=" ")

    async def test_bob_decrypt(self):
        """Bob 收到（push 或 pull）"""
        expected_text = self._payload["text"]
        for _ in range(30):
            await asyncio.sleep(0.2)
            for m in self._bob_msgs:
                if m.get("payload", {}).get("text") == expected_text and m.get("from") == _ALICE_AID:
                    print(f"(Bob: '{m['payload']['text'][:25]}...')", end=" ")
                    return
        # push 没到，尝试 pull
        msgs = (await self.bob_phone.call("message.pull", {})).get("messages", [])
        for m in msgs:
            if m.get("payload", {}).get("text") == expected_text:
                print(f"(Bob via pull: '{m['payload']['text'][:25]}...')", end=" ")
                return
        raise AssertionError(f"Bob got 0 matching messages (expected text='{expected_text[:30]}...')")

    # ── 场景 3：Alice(sync) self-sync 解密 ──

    async def test_self_sync_decrypt(self):
        """Alice(sync) 收到 main 发出的消息"""
        expected_text = self._payload["text"]
        for _ in range(30):
            await asyncio.sleep(0.2)
            for m in self._sync_msgs:
                if m.get("payload", {}).get("text") == expected_text and m.get("from") == _ALICE_AID:
                    print(f"(sync: '{m['payload']['text'][:25]}...')", end=" ")
                    return
        msgs = (await self.alice_sync.call("message.pull", {})).get("messages", [])
        for m in msgs:
            if m.get("payload", {}).get("text") == expected_text:
                print(f"(sync via pull: '{m['payload']['text'][:25]}...')", end=" ")
                return
        raise AssertionError(f"Alice sync got 0 matching messages (self-sync failed)")

    # ── 场景 4：Bob 回复，Alice 两个设备都收到 ──

    async def test_bob_reply_both_devices(self):
        """Bob 回复 Alice，两个设备都能解密"""
        await self.alice_main.call("message.ack", {})
        await self.alice_sync.call("message.ack", {})
        self._main_msgs.clear()
        self._sync_msgs.clear()

        reply = {"text": f"bob-reply-v2 {int(time.time())}"}
        await self.bob_phone.call("message.send", {"to": _ALICE_AID, "payload": reply})

        expected = reply["text"]

        def _has(msgs):
            return any(m.get("payload", {}).get("text") == expected for m in msgs)

        for _ in range(30):
            await asyncio.sleep(0.2)
            if _has(self._main_msgs) and _has(self._sync_msgs):
                break

        # 兜底
        if not _has(self._main_msgs):
            for m in (await self.alice_main.call("message.pull", {})).get("messages", []):
                if m.get("payload", {}).get("text") == expected:
                    self._main_msgs.append(m)
                    break
        if not _has(self._sync_msgs):
            for m in (await self.alice_sync.call("message.pull", {})).get("messages", []):
                if m.get("payload", {}).get("text") == expected:
                    self._sync_msgs.append(m)
                    break

        assert _has(self._main_msgs), "Alice main got 0"
        assert _has(self._sync_msgs), "Alice sync got 0"
        print(f"(both devices got reply)", end=" ")

    # ── 场景 5：sync 设备发消息，main 也能 self-sync ──

    async def test_sync_send_main_receives(self):
        """Alice(sync) 发给 Bob，Alice(main) 也能 self-sync"""
        await self.alice_main.call("message.ack", {})
        await self.alice_sync.call("message.ack", {})
        await self.bob_phone.call("message.ack", {})
        self._main_msgs.clear()
        self._sync_msgs.clear()
        self._bob_msgs.clear()

        payload = {"text": f"from-sync {int(time.time())}"}
        result = await self.alice_sync.call("message.send", {"to": _BOB_AID, "payload": payload})
        assert result.get("status") == "accepted" or result.get("message_id")

        expected = payload["text"]

        def _has(msgs):
            return any(m.get("payload", {}).get("text") == expected for m in msgs)

        for _ in range(30):
            await asyncio.sleep(0.2)
            if _has(self._main_msgs) and _has(self._bob_msgs):
                break

        if not _has(self._main_msgs):
            for m in (await self.alice_main.call("message.pull", {})).get("messages", []):
                if m.get("payload", {}).get("text") == expected:
                    self._main_msgs.append(m)
                    break
        if not _has(self._bob_msgs):
            for m in (await self.bob_phone.call("message.pull", {})).get("messages", []):
                if m.get("payload", {}).get("text") == expected:
                    self._bob_msgs.append(m)
                    break

        assert _has(self._bob_msgs), "Bob got 0"
        assert _has(self._main_msgs), "Alice main got 0 self-sync"
        print(f"(sync→Bob ✓, main self-sync ✓)", end=" ")

    # ── 运行所有测试 ──

    async def run_all(self):
        print("=" * 60)
        print("AUN E2EE V2: 多设备 + Self-Sync E2E 测试")
        print("=" * 60)
        print(f"  Alice: {_ALICE_AID}")
        print(f"  Bob:   {_BOB_AID}")
        print(f"  Data:  {_TEST_AUN_PATH}")

        await self.setup()

        try:
            await self.run_test("1. 独立 V2 session", self.test_independent_sessions)
            await self.run_test("2. Alice(main) 发给 Bob", self.test_send_to_bob)
            await self.run_test("3. Bob 解密", self.test_bob_decrypt)
            await self.run_test("4. Alice(sync) self-sync", self.test_self_sync_decrypt)
            await self.run_test("5. Bob 回复两设备都收到", self.test_bob_reply_both_devices)
            await self.run_test("6. sync 发送 main self-sync", self.test_sync_send_main_receives)
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


# ── 入口 ──────────────────────────────────────────────────────

async def main():
    runner = MultiDeviceTestRunner()
    success = await runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
