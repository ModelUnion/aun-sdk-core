#!/usr/bin/env python3
"""slot_id 分隔符场景 E2E 测试 — 验证同前缀不同 slot_id 的实例踢出与接收行为。

使用方法：
  AUN_DATA_ROOT="D:/modelunion/kite/docker-deploy/data/sdk-tester-aun" python -X utf8 tests/e2e_test_slot_id_separator.py

前置条件：
  - Docker 环境运行中（docker compose up -d）
"""
import asyncio
import os
import sys
import uuid
from pathlib import Path
from weakref import WeakKeyDictionary

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

# ---------------------------------------------------------------------------
# 环境配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

_CLIENT_GROUP_INBOXES: WeakKeyDictionary[AUNClient, dict[str, list[dict]]] = WeakKeyDictionary()
_CLIENT_P2P_INBOXES: WeakKeyDictionary[AUNClient, list[dict]] = WeakKeyDictionary()


def _run_id() -> str:
    return uuid.uuid4().hex[:8]


def _make_client(slot_id: str) -> AUNClient:
    client = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    _CLIENT_GROUP_INBOXES[client] = {}
    _CLIENT_P2P_INBOXES[client] = []

    def _on_group_msg(data):
        if isinstance(data, dict) and data.get("group_id"):
            gid = data["group_id"]
            _CLIENT_GROUP_INBOXES.setdefault(client, {}).setdefault(gid, []).append(data)

    def _on_p2p_msg(data):
        if isinstance(data, dict):
            _CLIENT_P2P_INBOXES.setdefault(client, []).append(data)

    client.on("group.message_created", _on_group_msg)
    client.on("message.received", _on_p2p_msg)
    return client


async def _connect(client: AUNClient, aid: str, slot_id: str) -> str:
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            print(f"[connect] aid={aid} slot_id={slot_id!r} attempt={attempt}")
            await ensure_connected_identity(
                client, aid,
                connect_options={"slot_id": slot_id, "auto_reconnect": False},
                attempts=1,
            )
            print(f"[connect] OK aid={aid} slot_id={client.slot_id!r} device_id={client.device_id!r}")
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
        except Exception as exc:
            print(f"[connect] fatal aid={aid}: {exc}")
            raise
    raise last_error or RuntimeError(f"{aid} connect failed")


async def _wait_p2p(client: AUNClient, text: str, timeout: float = 8.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        msgs = _CLIENT_P2P_INBOXES.get(client, [])
        for m in msgs:
            payload = m.get("payload") or {}
            if isinstance(payload, dict) and payload.get("text") == text:
                return m
            # 加密消息解密后
            if isinstance(m.get("e2ee"), dict):
                inner = m.get("payload") or {}
                if isinstance(inner, dict) and inner.get("text") == text:
                    return m
        await asyncio.sleep(0.3)
    raise AssertionError(f"未在 {timeout}s 内收到 P2P 消息 text={text!r}，收件箱={_CLIENT_P2P_INBOXES.get(client, [])}")


async def _wait_group(client: AUNClient, group_id: str, text: str, timeout: float = 8.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        msgs = _CLIENT_GROUP_INBOXES.get(client, {}).get(group_id, [])
        for m in msgs:
            payload = m.get("payload") or {}
            if isinstance(payload, dict) and payload.get("text") == text:
                return m
            if isinstance(m.get("e2ee"), dict):
                inner = m.get("payload") or {}
                if isinstance(inner, dict) and inner.get("text") == text:
                    return m
        await asyncio.sleep(0.3)
    raise AssertionError(f"未在 {timeout}s 内收到群消息 text={text!r}，收件箱={_CLIENT_GROUP_INBOXES.get(client, {}).get(group_id, [])}")


async def _wait_group_epoch(client: AUNClient, aid: str, group_id: str, *, min_epoch: int = 1, timeout: float = 20.0) -> int:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            bootstrap = await client.call("group.v2.bootstrap", {"group_id": group_id})
            epoch = int(bootstrap.get("epoch", 0) or 0)
            committed = list(bootstrap.get("committed_member_aids") or bootstrap.get("member_aids") or [])
            devices = bootstrap.get("devices", []) or []
            has_device = any(isinstance(d, dict) and str(d.get("aid") or "") == aid for d in devices)
            pending = bool(bootstrap.get("pending_adds")) or bool(bootstrap.get("pending_removes"))
            if aid in committed and has_device and not pending:
                return max(epoch, min_epoch)
        except Exception:
            pass
        await asyncio.sleep(0.5)
    raise AssertionError(f"{aid} group {group_id} 未在 {timeout}s 内就绪 (min_epoch={min_epoch})")


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def test_p2p_plaintext_same_prefix():
    """Test 1: P2P 明文消息 — 同前缀实例接收（c2 踢掉 c1）"""
    print("\n=== Test 1: P2P 明文消息 — 同前缀实例接收 ===")
    rid = _run_id()
    c1 = _make_client(f"evolclaw cli-{rid}")
    c2 = _make_client(f"evolclaw daemon-{rid}")
    bob = _make_client(f"bob-t1-{rid}")
    try:
        # c1 先连接
        await _connect(c1, _ALICE_AID, f"evolclaw cli-{rid}")
        await asyncio.sleep(0.5)
        # c2 连接（踢掉 c1）
        await _connect(c2, _ALICE_AID, f"evolclaw daemon-{rid}")
        await asyncio.sleep(0.5)
        await _connect(bob, _BOB_AID, f"bob-t1-{rid}")

        text = f"p2p-plain-{rid}"
        await bob.call("message.send", {"to": _ALICE_AID, "payload": {"type": "text", "text": text}})

        msg = await _wait_p2p(c2, text, timeout=8.0)
        slot_full = msg.get("slot_id_full") or msg.get("slot_id") or ""
        print(f"  slot_id_full={slot_full!r}")
        assert f"evolclaw daemon-{rid}" in slot_full or slot_full == f"evolclaw daemon-{rid}", \
            f"slot_id_full 应含 'evolclaw daemon-{rid}'，实际={slot_full!r}"

        print("[PASS] Test 1")
        return True
    except Exception as e:
        print(f"[FAIL] Test 1: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await c1.close(); await c2.close(); await bob.close()


async def test_p2p_encrypted_same_prefix():
    """Test 2: P2P 加密消息 — 同前缀实例接收（c2 踢掉 c1）"""
    print("\n=== Test 2: P2P 加密消息 — 同前缀实例接收 ===")
    rid = _run_id()
    c1 = _make_client(f"evolclaw cli-{rid}")
    c2 = _make_client(f"evolclaw daemon-{rid}")
    bob = _make_client(f"bob-t2-{rid}")
    try:
        await _connect(c1, _ALICE_AID, f"evolclaw cli-{rid}")
        await asyncio.sleep(0.5)
        await _connect(c2, _ALICE_AID, f"evolclaw daemon-{rid}")
        await asyncio.sleep(0.5)
        await _connect(bob, _BOB_AID, f"bob-t2-{rid}")

        text = f"p2p-enc-{rid}"
        await bob.call("message.send", {
            "to": _ALICE_AID,
            "payload": {"type": "text", "text": text},
            "encrypt": True,
        })

        msg = await _wait_p2p(c2, text, timeout=10.0)
        assert isinstance(msg.get("e2ee"), dict) or msg.get("payload", {}).get("text") == text, \
            f"消息未解密或内容不符: {msg}"
        slot_full = msg.get("slot_id_full") or msg.get("slot_id") or ""
        print(f"  slot_id_full={slot_full!r}")
        assert f"evolclaw daemon-{rid}" in slot_full or slot_full == f"evolclaw daemon-{rid}", \
            f"slot_id_full 应含 'evolclaw daemon-{rid}'，实际={slot_full!r}"

        print("[PASS] Test 2")
        return True
    except Exception as e:
        print(f"[FAIL] Test 2: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await c1.close(); await c2.close(); await bob.close()


async def test_group_plaintext_same_prefix():
    """Test 3: Group 明文消息 — 同前缀实例接收（c2 踢掉 c1）"""
    print("\n=== Test 3: Group 明文消息 — 同前缀实例接收 ===")
    rid = _run_id()
    c1 = _make_client(f"evolclaw cli-{rid}")
    c2 = _make_client(f"evolclaw daemon-{rid}")
    bob = _make_client(f"bob-t3-{rid}")
    try:
        await _connect(c1, _ALICE_AID, f"evolclaw cli-{rid}")
        await asyncio.sleep(0.5)
        await _connect(c2, _ALICE_AID, f"evolclaw daemon-{rid}")
        await asyncio.sleep(0.5)
        await _connect(bob, _BOB_AID, f"bob-t3-{rid}")

        # bob 建群，加 alice
        result = await bob.call("group.create", {"name": f"slot-plain-{rid}", "group_e2ee_protocol": "group_e2ee_v2"})
        group_id = result["group"]["group_id"]
        await bob.call("group.add_member", {"group_id": group_id, "aid": _ALICE_AID})
        await asyncio.sleep(1)

        text = f"grp-plain-{rid}"
        await bob.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": text},
            "encrypt": False,
        })

        msg = await _wait_group(c2, group_id, text, timeout=8.0)
        assert msg.get("payload", {}).get("text") == text, f"消息内容不符: {msg}"

        print("[PASS] Test 3")
        return True
    except Exception as e:
        print(f"[FAIL] Test 3: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await c1.close(); await c2.close(); await bob.close()


async def test_group_encrypted_same_prefix():
    """Test 4: Group 加密消息 — 同前缀实例接收（c2 踢掉 c1）"""
    print("\n=== Test 4: Group 加密消息 — 同前缀实例接收 ===")
    rid = _run_id()
    c1 = _make_client(f"evolclaw cli-{rid}")
    c2 = _make_client(f"evolclaw daemon-{rid}")
    bob = _make_client(f"bob-t4-{rid}")
    try:
        await _connect(c1, _ALICE_AID, f"evolclaw cli-{rid}")
        await asyncio.sleep(0.5)
        await _connect(c2, _ALICE_AID, f"evolclaw daemon-{rid}")
        await asyncio.sleep(0.5)
        await _connect(bob, _BOB_AID, f"bob-t4-{rid}")

        # bob 建群，加 alice，等密钥就绪
        result = await bob.call("group.create", {"name": f"slot-enc-{rid}", "group_e2ee_protocol": "group_e2ee_v2"})
        group_id = result["group"]["group_id"]
        await bob.call("group.add_member", {"group_id": group_id, "aid": _ALICE_AID})
        # 等 c2（alice）拿到群密钥
        await _wait_group_epoch(c2, _ALICE_AID, group_id, min_epoch=1, timeout=20.0)

        text = f"grp-enc-{rid}"
        await bob.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": text},
            "encrypt": True,
        })

        msg = await _wait_group(c2, group_id, text, timeout=10.0)
        assert isinstance(msg.get("e2ee"), dict) or msg.get("payload", {}).get("text") == text, \
            f"消息未解密或内容不符: {msg}"

        print("[PASS] Test 4")
        return True
    except Exception as e:
        print(f"[FAIL] Test 4: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await c1.close(); await c2.close(); await bob.close()


async def main():
    print("=" * 60)
    print("slot_id 分隔符场景 E2E 测试")
    print("=" * 60)
    print(f"aun_path={_TEST_AUN_PATH}")
    print(f"alice={_ALICE_AID}  bob={_BOB_AID}")

    tests = [
        ("1. P2P 明文消息 — 同前缀实例接收",   test_p2p_plaintext_same_prefix),
        ("2. P2P 加密消息 — 同前缀实例接收",   test_p2p_encrypted_same_prefix),
        ("3. Group 明文消息 — 同前缀实例接收", test_group_plaintext_same_prefix),
        ("4. Group 加密消息 — 同前缀实例接收", test_group_encrypted_same_prefix),
    ]

    results = []
    for name, fn in tests:
        ok = await fn()
        results.append((name, ok))
        await asyncio.sleep(0.5)

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for name, ok in results:
        print(f"  {'[PASS]' if ok else '[FAIL]'} {name}")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
