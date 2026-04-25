#!/usr/bin/env python3
"""Redis 在线状态 集成测试 — 需要运行中的 AUN Gateway + Message + Group 服务。

验证：
1. 客户端连接后，message.query_online 返回在线
2. 客户端断开后，message.query_online 返回离线
3. 多客户端批量在线查询
4. group.get_online_members 通过 Redis 返回正确的在线成员
5. 断开后群在线成员状态更新
6. 未连接的 AID 始终返回离线

使用方法：
  AUN_DATA_ROOT="D:/modelunion/kite/docker-deploy/data/sdk-tester-aun" \
    python -X utf8 tests/integration_test_online_status.py

前置条件：
  - Docker 环境运行中（docker compose up -d），含 Redis 容器
  - Gateway / Message / Group 服务正常
"""
import asyncio
import os
import re
import sys
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CHARLIE_AID = os.environ.get("AUN_TEST_CHARLIE_AID", f"charlie.{_ISSUER}").strip()
_DAVE_AID = os.environ.get("AUN_TEST_DAVE_AID", f"dave.{_ISSUER}").strip()


def _normalize_slot_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    return text.strip("-._") or "slot"


def _build_test_slot_id(tag: str, rid: str | None = None) -> str:
    tag_part = _normalize_slot_part(tag)
    rid_part = _normalize_slot_part(rid) if rid else uuid.uuid4().hex[:12]
    slot_id = f"{tag_part}-{rid_part}"
    return slot_id[:128]


def _make_client(tag: str) -> AUNClient:
    """创建测试客户端"""
    client = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    }, debug=True)
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


async def _query_online(client: AUNClient, aids: list[str]) -> dict[str, bool]:
    """调用 message.query_online，返回 {aid: bool}"""
    result = await client.call("message.query_online", {"aids": aids})
    return result.get("online", {})


async def _wait_online(client: AUNClient, aid: str, expected: bool, *, timeout: float = 6.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        result = await _query_online(client, [aid])
        if result.get(aid) is expected:
            return True
        if asyncio.get_running_loop().time() >= deadline:
            return False
        await asyncio.sleep(0.3)


async def _get_online_members(client: AUNClient, group_id: str) -> list[dict]:
    """调用 group.get_online_members，返回成员列表"""
    result = await client.call("group.get_online_members", {"group_id": group_id})
    return result.get("members", [])


async def _wait_group_members_online(
    client: AUNClient,
    group_id: str,
    expected_online: set[str],
    *,
    expected_offline: set[str] | None = None,
    timeout: float = 10.0,
) -> tuple[set[str], set[str]]:
    expected_offline = expected_offline or set()
    deadline = asyncio.get_running_loop().time() + timeout
    last_online: set[str] = set()
    last_offline: set[str] = set()
    while True:
        members = await _get_online_members(client, group_id)
        last_online = {m["aid"] for m in members if m.get("online")}
        last_offline = {m["aid"] for m in members if not m.get("online")}
        if expected_online.issubset(last_online) and expected_offline.issubset(last_offline):
            return last_online, last_offline
        if asyncio.get_running_loop().time() >= deadline:
            return last_online, last_offline
        await asyncio.sleep(0.3)


async def _create_group(client: AUNClient, name: str) -> str:
    """建群，返回 group_id"""
    result = await client.call("group.create", {"name": name})
    return result["group"]["group_id"]


async def _add_member(client: AUNClient, group_id: str, member_aid: str) -> None:
    """添加群成员"""
    await client.call("group.add_member", {"group_id": group_id, "aid": member_aid})


async def _dissolve_group(client: AUNClient, group_id: str) -> None:
    """解散群组（测试清理）"""
    try:
        await client.call("group.dissolve", {"group_id": group_id})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

async def test_online_after_connect():
    """Test 1: 客户端连接后，query_online 应返回在线"""
    print("\n=== Test 1: 连接后 query_online 返回在线 ===")
    alice = _make_client("alice-online")
    bob = _make_client("bob-online")
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)

        # alice 查询 bob 的在线状态
        assert await _wait_online(alice, bob_aid, True, timeout=10.0), "bob 应在线"

        # bob 查询 alice 的在线状态
        assert await _wait_online(bob, alice_aid, True, timeout=10.0), "alice 应在线"

        print("[PASS] Test 1")
        return True
    except Exception as e:
        print(f"[FAIL] Test 1: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_offline_after_disconnect():
    """Test 2: 客户端断开后，query_online 应返回离线"""
    print("\n=== Test 2: 断开后 query_online 返回离线 ===")
    alice = _make_client("alice-offline")
    bob = _make_client("bob-offline")
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)

        # 确认 bob 在线
        assert await _wait_online(alice, bob_aid, True, timeout=10.0), "bob 应在线"

        # bob 断开
        await bob.close()

        # 再次查询，bob 应离线
        assert await _wait_online(alice, bob_aid, False, timeout=10.0), "bob 已断开应离线"

        print("[PASS] Test 2")
        return True
    except Exception as e:
        print(f"[FAIL] Test 2: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_batch_query_online():
    """Test 3: 批量查询多个 AID 的在线状态"""
    print("\n=== Test 3: 批量查询在线状态 ===")
    alice = _make_client("alice-batch")
    bob = _make_client("bob-batch")
    charlie = _make_client("charlie-batch")
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)
        charlie_aid = await _ensure_connected(charlie, _CHARLIE_AID)
        assert await _wait_online(alice, bob_aid, True, timeout=10.0), "bob 应在线"
        assert await _wait_online(alice, charlie_aid, True, timeout=10.0), "charlie 应在线"

        # alice 批量查询 bob、charlie、dave（dave 未连接）
        result = await _query_online(alice, [bob_aid, charlie_aid, _DAVE_AID])
        assert result.get(bob_aid) is True, f"bob 应在线，实际: {result}"
        assert result.get(charlie_aid) is True, f"charlie 应在线，实际: {result}"
        assert result.get(_DAVE_AID) is False, f"dave 未连接应离线，实际: {result}"

        # charlie 断开
        await charlie.close()
        assert await _wait_online(alice, charlie_aid, False, timeout=10.0), "charlie 已断开应离线"
        assert await _wait_online(alice, bob_aid, True, timeout=10.0), "bob 应仍在线"

        # 再次批量查询
        result = await _query_online(alice, [bob_aid, charlie_aid])
        assert result.get(bob_aid) is True, f"bob 应仍在线，实际: {result}"
        assert result.get(charlie_aid) is False, f"charlie 已断开应离线，实际: {result}"

        print("[PASS] Test 3")
        return True
    except Exception as e:
        print(f"[FAIL] Test 3: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close(); await charlie.close()


async def test_never_connected_is_offline():
    """Test 4: 从未连接过的 AID 查询应返回离线"""
    print("\n=== Test 4: 未连接 AID 返回离线 ===")
    alice = _make_client("alice-never")
    try:
        await _ensure_connected(alice, _ALICE_AID)
        await asyncio.sleep(1.0)

        # 查询从未连接的 dave
        result = await _query_online(alice, [_DAVE_AID])
        assert result.get(_DAVE_AID) is False, f"dave 从未连接应离线，实际: {result}"

        # 查询不存在的 AID
        fake_aid = f"nonexist-{uuid.uuid4().hex[:8]}.{_ISSUER}"
        result = await _query_online(alice, [fake_aid])
        assert result.get(fake_aid) is False, f"不存在的 AID 应离线，实际: {result}"

        print("[PASS] Test 4")
        return True
    except Exception as e:
        print(f"[FAIL] Test 4: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close()


async def test_group_online_members():
    """Test 5: group.get_online_members 通过 Redis 返回在线成员"""
    print("\n=== Test 5: 群在线成员查询 ===")
    alice = _make_client("alice-grp")
    bob = _make_client("bob-grp")
    charlie = _make_client("charlie-grp")
    group_id = None
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)
        charlie_aid = await _ensure_connected(charlie, _CHARLIE_AID)
        await asyncio.sleep(1.0)

        # alice 建群，添加 bob 和 charlie
        run_id = uuid.uuid4().hex[:8]
        group_id = await _create_group(alice, f"online-test-{run_id}")
        await _add_member(alice, group_id, bob_aid)
        await _add_member(alice, group_id, charlie_aid)
        assert await _wait_online(alice, alice_aid, True), "alice 在线状态未收敛"
        assert await _wait_online(alice, bob_aid, True), "bob 在线状态未收敛"
        assert await _wait_online(alice, charlie_aid, True), "charlie 在线状态未收敛"

        # 查询群在线成员 — alice、bob、charlie 都应在线
        online_aids, _ = await _wait_group_members_online(
            alice, group_id, {alice_aid, bob_aid, charlie_aid},
        )
        assert alice_aid in online_aids, f"alice 应在线，实际在线: {online_aids}"
        assert bob_aid in online_aids, f"bob 应在线，实际在线: {online_aids}"
        assert charlie_aid in online_aids, f"charlie 应在线，实际在线: {online_aids}"

        print("[PASS] Test 5")
        return True
    except Exception as e:
        print(f"[FAIL] Test 5: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        if group_id:
            await _dissolve_group(alice, group_id)
        await alice.close(); await bob.close(); await charlie.close()


async def test_group_online_members_after_disconnect():
    """Test 6: 成员断开后，群在线成员状态更新"""
    print("\n=== Test 6: 成员断开后群在线状态更新 ===")
    alice = _make_client("alice-grp-dc")
    bob = _make_client("bob-grp-dc")
    charlie = _make_client("charlie-grp-dc")
    group_id = None
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)
        charlie_aid = await _ensure_connected(charlie, _CHARLIE_AID)
        await asyncio.sleep(1.0)

        # 建群
        run_id = uuid.uuid4().hex[:8]
        group_id = await _create_group(alice, f"online-dc-{run_id}")
        await _add_member(alice, group_id, bob_aid)
        await _add_member(alice, group_id, charlie_aid)
        assert await _wait_online(alice, alice_aid, True), "alice 在线状态未收敛"
        assert await _wait_online(alice, bob_aid, True), "bob 在线状态未收敛"
        assert await _wait_online(alice, charlie_aid, True), "charlie 在线状态未收敛"

        # charlie 断开
        await charlie.close()
        assert await _wait_online(alice, charlie_aid, False, timeout=10.0), "charlie 离线状态未收敛"

        # 查询群在线成员 — alice 和 bob 在线，charlie 离线
        online_aids, offline_aids = await _wait_group_members_online(
            alice, group_id, {alice_aid, bob_aid}, expected_offline={charlie_aid},
        )
        assert alice_aid in online_aids, f"alice 应在线，实际在线: {online_aids}"
        assert bob_aid in online_aids, f"bob 应在线，实际在线: {online_aids}"
        assert charlie_aid in offline_aids, f"charlie 应离线，实际在线: {online_aids}"

        print("[PASS] Test 6")
        return True
    except Exception as e:
        print(f"[FAIL] Test 6: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        if group_id:
            await _dissolve_group(alice, group_id)
        await alice.close(); await bob.close(); await charlie.close()


async def test_reconnect_online_status():
    """Test 7: 断开重连后在线状态恢复"""
    print("\n=== Test 7: 断开重连后在线状态恢复 ===")
    alice = _make_client("alice-reconn")
    bob = _make_client("bob-reconn")
    bob2 = _make_client("bob-reconn2")
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)
        await asyncio.sleep(1.0)

        # 确认 bob 在线
        assert await _wait_online(alice, bob_aid, True), "bob 应在线"

        # bob 断开
        await bob.close()
        await asyncio.sleep(2.0)

        # 确认 bob 离线
        assert await _wait_online(alice, bob_aid, False), "bob 断开后应离线"

        # bob 用新客户端重连
        await _ensure_connected(bob2, _BOBB_AID)
        await asyncio.sleep(1.0)

        # 确认 bob 重新上线
        assert await _wait_online(alice, bob_aid, True), "bob 重连后应在线"

        print("[PASS] Test 7")
        return True
    except Exception as e:
        print(f"[FAIL] Test 7: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close(); await bob2.close()


async def test_multi_device_online():
    """Test 8: 同一 AID 多设备连接，全断开后才离线"""
    print("\n=== Test 8: 多设备在线状态 ===")
    alice = _make_client("alice-multi")
    bob_dev1 = _make_client("bob-dev1")
    bob_dev2 = _make_client("bob-dev2")
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob_dev1, _BOBB_AID)
        await _ensure_connected(bob_dev2, _BOBB_AID)

        # bob 两个设备都在线
        assert await _wait_online(alice, bob_aid, True, timeout=10.0), \
            "bob 两设备在线，应返回 true"

        # 断开第一个设备
        await bob_dev1.close()

        # bob 仍然在线（还有 dev2）
        assert await _wait_online(alice, bob_aid, True, timeout=10.0), \
            "bob 还有一个设备在线，应返回 true"

        # 断开第二个设备
        await bob_dev2.close()

        # bob 完全离线
        assert await _wait_online(alice, bob_aid, False, timeout=10.0), \
            "bob 全部断开应离线"

        print("[PASS] Test 8")
        return True
    except Exception as e:
        print(f"[FAIL] Test 8: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob_dev1.close(); await bob_dev2.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("Redis 在线状态 集成测试")
    print("Gateway 写 Redis → Message/Group 读 Redis")
    print("=" * 60)

    tests = [
        ("连接后返回在线",          test_online_after_connect),
        ("断开后返回离线",          test_offline_after_disconnect),
        ("批量查询在线状态",        test_batch_query_online),
        ("未连接 AID 返回离线",     test_never_connected_is_offline),
        ("群在线成员查询",          test_group_online_members),
        ("断开后群在线更新",        test_group_online_members_after_disconnect),
        ("断开重连后恢复在线",      test_reconnect_online_status),
        ("多设备在线状态",          test_multi_device_online),
    ]

    results = []
    for name, fn in tests:
        result = await fn()
        results.append((name, result))
        await asyncio.sleep(0.5)

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    for name, ok in results:
        status = "[PASS]" if ok else "[FAIL]"
        print(f"  {status} {name}")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")

    if passed == total:
        print("\n[PASS] All Redis online status tests passed!")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
