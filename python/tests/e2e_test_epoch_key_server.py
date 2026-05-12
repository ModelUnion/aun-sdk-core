#!/usr/bin/env python3
"""群 epoch key 服务端托管 / P2P 恢复 E2E 测试。

覆盖：
  1. open 群允许提交/拉取 server ECIES epoch key
  2. invite_only 群允许提交/拉取 server ECIES epoch key
  3. private/approval 群不走 server epoch key，只走 P2P 恢复
  4. open 群离线成员可从服务端恢复 epoch key

使用方法：
  python -X utf8 tests/e2e_test_epoch_key_server.py

前置条件：
  - Docker 环境运行中（docker compose up -d）
  - 固定 AID 身份已就绪
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError
from aun_core.e2ee import load_all_group_secrets, load_group_secret


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


def _normalize_slot_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    return text.strip("-._") or "slot"


def _build_test_slot_id(tag: str, rid: str | None = None) -> str:
    tag_part = _normalize_slot_part(tag)
    rid_part = _normalize_slot_part(rid) if rid else uuid.uuid4().hex[:12]
    return f"{tag_part}-{rid_part}"[:128]


def _make_client(tag: str, rid: str | None = None) -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    client._test_slot_id = _build_test_slot_id(tag, rid)
    client._test_group_inbox = {}
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


def _run_id() -> str:
    return uuid.uuid4().hex[:12]


def _local_group_secret_epochs(client: AUNClient, aid: str, group_id: str) -> list[int]:
    return sorted(load_all_group_secrets(client._keystore, aid, group_id).keys())


def _clear_local_group_secret(client: AUNClient, aid: str, group_id: str) -> None:
    db = client._keystore._get_db(aid)
    db.delete_group_current(group_id)
    db.delete_all_group_old_epochs(group_id)


async def _wait_for_group_secret_epoch(
    client: AUNClient,
    aid: str,
    group_id: str,
    *,
    min_epoch: int = 1,
    timeout: float = 20.0,
) -> int:
    deadline = asyncio.get_running_loop().time() + timeout
    last_epochs: list[int] = []
    while asyncio.get_running_loop().time() < deadline:
        last_epochs = _local_group_secret_epochs(client, aid, group_id)
        for epoch in reversed(last_epochs):
            if epoch >= min_epoch and load_group_secret(client._keystore, aid, group_id, epoch):
                return epoch
        await asyncio.sleep(0.5)
    raise AssertionError(
        f"{aid} did not receive group {group_id} epoch >= {min_epoch} within {timeout}s; epochs={last_epochs}"
    )


async def _create_group(client: AUNClient, name: str, *, visibility: str = "public", join_mode: str | None = None) -> str:
    params = {"name": name, "visibility": visibility}
    if join_mode is not None:
        params["join_mode"] = join_mode
    result = await client.call("group.create", params)
    return result["group"]["group_id"]


async def _join_open_group(client: AUNClient, group_id: str) -> dict:
    return await client.call("group.request_join", {"group_id": group_id, "message": "join"})


async def _join_by_code(client: AUNClient, code: str) -> dict:
    return await client.call("group.use_invite_code", {"code": code})


async def test_open_group_server_key_roundtrip() -> None:
    rid = _run_id()
    print(f"\n{'=' * 60}")
    print(f"TEST: open_group_server_key_roundtrip (rid={rid})")
    print(f"{'=' * 60}")

    alice = _make_client("alice-open-key", rid)
    bob = _make_client("bob-open-key", rid)

    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(
            alice,
            f"open-epoch-key-{rid}",
            visibility="public",
            join_mode="open",
        )
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)
        print(f"  [OK] open 群已创建: group={group_id} epoch={before_epoch}")

        join_result = await _join_open_group(bob, group_id)
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"
        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=rotated_epoch, timeout=25.0)
        print(f"  [OK] open 群轮换到 epoch={rotated_epoch}")

        result = await bob.call("group.e2ee.get_epoch_key", {"group_id": group_id, "epoch": rotated_epoch})
        assert result.get("encrypted_key"), f"open group should return encrypted_key, got {result}"
        print(f"  [OK] group.e2ee.get_epoch_key 返回 encrypted_key")

        recovered = await bob._try_recover_epoch_key_from_server(group_id, rotated_epoch)
        assert recovered is True, "open group should recover from server"
        print(f"  [OK] Bob 从服务端恢复 epoch key 成功")

        print("[PASS] test_open_group_server_key_roundtrip")
    finally:
        await alice.disconnect()
        await bob.disconnect()


async def test_invite_code_group_server_key_roundtrip() -> None:
    rid = _run_id()
    print(f"\n{'=' * 60}")
    print(f"TEST: invite_code_group_server_key_roundtrip (rid={rid})")
    print(f"{'=' * 60}")

    alice = _make_client("alice-invite-key", rid)
    bob = _make_client("bob-invite-key", rid)

    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(
            alice,
            f"invite-epoch-key-{rid}",
            visibility="public",
            join_mode="invite_only",
        )
        invite_result = await alice.call("group.create_invite_code", {"group_id": group_id, "max_uses": 1})
        invite_obj = invite_result.get("invite_code")
        assert isinstance(invite_obj, dict), f"invite_code should be dict, got {type(invite_obj)}"
        code = invite_obj.get("code")
        assert isinstance(code, str) and code, f"invite code missing: {invite_result}"

        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)
        join_result = await _join_by_code(bob, code)
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"

        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=rotated_epoch, timeout=25.0)
        print(f"  [OK] invite_only 群轮换到 epoch={rotated_epoch}")

        result = await bob.call("group.e2ee.get_epoch_key", {"group_id": group_id})
        assert result.get("encrypted_key"), f"invite group should return encrypted_key, got {result}"
        recovered = await bob._try_recover_epoch_key_from_server(group_id, int(result["epoch"]))
        assert recovered is True, "invite group should recover from server"
        print(f"  [OK] Bob 从服务端恢复 invite_only 群 epoch key 成功")

        print("[PASS] test_invite_code_group_server_key_roundtrip")
    finally:
        await alice.disconnect()
        await bob.disconnect()


async def test_private_group_uses_p2p_only_recovery() -> None:
    rid = _run_id()
    print(f"\n{'=' * 60}")
    print(f"TEST: private_group_uses_p2p_only_recovery (rid={rid})")
    print(f"{'=' * 60}")

    alice = _make_client("alice-private-p2p", rid)
    bob = _make_client("bob-private-p2p", rid)

    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(
            alice,
            f"private-epoch-key-{rid}",
            visibility="private",
            join_mode="approval",
        )
        await alice.call("group.add_member", {
            "group_id": group_id,
            "aid": _BOBB_AID,
            "role": "member",
        })
        committed_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=committed_epoch, timeout=25.0)
        print(f"  [OK] private 群成员已收到 epoch={committed_epoch}")

        # 清掉 Bob 这个测试群的本地 group secret，只保留 AID 身份材料。
        _clear_local_group_secret(bob, b_aid, group_id)
        assert load_group_secret(bob._keystore, b_aid, group_id) is None

        # 私密群不应走服务端 epoch key；尝试恢复应转向 P2P。
        server_recover = await bob._try_recover_epoch_key_from_server(group_id, committed_epoch)
        assert server_recover is False, "private group should not recover from server"

        recovered = await bob._recover_group_epoch_key(group_id, committed_epoch, timeout_s=10.0)
        assert recovered is True, "private group should recover via P2P"
        assert load_group_secret(bob._keystore, b_aid, group_id, committed_epoch) is not None

        print("[PASS] test_private_group_uses_p2p_only_recovery")
    finally:
        await alice.disconnect()
        await bob.disconnect()


async def test_open_group_offline_member_recovers_from_server() -> None:
    rid = _run_id()
    print(f"\n{'=' * 60}")
    print(f"TEST: open_group_offline_member_recovers_from_server (rid={rid})")
    print(f"{'=' * 60}")

    alice = _make_client("alice-open-offline", rid)
    bob = _make_client("bob-open-offline", rid)

    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(
            alice,
            f"open-offline-{rid}",
            visibility="public",
            join_mode="open",
        )
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)
        await _join_open_group(bob, group_id)
        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=rotated_epoch, timeout=25.0)
        print(f"  [OK] open 群轮换到 epoch={rotated_epoch}")

        _clear_local_group_secret(bob, b_aid, group_id)
        assert load_group_secret(bob._keystore, b_aid, group_id) is None

        await alice.disconnect()
        await asyncio.sleep(0.5)
        recovered = await bob._recover_group_epoch_key(group_id, rotated_epoch, timeout_s=8.0)
        assert recovered is True, "offline member should recover from server in open group"
        assert load_group_secret(bob._keystore, b_aid, group_id, rotated_epoch) is not None
        print("[PASS] test_open_group_offline_member_recovers_from_server")
    finally:
        try:
            await alice.disconnect()
        except Exception:
            pass
        await bob.disconnect()


async def main() -> None:
    print("Epoch Key 服务端存储 E2E 测试")
    print(f"AUN_PATH: {_TEST_AUN_PATH}")
    print(f"ISSUER: {_ISSUER}")
    print(f"Alice: {_ALICE_AID}, Bob: {_BOBB_AID}, Charlie: {_CHARLIE_AID}")

    tests = [
        test_open_group_server_key_roundtrip,
        test_invite_code_group_server_key_roundtrip,
        test_private_group_uses_p2p_only_recovery,
        test_open_group_offline_member_recovers_from_server,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            await test_fn()
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"  [FAIL] {test_fn.__name__}: {exc}")
            import traceback
            traceback.print_exc()

    print(f"\n{'=' * 60}")
    print(f"结果: {passed} passed, {failed} failed / {len(tests)} total")
    print(f"{'=' * 60}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
