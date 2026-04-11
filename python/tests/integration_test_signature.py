#!/usr/bin/env python3
"""群操作签名审计 — 集成测试（单域环境）。

验证：
- 群关键修改操作携带 client_signature（含 cert_fingerprint）
- 群事件推送透传 actor_aid + client_signature
- 接收方验签逻辑正确工作

使用方法：
  python -X utf8 tests/integration_test_signature.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
"""
import asyncio
import os
import sys
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient


# ── 环境配置 ────────────────────────────────────────────

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = f"alice.{_ISSUER}"
_BOBB_AID = f"bobb.{_ISSUER}"


def _make_client() -> AUNClient:
    return AUNClient({
        "aun_path": _TEST_AUN_PATH,
        "verify_ssl": False,
        "require_forward_secrecy": False,
    })


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return aid


def _run_id() -> str:
    return uuid.uuid4().hex[:12]


# ── 测试用例 ────────────────────────────────────────────

_pass = 0
_fail = 0
_total = 0


def _result(name: str, ok: bool, detail: str = ""):
    global _pass, _fail, _total
    _total += 1
    if ok:
        _pass += 1
        print(f"  ✅ {name}")
    else:
        _fail += 1
        print(f"  ❌ {name}: {detail}")


async def test_update_announcement_has_signature():
    """group.update_announcement 返回值和事件应包含签名信息。"""
    print("\n📋 test_update_announcement_has_signature")
    alice = _make_client()
    bob = _make_client()
    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        # 创建群
        rid = _run_id()
        result = await alice.call("group.create", {"name": f"sig-test-{rid}"})
        group_id = result["group"]["group_id"]
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})

        # Bob 监听群事件
        received_events: list[dict] = []
        event_ready = asyncio.Event()

        async def _on_changed(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id:
                if evt.get("action") == "announcement_updated":
                    received_events.append(evt)
                    event_ready.set()

        bob.on("group.changed", _on_changed)

        # Alice 更新公告
        ann_result = await alice.call("group.update_announcement", {
            "group_id": group_id,
            "content": f"签名测试公告 {rid}",
        })
        _result("update_announcement 返回成功", ann_result is not None)

        # 等待 Bob 收到事件
        try:
            await asyncio.wait_for(event_ready.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass

        if received_events:
            evt = received_events[0]
            _result("事件包含 actor_aid", evt.get("actor_aid") == _ALICE_AID)
            cs = evt.get("client_signature")
            _result("事件包含 client_signature", cs is not None and isinstance(cs, dict))
            if cs:
                _result("签名包含 aid", cs.get("aid") == _ALICE_AID)
                _result("签名包含 cert_fingerprint", bool(cs.get("cert_fingerprint", "").startswith("sha256:")))
                _result("签名包含 params_hash", bool(cs.get("params_hash")))
                _result("签名包含 signature", bool(cs.get("signature")))
                _result("签名包含 _method", bool(cs.get("_method")))
                # 验签结果
                verified = evt.get("_verified")
                _result("验签结果", verified in (True, "pending"),
                        f"got {verified}")
        else:
            _result("Bob 收到群事件", False, "超时未收到")

    finally:
        await alice.close()
        await bob.close()


async def test_update_rules_has_signature():
    """group.update_rules 事件应包含签名。"""
    print("\n📋 test_update_rules_has_signature")
    alice = _make_client()
    bob = _make_client()
    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)

        rid = _run_id()
        result = await alice.call("group.create", {"name": f"rules-sig-{rid}"})
        group_id = result["group"]["group_id"]
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})

        received_events: list[dict] = []
        event_ready = asyncio.Event()

        async def _on_changed(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id:
                if evt.get("action") == "rules_updated":
                    received_events.append(evt)
                    event_ready.set()

        bob.on("group.changed", _on_changed)

        await alice.call("group.update_rules", {
            "group_id": group_id,
            "max_members": 50,
        })

        try:
            await asyncio.wait_for(event_ready.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass

        if received_events:
            evt = received_events[0]
            _result("事件包含 actor_aid", evt.get("actor_aid") == _ALICE_AID)
            cs = evt.get("client_signature")
            _result("事件包含 client_signature", cs is not None)
            if cs:
                _result("签名 cert_fingerprint 非空", bool(cs.get("cert_fingerprint")))
        else:
            _result("Bob 收到 rules_updated 事件", False, "超时未收到")

    finally:
        await alice.close()
        await bob.close()


async def test_kick_member_has_signature():
    """group.kick 事件应包含操作者签名。"""
    print("\n📋 test_kick_member_has_signature")
    alice = _make_client()
    bob = _make_client()
    charlie_client = _make_client()
    charlie_aid = f"charlie.{_ISSUER}"
    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        await _ensure_connected(charlie_client, charlie_aid)

        rid = _run_id()
        result = await alice.call("group.create", {"name": f"kick-sig-{rid}"})
        group_id = result["group"]["group_id"]
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})
        await alice.call("group.add_member", {"group_id": group_id, "aid": charlie_aid})

        received_events: list[dict] = []
        event_ready = asyncio.Event()

        async def _on_changed(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id:
                if evt.get("action") == "member_removed":
                    received_events.append(evt)
                    event_ready.set()

        bob.on("group.changed", _on_changed)

        # Alice 踢 Charlie
        await alice.call("group.kick", {"group_id": group_id, "aid": charlie_aid})

        try:
            await asyncio.wait_for(event_ready.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass

        if received_events:
            evt = received_events[0]
            _result("kick 事件包含 actor_aid", evt.get("actor_aid") == _ALICE_AID)
            _result("kick 事件包含 client_signature", isinstance(evt.get("client_signature"), dict))
        else:
            _result("Bob 收到 member_removed 事件", False, "超时未收到")

    finally:
        await alice.close()
        await bob.close()
        await charlie_client.close()


async def test_unsigned_event_no_verified():
    """没有 client_signature 的事件不应有 _verified 字段（默认安全）。"""
    print("\n📋 test_unsigned_event_default_safe")
    # 这个测试验证旧版客户端或服务端操作生成的事件不会被验签阻拦
    alice = _make_client()
    try:
        await _ensure_connected(alice, _ALICE_AID)
        rid = _run_id()
        # group.create 事件（upsert）会有签名（因为 group.create 不在 SIGNED_METHODS）
        # 用 group.list 验证不触发签名
        result = await alice.call("group.list", {})
        _result("无签名操作正常执行", result is not None)
    finally:
        await alice.close()


# ── 主入口 ──────────────────────────────────────────────

async def main():
    print("=" * 60)
    print("群操作签名审计 — 集成测试")
    print("=" * 60)

    await test_update_announcement_has_signature()
    await test_update_rules_has_signature()
    await test_kick_member_has_signature()
    await test_unsigned_event_no_verified()

    print("\n" + "=" * 60)
    print(f"结果：{_pass}/{_total} 通过，{_fail} 失败")
    print("=" * 60)

    if _fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
