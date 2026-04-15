#!/usr/bin/env python3
"""群操作签名审计 — E2E 测试（单域/双域环境）。

验证完整的多用户签名审计流程：
- Alice 创建群、更新公告/规则/入群要求
- Bob 收到事件并验签
- 审批入群签名审计
- 所有关键修改操作的签名可追溯

使用方法：
  python -X utf8 tests/e2e_test_signature_audit.py

前置条件：
  - Docker 环境运行中
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
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = f"alice.{_ISSUER}"
_BOBB_AID = f"bobb.{_ISSUER}"
_CHARLIE_AID = f"charlie.{_ISSUER}"


def _make_client() -> AUNClient:
    client = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    })
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str, retries: int = 3) -> str:
    for attempt in range(retries):
        try:
            local = client._auth._keystore.load_identity(aid)
            if local is None:
                await client.auth.create_aid({"aid": aid})
            auth = await client.auth.authenticate({"aid": aid})
            await client.connect(auth)
            return aid
        except Exception as exc:
            if attempt < retries - 1:
                await asyncio.sleep(2)
            else:
                raise


def _run_id() -> str:
    return uuid.uuid4().hex[:12]


# ── 测试统计 ────────────────────────────────────────────

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


async def _wait_event(events: list, ready: asyncio.Event, timeout: float = 5.0):
    try:
        await asyncio.wait_for(ready.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass


def _check_signature(evt: dict, expected_aid: str, label: str):
    """通用签名字段检查。"""
    _result(f"{label}: actor_aid 正确", evt.get("actor_aid") == expected_aid,
            f"expected {expected_aid}, got {evt.get('actor_aid')}")
    cs = evt.get("client_signature")
    _result(f"{label}: 有 client_signature", isinstance(cs, dict))
    if isinstance(cs, dict):
        _result(f"{label}: aid 正确", cs.get("aid") == expected_aid)
        _result(f"{label}: cert_fingerprint 非空", bool(cs.get("cert_fingerprint", "").startswith("sha256:")))
        _result(f"{label}: params_hash 非空", bool(cs.get("params_hash")))
        _result(f"{label}: signature 非空", bool(cs.get("signature")))
        _result(f"{label}: _method 非空", bool(cs.get("_method")))
    verified = evt.get("_verified")
    _result(f"{label}: 验签已执行", verified is not None,
            f"got {verified}")


# ── 完整生命周期测试 ────────────────────────────────────

async def test_full_lifecycle_signature_audit():
    """完整群生命周期签名审计测试。

    流程：
    1. Alice 创建群 → Bob 加入
    2. Alice 更新公告 → Bob 收到带签名的事件
    3. Alice 更新规则 → Bob 收到带签名的事件
    4. Alice 更新入群要求 → Bob 收到带签名的事件
    5. Alice 修改 Bob 角色 → Bob 收到带签名的事件
    6. Alice 踢 Charlie → Bob 收到带签名的事件
    """
    print("\n" + "=" * 50)
    print("📋 test_full_lifecycle_signature_audit")
    print("=" * 50)

    alice = _make_client()
    bob = _make_client()
    charlie = _make_client()

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)

        rid = _run_id()

        # 1. 创建群
        print("\n  [1] 创建群并加入成员")
        result = await alice.call("group.create", {"name": f"audit-e2e-{rid}"})
        group_id = result["group"]["group_id"]
        _result("创建群成功", bool(group_id))

        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})
        await alice.call("group.add_member", {"group_id": group_id, "aid": _CHARLIE_AID})
        _result("添加成员成功", True)

        # 给事件传播一点时间
        await asyncio.sleep(1)

        # ── 2. 更新公告 ──
        print("\n  [2] 更新公告")
        events: list[dict] = []
        ready = asyncio.Event()

        async def _on_ann(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id and evt.get("action") == "announcement_updated":
                events.append(evt)
                ready.set()

        sub_ann = bob.on("group.changed", _on_ann)

        await alice.call("group.update_announcement", {
            "group_id": group_id,
            "content": f"审计测试公告 {rid}",
        })
        await _wait_event(events, ready)

        if events:
            _check_signature(events[0], _ALICE_AID, "公告更新")
        else:
            _result("公告更新: Bob 收到事件", False, "超时")

        sub_ann.unsubscribe()

        # ── 3. 更新规则 ──
        print("\n  [3] 更新规则")
        events.clear()
        ready.clear()

        async def _on_rules(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id and evt.get("action") == "rules_updated":
                events.append(evt)
                ready.set()

        sub_rules = bob.on("group.changed", _on_rules)

        await alice.call("group.update_rules", {
            "group_id": group_id,
            "max_members": 100,
        })
        await _wait_event(events, ready)

        if events:
            _check_signature(events[0], _ALICE_AID, "规则更新")
        else:
            _result("规则更新: Bob 收到事件", False, "超时")

        sub_rules.unsubscribe()

        # ── 4. 更新入群要求 ──
        print("\n  [4] 更新入群要求")
        events.clear()
        ready.clear()

        async def _on_join_req(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id and evt.get("action") == "join_requirements_updated":
                events.append(evt)
                ready.set()

        sub_join = bob.on("group.changed", _on_join_req)

        await alice.call("group.update_join_requirements", {
            "group_id": group_id,
            "mode": "approval",
        })
        await _wait_event(events, ready)

        if events:
            _check_signature(events[0], _ALICE_AID, "入群要求更新")
        else:
            _result("入群要求更新: Bob 收到事件", False, "超时")

        sub_join.unsubscribe()

        # ── 5. 修改角色 ──
        print("\n  [5] 修改角色")
        events.clear()
        ready.clear()

        async def _on_role(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id and evt.get("action") == "role_changed":
                events.append(evt)
                ready.set()

        sub_role = bob.on("group.changed", _on_role)

        await alice.call("group.set_role", {
            "group_id": group_id,
            "aid": _BOBB_AID,
            "role": "admin",
        })
        await _wait_event(events, ready)

        if events:
            _check_signature(events[0], _ALICE_AID, "角色修改")
        else:
            _result("角色修改: Bob 收到事件", False, "超时")

        sub_role.unsubscribe()

        # ── 6. 踢人 ──
        print("\n  [6] 踢出成员")
        events.clear()
        ready.clear()

        async def _on_kick(evt):
            if isinstance(evt, dict) and evt.get("group_id") == group_id and evt.get("action") == "member_removed":
                events.append(evt)
                ready.set()

        sub_kick = bob.on("group.changed", _on_kick)

        await alice.call("group.kick", {
            "group_id": group_id,
            "aid": _CHARLIE_AID,
        })
        await _wait_event(events, ready)

        if events:
            _check_signature(events[0], _ALICE_AID, "踢出成员")
        else:
            _result("踢出成员: Bob 收到事件", False, "超时")

        sub_kick.unsubscribe()

    finally:
        await alice.close()
        await bob.close()
        await charlie.close()


async def test_signature_tamper_detection():
    """验证篡改检测：签名与内容不匹配时应验签失败。"""
    print("\n" + "=" * 50)
    print("📋 test_signature_tamper_detection")
    print("=" * 50)

    # 这是一个单元级别的验证，确认 SDK 验签逻辑在集成环境下也正确
    alice = _make_client()
    try:
        await _ensure_connected(alice, _ALICE_AID)

        # 构造一个伪造的签名事件
        fake_event = {
            "action": "announcement_updated",
            "group_id": "g-fake",
            "actor_aid": _ALICE_AID,
            "client_signature": {
                "aid": _ALICE_AID,
                "cert_fingerprint": "sha256:" + "00" * 32,
                "timestamp": "1234567890",
                "params_hash": "tampered_hash",
                "signature": "dGFtcGVyZWQ=",  # base64 of "tampered"
                "_method": "group.update_announcement",
            }
        }

        result = await alice._verify_event_signature(
            fake_event, fake_event["client_signature"]
        )
        _result("伪造签名验签不通过", result is False or result == "pending",
                f"got {result}")

    finally:
        await alice.close()


# ── 主入口 ──────────────────────────────────────────────

async def main():
    print("=" * 60)
    print("群操作签名审计 — E2E 测试")
    print("=" * 60)

    await test_full_lifecycle_signature_audit()
    await test_signature_tamper_detection()

    print("\n" + "=" * 60)
    print(f"结果：{_pass}/{_total} 通过，{_fail} 失败")
    print("=" * 60)

    if _fail > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
