#!/usr/bin/env python3
"""Group 管理面集成测试。

覆盖重点：
  1. 成员角色、管理员权限、群主转让、暂停/恢复幂等
  2. 入群要求、问题提示、待审批上限、单个/批量审批
  3. 邀请码大小写归一、code@domain、耗尽/撤销、封禁/解封

使用方法（Docker 容器内）：
  python /tests/integration_test_group_management.py
"""
from __future__ import annotations

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

from aun_core import AUNClient, AuthError, RateLimitError

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_management"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()
_CHARLIE_AID = os.environ.get("AUN_TEST_CHARLIE_AID", f"charlie.{_ISSUER}").strip()
_DAVE_AID = os.environ.get("AUN_TEST_DAVE_AID", f"dave.{_ISSUER}").strip()
_ERIN_AID = os.environ.get("AUN_TEST_ERIN_AID", f"erin.{_ISSUER}").strip()

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
    print(f"  [FAIL] {name} - {reason}")


def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.register_aid({"aid": aid})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            await client.connect(auth)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


async def _expect_failure(factory, label: str, *, contains: str | None = None):
    try:
        await factory()
    except Exception as exc:
        text = str(exc)
        if contains and contains.lower() not in text.lower():
            raise AssertionError(f"{label}: 失败信息不匹配: {text}") from exc
        print(f"  [OK] {label}: {exc}")
        return
    raise AssertionError(f"{label}: 期望失败但实际成功")


async def _create_group(client: AUNClient, name: str, **extra) -> str:
    params = {"name": name, "visibility": "private"}
    params.update(extra)
    result = await client.call("group.create", params)
    group_id = (result.get("group") or {}).get("group_id", "")
    if not group_id:
        raise AssertionError(f"group.create 未返回 group_id: {result}")
    return group_id


async def _close_all(*clients: AUNClient):
    for client in clients:
        try:
            await client.close()
        except Exception:
            pass


async def _cleanup_group(owner: AUNClient, group_id: str):
    if not group_id:
        return
    try:
        await owner.call("group.dissolve", {"group_id": group_id})
        print(f"  已解散群 {group_id}")
    except Exception as exc:
        print(f"  清理群失败（忽略）: {exc}")


def _member_role(members: list[dict], aid: str) -> str | None:
    for member in members:
        if member.get("aid") == aid:
            return member.get("role")
    return None


async def test_roles_transfer_and_lifecycle():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    charlie = _make_client()
    group_id = ""
    cleanup_owner = alice

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)

        group_id = await _create_group(alice, f"mgmt-roles-{rid}")
        _ok("创建私有群")

        member = (await alice.call("group.add_member", {
            "group_id": group_id,
            "aid": _BOBB_AID,
            "role": "member",
        })).get("member") or {}
        if member.get("role") != "member":
            raise AssertionError(f"Bob 初始角色异常: {member}")
        _ok("owner 可添加普通成员")

        await _expect_failure(
            lambda: bobb.call("group.set_role", {
                "group_id": group_id,
                "aid": _BOBB_AID,
                "role": "admin",
            }),
            "普通成员不能设置角色",
            contains="owner",
        )
        _ok("普通成员 set_role 被拒绝")

        promoted = await alice.call("group.set_role", {
            "group_id": group_id,
            "aid": _BOBB_AID,
            "role": "admin",
        })
        if (promoted.get("member") or {}).get("role") != "admin":
            raise AssertionError(f"Bob 提升 admin 失败: {promoted}")
        _ok("owner 可提升 admin")

        admins = await alice.call("group.get_members", {
            "group_id": group_id,
            "role": "admin",
        })
        if _member_role(admins.get("members", []), _BOBB_AID) != "admin":
            raise AssertionError(f"admin 过滤未返回 Bob: {admins}")
        _ok("get_members role=admin 过滤正确")

        added_by_admin = await bobb.call("group.add_member", {
            "group_id": group_id,
            "aid": _CHARLIE_AID,
            "role": "member",
        })
        if (added_by_admin.get("member") or {}).get("aid") != _CHARLIE_AID:
            raise AssertionError(f"admin 添加成员失败: {added_by_admin}")
        _ok("admin 可添加普通成员")

        await _expect_failure(
            lambda: bobb.call("group.kick", {
                "group_id": group_id,
                "aid": _ALICE_AID,
            }),
            "admin 不能踢 owner",
            contains="owner",
        )
        _ok("admin 不能管理 owner")

        transfer = await alice.call("group.transfer_owner", {
            "group_id": group_id,
            "new_owner": _BOBB_AID,
        })
        if transfer.get("old_owner") != _ALICE_AID or transfer.get("new_owner") != _BOBB_AID:
            raise AssertionError(f"群主转让返回异常: {transfer}")
        cleanup_owner = bobb
        _ok("owner 可转让群主")

        members = (await bobb.call("group.get_members", {"group_id": group_id})).get("members", [])
        if _member_role(members, _BOBB_AID) != "owner":
            raise AssertionError(f"新 owner 角色未更新: {members}")
        if _member_role(members, _ALICE_AID) != "admin":
            raise AssertionError(f"旧 owner 未降为 admin: {members}")
        _ok("转让后成员角色一致")

        await _expect_failure(
            lambda: alice.call("group.suspend", {"group_id": group_id}),
            "旧 owner 不能暂停群",
            contains="owner",
        )
        _ok("非 owner suspend 被拒绝")

        suspended = await bobb.call("group.suspend", {"group_id": group_id})
        if suspended.get("status") != "suspended":
            raise AssertionError(f"suspend 返回异常: {suspended}")
        unchanged_suspend = await bobb.call("group.suspend", {"group_id": group_id})
        if unchanged_suspend.get("status") != "unchanged":
            raise AssertionError(f"重复 suspend 未幂等: {unchanged_suspend}")
        _ok("owner suspend 幂等")

        await _expect_failure(
            lambda: charlie.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": "suspended"},
                "encrypt": False,
            }),
            "暂停群禁止发送消息",
            contains="suspended",
        )
        _ok("暂停状态阻止发消息")

        resumed = await bobb.call("group.resume", {"group_id": group_id})
        if resumed.get("status") != "active":
            raise AssertionError(f"resume 返回异常: {resumed}")
        unchanged_resume = await bobb.call("group.resume", {"group_id": group_id})
        if unchanged_resume.get("status") != "unchanged":
            raise AssertionError(f"重复 resume 未幂等: {unchanged_resume}")
        _ok("owner resume 幂等")
    finally:
        await _cleanup_group(cleanup_owner, group_id)
        await _close_all(alice, bobb, charlie)


async def test_join_requirements_and_batch_review():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    charlie = _make_client()
    dave = _make_client()
    group_question = ""
    group_batch = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)
        await _ensure_connected(dave, _DAVE_AID)

        group_question = await _create_group(
            alice,
            f"mgmt-join-question-{rid}",
            join_question="用途是什么？",
            max_pending=1,
        )
        _ok("创建带问题的审批群")

        req = (await alice.call("group.get_join_requirements", {
            "group_id": group_question,
        })).get("join_requirements") or {}
        if req.get("mode") != "approval" or req.get("question") != "用途是什么？":
            raise AssertionError(f"入群要求初始化异常: {req}")
        _ok("get_join_requirements 返回初始化配置")

        question = await bobb.call("group.request_join", {"group_id": group_question})
        if question.get("status") != "question_required":
            raise AssertionError(f"缺答案应返回 question_required: {question}")
        _ok("缺少答案时返回问题")

        pending = await bobb.call("group.request_join", {
            "group_id": group_question,
            "message": "申请加入",
            "answer": "用于集成测试",
        })
        if pending.get("status") != "pending":
            raise AssertionError(f"带答案应进入 pending: {pending}")
        _ok("带答案后进入待审批")

        await _expect_failure(
            lambda: charlie.call("group.request_join", {
                "group_id": group_question,
                "answer": "第二个申请",
            }),
            "max_pending=1 阻止额外申请",
            contains="too many pending",
        )
        _ok("待审批上限生效")

        await _expect_failure(
            lambda: bobb.call("group.list_join_requests", {"group_id": group_question}),
            "非成员不能列审批",
            contains="not a member",
        )
        _ok("list_join_requests 非成员权限生效")

        pending_list = await alice.call("group.list_join_requests", {
            "group_id": group_question,
            "status": "pending",
        })
        if not any(item.get("aid") == _BOBB_AID for item in pending_list.get("items", [])):
            raise AssertionError(f"pending 列表未包含 Bob: {pending_list}")
        _ok("pending 列表包含申请人")

        rejected = await alice.call("group.review_join_request", {
            "group_id": group_question,
            "aid": _BOBB_AID,
            "approve": False,
            "reason": "覆盖拒绝路径",
        })
        if rejected.get("status") != "rejected":
            raise AssertionError(f"拒绝审批返回异常: {rejected}")
        _ok("单个审批拒绝路径")

        await alice.call("group.update_join_requirements", {
            "group_id": group_question,
            "mode": "open",
        })
        joined = await bobb.call("group.request_join", {
            "group_id": group_question,
            "message": "open join",
        })
        if joined.get("status") != "joined":
            raise AssertionError(f"open 模式应直接加入: {joined}")
        _ok("open 模式直接入群")

        await _expect_failure(
            lambda: bobb.call("group.list_join_requests", {"group_id": group_question}),
            "普通成员不能列审批",
            contains="admin",
        )
        _ok("list_join_requests 普通成员权限生效")

        group_batch = await _create_group(alice, f"mgmt-join-batch-{rid}", max_pending=5)
        for client, aid in ((bobb, _BOBB_AID), (charlie, _CHARLIE_AID), (dave, _DAVE_AID)):
            res = await client.call("group.request_join", {
                "group_id": group_batch,
                "answer": f"{aid} 申请",
            })
            if res.get("status") != "pending":
                raise AssertionError(f"{aid} 未进入 pending: {res}")
        _ok("批量审批前置 pending 完成")

        batch = await alice.call("group.batch_review_join_request", {
            "group_id": group_batch,
            "requests": [
                {"aid": _BOBB_AID, "approve": True},
                {"aid": _CHARLIE_AID, "approve": False, "reason": "覆盖批量拒绝"},
                {"aid": f"missing-{rid}.{_ISSUER}", "approve": True},
            ],
        })
        if batch.get("success_count") != 2 or batch.get("fail_count") != 1:
            raise AssertionError(f"批量审批计数异常: {batch}")
        _ok("batch_review 混合成功和失败")

        members = (await alice.call("group.get_members", {"group_id": group_batch})).get("members", [])
        if _member_role(members, _BOBB_AID) != "member":
            raise AssertionError(f"批准成员未入群: {members}")
        if _member_role(members, _CHARLIE_AID) is not None:
            raise AssertionError(f"拒绝成员不应入群: {members}")
        _ok("批量审批成员状态正确")
    finally:
        await _cleanup_group(alice, group_question)
        await _cleanup_group(alice, group_batch)
        await _close_all(alice, bobb, charlie, dave)


async def test_invite_codes_ban_and_plaintext_path():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    charlie = _make_client()
    group_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)
        await _ensure_connected(charlie, _CHARLIE_AID)

        group_id = await _create_group(
            alice,
            f"mgmt-invite-ban-{rid}",
            join_mode="invite_only",
        )
        _ok("创建 invite_only 群")

        await _expect_failure(
            lambda: bobb.call("group.request_join", {
                "group_id": group_id,
                "message": "不走邀请码",
            }),
            "invite_only 群拒绝普通申请",
            contains="invite",
        )
        _ok("invite_only request_join 被拒绝")

        custom_code = f"IC-{rid}".upper()
        invite = await alice.call("group.create_invite_code", {
            "group_id": group_id,
            "code": custom_code,
            "max_uses": 1,
            "expires_in_seconds": 3600,
        })
        invite_code = (invite.get("invite_code") or {}).get("code")
        if invite_code != custom_code.lower():
            raise AssertionError(f"邀请码未小写归一: {invite}")
        _ok("自定义邀请码小写归一")

        await _expect_failure(
            lambda: bobb.call("group.list_invite_codes", {"group_id": group_id}),
            "非成员不能列邀请码",
            contains="not a member",
        )
        _ok("list_invite_codes 非成员权限生效")

        listed = await alice.call("group.list_invite_codes", {"group_id": group_id})
        if not any(item.get("code") == invite_code for item in listed.get("items", [])):
            raise AssertionError(f"邀请码列表未包含新码: {listed}")
        _ok("admin 可列邀请码")

        joined = await bobb.call("group.use_invite_code", {
            "code": f"{invite_code}@{_ISSUER}",
        })
        if joined.get("status") != "joined":
            raise AssertionError(f"code@domain 入群失败: {joined}")
        _ok("code@domain 可入群")

        await _expect_failure(
            lambda: bobb.call("group.list_invite_codes", {"group_id": group_id}),
            "普通成员不能列邀请码",
            contains="admin",
        )
        _ok("list_invite_codes 普通成员权限生效")

        await _expect_failure(
            lambda: charlie.call("group.use_invite_code", {"code": invite_code}),
            "max_uses=1 的邀请码耗尽",
            contains="exhausted",
        )
        _ok("邀请码耗尽后拒绝使用")

        revoked = await alice.call("group.create_invite_code", {
            "group_id": group_id,
            "code": f"ic-revoke-{rid}",
            "max_uses": 0,
        })
        revoked_code = (revoked.get("invite_code") or {}).get("code")
        await alice.call("group.revoke_invite_code", {
            "group_id": group_id,
            "code": revoked_code,
        })
        await _expect_failure(
            lambda: charlie.call("group.use_invite_code", {"code": revoked_code}),
            "已撤销邀请码不能使用",
            contains="not active",
        )
        _ok("撤销邀请码生效")

        ban = await alice.call("group.ban", {
            "group_id": group_id,
            "subject": _BOBB_AID,
            "reason": "覆盖封禁路径",
            "expires_in_seconds": 60,
        })
        if (ban.get("ban") or {}).get("subject") != _BOBB_AID:
            raise AssertionError(f"ban 返回异常: {ban}")
        _ok("admin 可封禁成员")

        banlist = await alice.call("group.get_banlist", {"group_id": group_id})
        if not any(item.get("subject") == _BOBB_AID for item in banlist.get("items", [])):
            raise AssertionError(f"banlist 未包含 Bob: {banlist}")
        _ok("get_banlist 包含封禁项")

        await _expect_failure(
            lambda: bobb.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": "banned"},
                "encrypt": False,
            }),
            "被封禁成员不能明文发送",
            contains="banned",
        )
        _ok("封禁阻止明文发送")

        unban = await alice.call("group.unban", {
            "group_id": group_id,
            "subject": _BOBB_AID,
        })
        if unban.get("status") != "removed":
            raise AssertionError(f"unban 返回异常: {unban}")
        _ok("admin 可解封成员")

        sent = await bobb.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"plain-after-unban-{rid}"},
            "encrypt": False,
        })
        if not (sent.get("message") or {}).get("seq"):
            raise AssertionError(f"解封后明文发送失败: {sent}")
        _ok("解封后明文发送不要求 epoch key")
    finally:
        await _cleanup_group(alice, group_id)
        await _close_all(alice, bobb, charlie)


async def test_query_stats_and_dissolve_guards():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    public_gid = ""
    private_gid = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)

        public_gid = await _create_group(
            alice,
            f"mgmt-query-public-{rid}",
            visibility="public",
        )
        private_gid = await _create_group(
            alice,
            f"mgmt-query-private-{rid}",
            visibility="private",
        )
        await alice.call("group.add_member", {"group_id": private_gid, "aid": _BOBB_AID})
        _ok("创建查询/统计测试群")

        got = await alice.call("group.get", {"group_id": public_gid})
        if not got.get("found") or (got.get("group") or {}).get("group_id") != public_gid:
            raise AssertionError(f"group.get 返回异常: {got}")
        _ok("group.get 返回群详情")

        info = await alice.call("group.get_info", {"group_id": public_gid})
        if info.get("group_id") != public_gid or "name" not in info:
            raise AssertionError(f"group.get_info 兼容返回异常: {info}")
        _ok("group.get_info 顶层兼容字段存在")

        public_info = await bobb.call("group.get_public_info", {"group_id": public_gid})
        if (public_info.get("group") or {}).get("group_id") != public_gid:
            raise AssertionError(f"非成员读取 public info 失败: {public_info}")
        _ok("非成员可读取 public info")

        await _expect_failure(
            lambda: bobb.call("group.get_public_info", {"group_id": private_gid}),
            "private 群 get_public_info 被拒绝",
            contains="not public",
        )
        _ok("private 群 public_info 被拒绝")

        mine = await alice.call("group.list_my", {})
        if not any(item.get("group_id") in {public_gid, private_gid} for item in mine.get("items", [])):
            raise AssertionError(f"group.list_my 未包含新建群: {mine}")
        _ok("group.list_my 包含成员索引")

        stats = await alice.call("group.get_stats", {"group_id": private_gid})
        if stats.get("group_id") != private_gid or "member_count" not in stats:
            raise AssertionError(f"owner get_stats 返回异常: {stats}")
        _ok("owner 可读取 get_stats")

        await _expect_failure(
            lambda: bobb.call("group.get_stats", {"group_id": private_gid}),
            "普通成员 get_stats 被拒绝",
            contains="admin",
        )
        _ok("普通成员 get_stats 权限生效")

        await _expect_failure(
            lambda: bobb.call("group.dissolve", {"group_id": private_gid}),
            "非 owner dissolve 被拒绝",
            contains="owner",
        )
        _ok("非 owner dissolve 被拒绝")

        await alice.call("group.suspend", {"group_id": private_gid})
        await _expect_failure(
            lambda: alice.call("group.dissolve", {"group_id": private_gid}),
            "suspended 群不能 dissolve",
            contains="current status",
        )
        _ok("suspended dissolve 前置状态校验生效")
        await alice.call("group.resume", {"group_id": private_gid})
    finally:
        await _cleanup_group(alice, public_gid)
        await _cleanup_group(alice, private_gid)
        await _close_all(alice, bobb)


async def _run_test(name: str, func):
    print(f"\n=== {name} ===")
    try:
        await func()
    except Exception as exc:
        _fail(name, str(exc))
        import traceback
        traceback.print_exc()


async def main():
    print("=== group.management 集成测试 ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOBB_AID}")
    print(f"CHARLIE  = {_CHARLIE_AID}")
    print(f"DAVE     = {_DAVE_AID}")
    print()

    await _run_test("角色/转让/暂停恢复", test_roles_transfer_and_lifecycle)
    await _run_test("入群要求/审批/批量审批", test_join_requirements_and_batch_review)
    await _run_test("邀请码/封禁/明文路径", test_invite_codes_ban_and_plaintext_path)
    await _run_test("查询/统计/dissolve 前置校验", test_query_stats_and_dissolve_guards)

    print(f"\n{'=' * 50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        print("失败详情:")
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
