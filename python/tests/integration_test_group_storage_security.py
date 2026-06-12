#!/usr/bin/env python3
"""批次 A · TDD 红灯先行：group-storage 安全边界真实集成测试

在 kite-sdk-tester 容器内连真实服务端运行：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester \
    python /tests/integration_test_group_storage_security.py

对应审查发现（docs/aun-fs/group-storage/2026-06-11-group-storage-审查发现与修复清单.md）：
- F12 (TEST-08)：群自有区写必须由 owner/admin，普通成员/非成员写被拒。
- F13 (TEST-02)：memberdata 访问真实触发 group.check_membership，退群后实时失效。
- F15 (TEST-03)：越权挂他人槽位、挂非 {aid}/{group_id} 源被拒（storage 侧真实拒绝）。
- F04 (GRP-04)：fs_mount 不校验 source_path 为 {source_aid}/{group_id} 格式 → 红灯坐实漏洞。
- CG1/CG2：CA 中 normal 类型但名字像 group 的 AID 不能冒充 group owner；MemberData/MEMBERDATA 大小写变体不能绕过。

红灯说明：F04/F15 的部分断言在修复落地前预期 FAIL，
用于真实坐实当前实现存在安全缺口（连真实服务端，非 mock）。
每个测试独立标注 [EXPECT-RED]（修复前应失败）/ [GUARD]（应已通过）。
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AIDStore, AUNClient  # noqa: E402
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path  # noqa: E402

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get(
    "AUN_TEST_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/persistent" if _AUN_DATA_ROOT else "./.aun_test_group_storage_security",
).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_SEED = os.environ.get("AUN_TEST_ENCRYPTION_SEED", "")
pytestmark = pytest.mark.asyncio

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} - {reason}")
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raise AssertionError(reason)


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


def _make_store() -> AIDStore:
    return AIDStore(_TEST_AUN_PATH, encryption_seed=_SEED, verify_ssl=False)


async def _rpc(client: AUNClient, method: str, params: dict[str, Any]) -> dict[str, Any]:
    result = await client.call(method, params)
    if not isinstance(result, dict):
        raise AssertionError(f"{method} 返回非对象: {result!r}")
    if isinstance(result.get("error"), dict):
        raise RuntimeError(f"{method} 失败: {result['error']}")
    return result


def _is_denied(exc: Exception) -> bool:
    """判断异常是否为明确权限/签名/证书拒绝，避免把格式或 not found 误判为安全通过。"""
    msg = str(exc).lower()
    needles = (
        "permission denied",
        "denied",
        "forbidden",
        "unauthorized",
        "owner required",
        "admin required",
        "not a member",
        "not_member",
        "signature",
        "certificate",
        "cert fingerprint",
        "cert mismatch",
        "rekey",
        "不是群成员",
        "权限",
        "无权",
    )
    return any(n in msg for n in needles)


async def _setup_named_group(owner: AUNClient, owner_store: AIDStore, rid: str) -> tuple[str, str]:
    """建命名群 + 初始化命名空间，返回 (group_id, group_aid)。"""
    created = await owner.create_group(
        {
            "name": f"gst-sec-{rid}",
            "group_name": f"gstsec{rid}",
            "visibility": "private",
        },
        aid_store=owner_store,
    )
    group = created.get("group") or {}
    group_id = str(group.get("group_id") or "").strip()
    group_aid = str(group.get("group_aid") or "").strip()
    if not group_id or not group_aid:
        raise AssertionError(f"create_group 未返回 group_id/group_aid: {created}")
    namespace = await owner.group.resources.initialize_namespace(
        group_id=group_id,
        group_aid=group_aid,
        aid_store=owner_store,
    )
    if not namespace.get("namespace_ready"):
        raise AssertionError(f"namespace_ready 返回异常: {namespace}")
    return group_id, group_aid


# ---------------------------------------------------------------------------
# F12 (TEST-08) — 三条铁律：群自有区写必须 owner/admin，普通成员/非成员被拒
# ---------------------------------------------------------------------------
async def test_f12_member_cannot_write_group_own_region() -> None:
    """[GUARD] 普通成员对 announce 自有区发起 group_storage 写，应被 group 服务拒绝。"""
    name = "f12_member_cannot_write_group_own_region"
    rid = uuid.uuid4().hex[:8]
    owner = _make_client()
    member = _make_client()
    owner_store = _make_store()
    member_aid = f"gstsec-mem-{rid}.{_ISSUER}"
    group_id = ""
    try:
        await ensure_connected_identity(owner, f"gstsec-own-{rid}.{_ISSUER}")
        await ensure_connected_identity(member, member_aid)
        group_id, _gaid = await _setup_named_group(owner, owner_store, rid)
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": member_aid, "role": "member"})

        # 普通成员尝试写群自有区（announce）—— 应被拒
        try:
            await member.group.resources.put({
                "group_id": group_id,
                "resource_path": f"announce/intruder-{rid}.txt",
                "resource_type": "file",
                "title": "intruder.txt",
                "content": "aW50cnVkZXI=",  # base64("intruder")
                "content_type": "text/plain",
                "visibility": "members_only",
            })
        except Exception as exc:  # noqa: BLE001
            if _is_denied(exc):
                _ok(name)
            else:
                _fail(name, f"成员写被拒但错误非权限类: {exc!r}")
            return
        _fail(name, "普通成员竟成功对群自有区发起写（应被拒绝）")
    finally:
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await member.close()
        await owner.close()


async def test_f12_non_member_cannot_write_group_own_region() -> None:
    """[GUARD] 非成员对群自有区发起 group_storage 写，应被拒。"""
    name = "f12_non_member_cannot_write_group_own_region"
    rid = uuid.uuid4().hex[:8]
    owner = _make_client()
    outsider = _make_client()
    owner_store = _make_store()
    group_id = ""
    try:
        await ensure_connected_identity(owner, f"gstsec-own2-{rid}.{_ISSUER}")
        await ensure_connected_identity(outsider, f"gstsec-out-{rid}.{_ISSUER}")
        group_id, _gaid = await _setup_named_group(owner, owner_store, rid)

        try:
            await outsider.group.resources.put({
                "group_id": group_id,
                "resource_path": f"announce/outsider-{rid}.txt",
                "resource_type": "file",
                "title": "outsider.txt",
                "content": "b3V0c2lkZXI=",
                "content_type": "text/plain",
                "visibility": "members_only",
            })
        except Exception as exc:  # noqa: BLE001
            if _is_denied(exc):
                _ok(name)
            else:
                _fail(name, f"非成员写被拒但错误非权限类: {exc!r}")
            return
        _fail(name, "非成员竟成功对群自有区发起写（应被拒绝）")
    finally:
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await outsider.close()
        await owner.close()


# ---------------------------------------------------------------------------
# CG1/CG2 — aid_type 强制链路 + memberdata 大小写绕过真实集成负向
# ---------------------------------------------------------------------------
async def test_cg1_normal_group_like_aid_cannot_impersonate_group_owner() -> None:
    """[GUARD] normal aid_type 的 AID 不能被其他 AID 当作群 owner 写 memberdata。"""
    name = "cg1_normal_group_like_aid_cannot_impersonate_group_owner"
    rid = uuid.uuid4().hex[:8]
    normal_owner = _make_client()
    alice = _make_client()
    normal_owner_aid = f"grp-normal-{rid}.{_ISSUER}"
    alice_aid = f"gstsec-alice-normal-{rid}.{_ISSUER}"

    async def _expect_denied(label: str, call) -> None:
        try:
            await call()
        except Exception as exc:  # noqa: BLE001
            if _is_denied(exc):
                return
            _fail(name, f"{label} 被拒但错误非权限/约束类: {exc!r}")
            return
        _fail(name, f"{label} 竟成功，normal AID 冒充 group owner 未被拒绝")

    try:
        await ensure_connected_identity(normal_owner, normal_owner_aid)
        await ensure_connected_identity(alice, alice_aid)
        await alice.call("storage.fs.mkdir", {
            "owner_aid": alice_aid,
            "bucket": "default",
            "path": f"{alice_aid}/{normal_owner_aid}",
            "parents": True,
        })

        await _expect_denied(
            "MemberData mount",
            lambda: alice.call("storage.fs.mount", {
                "owner_aid": normal_owner_aid,
                "bucket": "default",
                "mount_path": f"MemberData/{alice_aid}",
                "source_aid": alice_aid,
                "source_path": f"{alice_aid}/{normal_owner_aid}",
                "readonly": False,
            }),
        )
        await _expect_denied(
            "MEMBERDATA put",
            lambda: alice.call("storage.put_object", {
                "owner_aid": normal_owner_aid,
                "bucket": "default",
                "object_key": f"MEMBERDATA/{alice_aid}/probe.txt",
                "content": "cHJvYmU=",
                "content_type": "text/plain",
            }),
        )
        _ok(name)
    finally:
        await alice.close()
        await normal_owner.close()


# ---------------------------------------------------------------------------
# F15 (TEST-03) — memberdata 路径约束：越权挂他人槽位 / 挂他人卷被 storage 真实拒绝
# ---------------------------------------------------------------------------
async def test_f15_member_cannot_mount_into_others_slot() -> None:
    """[GUARD] alice 把 mount_path 指向 memberdata/{bob}，storage 应拒绝（非自己槽位）。"""
    name = "f15_member_cannot_mount_into_others_slot"
    rid = uuid.uuid4().hex[:8]
    owner = _make_client()
    alice = _make_client()
    bob = _make_client()
    owner_store = _make_store()
    alice_aid = f"gstsec-alice-{rid}.{_ISSUER}"
    bob_aid = f"gstsec-bob-{rid}.{_ISSUER}"
    group_id = ""
    try:
        await ensure_connected_identity(owner, f"gstsec-own3-{rid}.{_ISSUER}")
        await ensure_connected_identity(alice, alice_aid)
        await ensure_connected_identity(bob, bob_aid)
        group_id, group_aid = await _setup_named_group(owner, owner_store, rid)
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": alice_aid, "role": "member"})
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": bob_aid, "role": "member"})

        # alice 试图挂进 bob 的槽位
        try:
            await alice.call("storage.fs.mount", {
                "owner_aid": group_aid,
                "mount_path": f"memberdata/{bob_aid}",
                "source_aid": alice_aid,
                "source_path": f"{alice_aid}/{group_id}",
                "readonly": False,
            })
        except Exception as exc:  # noqa: BLE001
            if _is_denied(exc):
                _ok(name)
            else:
                _fail(name, f"挂他人槽位被拒但错误非约束类: {exc!r}")
            return
        _fail(name, "alice 竟成功挂进 bob 的 memberdata 槽位（应被拒绝）")
    finally:
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await alice.close()
        await bob.close()
        await owner.close()


async def test_f04_member_cannot_mount_arbitrary_source_path() -> None:
    """[EXPECT-RED] F04：源应固定指向 {aid}/{group_id}，但当前 fs_mount 不校验 source_path 格式。

    设计 §4.4：「挂载源固定指向成员自己空间的 {aid}/{group_id}」。
    alice 把 source_path 指向自己空间的任意目录（private-stuff），
    storage 应拒绝；修复前预期此挂载成功 → 红灯坐实漏洞。
    """
    name = "f04_member_cannot_mount_arbitrary_source_path"
    rid = uuid.uuid4().hex[:8]
    owner = _make_client()
    alice = _make_client()
    owner_store = _make_store()
    alice_aid = f"gstsec-alice2-{rid}.{_ISSUER}"
    group_id = ""
    mount_ok = False
    try:
        await ensure_connected_identity(owner, f"gstsec-own4-{rid}.{_ISSUER}")
        await ensure_connected_identity(alice, alice_aid)
        group_id, group_aid = await _setup_named_group(owner, owner_store, rid)
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": alice_aid, "role": "member"})

        # alice 在自己空间建一个与本群无关的任意目录
        await alice.call("storage.fs.mkdir", {
            "owner_aid": alice_aid,
            "path": f"private-stuff-{rid}",
            "parents": True,
        })

        # 把这个任意目录挂进自己的 memberdata 槽位（违反 {aid}/{group_id} 约束）
        try:
            await alice.call("storage.fs.mount", {
                "owner_aid": group_aid,
                "mount_path": f"memberdata/{alice_aid}",
                "source_aid": alice_aid,
                "source_path": f"private-stuff-{rid}",  # ← 不是 {alice_aid}/{group_id}
                "readonly": False,
            })
            mount_ok = True
        except Exception as exc:  # noqa: BLE001
            if _is_denied(exc):
                _ok(name)
                return
            _fail(name, f"挂任意源被拒但错误非约束类: {exc!r}")
            return
        if mount_ok:
            _fail(name, "[RED] alice 成功把任意目录挂进 memberdata（缺 source_path 格式校验，F04 漏洞坐实）")
    finally:
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await alice.close()
        await owner.close()


# ---------------------------------------------------------------------------
# F13 (TEST-02) — memberdata 访问真实触发 check_membership，退群后实时失效
# ---------------------------------------------------------------------------
async def test_f13_membership_realtime_invalidation_after_leave() -> None:
    """[GUARD] alice 挂载后退群，再访问挂载点应实时失效（check_membership 返回 false）。"""
    name = "f13_membership_realtime_invalidation_after_leave"
    rid = uuid.uuid4().hex[:8]
    owner = _make_client()
    alice = _make_client()
    owner_store = _make_store()
    alice_aid = f"gstsec-alice3-{rid}.{_ISSUER}"
    group_id = ""
    try:
        await ensure_connected_identity(owner, f"gstsec-own5-{rid}.{_ISSUER}")
        await ensure_connected_identity(alice, alice_aid)
        group_id, group_aid = await _setup_named_group(owner, owner_store, rid)
        await _rpc(owner, "group.add_member", {"group_id": group_id, "aid": alice_aid, "role": "member"})

        # alice 建群专属源目录并挂载（源根固定为 {alice_aid}/{group_aid}）
        source_root = f"{alice_aid}/{group_aid}"
        await alice.call("storage.fs.mkdir", {
            "owner_aid": alice_aid,
            "path": source_root,
            "parents": True,
        })
        try:
            await alice.call("storage.fs.mount", {
                "owner_aid": group_aid,
                "mount_path": f"memberdata/{alice_aid}",
                "source_aid": alice_aid,
                "source_path": source_root,
                "readonly": False,
            })
        except Exception as exc:  # noqa: BLE001
            _fail(name, f"合法挂载意外失败，无法验证退群失效: {exc!r}")
            return

        # 挂载后访问应成功
        await alice.call("storage.fs.stat", {"owner_aid": group_aid, "path": f"memberdata/{alice_aid}"})

        # alice 退群
        await _rpc(alice, "group.leave", {"group_id": group_id})

        # 退群后再访问挂载点 —— 应实时失效。
        # 失效语义可能为：(a) check_membership 返回 false → PermissionError；
        # (b) 退群联动清理挂载点 → NotFoundError。两者都达成"退群即无法访问"的安全目标。
        try:
            await alice.call("storage.fs.stat", {"owner_aid": group_aid, "path": f"memberdata/{alice_aid}"})
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            not_found = ("not" in msg and "found" in msg) or ("不存在" in msg)
            if _is_denied(exc) or not_found:
                _ok(name)
            else:
                _fail(name, f"退群后访问失败但错误语义异常: {exc!r}")
            return
        _fail(name, "alice 退群后仍能访问 memberdata 挂载点（check_membership 未实时失效）")
    finally:
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await alice.close()
        await owner.close()


# ---------------------------------------------------------------------------
# F01 (GRP-001) — confirm 拒绝过期 pending op（op_id 自包含时间戳）
# ---------------------------------------------------------------------------
async def test_f01_confirm_rejects_expired_pending_op() -> None:
    """[GUARD] 用过期 op_id 调 confirm，应被拒（TTL 校验）。"""
    name = "f01_confirm_rejects_expired_pending_op"
    rid = uuid.uuid4().hex[:8]
    owner = _make_client()
    owner_store = _make_store()
    group_id = ""
    try:
        await ensure_connected_identity(owner, f"gstsec-own6-{rid}.{_ISSUER}")
        group_id, group_aid = await _setup_named_group(owner, owner_store, rid)

        # 构造一个远超 TTL 的过期 op_id（格式 gso_{issued_ms}_{hex}）
        stale_ms = 1_000_000_000_000  # 2001 年，远超任何 TTL
        stale_op_id = f"gso_{stale_ms}_{rid}"

        loaded_group = owner_store.load(group_aid)
        if not getattr(loaded_group, "ok", False) or not getattr(loaded_group, "data", None):
            raise AssertionError(f"未能加载 group_identity: {group_aid}")
        group_identity = loaded_group.data.get("aid") if isinstance(loaded_group.data, dict) else None
        if group_identity is None:
            raise AssertionError(f"group_identity 记录缺少 aid 对象: {group_aid}")

        group_signer = AUNClient(group_identity)
        await group_signer.connect({"heartbeat_interval": 0})
        try:
            await group_signer.group.resources.confirm({
                "group_id": group_id,
                "group_aid": group_aid,
                "op_id": stale_op_id,
                "operation": "put",
                "resource_path": f"announce/stale-{rid}.txt",
                "resource_type": "file",
                "confirm_key": "op_0",
                "storage_result": {"object_id": "obj_fake", "version": 1},
            })
        except Exception as exc:  # noqa: BLE001
            if "expired" in str(exc).lower() or "过期" in str(exc):
                _ok(name)
            else:
                _fail(name, f"confirm 被拒但错误非过期类: {exc!r}")
            return
        finally:
            await group_signer.close()
        _fail(name, "confirm 接受了过期 op_id（TTL 校验未生效）")
    finally:
        if group_id:
            try:
                await _rpc(owner, "group.dissolve", {"group_id": group_id})
            except Exception:
                pass
        owner_store.close()
        await owner.close()


async def main() -> None:
    print("=== AUN group-storage 安全边界集成测试（批次 A 红灯）===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    tests = [
        ("f12_member_cannot_write_group_own_region", test_f12_member_cannot_write_group_own_region),
        ("f12_non_member_cannot_write_group_own_region", test_f12_non_member_cannot_write_group_own_region),
        ("cg1_normal_group_like_aid_cannot_impersonate_group_owner", test_cg1_normal_group_like_aid_cannot_impersonate_group_owner),
        ("f15_member_cannot_mount_into_others_slot", test_f15_member_cannot_mount_into_others_slot),
        ("f04_member_cannot_mount_arbitrary_source_path", test_f04_member_cannot_mount_arbitrary_source_path),
        ("f13_membership_realtime_invalidation_after_leave", test_f13_membership_realtime_invalidation_after_leave),
        ("f01_confirm_rejects_expired_pending_op", test_f01_confirm_rejects_expired_pending_op),
    ]
    for tname, fn in tests:
        try:
            await fn()
        except Exception as exc:  # noqa: BLE001
            _fail(tname, f"测试自身异常: {exc!r}")

    print("=" * 60)
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
