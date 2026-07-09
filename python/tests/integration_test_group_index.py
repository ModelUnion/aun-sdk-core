#!/usr/bin/env python3
"""group.index 签名索引 + CAS 集成测试。

前置条件：Docker 单域环境运行中。
"""
import asyncio
import os
import sys
import time
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.group_index import (
    GROUP_INDEX_KEY,
    parse_group_index,
    prepare_group_settings_with_index,
    verify_group_index,
)
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_index"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_passed = 0
_failed = 0
_run_id = uuid.uuid4().hex[:8]
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice{_run_id}.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb{_run_id}.{_ISSUER}").strip()


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    await ensure_connected_identity(client, aid)


def _check(name: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  ✅ {name}")
        return
    _failed += 1
    print(f"  ❌ {name}" + (f" — {detail}" if detail else ""))


def _settings_map(result: dict) -> dict:
    return {item.get("key"): item.get("value") for item in result.get("settings", [])}


def _index_from_settings(result: dict) -> object:
    return _settings_map(result).get(GROUP_INDEX_KEY)


def _etag(index_value: object) -> str:
    return str(parse_group_index(index_value)["meta"].get("etag") or "")


async def main() -> None:
    global _failed

    print(f"=== group.index 集成/E2E 测试 (run={_run_id}) ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOB_AID}\n")

    alice = _make_client()
    bob = _make_client()
    group_id = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bob, _BOB_AID)
        print("Alice/Bob 已连接\n")

        create_r = await alice.call("group.create", {
            "name": f"GroupIndex-{_run_id}",
            "visibility": "public",
        })
        group_id = (create_r.get("group") or {}).get("group_id", "")
        _check("测试群已创建", bool(group_id), group_id)

        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOB_AID})
        await alice.call("group.set_role", {"group_id": group_id, "aid": _BOB_AID, "role": "admin"})
        print("Bob 已加入并设为 admin\n")

        print("--- 1. SDK update_group_index 写入签名 group.index ---")
        rules_v1_attachments = [
            {
                "type": "group.fs",
                "path": f"/.group/attachments/rules/rules-v1-{_run_id}.md",
                "name": "rules-v1.md",
            }
        ]
        r1 = await alice.group.update_group_index(
            group_id=group_id,
            settings={
                "rules.content": f"群规 v1 {_run_id}",
                "rules.attachments": rules_v1_attachments,
            },
            last_modified=int(time.time() * 1000),
        )
        _check("updated_keys 含 group.index", GROUP_INDEX_KEY in r1.get("updated_keys", []), str(r1))
        _check("updated_keys 含 rules.content", "rules.content" in r1.get("updated_keys", []), str(r1))
        _check("updated_keys 含 rules.attachments", "rules.attachments" in r1.get("updated_keys", []), str(r1))

        got1 = await bob.group.get_settings(group_id=group_id, keys=[GROUP_INDEX_KEY])
        group_aid = str(got1.get("group_aid") or group_id)
        index1 = _index_from_settings(got1)
        verify1 = verify_group_index(index1, alice.current_aid)
        _check("Bob 可读取 group.index", bool(index1))
        _check("Alice 签名 index 验签通过", bool(verify1.ok and verify1.data.get("valid")), str(verify1))
        _check("Bob 观察到 group.index stale", bob.is_group_index_stale(group_aid))
        bob.mark_group_index_fresh(group_aid, etag=_etag(index1))
        _check("Bob 标记 fresh 后 stale 清除", not bob.is_group_index_stale(group_aid))
        print()

        print("--- 2. 裸写 indexed settings 被拒绝 ---")
        try:
            await alice.group.set_settings(group_id=group_id, settings={"rules.content": "裸写应失败"})
            _check("裸写 rules.content 应失败", False, "没有抛异常")
        except Exception as exc:
            _check("裸写 rules.content 被拒绝", "group.index" in str(exc) or "indexed" in str(exc).lower(), str(exc)[:120])
        print()

        print("--- 3. 旧 etag CAS 冲突返回 SDK ---")
        base_r = await alice.group.get_settings(group_id=group_id, keys=[GROUP_INDEX_KEY])
        base_index = _index_from_settings(base_r)
        base_etag = _etag(base_index)

        alice_update = prepare_group_settings_with_index(
            group_aid=group_aid,
            settings={"rules.content": f"群规 v2 {_run_id}"},
            signer=alice.current_aid,
            last_modified=int(time.time() * 1000),
            base_index=base_index,
        )
        await alice.group.set_settings(group_id=group_id, settings=alice_update, expected_index_etag=base_etag)

        stale_bob_update = prepare_group_settings_with_index(
            group_aid=group_aid,
            settings={"announcement.content": f"公告 stale {_run_id}"},
            signer=bob.current_aid,
            last_modified=int(time.time() * 1000),
            base_index=base_index,
        )
        try:
            await bob.group.set_settings(group_id=group_id, settings=stale_bob_update, expected_index_etag=base_etag)
            _check("旧 etag 写入应 CAS 失败", False, "没有抛异常")
        except Exception as exc:
            _check("旧 etag 写入 CAS 失败", "etag conflict" in str(exc).lower(), str(exc)[:120])
        print()

        print("--- 4. SDK 重新拉取 index 后保存自己的版本 ---")
        r4 = await bob.group.update_group_index(
            group_id=group_id,
            settings={"announcement.content": f"公告 v2 {_run_id}"},
            last_modified=int(time.time() * 1000),
        )
        _check("Bob SDK 重试路径保存成功", GROUP_INDEX_KEY in r4.get("updated_keys", []), str(r4))

        got4 = await alice.group.get_settings(
            group_id=group_id,
            keys=[GROUP_INDEX_KEY, "rules.content", "rules.attachments", "announcement.content"],
        )
        settings4 = _settings_map(got4)
        index4 = settings4.get(GROUP_INDEX_KEY)
        parsed4 = parse_group_index(index4)
        keys4 = {entry.get("key") for entry in parsed4["entries"]}
        verify4 = verify_group_index(index4, bob.current_aid)
        _check("最新 index 由 Bob 签名且验签通过", bool(verify4.ok and verify4.data.get("valid")), str(verify4))
        _check("最新 index 保留 Alice 的 rules.content", "rules.content" in keys4, str(keys4))
        _check("最新 index 保留 Alice 的 rules.attachments", "rules.attachments" in keys4, str(keys4))
        _check("最新 index 包含 Bob 的 announcement.content", "announcement.content" in keys4, str(keys4))
        _check("DB rules.content 是 Alice v2", settings4.get("rules.content") == f"群规 v2 {_run_id}", str(settings4))
        _check("DB rules.attachments 保留 Alice v1", settings4.get("rules.attachments") == rules_v1_attachments, str(settings4))
        _check("DB announcement.content 是 Bob v2", settings4.get("announcement.content") == f"公告 v2 {_run_id}", str(settings4))

    except Exception as exc:
        print(f"\n💥 测试异常: {exc}")
        import traceback
        traceback.print_exc()
        _failed += 1
    finally:
        print("\n--- 清理 ---")
        if group_id:
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
                print(f"  已解散群 {group_id}")
            except Exception as exc:
                print(f"  解散群失败: {exc}")
        await alice.close()
        await bob.close()

    print(f"\n{'=' * 50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _failed:
        sys.exit(1)
    print("全部通过 ✅")


if __name__ == "__main__":
    asyncio.run(main())
