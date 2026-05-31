#!/usr/bin/env python3
"""group.set_settings / group.get_settings / group.info 集成测试。

覆盖：
  1. set_settings 写入 groups 表字段（name, visibility）
  2. set_settings 写入 settings 表字段（rules.content, announcement.content, duty.config）
  3. set_settings 混合写入
  4. set_settings 未知 key 被拒绝
  5. set_settings 非管理员被拒绝
  6. get_settings 全量读取
  7. get_settings keys 过滤读取
  8. info 基本信息（成员视角）
  9. info include=["stats"]
  10. info 非成员看公开群
  11. info 非成员看私有群被拒
  12. 老方法写入 → 新方法能读到（兼容性）
  13. 新方法写入 → 老方法能读到（兼容性）
  14. 老方法返回含 _deprecated 字段
  15. visibility=invite_only 向后兼容映射到 private
  16. info include=["metrics"] 仅 admin 可见

使用方法：
  AUN_DATA_ROOT="D:/modelunion/kite/docker-deploy/data/sdk-tester-aun" \
    python -X utf8 tests/integration_test_group_settings.py

前置条件：
  - Docker 单域环境运行中
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
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_settings"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0
_run_id = uuid.uuid4().hex[:8]


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    return await ensure_connected_identity(client, aid)


def _check(name: str, condition: bool, detail: str = ""):
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  ✅ {name}")
    else:
        _failed += 1
        msg = f"  ❌ {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def main():
    global _passed, _failed

    print(f"=== group.settings 集成测试 (run={_run_id}) ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOBB_AID}")
    print()

    alice = _make_client()
    bob = _make_client()
    group_id = ""
    private_gid = ""

    try:
        await _ensure_connected(alice, _ALICE_AID)
        print("Alice 已连接")
        await _ensure_connected(bob, _BOBB_AID)
        print("Bob 已连接\n")

        # ── 创建测试群 ──
        unique_name = f"SettingsTest-{_run_id}"
        print(f"--- 创建 public 测试群: {unique_name} ---")
        create_r = await alice.call("group.create", {
            "name": unique_name,
            "visibility": "public",
        })
        group_id = (create_r.get("group") or {}).get("group_id", "")
        _check("public 群已创建", bool(group_id), f"group_id={group_id}")

        # 创建 private 群用于 info 非成员拒绝测试
        private_name = f"PrivSettings-{_run_id}"
        create_p = await alice.call("group.create", {
            "name": private_name,
            "visibility": "private",
        })
        private_gid = (create_p.get("group") or {}).get("group_id", "")
        _check("private 群已创建", bool(private_gid))

        # Bob 加入 public 群
        await alice.call("group.add_member", {"group_id": group_id, "aid": _BOBB_AID})
        print()

        # ── 1. set_settings: groups 表字段 ──
        print("--- 1. set_settings: name + visibility ---")
        new_name = f"Renamed-{_run_id}"
        r1 = await alice.call("group.set_settings", {
            "group_id": group_id,
            "settings": {
                "name": new_name,
                "description": "集成测试描述",
            },
        })
        _check("set_settings 返回 group_id", r1.get("group_id") == group_id)
        _check("updated_keys 包含 name", "name" in r1.get("updated_keys", []))
        _check("updated_keys 包含 description", "description" in r1.get("updated_keys", []))
        print()

        # ── 2. set_settings: settings 表字段 ──
        print("--- 2. set_settings: rules.content + announcement.content ---")
        r2 = await alice.call("group.set_settings", {
            "group_id": group_id,
            "settings": {
                "rules.content": "请遵守测试群规",
                "announcement.content": "欢迎来到测试群",
            },
        })
        _check("set rules+announcement 成功", r2.get("group_id") == group_id)
        _check("updated_keys 含 rules.content",
               "rules.content" in r2.get("updated_keys", []))
        print()

        # ── 3. set_settings: 混合写入 ──
        print("--- 3. set_settings: 混合写入（name + duty.config）---")
        r3 = await alice.call("group.set_settings", {
            "group_id": group_id,
            "settings": {
                "name": f"Mixed-{_run_id}",
                "duty.config": {"duty_mode": "fixed", "duty_fixed_agents": ["bot.aid"]},
            },
        })
        _check("混合写入成功", r3.get("group_id") == group_id)
        _check("updated_keys 含 name", "name" in r3.get("updated_keys", []))
        _check("updated_keys 含 duty.config", "duty.config" in r3.get("updated_keys", []))
        print()

        # ── 4. set_settings: 未知 key 被拒 ──
        print("--- 4. set_settings: 未知 key ---")
        try:
            await alice.call("group.set_settings", {
                "group_id": group_id,
                "settings": {"nonexistent_key": "value"},
            })
            _check("未知 key 应该被拒绝", False, "没有抛异常")
        except Exception as exc:
            _check("未知 key 被拒绝", "unknown" in str(exc).lower(),
                   str(exc)[:80])
        print()

        # ── 5. set_settings: 非管理员被拒 ──
        print("--- 5. set_settings: Bob（非管理员）被拒 ---")
        try:
            await bob.call("group.set_settings", {
                "group_id": group_id,
                "settings": {"name": "Hacked"},
            })
            _check("非管理员应该被拒绝", False, "没有抛异常")
        except Exception as exc:
            _check("非管理员被拒绝", True, str(exc)[:80])
        print()

        # ── 6. get_settings: 全量 ──
        print("--- 6. get_settings: 全量 ---")
        r6 = await alice.call("group.get_settings", {"group_id": group_id})
        settings_list = r6.get("settings", [])
        keys_returned = {s["key"] for s in settings_list}
        _check("返回 group_id", r6.get("group_id") == group_id)
        _check("含 name", "name" in keys_returned)
        _check("含 visibility", "visibility" in keys_returned)
        _check("含 rules.content", "rules.content" in keys_returned)
        _check("含 announcement.content", "announcement.content" in keys_returned)
        _check("含 duty.config", "duty.config" in keys_returned)

        # 验证值正确性
        settings_map = {s["key"]: s["value"] for s in settings_list}
        _check("name 值正确", settings_map.get("name") == f"Mixed-{_run_id}",
               f"got: {settings_map.get('name')}")
        _check("rules.content 值正确", settings_map.get("rules.content") == "请遵守测试群规",
               f"got: {settings_map.get('rules.content')}")
        _check("announcement.content 值正确",
               settings_map.get("announcement.content") == "欢迎来到测试群",
               f"got: {settings_map.get('announcement.content')}")
        print()

        # ── 7. get_settings: keys 过滤 ──
        print("--- 7. get_settings: keys 过滤 ---")
        r7 = await alice.call("group.get_settings", {
            "group_id": group_id,
            "keys": ["name", "rules.content"],
        })
        keys_7 = {s["key"] for s in r7.get("settings", [])}
        _check("仅返回请求的 keys", keys_7 == {"name", "rules.content"},
               f"got: {keys_7}")
        print()

        # ── 8. info: 成员视角 ──
        print("--- 8. info: 成员视角 ---")
        r8 = await alice.call("group.info", {"group_id": group_id})
        _check("info 返回 group_id", r8.get("group_id") == group_id)
        _check("info 含 name", r8.get("name") == f"Mixed-{_run_id}")
        _check("info 含 owner_aid", r8.get("owner_aid") == _ALICE_AID)
        _check("info 含 member_count", isinstance(r8.get("member_count"), int))
        _check("info 含 message_seq", "message_seq" in r8)
        _check("info 含 updated_at", "updated_at" in r8)
        print()

        # ── 9. info: include=["stats"] ──
        print("--- 9. info: include=[\"stats\"] ---")
        r9 = await alice.call("group.info", {
            "group_id": group_id,
            "include": ["stats"],
        })
        stats = r9.get("stats", {})
        _check("stats 存在", isinstance(stats, dict) and len(stats) > 0)
        _check("stats.human_count >= 0", stats.get("human_count", -1) >= 0)
        _check("stats.admin_count >= 0", stats.get("admin_count", -1) >= 0)
        # Alice 是 owner/admin，应看到额外字段
        _check("admin 可见 pending_join_request_count",
               "pending_join_request_count" in stats)
        _check("admin 可见 ban_count", "ban_count" in stats)
        print()

        # ── 10. info: 非成员看公开群 ──
        print("--- 10. info: 非成员看公开群 ---")
        # Bob 不在 private 群里，但 public 群他是成员。用 private_gid 不行因为它是 private。
        # 创建另一个 public 群，Bob 不加入
        pub2_name = f"PubNoMember-{_run_id}"
        cr_pub2 = await alice.call("group.create", {
            "name": pub2_name,
            "visibility": "public",
        })
        pub2_gid = (cr_pub2.get("group") or {}).get("group_id", "")
        r10 = await bob.call("group.info", {"group_id": pub2_gid})
        _check("非成员能看公开群基础信息", r10.get("group_id") == pub2_gid)
        _check("非成员看到 name", r10.get("name") == pub2_name)
        _check("非成员看不到 owner_aid", "owner_aid" not in r10)
        # 清理（dissolve 可能因 leaderboard 事件失败，忽略）
        try:
            await alice.call("group.dissolve", {"group_id": pub2_gid})
        except Exception:
            pass
        print()

        # ── 11. info: 非成员看私有群被拒 ──
        print("--- 11. info: 非成员看私有群被拒 ---")
        try:
            await bob.call("group.info", {"group_id": private_gid})
            _check("非成员看私有群应被拒", False, "没有抛异常")
        except Exception as exc:
            _check("非成员看私有群被拒", True, str(exc)[:80])
        print()

        # ── 12. 老方法写 → 新方法读（兼容性）──
        print("--- 12. 老方法写 → 新方法读 ---")
        await alice.call("group.update_rules", {
            "group_id": group_id,
            "content": "老方法写的群规",
        })
        r12 = await alice.call("group.get_settings", {
            "group_id": group_id,
            "keys": ["rules.content"],
        })
        rules_from_new = None
        for s in r12.get("settings", []):
            if s["key"] == "rules.content":
                rules_from_new = s["value"]
        _check("新方法能读到老方法写的群规",
               rules_from_new == "老方法写的群规",
               f"got: {rules_from_new}")
        print()

        # ── 13. 新方法写 → 老方法读（兼容性）──
        print("--- 13. 新方法写 → 老方法读 ---")
        await alice.call("group.set_settings", {
            "group_id": group_id,
            "settings": {"rules.content": "新方法写的群规"},
        })
        r13 = await alice.call("group.get_rules", {"group_id": group_id})
        _check("老方法能读到新方法写的群规",
               r13.get("rules", {}).get("content") == "新方法写的群规",
               f"got: {r13.get('rules', {}).get('content')}")
        print()

        # ── 14. 老方法返回 _deprecated ──
        print("--- 14. 老方法返回 _deprecated ---")
        r14_rules = await alice.call("group.update_rules", {
            "group_id": group_id,
            "content": "再次写入",
        })
        _check("update_rules 返回含 _deprecated",
               "_deprecated" in r14_rules,
               f"keys: {list(r14_rules.keys())}")

        r14_ann = await alice.call("group.get_announcement", {"group_id": group_id})
        _check("get_announcement 返回含 _deprecated",
               "_deprecated" in r14_ann,
               f"keys: {list(r14_ann.keys())}")
        print()

        # ── 15. invite_only 向后兼容 ──
        print("--- 15. visibility=invite_only 向后兼容 ---")
        await alice.call("group.set_settings", {
            "group_id": group_id,
            "settings": {"visibility": "invite_only"},
        })
        r15 = await alice.call("group.get_settings", {
            "group_id": group_id,
            "keys": ["visibility"],
        })
        visibility_value = None
        for s in r15.get("settings", []):
            if s["key"] == "visibility":
                visibility_value = s["value"]
        _check("invite_only 被映射为 private", visibility_value == "private",
               f"got: {visibility_value}")
        print()

        # ── 16. info: metrics 仅 admin 可见 ──
        print("--- 16. info: metrics 仅 admin 可见 ---")
        r16 = await alice.call("group.info", {
            "group_id": group_id,
            "include": ["metrics"],
        })
        _check("admin 可见 metrics", "metrics" in r16,
               f"keys: {list(r16.keys())}")
        try:
            await bob.call("group.info", {
                "group_id": group_id,
                "include": ["metrics"],
            })
            _check("非 admin 应被拒绝 metrics", False, "没有抛异常")
        except Exception as exc:
            _check("非 admin 被拒绝 metrics", True, str(exc)[:80])
        print()

    except Exception as exc:
        print(f"\n💥 测试异常: {exc}")
        import traceback
        traceback.print_exc()
        _failed += 1
    finally:
        # 清理
        print("--- 清理 ---")
        for gid, label in [(group_id, "public"), (private_gid, "private")]:
            if gid:
                try:
                    await alice.call("group.dissolve", {"group_id": gid})
                    print(f"  已解散 {label} 群 {gid}")
                except Exception as e:
                    print(f"  解散 {label} 群失败: {e}")
        await alice.close()
        await bob.close()

    print(f"\n{'='*50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _failed:
        sys.exit(1)
    print("全部通过 ✅")


if __name__ == "__main__":
    asyncio.run(main())

