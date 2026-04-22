#!/usr/bin/env python3
"""group.search 集成测试 — 验证搜索参数兼容性和结果正确性。

覆盖：
  - 空参数搜索（列出 public 群）
  - query 参数搜索
  - keyword 参数搜索（兼容别名）
  - q 参数搜索（兼容别名）
  - 创建 public 群后能被搜索到
  - 创建 private 群后不会被搜索到

使用方法（Docker 容器内）：
  MSYS_NO_PATHCONV=1 docker exec kite-sdk-tester python /tests/integration_test_group_search.py

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

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_group_search"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()

# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0
_run_id = uuid.uuid4().hex[:8]


def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return aid


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

    print(f"=== group.search 集成测试 (run={_run_id}) ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    print(f"ALICE    = {_ALICE_AID}")
    print()

    client = _make_client()
    try:
        await _ensure_connected(client, _ALICE_AID)
        print(f"Alice 已连接\n")

        # ── 1. 空参数搜索 ──
        print("--- 1. 空参数搜索 ---")
        r1 = await client.call("group.search", {})
        items1 = r1.get("items", [])
        _check("空参数返回列表", isinstance(items1, list))
        _check("query 字段为空字符串", r1.get("query", None) == "")
        print(f"  返回 {len(items1)} 条\n")

        # ── 2. 创建一个 public 群 ──
        unique_name = f"SearchTest-{_run_id}"
        print(f"--- 2. 创建 public 群: {unique_name} ---")
        create_r = await client.call("group.create", {
            "name": unique_name,
            "visibility": "public",
        })
        group_id = (create_r.get("group") or {}).get("group_id", "")
        _check("群已创建", bool(group_id), f"group_id={group_id}")
        print()

        # ── 3. 创建一个 private 群 ──
        private_name = f"PrivateSearch-{_run_id}"
        print(f"--- 3. 创建 private 群: {private_name} ---")
        create_p = await client.call("group.create", {
            "name": private_name,
            "visibility": "private",
        })
        private_gid = (create_p.get("group") or {}).get("group_id", "")
        _check("private 群已创建", bool(private_gid))
        print()

        # 等待索引生效
        await asyncio.sleep(0.5)

        # ── 4. query 参数搜索 ──
        print(f"--- 4. query=\"{unique_name}\" ---")
        r_query = await client.call("group.search", {"query": unique_name})
        items_query = r_query.get("items", [])
        _check("query 字段回显正确", r_query.get("query") == unique_name)
        found_by_query = any(g.get("group_id") == group_id for g in items_query)
        _check("query 能搜到 public 群", found_by_query,
               f"返回 {len(items_query)} 条")
        private_in_query = any(g.get("group_id") == private_gid for g in items_query)
        _check("query 搜不到 private 群", not private_in_query)
        print()

        # ── 5. keyword 参数搜索（兼容别名）──
        print(f"--- 5. keyword=\"{unique_name}\" ---")
        r_kw = await client.call("group.search", {"keyword": unique_name})
        items_kw = r_kw.get("items", [])
        _check("keyword 字段回显正确（映射到 query）", r_kw.get("query") == unique_name)
        found_by_kw = any(g.get("group_id") == group_id for g in items_kw)
        _check("keyword 能搜到 public 群", found_by_kw,
               f"返回 {len(items_kw)} 条")
        print()

        # ── 6. q 参数搜索（兼容别名）──
        print(f"--- 6. q=\"{unique_name}\" ---")
        r_q = await client.call("group.search", {"q": unique_name})
        items_q = r_q.get("items", [])
        _check("q 字段回显正确", r_q.get("query") == unique_name)
        found_by_q = any(g.get("group_id") == group_id for g in items_q)
        _check("q 能搜到 public 群", found_by_q,
               f"返回 {len(items_q)} 条")
        print()

        # ── 7. 搜索不存在的关键词 ──
        nonsense = f"zzznoexist-{_run_id}"
        print(f"--- 7. query=\"{nonsense}\" ---")
        r_none = await client.call("group.search", {"query": nonsense})
        items_none = r_none.get("items", [])
        _check("不存在的关键词返回 0 条", len(items_none) == 0,
               f"返回 {len(items_none)} 条")
        print()

        # ── 8. size 限制 ──
        print("--- 8. size=1 ---")
        r_size = await client.call("group.search", {"size": 1})
        items_size = r_size.get("items", [])
        _check("size=1 最多返回 1 条", len(items_size) <= 1,
               f"返回 {len(items_size)} 条")
        print()

        # ── 清理：解散测试群 ──
        print("--- 清理 ---")
        try:
            await client.call("group.dissolve", {"group_id": group_id})
            print(f"  已解散 public 群 {group_id}")
        except Exception as e:
            print(f"  解散 public 群失败: {e}")
        try:
            await client.call("group.dissolve", {"group_id": private_gid})
            print(f"  已解散 private 群 {private_gid}")
        except Exception as e:
            print(f"  解散 private 群失败: {e}")

    except Exception as exc:
        print(f"\n💥 测试异常: {exc}")
        import traceback
        traceback.print_exc()
        _failed += 1
    finally:
        await client.close()

    print(f"\n{'='*50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _failed:
        sys.exit(1)
    print("全部通过 ✅")


if __name__ == "__main__":
    asyncio.run(main())
