#!/usr/bin/env python3
"""E2E 复现场景：slot_id 变化是否触发不必要的 epoch key request storm。

场景：
  1. Alice + Bob 建群，Alice 发送加密消息（建立 epoch key）
  2. Alice 断开连接
  3. Alice 用不同 slot_id 重连（同 aid/device_id）
  4. 重连后观察：
     - SeqTracker 是否重置？
     - group.pull 是否从 seq=0 拉回旧消息？
     - 旧消息解密是否成功（group secret 仍在本地）？
     - 是否触发了不必要的 _recover_group_epoch_key？

前置条件：
  - Docker 环境运行中
  - AUN_DATA_ROOT 指向持久化数据目录

使用方法：
  AUN_DATA_ROOT="D:/modelunion/kite/docker-deploy/data/sdk-tester-aun" \
    python -X utf8 tests/e2e_test_slot_id_storm.py
"""
import asyncio
import logging
import os
import re
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.e2ee import load_all_group_secrets

# ---------------------------------------------------------------------------
# 日志配置 — 打开 SDK 内部 DIAG 日志
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
# 只显示 aun_core.client 的 INFO+（DIAG 日志在 INFO 级别）
logging.getLogger("aun_core.client").setLevel(logging.DEBUG)
# 降低其他噪音
for name in ("aun_core.transport", "aun_core.e2ee", "websockets", "asyncio"):
    logging.getLogger(name).setLevel(logging.WARNING)

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


def _normalize(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    return text.strip("-._") or "slot"


def _run_id() -> str:
    return uuid.uuid4().hex[:12]


def _make_client(tag: str, rid: str, *, slot_suffix: str = "") -> AUNClient:
    """创建测试客户端。slot_suffix 用于生成不同的 slot_id。"""
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    base = f"{_normalize(tag)}-{_normalize(rid)}"
    slot_id = f"{base}{slot_suffix}" if slot_suffix else base
    client._test_slot_id = slot_id[:128]
    client._test_group_inbox = {}

    def _collect_group_msg(data):
        if not isinstance(data, dict):
            return
        gid = data.get("group_id", "")
        if gid:
            client._test_group_inbox.setdefault(gid, []).append(data)

    client._dispatcher.subscribe("group.message_created", _collect_group_msg)

    # 追踪 undecryptable 事件
    client._test_undecryptable = []
    client._dispatcher.subscribe("group.message_undecryptable", lambda d: client._test_undecryptable.append(d))

    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    connect_params = dict(auth)
    slot_id = str(getattr(client, "_test_slot_id", "") or "")
    if slot_id:
        connect_params["slot_id"] = slot_id
    connect_params["auto_reconnect"] = False
    await client.connect(connect_params)
    print(f"  连接成功: {aid} slot_id={slot_id} device_id={client._device_id}")
    return aid


async def _create_group(client: AUNClient, name: str) -> str:
    result = await client.call("group.create", {"name": name})
    return result["group"]["group_id"]


async def _add_member(client: AUNClient, group_id: str, member_aid: str) -> None:
    await client.call("group.add_member", {"group_id": group_id, "aid": member_aid})


# ---------------------------------------------------------------------------
# 测试主体
# ---------------------------------------------------------------------------

async def test_slot_id_change_storm():
    """复现场景：slot_id 变化是否触发 epoch key request storm。"""
    print("\n" + "=" * 70)
    print("E2E: slot_id 变化 epoch key request storm 复现")
    print("=" * 70)

    rid = _run_id()
    alice_1 = _make_client("alice", rid, slot_suffix="-v1")
    bob = _make_client("bob", rid)

    try:
        # Step 1: Alice(slot-v1) + Bob 建群
        print("\n--- Step 1: 建群 + 发消息（建立 epoch key）---")
        a_aid = await _ensure_connected(alice_1, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice_1, f"storm-test-{rid}")
        print(f"  建群成功: {group_id}")

        await _add_member(alice_1, group_id, b_aid)
        await asyncio.sleep(2)

        # 发送几条加密群消息
        for i in range(3):
            await alice_1.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": f"消息-{i}"},
                "encrypt": True,
            })
            await asyncio.sleep(0.5)
        print(f"  Alice 发送 3 条加密消息")

        await asyncio.sleep(2)

        # 确认 Alice 本地有 group secret
        local_secrets = load_all_group_secrets(alice_1._keystore, a_aid, group_id)
        print(f"  Alice 本地 epoch keys: {sorted(local_secrets.keys())}")
        assert local_secrets, "Alice 应该有本地 group secret"

        # 记录 Alice 当前 slot_id 和 seq 状态
        old_slot = alice_1._slot_id
        old_seq_state = alice_1._seq_tracker.export_state()
        print(f"  Alice slot_id={old_slot}, seq_state={old_seq_state}")

        # Step 2: Alice 断开
        print("\n--- Step 2: Alice 断开连接 ---")
        await alice_1.close()
        print(f"  Alice 已断开")

        # Step 3: Alice 用不同 slot_id 重连
        print("\n--- Step 3: Alice 用不同 slot_id 重连 ---")
        alice_2 = _make_client("alice", rid, slot_suffix="-v2")

        print(f"  新 slot_id={alice_2._test_slot_id}")
        print(f"  期望：SeqTracker 重置 → group.pull 从 seq=0 拉回旧消息")
        print(f"  期望：group secret 仍在本地 → 不应触发 recover")
        print()
        print("  ⬇⬇⬇ 以下 DIAG 日志将显示实际行为 ⬇⬇⬇")
        print()

        a_aid_2 = await _ensure_connected(alice_2, _ALICE_AID)

        # 确认重连后 group secret 仍在本地
        local_secrets_2 = load_all_group_secrets(alice_2._keystore, a_aid_2, group_id)
        print(f"\n  重连后 Alice 本地 epoch keys: {sorted(local_secrets_2.keys())}")

        new_slot = alice_2._slot_id
        new_seq_state = alice_2._seq_tracker.export_state()
        print(f"  重连后 slot_id={new_slot}, seq_state={new_seq_state}")

        # 等待推送消息到达 + 自动解密
        await asyncio.sleep(5)

        # Step 4: 分析结果
        print("\n--- Step 4: 分析 ---")
        inbox = alice_2._test_group_inbox.get(group_id, [])
        undecryptable = alice_2._test_undecryptable
        print(f"  收到群消息数: {len(inbox)}")
        print(f"  undecryptable 事件数: {len(undecryptable)}")

        decrypted_ok = [m for m in inbox if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        decrypted_fail = [m for m in inbox if not m.get("e2ee")]
        print(f"  成功解密: {len(decrypted_ok)}")
        print(f"  解密失败（密文泄露到应用层）: {len(decrypted_fail)}")

        if undecryptable:
            print("\n  ⚠️ 存在 undecryptable 消息 — 说明 decrypt 失败触发了不必要的 recover!")
            for u in undecryptable[:5]:
                print(f"    seq={u.get('seq')} from={u.get('from')} error={u.get('_decrypt_error')}")

        if decrypted_fail:
            print("\n  ⚠️ 存在解密失败的消息泄露到应用层!")

        # 也主动 pull 一次看看
        print("\n--- Step 5: 主动 group.pull（after_seq=0）---")
        pull_result = await alice_2.call("group.pull", {
            "group_id": group_id,
            "after_message_seq": 0,
        })
        pulled_msgs = pull_result.get("messages", [])
        print(f"  pull 返回消息数: {len(pulled_msgs)}")
        for m in pulled_msgs[:5]:
            p = m.get("payload", {})
            print(f"    seq={m.get('seq')} type={p.get('type') if isinstance(p, dict) else type(p).__name__} "
                  f"epoch={p.get('epoch') if isinstance(p, dict) else 'N/A'} "
                  f"e2ee={bool(m.get('e2ee'))}")

        print("\n" + "=" * 70)
        if not undecryptable and not decrypted_fail:
            print("✅ 无 epoch key request storm — slot_id 变化后解密仍正常")
        else:
            print("❌ 存在问题 — 需要根据上方 DIAG 日志分析根因")
        print("=" * 70)

        return not undecryptable and not decrypted_fail

    except Exception as e:
        print(f"\n❌ 测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            await alice_1.close()
        except Exception:
            pass
        try:
            await alice_2.close()
        except Exception:
            pass
        try:
            await bob.close()
        except Exception:
            pass


if __name__ == "__main__":
    success = asyncio.run(test_slot_id_change_storm())
    sys.exit(0 if success else 1)
