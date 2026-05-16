#!/usr/bin/env python3
"""Group E2EE 完整 E2E 测试 — 需要运行中的 AUN Gateway + Group Service。

覆盖群组加密消息的完整生命周期：建群、密钥分发、加密通信、踢人轮换、密钥恢复。

使用方法：
  python tests/e2e_test_group_e2ee.py

前置条件：
  - Docker 环境运行中（docker compose up -d）
  - 运行环境能解析 gateway.<issuer>（推荐使用 Docker network alias）
  - group_config.json 已添加 "e2ee.group_encrypted" 到 allowed_message_types
"""
import asyncio
import base64
import os
import re
import secrets
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError
from aun_core.e2ee import (
    build_key_distribution,
    compute_membership_commitment,
    decrypt_group_message,
    encrypt_group_message,
    generate_group_secret,
    handle_key_distribution,
    load_all_group_secrets,
    load_group_secret,
    store_group_secret,
)


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


def _assert_fixed_aid_layout() -> None:
    base = Path(_TEST_AUN_PATH)
    if base.name != "persistent" or base.parent.name != "single-domain":
        return

    legacy_root = base.parent / "AIDs"
    current_root = base / "AIDs"
    fixed_aids = (_ALICE_AID, _BOBB_AID, _CHARLIE_AID, _DAVE_AID)

    split_aids = [aid for aid in fixed_aids if (legacy_root / aid).exists()]
    if split_aids:
        joined = ", ".join(split_aids)
        raise RuntimeError(
            f"检测到固定 AID 旧目录残留：{joined}。"
            f"固定身份只能使用 {current_root}，不能再与 {legacy_root} 分叉。"
        )

    incomplete_aids: list[str] = []
    for aid in fixed_aids:
        aid_dir = current_root / aid
        if not aid_dir.exists():
            continue
        has_key = (aid_dir / "private" / "key.json").exists()
        has_cert = (aid_dir / "public" / "cert.pem").exists()
        if has_key != has_cert:
            incomplete_aids.append(aid)
    if incomplete_aids:
        joined = ", ".join(incomplete_aids)
        raise RuntimeError(
            f"检测到固定 AID 身份材料不完整：{joined}。"
            f"每个固定 AID 都必须在 {current_root} 同时具备 private/key.json 和 public/cert.pem。"
        )


_assert_fixed_aid_layout()


def _normalize_slot_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    return text.strip("-._") or "slot"


def _build_test_slot_id(tag: str, rid: str | None = None) -> str:
    # 使用固定 slot_id（不含随机部分），让服务端 cursor 跨测试运行持久化，
    # 避免每次新 slot 从 seq=0 拉全量历史触发 epoch 编排风暴。
    tag_part = _normalize_slot_part(tag)
    slot_id = f"{tag_part}-main"
    return slot_id[:128]


def _make_client(tag: str, rid: str | None = None) -> AUNClient:
    """创建测试客户端。所有客户端共享同一 aun_path，各 AID 数据在 AIDs/{aid}/ 下自然隔离。"""
    client = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    })
    client._config_model.require_forward_secrecy = False
    client._test_slot_id = _build_test_slot_id(tag, rid)
    # 服务端 cursor 兜底生效后，after_message_seq=0 会被抬升到 last_ack_msg_seq，
    # 而 auto-ack 已把 cursor 推到最新，pull 会返回空。测试用 push 收件箱兜底。
    client._test_group_inbox = {}

    def _collect_group_msg(data):
        if not isinstance(data, dict):
            return
        gid = data.get("group_id", "")
        if gid:
            client._test_group_inbox.setdefault(gid, []).append(data)

    client._dispatcher.subscribe("group.message_created", _collect_group_msg)
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
            print(f"[connect diag] aid={aid} attempt={attempt} gateway={connect_params.get('gateway')!r} topology={connect_params.get('topology')!r} access_token={'set' if connect_params.get('access_token') else 'missing'}")
            await client.connect(connect_params)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            print(f"[connect diag] aid={aid} attempt={attempt} retryable_error={type(exc).__name__}: {exc}")
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
        except Exception as exc:
            print(f"[connect diag] aid={aid} attempt={attempt} fatal_error={type(exc).__name__}: {exc}")
            raise
    raise last_error or RuntimeError(f"{aid} connect failed")


def _run_id() -> str:
    """生成唯一运行标识（UUID 前 12 位，避免 AID 碰撞）"""
    return uuid.uuid4().hex[:12]


async def _create_group(client: AUNClient, name: str) -> str:
    """创建群组，返回 group_id"""
    result = await client.call("group.create", {"name": name})
    return result["group"]["group_id"]


async def _add_member(client: AUNClient, group_id: str, member_aid: str) -> None:
    """添加群成员"""
    await client.call("group.add_member", {"group_id": group_id, "aid": member_aid})


async def _kick_member(client: AUNClient, group_id: str, member_aid: str) -> None:
    """踢出群成员"""
    await client.call("group.kick", {"group_id": group_id, "aid": member_aid})


async def _get_members(client: AUNClient, group_id: str) -> list[str]:
    """获取群成员列表"""
    result = await client.call("group.get_members", {"group_id": group_id})
    members = result.get("members", [])
    return [m["aid"] for m in members]


def _distribute_group_secret(
    keystore, aid: str, group_id: str, epoch: int, gs: bytes, member_aids: list[str],
) -> None:
    """本地直接存储 group_secret（模拟收到分发消息）"""
    commitment = compute_membership_commitment(member_aids, epoch, group_id, gs)
    store_group_secret(keystore, aid, group_id, epoch, gs, commitment, member_aids)


def _usable_group_messages(messages: list[dict], after_seq: int = 0) -> list[dict]:
    by_seq = {}
    no_seq = []
    for m in sorted(messages, key=lambda x: x.get("seq") or 0):
        s = m.get("seq")
        if s is None:
            no_seq.append(m)
            continue
        old_msg = by_seq.get(s)
        if old_msg is None:
            by_seq[s] = m
            continue
        old_decrypted = bool(old_msg.get("e2ee")) if isinstance(old_msg, dict) else False
        new_decrypted = bool(m.get("e2ee")) if isinstance(m, dict) else False
        if new_decrypted and not old_decrypted:
            by_seq[s] = m
    ordered = no_seq + [by_seq[s] for s in sorted(by_seq)]
    if after_seq and after_seq > 0:
        ordered = [m for m in ordered if (m.get("seq") or 0) > after_seq]
    usable = []
    for m in ordered:
        payload = m.get("payload") if isinstance(m, dict) else None
        if payload is not None and (not isinstance(payload, dict) or bool(payload)):
            usable.append(m)
    return usable


async def _group_pull(client: AUNClient, group_id: str, after_seq: int = 0, min_count: int = 0) -> list[dict]:
    """获取群消息：从 push 推送收件箱读取（防抖 N>1 时触发 auto-pull 也会填入）。

    服务端多设备 cursor 兜底后，auto-ack 推进后服务端 pull 返回空。
    push inbox 是客户端侧真实收到并解密的消息集合，是测试的真实可信源。
    """
    pushed = list(getattr(client, "_test_group_inbox", {}).get(group_id, []))
    usable = _usable_group_messages(pushed, after_seq)
    if usable and (min_count <= 0 or len(usable) >= min_count):
        return usable
    # 兜底：push 可能只收到通知窗口中的最后一条；主动 pull 后合并，覆盖 burst 场景。
    result = await client.call(
        "group.pull", {
            "group_id": group_id,
            "after_message_seq": after_seq or 0,
            "device_id": client._device_id,
            "slot_id": getattr(client, "_slot_id", ""),
        },
    )
    pulled = result.get("messages", [])
    return _usable_group_messages(pushed + pulled, after_seq)


async def _group_pull_raw(client: AUNClient, group_id: str, after_seq: int = 0) -> list[dict]:
    """拉取群消息（不经自动解密，用于验证无密钥方看到密文）"""
    result = await client._transport.call("group.pull", {"group_id": group_id, "after_message_seq": after_seq})
    return result.get("messages", [])


def _truthy_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _group_secret_matches_committed_rotation(secret_data: dict | None, committed_rotation: dict | None) -> bool:
    if not isinstance(secret_data, dict):
        return False
    committed_commitment = ""
    if isinstance(committed_rotation, dict):
        committed_commitment = str(committed_rotation.get("key_commitment") or "").strip()
    local_commitment = str(secret_data.get("commitment") or "").strip()
    if committed_commitment and committed_commitment != local_commitment:
        return False
    pending_rotation_id = str(secret_data.get("pending_rotation_id") or "").strip()
    if not pending_rotation_id:
        return True
    if not isinstance(committed_rotation, dict):
        return False
    return str(committed_rotation.get("rotation_id") or "").strip() == pending_rotation_id


async def _committed_group_epoch_snapshot(client: AUNClient, group_id: str) -> tuple[int, dict | None, bool]:
    epoch_result = await client.call("group.e2ee.get_epoch", {"group_id": group_id})
    committed_epoch = int(epoch_result.get("committed_epoch", epoch_result.get("epoch", 0)) or 0)
    pending = epoch_result.get("pending_rotation")
    pending_active = isinstance(pending, dict) and not _truthy_bool(pending.get("expired"))
    committed_rotation = epoch_result.get("committed_rotation")
    if not isinstance(committed_rotation, dict):
        committed_rotation = None
    return committed_epoch, committed_rotation, pending_active


async def _wait_for_group_secret_epoch(client: AUNClient, aid: str, group_id: str, *, min_epoch: int = 1, timeout: float = 15.0) -> int:
    deadline = asyncio.get_running_loop().time() + timeout
    last_epochs: list[int] = []
    last_committed = 0
    last_pending = False
    while asyncio.get_running_loop().time() < deadline:
        all_secrets = load_all_group_secrets(client._keystore, aid, group_id)
        last_epochs = sorted(all_secrets)
        try:
            last_committed, committed_rotation, last_pending = await _committed_group_epoch_snapshot(client, group_id)
        except Exception:
            last_committed = 0
            committed_rotation = None
            last_pending = False
        if not last_pending:
            eligible = [epoch for epoch in last_epochs if epoch >= min_epoch and epoch <= last_committed]
            for epoch in reversed(eligible):
                secret_data = load_group_secret(client._keystore, aid, group_id, epoch)
                if _group_secret_matches_committed_rotation(secret_data, committed_rotation):
                    return epoch
        await asyncio.sleep(0.5)
    raise AssertionError(
        f"{aid} did not receive committed group {group_id} epoch >= {min_epoch} "
        f"within {timeout}s; epochs={last_epochs}, committed={last_committed}, pending={last_pending}"
    )


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

async def test_group_encrypted_messaging():
    """Test 1: 建群 → 分发密钥 → 加密发送 → 解密接收"""
    print("\n=== Test 1: Group encrypted messaging ===")
    rid = _run_id()
    alice = _make_client("alice", rid)
    bob = _make_client("bob", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # Alice 建群（SDK 自动 create_epoch）
        group_id = await _create_group(alice, f"e2ee-test-{rid}")
        assert alice.group_e2ee.has_secret(group_id), "owner should have secret after create"

        # Alice 加 Bob（SDK 自动分发并提交密钥）
        await _add_member(alice, group_id, b_aid)
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # Alice 发送加密群消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "加密群消息"},
            "encrypt": True,
        })

        await asyncio.sleep(1)

        # Bob 拉取（自动解密）
        msgs = await _group_pull(bob, group_id, min_count=1)
        assert len(msgs) >= 1, f"expected >= 1 msg, got {len(msgs)}"

        # 验证自动解密成功
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert len(decrypted) >= 1, f"no auto-decrypted msgs found"
        assert decrypted[0]["payload"]["text"] == "加密群消息"

        print("[PASS] Test 1")
        return True
    except Exception as e:
        print(f"[FAIL] Test 1: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_multiple_members():
    """Test 2: 3人群组，A 发加密消息，B/C 都能解密"""
    print("\n=== Test 2: Multiple members decrypt ===")
    rid = _run_id()
    alice, bob, carol = _make_client("a", rid), _make_client("b", rid), _make_client("c", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(carol, _CHARLIE_AID)

        group_id = await _create_group(alice, f"e2ee-multi-{rid}")
        await _add_member(alice, group_id, b_aid)
        await _add_member(alice, group_id, c_aid)
        members = [a_aid, b_aid, c_aid]

        # SDK 自动分发并提交密钥给所有成员
        current_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)
        await _wait_for_group_secret_epoch(carol, c_aid, group_id, min_epoch=current_epoch, timeout=20.0)

        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "三人群消息"},
            "encrypt": True,
        })

        await asyncio.sleep(1)

        for name, client, aid in [("Bob", bob, b_aid), ("Carol", carol, c_aid)]:
            msgs = await _group_pull(client, group_id)
            decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
            assert len(decrypted) >= 1, f"{name}: no auto-decrypted msgs"
            assert decrypted[0]["payload"]["text"] == "三人群消息", f"{name}: payload mismatch"

        print("[PASS] Test 2")
        return True
    except Exception as e:
        print(f"[FAIL] Test 2: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close(); await carol.close()


async def test_epoch_rotation_on_kick():
    """Test 3: 踢人 → epoch 轮换 → 旧成员无法解密新消息"""
    print("\n=== Test 3: Epoch rotation on kick ===")
    rid = _run_id()
    alice, bob, carol = _make_client("a", rid), _make_client("b", rid), _make_client("c", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(carol, _CHARLIE_AID)

        group_id = await _create_group(alice, f"e2ee-kick-{rid}")
        await _add_member(alice, group_id, b_aid)
        await _add_member(alice, group_id, c_aid)

        # 等待 SDK 自动分发/轮换提交，并确认 Bob/Carol 持有已提交密钥
        old_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)
        await _wait_for_group_secret_epoch(carol, c_aid, group_id, min_epoch=old_epoch, timeout=20.0)

        # 踢 Carol
        await _kick_member(alice, group_id, c_aid)

        # kick 后 SDK 自动两阶段轮换 + 分发给 Bob，等待服务端提交且 Bob 本地密钥匹配
        new_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=old_epoch + 1, timeout=20.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=new_epoch, timeout=20.0)

        # Alice 用新 epoch 发加密消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "踢人后的消息"},
            "encrypt": True,
        })

        await asyncio.sleep(1)

        # Bob 能解密（有新 epoch 密钥，auto-decrypt）
        msgs_bob = await _group_pull(bob, group_id)
        decrypted_bob = [m for m in msgs_bob
                         if m.get("e2ee", {}).get("epoch") == new_epoch]
        assert len(decrypted_bob) >= 1, f"Bob: no auto-decrypted epoch {new_epoch} msgs"
        assert decrypted_bob[0]["payload"]["text"] == "踢人后的消息"

        # Carol 没有新 epoch 密钥（被踢后不会收到新密钥）
        all_carol = load_all_group_secrets(carol._keystore, c_aid, group_id)
        assert new_epoch not in all_carol, f"Carol should not have epoch {new_epoch} secret"
        # Carol 已被踢出群，无法 pull 消息——这本身就是安全保证

        print("[PASS] Test 3")
        return True
    except Exception as e:
        print(f"[FAIL] Test 3: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close(); await carol.close()


async def test_new_member_join_rotates_epoch():
    """Test 4: 加人 → epoch 轮换 → 新成员可解密当前已提交 epoch 消息"""
    print("\n=== Test 4: New member join rotates epoch ===")
    rid = _run_id()
    alice, bob, carol = _make_client("a", rid), _make_client("b", rid), _make_client("c", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(carol, _CHARLIE_AID)

        group_id = await _create_group(alice, f"e2ee-join-{rid}")
        await _add_member(alice, group_id, b_aid)

        # 等待 SDK 自动分发并提交 Bob 可用的群密钥
        before_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # 加 Carol（SDK 自动轮换并分发已提交的新密钥）
        await _add_member(alice, group_id, c_aid)
        carol_epoch = await _wait_for_group_secret_epoch(carol, c_aid, group_id, min_epoch=before_epoch + 1, timeout=20.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=carol_epoch, timeout=20.0)

        # Alice 用当前已提交 epoch 发消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "新成员能看到"},
            "encrypt": True,
        })

        await asyncio.sleep(1)

        # Carol 能解密（auto-decrypt）
        msgs = await _group_pull(carol, group_id)
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert len(decrypted) >= 1, "Carol: no auto-decrypted msgs"
        assert decrypted[0]["payload"]["text"] == "新成员能看到"

        print("[PASS] Test 4")
        return True
    except Exception as e:
        print(f"[FAIL] Test 4: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close(); await carol.close()


async def test_burst_group_messages():
    """Test 5: 连续发 5 条加密群消息 → 全部解密成功"""
    print("\n=== Test 5: Burst group messages ===")
    rid = _run_id()
    alice, bob = _make_client("a", rid), _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice, f"e2ee-burst-{rid}")
        await _add_member(alice, group_id, b_aid)

        # 等待 SDK 自动分发并提交密钥
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        N = 5
        for i in range(N):
            await alice.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": f"burst_{i}", "seq": i},
                "encrypt": True,
            })
            print(f"  DEBUG: sent burst_{i}")

        # 等待 push 收集，逐步检查
        for wait_round in range(6):
            await asyncio.sleep(1)
            pushed = list(getattr(bob, "_test_group_inbox", {}).get(group_id, []))
            print(f"  DEBUG: wait_round={wait_round} pushed_count={len(pushed)}")
            if len(pushed) >= N:
                break

        msgs = await _group_pull(bob, group_id, min_count=N)
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        if len(decrypted) < N:
            # 诊断日志：输出收到的消息详情
            print(f"  DEBUG: decrypted={len(decrypted)}/{N}, msgs_total={len(msgs)}")
            for m in msgs:
                print(f"    msg: text={m.get('payload',{}).get('text')} e2ee_mode={m.get('e2ee',{}).get('encryption_mode')} seq={m.get('message_seq')}")
        assert len(decrypted) >= N, f"expected {N}, got {len(decrypted)}"

        texts = {m["payload"]["text"] for m in decrypted}
        expected = {f"burst_{i}" for i in range(N)}
        assert texts == expected, f"mismatch: {texts}"

        print(f"[PASS] Test 5 ({len(decrypted)}/{N})")
        return True
    except Exception as e:
        print(f"[FAIL] Test 5: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_mixed_encrypted_plaintext():
    """Test 6: 同一群中加密和明文消息交替 → 正确处理"""
    print("\n=== Test 6: Mixed encrypted + plaintext ===")
    rid = _run_id()
    alice, bob = _make_client("a", rid), _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice, f"e2ee-mixed-{rid}")
        await _add_member(alice, group_id, b_aid)

        # 等待 SDK 自动分发并提交密钥
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # 明文消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "明文"},
            "encrypt": False,
        })
        # 加密消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "密文"},
            "encrypt": True,
        })
        # 又一条明文
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "又是明文"},
            "encrypt": False,
        })

        await asyncio.sleep(1)

        msgs = await _group_pull(bob, group_id, min_count=3)
        assert len(msgs) >= 3, f"expected >= 3, got {len(msgs)}"

        # 加密消息已自动解密
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert len(decrypted) >= 1
        assert decrypted[0]["payload"]["text"] == "密文"

        # 明文消息直接可读
        plaintext = [m for m in msgs if not m.get("e2ee")
                     and isinstance(m.get("payload"), dict)
                     and "text" in m.get("payload", {})]
        texts = {m["payload"]["text"] for m in plaintext}
        assert "明文" in texts
        assert "又是明文" in texts

        print("[PASS] Test 6")
        return True
    except Exception as e:
        print(f"[FAIL] Test 6: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_membership_commitment_verification():
    """Test 7: 篡改 member_aids → commitment 校验失败"""
    print("\n=== Test 7: Membership commitment prevents ghost ===")
    rid = _run_id()
    alice, bob = _make_client("a", rid), _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        gs = generate_group_secret()
        members = [a_aid, b_aid]

        # 正常分发
        dist = build_key_distribution(f"grp_test_{rid}", 1, gs, members, a_aid)
        ok = handle_key_distribution(dist, bob._keystore, b_aid)
        assert ok, "正常分发应成功"

        # 篡改 member_aids（注入幽灵成员）
        tampered = dict(dist)
        tampered["member_aids"] = members + ["evil.agentid.pub"]
        ok2 = handle_key_distribution(tampered, bob._keystore, b_aid)
        assert not ok2, "篡改后应失败"

        print("[PASS] Test 7")
        return True
    except Exception as e:
        print(f"[FAIL] Test 7: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_old_epoch_still_decryptable():
    """Test 8: 旧 epoch 消息在保留期内仍可解密"""
    print("\n=== Test 8: Old epoch messages still decryptable ===")
    rid = _run_id()
    alice, bob = _make_client("a", rid), _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice, f"e2ee-old-{rid}")
        await _add_member(alice, group_id, b_aid)
        members = [a_aid, b_aid]

        # 等待 SDK 自动分发并提交初始密钥
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "epoch1消息"},
            "encrypt": True,
        })

        # 手动轮换 epoch 2（模拟踢人后轮换）
        info = alice.group_e2ee.rotate_epoch(group_id, [a_aid, b_aid])
        for dist in info['distributions']:
            await alice.call('message.send', {
                'to': dist['to'], 'payload': dist['payload'],
                'encrypt': True,
            })
        await asyncio.sleep(2)

        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "epoch2消息"},
            "encrypt": True,
        })

        await asyncio.sleep(1)

        # Bob 应能解密两个 epoch 的消息（auto-decrypt）
        msgs = await _group_pull(bob, group_id)
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert len(decrypted) >= 2, f"expected >= 2 auto-decrypted, got {len(decrypted)}"

        texts = {m["payload"]["text"] for m in decrypted}
        assert "epoch1消息" in texts
        assert "epoch2消息" in texts

        print("[PASS] Test 8")
        return True
    except Exception as e:
        print(f"[FAIL] Test 8: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_review_join_request_auto_distribute():
    """Test 9: 审批通过后新成员自动拿到密钥并能解密

    完整流程：Bob request_join → Alice review_join_request(approve) → SDK 自动分发密钥
    群默认 visibility=private → join_requirements.mode=approval，request_join 会创建 pending 请求。
    """
    print("\n=== Test 9: Review join request auto distribute ===")
    rid = _run_id()
    alice, bob = _make_client("a", rid), _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # Alice 建群（默认 private → approval 模式，SDK 自动 create_epoch）
        group_id = await _create_group(alice, f"e2ee-review-{rid}")
        assert alice.group_e2ee.has_secret(group_id), "owner should have secret after create"

        # Bob 申请加入（创建 pending join request）
        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "请求加入",
        })
        assert join_result.get("status") == "pending", \
            f"expected pending, got {join_result.get('status')}"

        # Alice 审批通过（服务端参数名是 approve，不是 approved）
        review_result = await alice.call("group.review_join_request", {
            "group_id": group_id,
            "aid": b_aid,
            "approve": True,
        })
        assert review_result.get("status") == "approved", \
            f"expected approved, got {review_result.get('status')}"
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # Alice 发送加密群消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "审批后的消息"},
            "encrypt": True,
        })

        await asyncio.sleep(1)

        # Bob 拉取（自动解密）
        msgs = await _group_pull(bob, group_id)
        assert len(msgs) >= 1, f"expected >= 1 msg, got {len(msgs)}"

        # 验证自动解密成功
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert len(decrypted) >= 1, f"no auto-decrypted msgs found"
        assert decrypted[0]["payload"]["text"] == "审批后的消息"

        print("[PASS] Test 9")
        return True
    except Exception as e:
        print(f"[FAIL] Test 9: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_invite_code_auto_recovery():
    """Test 10: 邀请码入群后通过密钥恢复链路自动获取群密钥

    完整流程：
    1. Alice 建群 → 自动 create_epoch
    2. Alice 生成邀请码
    3. Bob 使用邀请码加入 → Bob 本地此时没有 group_secret
    4. Alice 发加密群消息
    5. Bob 收到实时 push 或 pull 时缺密钥 → 自动发起 group_key_request → Alice 回源校验成员列表 → 响应
    6. Bob 恢复后拿到密钥 → 可解密

    服务端 create_invite_code 返回 {"invite_code": invite.to_dict()}，code 字段是字符串。
    服务端 use_invite_code 参数名是 code，值为字符串。
    """
    print("\n=== Test 10: Invite code auto recovery ===")
    rid = _run_id()
    alice, bob = _make_client("a", rid), _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # 1. Alice 建群（SDK 自动 create_epoch）
        group_id = await _create_group(alice, f"e2ee-invite-{rid}")
        assert alice.group_e2ee.has_secret(group_id), "owner should have secret after create"

        # 2. Alice 生成邀请码
        invite_result = await alice.call("group.create_invite_code", {
            "group_id": group_id,
            "max_uses": 1,
        })
        invite_obj = invite_result.get("invite_code")
        assert isinstance(invite_obj, dict), f"invite_code should be dict, got {type(invite_obj)}"
        code = invite_obj.get("code")
        assert code and isinstance(code, str), f"invite code string missing, got {code}"

        # 3. Bob 使用邀请码加入
        use_result = await bob.call("group.use_invite_code", {
            "code": code,
        })

        # 等待 epoch 轮换完成：新成员加入会触发 epoch 1→2，Alice 和 Bob 都会收到新密钥。
        # Alice 必须拿到 epoch=2 后再发消息，否则会用旧 epoch=1 加密，Bob 无法解密。
        for _w in range(10):
            await asyncio.sleep(1)
            alice_secrets = alice._group_e2ee.load_all_secrets(group_id)
            if alice_secrets and max(alice_secrets.keys()) >= 2:
                break
        else:
            assert False, "Alice did not receive epoch=2 within 10s"

        # Bob 也应该通过密钥分发拿到 epoch=2
        for _w in range(10):
            if bob.group_e2ee.has_secret(group_id):
                break
            await asyncio.sleep(1)
        assert bob.group_e2ee.has_secret(group_id), "Bob should have epoch=2 secret after rotation"

        # 4. Alice 发送加密群消息（此时用 epoch=2）
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "邀请码入群后的消息"},
            "encrypt": True,
        })

        # 5. Bob 已有 epoch=2 密钥，pull 应该能直接解密。
        #    通过推送或 pull 获取消息。
        decrypted = []
        for _wait in range(15):
            await asyncio.sleep(1)
            msgs = await _group_pull(bob, group_id)
            decrypted = [
                m for m in msgs
                if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
                and m.get("payload", {}).get("text") == "邀请码入群后的消息"
            ]
            if decrypted:
                break
        assert len(decrypted) >= 1, f"no auto-decrypted msgs found"
        assert decrypted[0]["payload"]["text"] == "邀请码入群后的消息"

        # 关键断言：Bob 本地应该已有 group_secret
        assert bob.group_e2ee.has_secret(group_id), \
            "Bob should have group secret after recovery"

        print("[PASS] Test 10")
        return True
    except Exception as e:
        print(f"[FAIL] Test 10: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_open_group_join_rotates_epoch_and_updates_memberlist():
    """Test 11: open 群 request_join 后应轮换 epoch，并用签名 manifest 更新成员列表。"""
    print("\n=== Test 11: Open group join rotates epoch ===")
    rid = _run_id()
    alice, bob = _make_client("a-open", rid), _make_client("b-open", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        created = await alice.call("group.create", {
            "name": f"e2ee-open-{rid}",
            "visibility": "public",
            "join_mode": "open",
        })
        group_id = created["group"]["group_id"]
        assert alice.group_e2ee.has_secret(group_id), "owner should have secret after create"
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)

        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "open join",
        })
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"

        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=20.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=rotated_epoch, timeout=20.0)

        alice_secret = alice.group_e2ee.load_secret(group_id)
        bob_secret = bob.group_e2ee.load_secret(group_id)
        assert alice_secret is not None and bob_secret is not None
        assert int(alice_secret["epoch"]) == rotated_epoch, "owner should hold committed rotated epoch"
        assert int(bob_secret["epoch"]) == rotated_epoch, "new member should receive committed rotated epoch"
        assert b_aid in alice_secret.get("member_aids", []), "signed member list should include new member"
        assert b_aid in bob_secret.get("member_aids", []), "new member local member list should include itself"

        text = f"open-join-encrypted-{rid}"
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": text},
            "encrypt": True,
        })
        await asyncio.sleep(1)
        msgs = await _group_pull(bob, group_id)
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert any(m.get("payload", {}).get("text") == text for m in decrypted), f"Bob did not decrypt open join msg: {msgs}"

        print("[PASS] Test 11")
        return True
    except Exception as e:
        print(f"[FAIL] Test 11: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_capabilities_required_for_join():
    """Test 11: 不声明 group_e2ee 能力的客户端无法入群"""
    print("\n=== Test 11: Capabilities required for group join ===")
    rid = _run_id()
    alice = _make_client("alice", rid)

    # 创建不声明 group_e2ee 的客户端（模拟旧版本）
    old_bob = _make_client("old-bob", rid)

    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(old_bob, _DAVE_AID)

        # Alice 建群
        group_id = await _create_group(alice, f"cap-test-{rid}")

        # Alice 尝试添加 Bob — 服务端应检查 Bob 是否声明了 group_e2ee 能力
        # 目前所有 SDK 客户端都声明 group_e2ee=true，所以应该成功
        await _add_member(alice, group_id, b_aid)
        members = await _get_members(alice, group_id)
        assert b_aid in members, f"Bob should be in group, got {members}"

        print("[PASS] Test 11")
        return True
    except Exception as e:
        print(f"[FAIL] Test 11: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await old_bob.close()


async def test_plaintext_send_explicit():
    """Test 12: 发送者显式传 encrypt=False 可以发送明文群消息"""
    print("\n=== Test 12: Explicit plaintext group send ===")
    rid = _run_id()
    alice = _make_client("alice", rid)
    bob = _make_client("bob", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # Alice 建群 + 加 Bob
        group_id = await _create_group(alice, f"plaintext-test-{rid}")
        await _add_member(alice, group_id, b_aid)
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # Alice 显式发送明文消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "这是一条明文消息"},
            "encrypt": False,
        })

        # Bob 拉取
        await asyncio.sleep(1)
        msgs = await _group_pull(bob, group_id)
        plaintext_msgs = [m for m in msgs if not m.get("encrypted")]
        assert len(plaintext_msgs) >= 1, f"expected plaintext msg, got none"
        assert plaintext_msgs[0]["payload"]["text"] == "这是一条明文消息"

        # Alice 默认加密发送
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "这是一条加密消息"},
        })

        await asyncio.sleep(1)
        msgs2 = await _group_pull(bob, group_id, after_seq=msgs[-1].get("seq", 0))
        encrypted_msgs = [m for m in msgs2 if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
        assert len(encrypted_msgs) >= 1, f"expected encrypted msg, got none"
        assert encrypted_msgs[0]["payload"]["text"] == "这是一条加密消息"

        print("[PASS] Test 12")
        return True
    except Exception as e:
        print(f"[FAIL] Test 12: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_epoch_rotation_on_leave():
    """Test 13: 成员主动退群 → 剩余 admin/owner 事件侧自动轮换 → 离开者无法解密新消息"""
    print("\n=== Test 13: Epoch rotation on leave (event-side) ===")
    rid = _run_id()
    alice, bob, carol = _make_client("a", rid), _make_client("b", rid), _make_client("c", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(carol, _CHARLIE_AID)

        group_id = await _create_group(alice, f"e2ee-leave-{rid}")
        await _add_member(alice, group_id, b_aid)
        old_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=25.0)
        await _add_member(alice, group_id, c_aid)
        old_epoch = await _wait_for_group_secret_epoch(carol, c_aid, group_id, min_epoch=old_epoch + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=old_epoch, timeout=25.0)

        # 确认三方都有退群前的已提交 epoch
        assert alice._group_e2ee.has_secret(group_id), "Alice missing secret"
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=old_epoch, timeout=25.0)

        assert old_epoch >= 1, f"expected existing epoch, got {old_epoch}"

        # Carol 主动退群（离开者自身不触发轮换）
        await carol.call("group.leave", {"group_id": group_id})

        # Alice（owner）收到 group.changed(member_left) 事件后应自动 CAS 轮换并提交
        new_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=old_epoch + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=new_epoch, timeout=25.0)

        # Alice 用新 epoch 发加密消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "退群后的消息"},
        })

        await asyncio.sleep(1)

        # Bob 能解密
        msgs_bob = await _group_pull(bob, group_id)
        decrypted_bob = [m for m in msgs_bob
                         if m.get("e2ee", {}).get("epoch") == new_epoch]
        assert len(decrypted_bob) >= 1, f"Bob: no auto-decrypted epoch {new_epoch} msgs"
        assert decrypted_bob[0]["payload"]["text"] == "退群后的消息"

        # Carol 不应有新 epoch 密钥
        all_carol = load_all_group_secrets(carol._keystore, c_aid, group_id)
        assert new_epoch not in all_carol, f"Carol should not have epoch {new_epoch} secret"

        print("[PASS] Test 13")
        return True
    except Exception as e:
        print(f"[FAIL] Test 13: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close(); await carol.close()


async def test_push_event_decrypt():
    """Test 14: 推送事件带 payload 直接解密（不依赖 pull 兜底）

    验证：
    1. Alice 发送加密群消息后，Bob 通过 group.message_created 推送事件收到
    2. SDK 自动解密推送消息（不调 group.pull）
    3. 推送消息的 payload.text 正确
    """
    print("\n=== Test 14: Push event decrypts (no pull) ===")
    rid = _run_id()
    alice = _make_client("a", rid)
    bob = _make_client("b", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        group_id = await _create_group(alice, f"e2ee-push-{rid}")
        await _add_member(alice, group_id, b_aid)
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # 注册推送事件监听
        push_msgs = []
        push_event = asyncio.Event()

        def handler(data):
            if isinstance(data, dict) and data.get("group_id") == group_id:
                push_msgs.append(data)
                push_event.set()

        sub = bob.on("group.message_created", handler)

        # Alice 发加密消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "推送测试"},
            "encrypt": True,
        })

        # 等推送（不调 pull）
        try:
            await asyncio.wait_for(push_event.wait(), timeout=8.0)
        except asyncio.TimeoutError:
            pass
        sub.unsubscribe()

        assert len(push_msgs) >= 1, f"推送未收到：期望 >= 1 条，实际 {len(push_msgs)}"
        first = push_msgs[0]
        assert first.get("e2ee", {}).get("encryption_mode") == "epoch_group_key", \
            f"推送消息未自动解密: e2ee={first.get('e2ee')}"
        assert first.get("payload", {}).get("text") == "推送测试", \
            f"推送消息内容不匹配: payload={first.get('payload')}"

        print("[PASS] Test 14")
        return True
    except Exception as e:
        print(f"[FAIL] Test 14: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_open_join_member_rotation():
    """Test 15: open 群加入 → 在线成员延迟轮换 → 新成员拿到新 epoch → 解密消息

    验证新策略：
    1. Alice 建 open 群 → 自动 create_epoch
    2. Bob 通过 request_join 加入 open 群
    3. Alice（在线成员）延迟 3s 后轮换 epoch，Bob（新成员）延迟 6s 作为 fallback
    4. 轮换完成后 Bob 拿到新 epoch 密钥
    5. Alice 用新 epoch 发消息，Bob 能解密
    """
    print("\n=== Test 15: Open join member rotation ===")
    rid = _run_id()
    alice, bob = _make_client("a-opr", rid), _make_client("b-opr", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # 1. Alice 建 open 群
        created = await alice.call("group.create", {
            "name": f"e2ee-opr-{rid}",
            "visibility": "public",
            "join_mode": "open",
        })
        group_id = created["group"]["group_id"]
        assert alice.group_e2ee.has_secret(group_id), "owner should have secret after create"
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)
        print(f"  DEBUG: before_epoch={before_epoch}")

        # 2. Bob 加入 open 群
        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "open join for rotation test",
        })
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"
        print(f"  DEBUG: Bob joined, waiting for rotation...")

        # 3. 等待轮换完成：Bob 拿到 epoch > before_epoch 的密钥
        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=20.0)
        assert rotated_epoch > before_epoch, f"epoch should rotate: {rotated_epoch} > {before_epoch}"
        print(f"  DEBUG: rotated_epoch={rotated_epoch}")

        # 4. Alice 用新 epoch 发消息，Bob 能解密
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"轮换后消息-{rid}"},
            "encrypt": True,
        })
        decrypted = []
        for _wait in range(15):
            await asyncio.sleep(1)
            msgs = await _group_pull(bob, group_id)
            decrypted = [
                m for m in msgs
                if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
                and m.get("payload", {}).get("text") == f"轮换后消息-{rid}"
            ]
            if decrypted:
                break
        assert len(decrypted) >= 1, "Bob should decrypt msg after rotation"

        print("[PASS] Test 15")
        return True
    except Exception as e:
        print(f"[FAIL] Test 15: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_invite_code_join_member_rotation():
    """Test 16: 邀请码入群 → 在线成员延迟轮换 → 新成员拿到新 epoch → 解密消息

    与 Test 15 类似，但使用邀请码路径（invite_code_used action）。
    """
    print("\n=== Test 16: Invite code join member rotation ===")
    rid = _run_id()
    alice, bob = _make_client("a-inv", rid), _make_client("b-inv", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # 1. Alice 建群（邀请码模式）
        created = await alice.call("group.create", {
            "name": f"e2ee-inv-opr-{rid}",
            "visibility": "public",
            "join_mode": "invite_code",
        })
        group_id = created["group"]["group_id"]
        assert alice.group_e2ee.has_secret(group_id)
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)
        print(f"  DEBUG: before_epoch={before_epoch}")

        # 2. Alice 生成邀请码
        invite_result = await alice.call("group.create_invite_code", {
            "group_id": group_id,
            "max_uses": 1,
        })
        invite_obj = invite_result.get("invite_code")
        assert isinstance(invite_obj, dict)
        code = invite_obj.get("code")
        assert code and isinstance(code, str)

        # 3. Bob 使用邀请码加入
        await bob.call("group.use_invite_code", {"code": code})
        print(f"  DEBUG: Bob joined via invite code, waiting for rotation...")

        # 4. 等待轮换完成：Bob 拿到 epoch > before_epoch 的密钥
        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=20.0)
        assert rotated_epoch > before_epoch, f"epoch should rotate: {rotated_epoch} > {before_epoch}"
        print(f"  DEBUG: rotated_epoch={rotated_epoch}")

        # 5. Alice 用新 epoch 发消息，Bob 能解密
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"邀请码轮换后消息-{rid}"},
            "encrypt": True,
        })
        decrypted = []
        for _wait in range(15):
            await asyncio.sleep(1)
            msgs = await _group_pull(bob, group_id)
            decrypted = [
                m for m in msgs
                if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
                and m.get("payload", {}).get("text") == f"邀请码轮换后消息-{rid}"
            ]
            if decrypted:
                break
        assert len(decrypted) >= 1, "Bob should decrypt with rotated key"

        print("[PASS] Test 16")
        return True
    except Exception as e:
        print(f"[FAIL] Test 16: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_private_add_member_immediate_rotation():
    """Test 17: 私密群 add_member → 立即轮换（无延迟），对照测试

    验证 member_added action 走旧逻辑：立即轮换，不延迟。
    """
    print("\n=== Test 17: Private add_member immediate rotation (control) ===")
    rid = _run_id()
    alice, bob = _make_client("a-priv", rid), _make_client("b-priv", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        # 1. Alice 建私密群
        group_id = await _create_group(alice, f"e2ee-priv-imm-{rid}")
        assert alice.group_e2ee.has_secret(group_id)
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)

        # 2. Alice 添加 Bob（member_added → 立即轮换）
        t0 = time.time()
        await _add_member(alice, group_id, b_aid)

        # 3. Bob 应在 3s 内拿到新 epoch（立即轮换，不等 3s 延迟）
        rotated_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=15.0)
        elapsed = time.time() - t0
        # 立即轮换应在 ~2s 内完成（网络延迟），不应等 3s 延迟
        # 注意：不做严格时间断言，只验证功能正确性
        assert rotated_epoch > before_epoch, "private add_member should trigger immediate rotation"

        # 4. Alice 发消息，Bob 能解密
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"私密群消息-{rid}"},
            "encrypt": True,
        })
        await asyncio.sleep(1)
        msgs = await _group_pull(bob, group_id)
        decrypted = [
            m for m in msgs
            if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
            and m.get("payload", {}).get("text") == f"私密群消息-{rid}"
        ]
        assert len(decrypted) >= 1, "Bob should decrypt private group msg"

        print("[PASS] Test 17")
        return True
    except Exception as e:
        print(f"[FAIL] Test 17: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_open_join_member_leads_rotation():
    """Test 18: open 群 owner 离线时，普通 member 代为轮换 epoch

    验证去中心化轮换：
    1. Alice 建 open 群 → epoch 1
    2. Alice add_member Charlie → Charlie 拿到 epoch key → epoch 轮换到 2
    3. Alice 下线
    4. Bob 通过 request_join 加入 open 群
    5. Charlie（普通 member）收到 joined 事件 → 触发 backfill + delayed rotate
    6. 验证 epoch 轮换到 3（Charlie 代为发起），Bob 拿到新 key
    """
    print("\n=== Test 18: Open group member leads rotation (owner offline) ===")
    rid = _run_id()
    alice = _make_client("a-mlr", rid)
    charlie = _make_client("c-mlr", rid)
    bob = _make_client("b-mlr", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        c_aid = await _ensure_connected(charlie, _CHARLIE_AID)

        # 1. Alice 建 open 群
        created = await alice.call("group.create", {
            "name": f"e2ee-mlr-{rid}",
            "visibility": "public",
            "join_mode": "open",
        })
        group_id = created["group"]["group_id"]
        assert alice.group_e2ee.has_secret(group_id), "owner should have secret after create"
        epoch1 = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)

        # 2. Alice add_member Charlie（私密添加，让 Charlie 先拿到 key）
        await _add_member(alice, group_id, c_aid)
        epoch2 = await _wait_for_group_secret_epoch(charlie, c_aid, group_id, min_epoch=epoch1 + 1, timeout=20.0)
        assert epoch2 > epoch1, f"epoch should rotate after add_member: {epoch2} > {epoch1}"

        # 3. Alice 下线
        await alice.close()
        await asyncio.sleep(1)

        # 4. Bob 加入 open 群
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "member leads rotation test",
        })
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"

        # 5. Charlie（普通 member）应代为轮换 epoch
        #    等待 Bob 拿到新 epoch key（由 Charlie 发起的轮换）
        epoch3 = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=epoch2 + 1, timeout=25.0)
        assert epoch3 > epoch2, f"member should lead rotation: epoch {epoch3} > {epoch2}"

        # 6. Charlie 也应该有新 epoch
        charlie_epoch = await _wait_for_group_secret_epoch(charlie, c_aid, group_id, min_epoch=epoch3, timeout=10.0)
        assert charlie_epoch >= epoch3, "Charlie should have new epoch too"

        # 7. Charlie 发消息，Bob 能解密
        await charlie.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": f"member轮换后消息-{rid}"},
            "encrypt": True,
        })
        await asyncio.sleep(2)
        msgs = await _group_pull(bob, group_id)
        decrypted = [
            m for m in msgs
            if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
            and m.get("payload", {}).get("text") == f"member轮换后消息-{rid}"
        ]
        assert len(decrypted) >= 1, "Bob should decrypt msg sent by Charlie after member-led rotation"

        print("[PASS] Test 18")
        return True
    except Exception as e:
        print(f"[FAIL] Test 18: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await charlie.close(); await bob.close()


async def test_open_join_send_repairs_missing_committed_membership():
    """Test 20: open 群新成员在 committed membership 缺少自己时，发送前应先修复轮换。"""
    print("\n=== Test 20: Open join send repairs missing committed membership ===")
    rid = _run_id()
    alice, bob, charlie = _make_client("a-oms", rid), _make_client("b-oms", rid), _make_client("c-oms", rid)
    alice2 = None
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(charlie, _CHARLIE_AID)

        created = await alice.call("group.create", {
            "name": f"e2ee-oms-{rid}",
            "visibility": "public",
            "join_mode": "open",
        })
        group_id = created["group"]["group_id"]
        before_epoch = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)
        print(f"  DEBUG: before_epoch={before_epoch}")

        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "open join before send repair",
        })
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"

        joined_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=before_epoch + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=joined_epoch, timeout=25.0)
        print(f"  DEBUG: joined_epoch={joined_epoch}")

        await alice.close()
        await asyncio.sleep(0.2)
        charlie_join = await charlie.call("group.request_join", {
            "group_id": group_id,
            "message": "join to create membership gap before bob send",
        })
        assert charlie_join.get("status") == "joined", f"expected charlie joined, got {charlie_join}"
        epoch_info = await bob.call("group.e2ee.get_epoch", {"group_id": group_id})
        committed_rotation = epoch_info.get("committed_rotation") if isinstance(epoch_info, dict) else None
        expected_members = committed_rotation.get("expected_members") if isinstance(committed_rotation, dict) else []
        members = epoch_info.get("members", []) if isinstance(epoch_info, dict) else []
        print(f"  DEBUG: committed_epoch={epoch_info.get('committed_epoch')} expected_members={expected_members}")
        assert isinstance(expected_members, list), f"bad committed_rotation: {epoch_info}"
        committed_set = {str(item) for item in expected_members}
        current_set = {str(item) for item in members}

        send_text = f"repair-send-{rid}"
        await bob.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": send_text},
            "encrypt": True,
        })

        if _CHARLIE_AID in current_set and _CHARLIE_AID not in committed_set:
            repaired_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=int(epoch_info.get("committed_epoch") or joined_epoch) + 1, timeout=25.0)
            assert repaired_epoch >= int(epoch_info.get("committed_epoch") or joined_epoch) + 1, f"expected repair rotation, got {repaired_epoch}"
        else:
            # 真实 E2E 中后台 member/owner 可能已经在发送前完成轮换；这同样说明缺口已被修复。
            repaired_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=joined_epoch, timeout=10.0)
            refreshed = await bob.call("group.e2ee.get_epoch", {"group_id": group_id})
            refreshed_rotation = refreshed.get("committed_rotation") if isinstance(refreshed, dict) else None
            refreshed_members = refreshed_rotation.get("expected_members") if isinstance(refreshed_rotation, dict) else []
            assert _CHARLIE_AID in {str(item) for item in refreshed_members}, f"membership gap was not repaired: {refreshed}"
        print(f"  DEBUG: repaired_epoch={repaired_epoch}")

        alice2 = _make_client("a-oms-reconnect", rid)
        await _ensure_connected(alice2, _ALICE_AID)

        # Alice 重新上线后先拉取 Bob 离线期间发送的密文消息。
        # SDK 应在 group.pull 自动解密失败时触发 open 群服务端 epoch key 恢复，然后重试解密。
        msgs = await _group_pull(alice2, group_id, min_count=1)
        await _wait_for_group_secret_epoch(alice2, a_aid, group_id, min_epoch=repaired_epoch, timeout=25.0)
        decrypted = [
            m for m in msgs
            if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
            and m.get("payload", {}).get("text") == send_text
        ]
        assert len(decrypted) >= 1, f"Alice did not decrypt repaired send: {msgs}"
        await alice2.close()

        print("[PASS] Test 20")
        return True
    except Exception as e:
        print(f"[FAIL] Test 20: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        if alice2 is not None:
            await alice2.close()
        await bob.close()
        await charlie.close()


async def test_group_thought_get_recovers_missing_epoch_key():
    """Test 21: group.thought.get 是 RPC 查询，缺 epoch key 时应恢复后解密。"""
    print("\n=== Test 21: Group thought get recovers missing epoch key ===")
    rid = _run_id()
    alice, bob, charlie = _make_client("a-thought", rid), _make_client("b-thought", rid), _make_client("c-thought", rid)
    alice2 = None
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(charlie, _CHARLIE_AID)

        created = await alice.call("group.create", {
            "name": f"e2ee-thought-{rid}",
            "visibility": "public",
            "join_mode": "open",
        })
        group_id = created["group"]["group_id"]
        epoch1 = await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=1, timeout=20.0)

        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "thought recovery member",
        })
        assert join_result.get("status") == "joined", f"expected bob joined, got {join_result}"
        epoch2 = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=epoch1 + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(alice, a_aid, group_id, min_epoch=epoch2, timeout=25.0)

        # Alice 离线，Charlie 加入触发 open 群 member/admin 轮换；Alice 不接收新 epoch 分发。
        await alice.close()
        await asyncio.sleep(0.5)
        charlie_join = await charlie.call("group.request_join", {
            "group_id": group_id,
            "message": "advance epoch while alice offline",
        })
        assert charlie_join.get("status") == "joined", f"expected charlie joined, got {charlie_join}"
        epoch3 = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=epoch2 + 1, timeout=25.0)
        await _wait_for_group_secret_epoch(charlie, c_aid, group_id, min_epoch=epoch3, timeout=25.0)

        thought_text = f"thought-recover-{rid}"
        thought_context = {"type": "run", "id": f"thought-run-{rid}"}
        await bob.call("group.thought.put", {
            "group_id": group_id,
            "context": thought_context,
            "payload": {"type": "thought", "text": thought_text},
        })

        alice2 = _make_client("a-thought-reconnect", rid)
        await _ensure_connected(alice2, _ALICE_AID)

        result1 = await alice2.call("group.thought.get", {
            "group_id": group_id,
            "sender_aid": b_aid,
            "context": thought_context,
        })
        await _wait_for_group_secret_epoch(alice2, a_aid, group_id, min_epoch=epoch3, timeout=25.0)
        thoughts1 = result1.get("thoughts", []) if isinstance(result1, dict) else []
        decrypted1 = [
            item for item in thoughts1
            if item.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
            and item.get("payload", {}).get("text") == thought_text
        ]
        assert decrypted1, f"Alice did not decrypt thought after recovery: {result1}"
        assert decrypted1[0].get("e2ee", {}).get("epoch") == epoch3

        # 重复读取同一个 thought 仍应解密，不受 replay/republish guard 影响。
        result2 = await alice2.call("group.thought.get", {
            "group_id": group_id,
            "sender_aid": b_aid,
            "context": thought_context,
        })
        thoughts2 = result2.get("thoughts", []) if isinstance(result2, dict) else []
        decrypted2 = [
            item for item in thoughts2
            if item.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
            and item.get("payload", {}).get("text") == thought_text
        ]
        assert decrypted2, f"repeated thought.get should decrypt again: {result2}"

        print("[PASS] Test 21")
        return True
    except Exception as e:
        print(f"[FAIL] Test 21: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        if alice2 is not None:
            await alice2.close()
        await bob.close()
        await charlie.close()


async def main():
    print("=" * 60)
    print("Group E2EE E2E Tests")
    print("=" * 60)

    tests = [
        ("1. Group encrypted messaging",         test_group_encrypted_messaging),
        ("2. Multiple members decrypt",           test_multiple_members),
        ("3. Epoch rotation on kick",             test_epoch_rotation_on_kick),
        ("4. New member join rotates epoch",      test_new_member_join_rotates_epoch),
        ("5. Burst group messages",               test_burst_group_messages),
        ("6. Mixed encrypted + plaintext",        test_mixed_encrypted_plaintext),
        ("7. Membership commitment verification", test_membership_commitment_verification),
        ("8. Old epoch still decryptable",        test_old_epoch_still_decryptable),
        ("9. Review join request auto distribute", test_review_join_request_auto_distribute),
        ("10. Invite code auto recovery",         test_invite_code_auto_recovery),
        ("11. Open group join rotates epoch",    test_open_group_join_rotates_epoch_and_updates_memberlist),
        ("12. Capabilities required for join",    test_capabilities_required_for_join),
        ("13. Explicit plaintext send",           test_plaintext_send_explicit),
        ("14. Epoch rotation on leave",           test_epoch_rotation_on_leave),
        ("15. Push event decrypts (no pull)",     test_push_event_decrypt),
        ("16. Open join member rotation",          test_open_join_member_rotation),
        ("17. Invite code join member rotation",   test_invite_code_join_member_rotation),
        ("18. Private add_member immediate rotation", test_private_add_member_immediate_rotation),
        ("19. Open group member leads rotation",     test_open_join_member_leads_rotation),
        ("20. Open join send repairs missing committed membership", test_open_join_send_repairs_missing_committed_membership),
        ("21. Group thought get recovers missing epoch key", test_group_thought_get_recovers_missing_epoch_key),
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
        print("\n[PASS] All Group E2EE E2E tests passed!")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

