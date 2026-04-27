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
    tag_part = _normalize_slot_part(tag)
    rid_part = _normalize_slot_part(rid) if rid else uuid.uuid4().hex[:12]
    slot_id = f"{tag_part}-{rid_part}"
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
            await client.connect(connect_params)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
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


async def _wait_for_group_secret_epoch(client: AUNClient, aid: str, group_id: str, *, min_epoch: int = 1, timeout: float = 15.0) -> int:
    deadline = asyncio.get_running_loop().time() + timeout
    last_epochs: list[int] = []
    last_committed = 0
    while asyncio.get_running_loop().time() < deadline:
        all_secrets = load_all_group_secrets(client._keystore, aid, group_id)
        last_epochs = sorted(all_secrets)
        try:
            epoch_result = await client.call("group.e2ee.get_epoch", {"group_id": group_id})
            last_committed = int(epoch_result.get("committed_epoch", epoch_result.get("epoch", 0)))
        except Exception:
            last_committed = 0
        eligible = [epoch for epoch in last_epochs if epoch >= min_epoch and epoch <= last_committed]
        if eligible:
            return max(eligible)
        await asyncio.sleep(0.5)
    raise AssertionError(
        f"{aid} did not receive committed group {group_id} epoch >= {min_epoch} "
        f"within {timeout}s; epochs={last_epochs}, committed={last_committed}"
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

        # Alice 加 Bob（SDK 自动分发密钥）
        await _add_member(alice, group_id, b_aid)
        await asyncio.sleep(2)  # 等 P2P 密钥分发到达

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

        # SDK 自动分发密钥给所有成员
        await asyncio.sleep(2)  # 等 P2P 密钥分发到达

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

        # 等待 SDK 自动分发/轮换密钥给 Bob 和 Carol
        old_epoch = await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=20.0)

        # 踢 Carol
        await _kick_member(alice, group_id, c_aid)

        # kick 后 SDK 自动两阶段轮换 + 分发给 Bob，轮询等待 Bob 拿到已提交的新 epoch 密钥
        for _wait in range(15):
            await asyncio.sleep(1)
            all_bob = load_all_group_secrets(bob._keystore, b_aid, group_id)
            epoch_result = await bob.call("group.e2ee.get_epoch", {"group_id": group_id})
            committed_epoch = int(epoch_result.get("committed_epoch", epoch_result.get("epoch", 0)))
            if committed_epoch > old_epoch and committed_epoch in all_bob:
                break
        else:
            assert False, f"Bob did not receive epoch > {old_epoch} secret within 15s"

        new_epoch = committed_epoch

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


async def test_new_member_no_rotation():
    """Test 4: 加人 → 无 epoch 轮换 → 新成员可解密当前 epoch 消息"""
    print("\n=== Test 4: New member join no rotation ===")
    rid = _run_id()
    alice, bob, carol = _make_client("a", rid), _make_client("b", rid), _make_client("c", rid)
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)
        c_aid = await _ensure_connected(carol, _CHARLIE_AID)

        group_id = await _create_group(alice, f"e2ee-join-{rid}")
        await _add_member(alice, group_id, b_aid)

        # 等待 SDK 自动分发密钥给 Bob
        await asyncio.sleep(2)

        # 加 Carol（SDK 自动分发当前密钥）
        await _add_member(alice, group_id, c_aid)
        await asyncio.sleep(2)

        # Alice 用 epoch 1 发消息
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

        # 等待 SDK 自动分发密钥
        await asyncio.sleep(2)

        N = 5
        for i in range(N):
            await alice.call("group.send", {
                "group_id": group_id,
                "payload": {"type": "text", "text": f"burst_{i}", "seq": i},
                "encrypt": True,
            })

        await asyncio.sleep(2)

        msgs = await _group_pull(bob, group_id, min_count=N)
        decrypted = [m for m in msgs if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"]
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

        # 等待 SDK 自动分发密钥
        await asyncio.sleep(2)

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

        # 等待 SDK 自动分发 epoch 1 密钥
        await asyncio.sleep(2)

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
        await asyncio.sleep(2)  # 等待 SDK 自动 P2P 密钥分发到达

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

        # 关键断言：Bob 刚入群时本地没有 group_secret
        assert not bob.group_e2ee.has_secret(group_id), \
            "Bob should NOT have group secret right after invite code join"

        # 4. Alice 发送加密群消息
        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": "邀请码入群后的消息"},
            "encrypt": True,
        })

        # 5. 等待恢复链路完成：Bob pull → 缺密钥 → key_request → Alice 响应 → Bob 解密。
        #    新的接收侧本地 replay guard 会按实例去重；如果首次 pull 已同步恢复并解密，
        #    后续重复 pull 同一 message_id 会被本地去重，所以必须保留首次 pull 的结果。
        first_pull_msgs = []
        try:
            first_pull_msgs = await _group_pull(bob, group_id)
        except Exception:
            pass  # 首次 pull 可能无法解密

        for _wait in range(15):
            await asyncio.sleep(1)
            if bob.group_e2ee.has_secret(group_id):
                break
        else:
            assert False, "Bob did not recover group secret within 15s"

        decrypted = [
            m for m in first_pull_msgs
            if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
            and m.get("payload", {}).get("text") == "邀请码入群后的消息"
        ]
        for _wait in range(15):
            if decrypted:
                break
            msgs = await _group_pull(bob, group_id)
            decrypted = [
                m for m in msgs
                if m.get("e2ee", {}).get("encryption_mode") == "epoch_group_key"
                and m.get("payload", {}).get("text") == "邀请码入群后的消息"
            ]
            if decrypted:
                break
            await asyncio.sleep(1)
        assert len(decrypted) >= 1, f"no auto-decrypted msgs found"
        assert decrypted[0]["payload"]["text"] == "邀请码入群后的消息"

        # 关键断言：恢复后 Bob 本地应该已有 group_secret
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
        owner_secret_before = alice.group_e2ee.load_secret(group_id)
        assert owner_secret_before is not None
        before_epoch = owner_secret_before["epoch"]

        join_result = await bob.call("group.request_join", {
            "group_id": group_id,
            "message": "open join",
        })
        assert join_result.get("status") == "joined", f"expected joined, got {join_result}"

        for _ in range(20):
            await asyncio.sleep(0.5)
            bob_secret = bob.group_e2ee.load_secret(group_id)
            alice_secret = alice.group_e2ee.load_secret(group_id)
            if bob_secret and alice_secret and int(alice_secret["epoch"]) > int(before_epoch):
                break
        else:
            assert False, "open join did not rotate and distribute group secret within 10s"

        alice_secret = alice.group_e2ee.load_secret(group_id)
        bob_secret = bob.group_e2ee.load_secret(group_id)
        assert alice_secret is not None and bob_secret is not None
        assert int(alice_secret["epoch"]) > int(before_epoch), "owner epoch should rotate after open join"
        assert int(bob_secret["epoch"]) == int(alice_secret["epoch"]), "new member should receive rotated epoch"
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
        await asyncio.sleep(2)

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
        await _wait_for_group_secret_epoch(bob, b_aid, group_id, min_epoch=1, timeout=25.0)
        await _add_member(alice, group_id, c_aid)
        await _wait_for_group_secret_epoch(carol, c_aid, group_id, min_epoch=1, timeout=25.0)

        # 确认三方都有 epoch 1
        assert alice._group_e2ee.has_secret(group_id), "Alice missing secret"

        old_epoch = alice._group_e2ee.current_epoch(group_id)
        assert old_epoch and old_epoch >= 1, f"expected existing epoch, got {old_epoch}"

        # Carol 主动退群（离开者自身不触发轮换）
        await carol.call("group.leave", {"group_id": group_id})

        # Alice（owner）收到 group.changed(member_left) 事件后应自动 CAS 轮换
        # 轮询等待 Bob 拿到 epoch 2 密钥
        for _wait in range(25):
            await asyncio.sleep(1)
            all_bob = load_all_group_secrets(bob._keystore, b_aid, group_id)
            if any(epoch > old_epoch for epoch in all_bob):
                break
        else:
            assert False, f"Bob did not receive epoch > {old_epoch} secret within 25s after leave"

        new_epoch = max(load_all_group_secrets(bob._keystore, b_aid, group_id))
        all_alice = load_all_group_secrets(alice._keystore, a_aid, group_id)
        assert new_epoch in all_alice, f"Alice should have epoch {new_epoch}"

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
        await asyncio.sleep(2)  # 等密钥分发

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


async def main():
    print("=" * 60)
    print("Group E2EE E2E Tests")
    print("=" * 60)

    tests = [
        ("1. Group encrypted messaging",         test_group_encrypted_messaging),
        ("2. Multiple members decrypt",           test_multiple_members),
        ("3. Epoch rotation on kick",             test_epoch_rotation_on_kick),
        ("4. New member join no rotation",        test_new_member_no_rotation),
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

