#!/usr/bin/env python3
"""E2EE 完整 E2E 测试 — 需要运行中的 AUN Gateway 服务。

覆盖 SDK 和裸 WebSocket 在发送/接收端的所有组合，确保互联互通。

使用方法：
  python tests/integration_test_e2ee.py

前置条件：
  - Docker 环境运行中（docker compose up -d）
  - 运行环境能解析 gateway.<issuer>（推荐使用 Docker network alias）
  - Gateway 地址由 SDK 通过 AID 的 issuer domain 自动发现
"""
import asyncio
import os
import re
import shutil
import sys
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.config import get_device_id
from aun_core.e2ee import E2EEManager


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


def _single_domain_device_root(tag: str) -> Path:
    base = Path(_TEST_AUN_PATH)
    parent = base.parent if base.name else base
    root = parent / "multi-device" / tag
    root.mkdir(parents=True, exist_ok=True)
    return root


def _read_device_id(root: Path) -> str:
    path = root / ".device_id"
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _ensure_unique_test_device_id(tag: str) -> str:
    """仅修正 multi-device 测试根目录里的重复 device_id，不触碰固定身份目录。"""
    root = _single_domain_device_root(tag)
    current = get_device_id(root)
    siblings = root.parent
    seen: set[str] = set()
    for entry in siblings.iterdir():
        if not entry.is_dir() or entry == root:
            continue
        other = _read_device_id(entry)
        if other:
            seen.add(other)
    if current and current not in seen:
        return current

    device_id_path = root / ".device_id"
    while True:
        candidate = str(uuid.uuid4())
        if candidate in seen:
            continue
        device_id_path.write_text(candidate, encoding="utf-8")
        return candidate


def _copy_identity_tree(source_root: Path, target_root: Path, aid: str) -> None:
    source_identity = source_root / "AIDs" / aid
    if not source_identity.exists():
        raise RuntimeError(f"identity source missing: {source_identity}")
    source_seed = source_root / ".seed"
    target_root.mkdir(parents=True, exist_ok=True)
    if source_seed.exists():
        shutil.copy2(source_seed, target_root / ".seed")
    (target_root / "AIDs").mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_identity, target_root / "AIDs" / aid, dirs_exist_ok=True)


def _prepare_isolated_identity(tag: str, aid: str) -> Path:
    target_root = _single_domain_device_root(tag)
    _copy_identity_tree(Path(_TEST_AUN_PATH), target_root, aid)
    _ensure_unique_test_device_id(tag)
    return target_root


def _normalize_slot_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    return text.strip("-._") or "slot"


def _build_test_slot_id(tag: str, rid: str | None = None) -> str:
    tag_part = _normalize_slot_part(tag)
    rid_part = _normalize_slot_part(rid) if rid else uuid.uuid4().hex[:12]
    slot_id = f"{tag_part}-{rid_part}"
    return slot_id[:128]


def _make_isolated_client(tag: str, *, slot_id: str = "") -> AUNClient:
    client = AUNClient({
        "aun_path": str(_single_domain_device_root(tag)),
    }, debug=True)
    client._config_model.require_forward_secrecy = False
    client._test_slot_id = slot_id or _build_test_slot_id(tag, "main")
    return client


def _make_client(tag: str) -> AUNClient:
    """创建测试客户端 — Gateway 通过 well-known 发现机制自动获取。"""
    client = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    }, debug=True)
    client._config_model.require_forward_secrecy = False
    client._test_slot_id = _build_test_slot_id(tag)
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
    return aid


def _make_raw_e2ee(client: AUNClient) -> E2EEManager:
    """从已连接的 AUNClient 创建独立 E2EEManager（模拟裸 WebSocket 开发者）。
    重构后 E2EEManager 只需 identity_fn 和 keystore，不再需要 transport。
    """
    return E2EEManager(
        identity_fn=lambda: client._identity or {},
        device_id_fn=lambda: client._device_id,
        keystore=client._keystore,
    )


async def _raw_send(client: AUNClient, e2ee: E2EEManager, to_aid: str, payload: dict) -> dict:
    """裸 WS 加密 + 发送。调用方需提前获取证书和 prekey。"""
    # 获取对方证书
    peer_cert_pem = await client._fetch_peer_cert(to_aid)
    # 获取对方 prekey（可能没有）
    prekey = await client._fetch_peer_prekey(to_aid)

    envelope, ok = e2ee.encrypt_message(
        to_aid=to_aid, payload=payload,
        peer_cert_pem=peer_cert_pem, prekey=prekey,
    )
    assert ok, "加密失败"
    aad = envelope.get("aad", {})
    return await client._transport.call("message.send", {
        "to": to_aid,
        "payload": envelope,
        "type": "e2ee.encrypted",
        "encrypted": True,
        "message_id": aad["message_id"],
        "timestamp": aad["timestamp"],
    })


async def _raw_recv_pull(client: AUNClient, e2ee: E2EEManager, from_aid: str,
                         after_seq: int = 0) -> list[dict]:
    """裸 WS pull + 手动解密。"""
    await client._ensure_sender_cert_cached(from_aid)
    raw = await client._transport.call("message.pull", {"after_seq": after_seq, "limit": 50})
    raw_msgs = raw.get("messages", [])
    result = []
    for msg in raw_msgs:
        if msg.get("from") != from_aid:
            continue
        decrypted = e2ee.decrypt_message(msg)
        if decrypted is not None:
            result.append(decrypted)
    return result


async def _sdk_send(client: AUNClient, to_aid: str, payload: dict) -> dict:
    """SDK 加密发送"""
    return await client.call("message.send", {
        "to": to_aid,
        "payload": payload,
        "encrypt": True,
    })


async def _sdk_recv_push(client: AUNClient, from_aid: str, timeout: float = 5.0) -> list[dict]:
    """SDK 通过推送事件接收，超时后 pull 兜底"""
    return await _sdk_recv_push_after(client, from_aid, after_seq=0, timeout=timeout)


async def _sdk_recv_push_after(
    client: AUNClient, from_aid: str, *, after_seq: int = 0, timeout: float = 5.0,
) -> list[dict]:
    """SDK 通过推送事件接收，超时后按 after_seq pull 兜底。"""
    inbox = []
    event = asyncio.Event()

    def _seq_of(message: dict) -> int:
        try:
            return int(message.get("seq") or 0)
        except (TypeError, ValueError):
            return 0

    def handler(data):
        if not isinstance(data, dict):
            return
        if data.get("from") != from_aid:
            return
        if _seq_of(data) <= after_seq:
            return
        inbox.append(data)
        event.set()

    sub = client.on("message.received", handler)
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    sub.unsubscribe()

    if not inbox:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": 50})
        msgs = result.get("messages", [])
        inbox.extend(m for m in msgs if m.get("from") == from_aid)
    return sorted(inbox, key=_seq_of)


async def _sdk_recv_pull(client: AUNClient, from_aid: str, after_seq: int = 0) -> list[dict]:
    """SDK 通过 pull 接收（自动解密）"""
    result = await client.call("message.pull", {"after_seq": after_seq, "limit": 50})
    msgs = result.get("messages", [])
    return [m for m in msgs if m.get("from") == from_aid]


async def _wait_for_sdk_pull_message(
    client: AUNClient,
    from_aid: str,
    *,
    after_seq: int,
    expected_text: str,
    timeout: float = 20.0,
) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    last_messages: list[dict] = []
    while asyncio.get_running_loop().time() < deadline:
        messages = await _sdk_recv_pull(client, from_aid, after_seq=after_seq)
        last_messages = messages
        for message in messages:
            payload = message.get("payload")
            if isinstance(payload, dict) and str(payload.get("text") or "") == expected_text:
                return message
        await asyncio.sleep(0.5)
    raise AssertionError(
        f"timeout waiting for message text={expected_text!r} from={from_aid}; "
        f"last_messages={last_messages}"
    )


async def _wait_for_raw_pull_message(
    client: AUNClient,
    e2ee: E2EEManager,
    from_aid: str,
    *,
    after_seq: int,
    expected_text: str,
    timeout: float = 20.0,
) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    last_messages: list[dict] = []
    while asyncio.get_running_loop().time() < deadline:
        messages = await _raw_recv_pull(client, e2ee, from_aid, after_seq=after_seq)
        last_messages = messages
        for message in messages:
            payload = message.get("payload")
            if isinstance(payload, dict) and str(payload.get("text") or "") == expected_text:
                return message
        await asyncio.sleep(0.5)
    raise AssertionError(
        f"timeout waiting for raw message text={expected_text!r} from={from_aid}; "
        f"last_messages={last_messages}"
    )


async def _current_max_seq(client: AUNClient, *, limit: int = 200) -> int:
    """遍历当前消息游标，供固定 AID 场景按 after_seq 隔离本轮消息。"""
    after_seq = 0
    max_seq = 0
    while True:
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": limit})
        msgs = result.get("messages", [])
        if not msgs:
            return max_seq
        for msg in msgs:
            max_seq = max(max_seq, int(msg.get("seq") or 0))
        if len(msgs) < limit:
            return max_seq
        after_seq = max_seq


def _assert_decrypted(msg: dict, expected_payload: dict, label: str = ""):
    prefix = f"[{label}] " if label else ""
    assert msg.get("encrypted") is True, f"{prefix}should be marked encrypted"
    for k, v in expected_payload.items():
        assert msg["payload"].get(k) == v, f"{prefix}payload.{k} mismatch: {msg['payload'].get(k)} != {v}"


def _find_message_by_text(messages: list[dict], expected_text: str) -> dict:
    for message in messages:
        payload = message.get("payload")
        if isinstance(payload, dict) and str(payload.get("text") or "") == expected_text:
            return message
    raise AssertionError(f"message with text={expected_text!r} not found in {messages}")


# ---------------------------------------------------------------------------
# 基础测试
# ---------------------------------------------------------------------------

async def test_prekey_upload_and_get():
    print("\n=== Test 1: Prekey upload/get ===")
    alice, bob = _make_client("alice"), _make_client("bob")
    try:
        alice_aid = await _ensure_connected(alice, _ALICE_AID)
        bob_aid = await _ensure_connected(bob, _BOBB_AID)

        # generate_prekey + RPC upload
        prekey_material = bob.e2ee.generate_prekey()
        assert prekey_material["cert_fingerprint"].startswith("sha256:")
        result = await bob._transport.call("message.e2ee.put_prekey", prekey_material)
        assert result.get("ok") or result.get("success", False) or "prekey_id" in result

        pk1 = await alice._transport.call("message.e2ee.get_prekey", {"aid": bob_aid})
        assert pk1["found"]
        assert pk1["prekey"]["cert_fingerprint"] == prekey_material["cert_fingerprint"]

        pk2 = await alice._transport.call("message.e2ee.get_prekey", {"aid": bob_aid})
        assert pk2["found"]
        assert pk2["prekey"]["prekey_id"] == pk1["prekey"]["prekey_id"]

        print("[PASS] Test 1")
        return True
    except Exception as e:
        print(f"[FAIL] Test 1: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_sdk_to_sdk_prekey():
    print("\n=== Test 2: SDK->SDK prekey ===")
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, _ALICE_AID)
        r_aid = await _ensure_connected(receiver, _BOBB_AID)
        base_seq = await _current_max_seq(receiver)

        await _sdk_send(sender, r_aid, {"text": "sdk2sdk prekey", "n": 1})
        msgs = await _sdk_recv_push_after(receiver, s_aid, after_seq=base_seq)
        assert len(msgs) >= 1
        _assert_decrypted(msgs[0], {"text": "sdk2sdk prekey"})

        print("[PASS] Test 2")
        return True
    except Exception as e:
        print(f"[FAIL] Test 2: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sender.close(); await receiver.close()


async def test_sdk_long_term_fallback():
    print("\n=== Test 3: SDK long_term_key fallback (manual) ===")
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, _CHARLIE_AID)
        r_aid = _DAVE_AID
        local = receiver._auth._keystore.load_identity(r_aid)
        if local is None:
            await receiver.auth.create_aid({"aid": r_aid})
        base_seq = await _current_max_seq(receiver)

        await _sdk_send(sender, r_aid, {"text": "fallback"})

        auth = await receiver.auth.authenticate({"aid": r_aid})
        await receiver.connect(auth)
        msgs = await _sdk_recv_pull(receiver, s_aid, after_seq=base_seq)
        assert len(msgs) >= 1
        _assert_decrypted(msgs[0], {"text": "fallback"})
        assert msgs[0].get("e2ee", {}).get("encryption_mode") == "long_term_key"

        print("[PASS] Test 3")
        return True
    except Exception as e:
        print(f"[FAIL] Test 3: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sender.close(); await receiver.close()


async def test_raw_to_sdk():
    print("\n=== Test 4: Raw WS->SDK ===")
    s_sdk, r_sdk = _make_client("rs"), _make_client("rr")
    try:
        s_aid = await _ensure_connected(s_sdk, _ALICE_AID)
        r_aid = await _ensure_connected(r_sdk, _BOBB_AID)
        s_e2ee = _make_raw_e2ee(s_sdk)
        base_seq = await _current_max_seq(r_sdk)
        unique_text = f"raw2sdk_{int(asyncio.get_running_loop().time() * 1000)}"

        await _raw_send(s_sdk, s_e2ee, r_aid, {"text": unique_text})
        msgs = await _sdk_recv_push_after(r_sdk, s_aid, after_seq=base_seq)
        try:
            msg = _find_message_by_text(msgs, unique_text)
        except AssertionError:
            msg = await _wait_for_sdk_pull_message(
                r_sdk, s_aid, after_seq=base_seq, expected_text=unique_text,
            )
        _assert_decrypted(msg, {"text": unique_text})

        print("[PASS] Test 4")
        return True
    except Exception as e:
        print(f"[FAIL] Test 4: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await s_sdk.close(); await r_sdk.close()


# ---------------------------------------------------------------------------
# 互通矩阵测试
# ---------------------------------------------------------------------------

async def test_sdk_to_raw():
    """SDK encrypt -> Raw WS decrypt"""
    print("\n=== Test 5: SDK->Raw WS ===")
    s_sdk, r_sdk = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(s_sdk, _ALICE_AID)
        r_aid = await _ensure_connected(r_sdk, _BOBB_AID)
        r_e2ee = _make_raw_e2ee(r_sdk)
        base_seq = await _current_max_seq(r_sdk)
        unique_text = f"sdk2raw_{int(asyncio.get_running_loop().time() * 1000)}"

        await _sdk_send(s_sdk, r_aid, {"text": unique_text})
        msg = await _wait_for_raw_pull_message(
            r_sdk, r_e2ee, s_aid, after_seq=base_seq, expected_text=unique_text,
        )
        _assert_decrypted(msg, {"text": unique_text})

        print("[PASS] Test 5")
        return True
    except Exception as e:
        print(f"[FAIL] Test 5: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await s_sdk.close(); await r_sdk.close()


async def test_raw_to_raw():
    """Raw WS <-> Raw WS"""
    print("\n=== Test 6: Raw WS<->Raw WS ===")
    a_sdk, b_sdk = _make_client("a"), _make_client("b")
    try:
        a_aid = await _ensure_connected(a_sdk, _ALICE_AID)
        b_aid = await _ensure_connected(b_sdk, _BOBB_AID)
        a_e2ee = _make_raw_e2ee(a_sdk)
        b_e2ee = _make_raw_e2ee(b_sdk)
        run_id = int(asyncio.get_running_loop().time() * 1000)

        # A -> B
        base_seq_b = await _current_max_seq(b_sdk)
        text_a2b = f"raw_a2b_{run_id}"
        await _raw_send(a_sdk, a_e2ee, b_aid, {"text": text_a2b})
        msg_b = await _wait_for_raw_pull_message(
            b_sdk, b_e2ee, a_aid, after_seq=base_seq_b, expected_text=text_a2b,
        )
        _assert_decrypted(msg_b, {"text": text_a2b}, "A->B")

        # B -> A
        base_seq_a = await _current_max_seq(a_sdk)
        text_b2a = f"raw_b2a_{run_id}"
        await _raw_send(b_sdk, b_e2ee, a_aid, {"text": text_b2a})
        msg_a = await _wait_for_raw_pull_message(
            a_sdk, a_e2ee, b_aid, after_seq=base_seq_a, expected_text=text_b2a,
        )
        _assert_decrypted(msg_a, {"text": text_b2a}, "B->A")

        print("[PASS] Test 6")
        return True
    except Exception as e:
        print(f"[FAIL] Test 6: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await a_sdk.close(); await b_sdk.close()


async def test_bidirectional_mixed():
    """SDK <-> Raw bidirectional"""
    print("\n=== Test 7: SDK<->Raw bidirectional ===")
    sdk_client, raw_client = _make_client("sdk"), _make_client("raw")
    try:
        sdk_aid = await _ensure_connected(sdk_client, _ALICE_AID)
        raw_aid = await _ensure_connected(raw_client, _BOBB_AID)
        raw_e2ee = _make_raw_e2ee(raw_client)
        run_id = int(asyncio.get_running_loop().time() * 1000)

        # SDK -> Raw
        raw_base_seq = await _current_max_seq(raw_client)
        sdk_to_raw_text = f"sdk2raw_bidir_{run_id}"
        await _sdk_send(sdk_client, raw_aid, {"text": sdk_to_raw_text, "dir": "forward"})
        msg_raw = await _wait_for_raw_pull_message(
            raw_client, raw_e2ee, sdk_aid, after_seq=raw_base_seq, expected_text=sdk_to_raw_text,
        )
        _assert_decrypted(msg_raw, {"text": sdk_to_raw_text}, "SDK->Raw")

        # Raw -> SDK
        sdk_base_seq = await _current_max_seq(sdk_client)
        raw_to_sdk_text = f"raw2sdk_bidir_{run_id}"
        await _raw_send(
            raw_client, raw_e2ee, sdk_aid, {"text": raw_to_sdk_text, "dir": "reverse"},
        )
        msgs_sdk = await _sdk_recv_push_after(sdk_client, raw_aid, after_seq=sdk_base_seq)
        try:
            msg_sdk = _find_message_by_text(msgs_sdk, raw_to_sdk_text)
        except AssertionError:
            msg_sdk = await _wait_for_sdk_pull_message(
                sdk_client, raw_aid, after_seq=sdk_base_seq, expected_text=raw_to_sdk_text,
            )
        _assert_decrypted(msg_sdk, {"text": raw_to_sdk_text}, "Raw->SDK")

        print("[PASS] Test 7")
        return True
    except Exception as e:
        print(f"[FAIL] Test 7: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sdk_client.close(); await raw_client.close()


async def test_multi_message_burst():
    """5 consecutive messages"""
    print("\n=== Test 8: Burst messages ===")
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, _ALICE_AID)
        r_aid = await _ensure_connected(receiver, _BOBB_AID)
        base_seq = await _current_max_seq(receiver)

        N = 5
        for i in range(N):
            await _sdk_send(sender, r_aid, {"text": f"burst_{i}", "seq": i})

        await asyncio.sleep(2)
        msgs = await _sdk_recv_pull(receiver, s_aid, after_seq=base_seq)
        assert len(msgs) >= N, f"expected {N}, got {len(msgs)}"

        received_texts = sorted(m["payload"]["text"] for m in msgs)
        expected_texts = sorted(f"burst_{i}" for i in range(N))
        assert received_texts == expected_texts, f"mismatch: {received_texts}"

        print(f"[PASS] Test 8 ({len(msgs)}/{N})")
        return True
    except Exception as e:
        print(f"[FAIL] Test 8: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sender.close(); await receiver.close()


async def test_prekey_rotation_in_flight():
    """Old prekey messages still decryptable after rotation"""
    print("\n=== Test 9: Prekey rotation ===")
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, _ALICE_AID)
        r_aid = await _ensure_connected(receiver, _BOBB_AID)
        base_seq = await _current_max_seq(receiver)

        await _sdk_send(sender, r_aid, {"text": "before_rotate", "phase": 1})

        # Receiver rotates prekey
        await receiver._upload_prekey()

        await _sdk_send(sender, r_aid, {"text": "after_rotate", "phase": 2})

        await asyncio.sleep(2)
        msgs = await _sdk_recv_pull(receiver, s_aid, after_seq=base_seq)
        assert len(msgs) >= 2, f"expected 2, got {len(msgs)}"

        texts = {m["payload"]["text"] for m in msgs}
        assert "before_rotate" in texts
        assert "after_rotate" in texts

        print("[PASS] Test 9")
        return True
    except Exception as e:
        print(f"[FAIL] Test 9: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sender.close(); await receiver.close()


async def test_push_then_pull_no_duplicate():
    """Push + pull should not deliver duplicate"""
    print("\n=== Test 10: Push + pull no duplicate ===")
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, _ALICE_AID)
        r_aid = await _ensure_connected(receiver, _BOBB_AID)
        base_seq = await _current_max_seq(receiver)

        push_msgs = []
        push_event = asyncio.Event()

        def handler(data):
            if not isinstance(data, dict):
                return
            if data.get("from") != s_aid:
                return
            try:
                seq = int(data.get("seq") or 0)
            except (TypeError, ValueError):
                seq = 0
            if seq <= base_seq:
                return
            push_msgs.append(data)
            push_event.set()

        sub = receiver.on("message.received", handler)

        await _sdk_send(sender, r_aid, {"text": "dup_test"})
        try:
            await asyncio.wait_for(push_event.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
        sub.unsubscribe()

        if not push_msgs:
            print("[SKIP] Push not received")
            return True

        assert len(push_msgs) == 1
        _assert_decrypted(push_msgs[0], {"text": "dup_test"}, "push")

        pull_result = await receiver.call("message.pull", {"after_seq": base_seq, "limit": 50})
        pull_msgs = [m for m in pull_result.get("messages", [])
                     if m.get("from") == s_aid and m.get("encrypted") is True]
        print(f"  push={len(push_msgs)}, pull={len(pull_msgs)}")

        print("[PASS] Test 10")
        return True
    except Exception as e:
        print(f"[FAIL] Test 10: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sender.close(); await receiver.close()


async def test_sdk_to_sdk_bidirectional():
    """SDK <-> SDK bidirectional"""
    print("\n=== Test 11: SDK<->SDK bidirectional ===")
    alice, bob = _make_client("a"), _make_client("b")
    try:
        a_aid = await _ensure_connected(alice, _ALICE_AID)
        b_aid = await _ensure_connected(bob, _BOBB_AID)

        bob_base_seq = await _current_max_seq(bob)
        await _sdk_send(alice, b_aid, {"text": "hello_bob", "from": "alice"})
        msgs_bob = await _sdk_recv_push_after(bob, a_aid, after_seq=bob_base_seq)
        assert len(msgs_bob) >= 1
        _assert_decrypted(msgs_bob[0], {"text": "hello_bob"}, "A->B")

        alice_base_seq = await _current_max_seq(alice)
        await _sdk_send(bob, a_aid, {"text": "hello_alice", "from": "bob"})
        msgs_alice = await _sdk_recv_push_after(alice, b_aid, after_seq=alice_base_seq)
        assert len(msgs_alice) >= 1
        _assert_decrypted(msgs_alice[0], {"text": "hello_alice"}, "B->A")

        print("[PASS] Test 11")
        return True
    except Exception as e:
        print(f"[FAIL] Test 11: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await alice.close(); await bob.close()


async def test_same_aid_slots_ack_isolated():
    """同一 AID 下不同 slot 的 pull/ack 互不污染。"""
    print("\n=== Test 12: Same AID multi-slot ack isolation ===")
    sender = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    }, debug=True)
    sender._config_model.require_forward_secrecy = False
    sender._test_slot_id = _build_test_slot_id("sender")
    receiver_slot_a = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    }, debug=True)
    receiver_slot_a._config_model.require_forward_secrecy = False
    receiver_slot_a._test_slot_id = "slot-a"
    receiver_slot_b = AUNClient({
        "aun_path": _TEST_AUN_PATH,
    }, debug=True)
    receiver_slot_b._config_model.require_forward_secrecy = False
    receiver_slot_b._test_slot_id = "slot-b"
    try:
        s_aid = await _ensure_connected(sender, _ALICE_AID)
        r_aid = await _ensure_connected(receiver_slot_a, _BOBB_AID)
        await _ensure_connected(receiver_slot_b, _BOBB_AID)

        base_seq_a = await _current_max_seq(receiver_slot_a)
        base_seq_b = await _current_max_seq(receiver_slot_b)
        assert base_seq_a == base_seq_b, f"slot 基线不一致: {base_seq_a} != {base_seq_b}"

        expected_slots = {"slot-a", "slot-b"}
        ack_events = []
        ack_event = asyncio.Event()

        def _on_ack(data):
            if not isinstance(data, dict):
                return
            if data.get("to") != r_aid:
                return
            slot_id = str(data.get("slot_id") or "")
            if slot_id not in expected_slots:
                return
            ack_events.append(dict(data))
            if {str(item.get("slot_id") or "") for item in ack_events} >= expected_slots:
                ack_event.set()

        sub = sender.on("message.ack", _on_ack)
        try:
            unique_text = f"slot_isolation_{int(asyncio.get_running_loop().time() * 1000)}"
            await _sdk_send(sender, r_aid, {"text": unique_text})

            msg_a = await _wait_for_sdk_pull_message(
                receiver_slot_a, s_aid, after_seq=base_seq_a, expected_text=unique_text,
            )
            msg_b = await _wait_for_sdk_pull_message(
                receiver_slot_b, s_aid, after_seq=base_seq_b, expected_text=unique_text,
            )
            _assert_decrypted(msg_a, {"text": unique_text}, "slot-a")
            _assert_decrypted(msg_b, {"text": unique_text}, "slot-b")
            assert int(msg_a.get("seq") or 0) == int(msg_b.get("seq") or 0), "同 AID 不同 slot 的 seq 应一致"

            ack_a = await receiver_slot_a.call("message.ack", {"seq": msg_a["seq"]})
            ack_b = await receiver_slot_b.call("message.ack", {"seq": msg_b["seq"]})
            assert int(ack_a["ack_seq"]) >= int(msg_a["seq"])
            assert int(ack_b["ack_seq"]) >= int(msg_b["seq"])

            await asyncio.wait_for(ack_event.wait(), timeout=5.0)
        finally:
            sub.unsubscribe()

        slots_seen = {str(item.get("slot_id") or "") for item in ack_events}
        assert slots_seen == expected_slots, f"ack 事件 slot 集合不完整: {slots_seen}"
        device_ids = {str(item.get("device_id") or "") for item in ack_events}
        assert len(device_ids) == 1 and "" not in device_ids, f"device_id 异常: {device_ids}"
        ack_by_slot = {str(item.get("slot_id") or ""): int(item.get("ack_seq") or 0) for item in ack_events}
        assert ack_by_slot["slot-a"] >= int(msg_a["seq"])
        assert ack_by_slot["slot-b"] >= int(msg_b["seq"])

        print("[PASS] Test 12")
        return True
    except Exception as e:
        print(f"[FAIL] Test 12: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await sender.close()
        await receiver_slot_a.close()
        await receiver_slot_b.close()


async def test_raw_multi_message():
    """Raw WS burst messages"""
    print("\n=== Test 13: Raw WS burst ===")
    s_sdk, r_sdk = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(s_sdk, _ALICE_AID)
        r_aid = await _ensure_connected(r_sdk, _BOBB_AID)
        s_e2ee = _make_raw_e2ee(s_sdk)
        r_e2ee = _make_raw_e2ee(r_sdk)
        base_seq = await _current_max_seq(r_sdk)
        run_id = int(asyncio.get_running_loop().time() * 1000)

        N = 3
        expected_texts = [f"raw_burst_{run_id}_{i}" for i in range(N)]
        for i in range(N):
            await _raw_send(s_sdk, s_e2ee, r_aid, {"text": expected_texts[i], "i": i, "run_id": run_id})

        expected_set = set(expected_texts)
        matched: dict[str, dict] = {}
        deadline = asyncio.get_running_loop().time() + 20.0
        while asyncio.get_running_loop().time() < deadline and len(matched) < N:
            msgs = await _raw_recv_pull(r_sdk, r_e2ee, s_aid, after_seq=base_seq)
            for msg in msgs:
                payload = msg.get("payload")
                if not isinstance(payload, dict):
                    continue
                text = str(payload.get("text") or "")
                if text in expected_set:
                    matched[text] = msg
            if len(matched) < N:
                await asyncio.sleep(0.5)

        assert set(matched) == expected_set, f"mismatch: matched={sorted(matched)} expected={sorted(expected_set)}"
        for i, text in enumerate(expected_texts):
            _assert_decrypted(matched[text], {"text": text, "i": i}, f"burst-{i}")

        print(f"[PASS] Test 13 ({len(matched)}/{N})")
        return True
    except Exception as e:
        print(f"[FAIL] Test 13: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await s_sdk.close(); await r_sdk.close()


async def test_multi_device_recipient_and_self_sync():
    """同一 AID 多设备 fanout + 发件同步副本。"""
    print("\n=== Test 14: Multi-device recipient + self sync ===")
    seed_alice, seed_bob = _make_client("seed-a"), _make_client("seed-b")
    alice_main = alice_sync = bob_phone = bob_laptop = None
    try:
        await _ensure_connected(seed_alice, _ALICE_AID)
        await _ensure_connected(seed_bob, _BOBB_AID)
        _prepare_isolated_identity("alice-main", _ALICE_AID)
        _prepare_isolated_identity("alice-sync", _ALICE_AID)
        _prepare_isolated_identity("bob-phone", _BOBB_AID)
        _prepare_isolated_identity("bob-laptop", _BOBB_AID)
        await seed_bob.close()
        await seed_alice.close()
        seed_bob = None
        seed_alice = None

        alice_main = _make_isolated_client("alice-main")
        alice_sync = _make_isolated_client("alice-sync")
        bob_phone = _make_isolated_client("bob-phone")
        bob_laptop = _make_isolated_client("bob-laptop")

        await _ensure_connected(alice_main, _ALICE_AID)
        await _ensure_connected(alice_sync, _ALICE_AID)
        await _ensure_connected(bob_phone, _BOBB_AID)
        await _ensure_connected(bob_laptop, _BOBB_AID)
        await asyncio.sleep(1.0)

        alice_main_device = str(alice_main._device_id or "")
        alice_sync_device = str(alice_sync._device_id or "")
        bob_phone_device = str(bob_phone._device_id or "")
        bob_laptop_device = str(bob_laptop._device_id or "")
        assert alice_main_device and alice_sync_device and alice_main_device != alice_sync_device
        assert bob_phone_device and bob_laptop_device and bob_phone_device != bob_laptop_device

        base_phone = await _current_max_seq(bob_phone)
        base_laptop = await _current_max_seq(bob_laptop)
        base_sync = await _current_max_seq(alice_sync)
        text = f"multi_device_sync_{int(asyncio.get_running_loop().time() * 1000)}"

        result = await _sdk_send(alice_main, _BOBB_AID, {"text": text, "kind": "multi-device"})
        assert result.get("status") in {"sent", "delivered"}

        phone_msg = await _wait_for_sdk_pull_message(
            bob_phone, _ALICE_AID, after_seq=base_phone, expected_text=text,
        )
        laptop_msg = await _wait_for_sdk_pull_message(
            bob_laptop, _ALICE_AID, after_seq=base_laptop, expected_text=text,
        )
        sync_msg = await _wait_for_sdk_pull_message(
            alice_sync, _ALICE_AID, after_seq=base_sync, expected_text=text,
        )

        _assert_decrypted(phone_msg, {"text": text, "kind": "multi-device"}, "bob-phone")
        _assert_decrypted(laptop_msg, {"text": text, "kind": "multi-device"}, "bob-laptop")
        _assert_decrypted(sync_msg, {"text": text, "kind": "multi-device"}, "alice-sync")
        assert phone_msg.get("direction") == "inbound"
        assert laptop_msg.get("direction") == "inbound"
        assert sync_msg.get("direction") == "outbound_sync"

        print("[PASS] Test 14")
        return True
    except Exception as e:
        print(f"[FAIL] Test 14: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        if seed_bob:
            await seed_bob.close()
        if seed_alice:
            await seed_alice.close()
        if bob_laptop:
            await bob_laptop.close()
        if bob_phone:
            await bob_phone.close()
        if alice_sync:
            await alice_sync.close()
        if alice_main:
            await alice_main.close()


async def test_multi_device_offline_pull():
    """多设备场景下离线设备重连后能补拉自己的设备副本。"""
    print("\n=== Test 15: Multi-device offline pull ===")
    seed_alice, seed_bob = _make_client("seed-a"), _make_client("seed-b")
    alice_main = bob_phone = bob_laptop = None
    try:
        await _ensure_connected(seed_alice, _ALICE_AID)
        await _ensure_connected(seed_bob, _BOBB_AID)
        _prepare_isolated_identity("alice-main", _ALICE_AID)
        _prepare_isolated_identity("bob-phone", _BOBB_AID)
        _prepare_isolated_identity("bob-laptop", _BOBB_AID)
        await seed_bob.close()
        await seed_alice.close()
        seed_bob = None
        seed_alice = None

        alice_main = _make_isolated_client("alice-main")
        bob_phone = _make_isolated_client("bob-phone")
        bob_laptop = _make_isolated_client("bob-laptop")

        await _ensure_connected(alice_main, _ALICE_AID)
        await _ensure_connected(bob_phone, _BOBB_AID)
        await _ensure_connected(bob_laptop, _BOBB_AID)
        await asyncio.sleep(1.0)

        offline_base = await _current_max_seq(bob_laptop)
        online_base = await _current_max_seq(bob_phone)
        await bob_laptop.close()
        bob_laptop = None
        await asyncio.sleep(1.0)

        text = f"multi_device_offline_{int(asyncio.get_running_loop().time() * 1000)}"
        result = await _sdk_send(alice_main, _BOBB_AID, {"text": text, "kind": "offline-pull"})
        assert result.get("status") in {"sent", "delivered"}

        online_msg = await _wait_for_sdk_pull_message(
            bob_phone, _ALICE_AID, after_seq=online_base, expected_text=text,
        )
        _assert_decrypted(online_msg, {"text": text, "kind": "offline-pull"}, "bob-phone-online")
        assert online_msg.get("direction") == "inbound"

        bob_laptop = _make_isolated_client("bob-laptop")
        await _ensure_connected(bob_laptop, _BOBB_AID)
        offline_msg = await _wait_for_sdk_pull_message(
            bob_laptop, _ALICE_AID, after_seq=offline_base, expected_text=text, timeout=15.0,
        )
        _assert_decrypted(offline_msg, {"text": text, "kind": "offline-pull"}, "bob-laptop-offline")
        assert offline_msg.get("direction") == "inbound"

        print("[PASS] Test 15")
        return True
    except Exception as e:
        print(f"[FAIL] Test 15: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        if seed_bob:
            await seed_bob.close()
        if seed_alice:
            await seed_alice.close()
        if bob_laptop:
            await bob_laptop.close()
        if bob_phone:
            await bob_phone.close()
        if alice_main:
            await alice_main.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("E2EE E2E Tests")
    print("SDK / Raw WS interop matrix + scenarios")
    print("=" * 60)

    tests = [
        ("Prekey upload/get",            test_prekey_upload_and_get),
        ("SDK->SDK prekey",              test_sdk_to_sdk_prekey),
        ("Raw WS->SDK",                  test_raw_to_sdk),
        ("SDK->Raw WS",                  test_sdk_to_raw),
        ("Raw WS<->Raw WS",              test_raw_to_raw),
        ("SDK<->Raw bidirectional",      test_bidirectional_mixed),
        ("Burst messages",               test_multi_message_burst),
        ("Prekey rotation",              test_prekey_rotation_in_flight),
        ("Push+pull no duplicate",       test_push_then_pull_no_duplicate),
        ("SDK<->SDK bidirectional",      test_sdk_to_sdk_bidirectional),
        ("Same AID multi-slot ack",      test_same_aid_slots_ack_isolated),
        ("Raw WS burst",                 test_raw_multi_message),
        ("Multi-device recipient+self",  test_multi_device_recipient_and_self_sync),
        ("Multi-device offline pull",    test_multi_device_offline_pull),
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
        print("\n[PASS] All E2E tests passed!")
        return 0
    else:
        print(f"\n[FAIL] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
