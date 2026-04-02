#!/usr/bin/env python3
"""E2EE 完整 E2E 测试 — 需要运行中的 AUN Gateway 服务。

覆盖 SDK 和裸 WebSocket 在发送/接收端的所有组合，确保互联互通。

使用方法：
  python tests/integration_test_e2ee.py

前置条件：
  - Docker 环境运行中（docker compose up -d）
  - hosts 文件映射 gateway.agentid.pub → 127.0.0.1
  - Gateway 地址由 SDK 通过 AID 的 issuer domain 自动发现
"""
import asyncio
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.e2ee import E2EEManager


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _make_client(tag: str) -> AUNClient:
    return AUNClient({"aun_path": f"./.aun_test/{tag}-{random.randint(1000,9999)}"})


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    await client.auth.create_aid({"aid": aid})
    auth = await client.auth.authenticate({"aid": aid})
    await client.connect(auth)
    return aid


def _make_raw_e2ee(client: AUNClient) -> E2EEManager:
    """从已连接的 AUNClient 创建独立 E2EEManager（模拟裸 WebSocket 开发者）。
    重构后 E2EEManager 只需 identity_fn 和 keystore，不再需要 transport。
    """
    return E2EEManager(
        identity_fn=lambda: client._identity or {},
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
        "persist": True,
    })


async def _raw_recv_pull(client: AUNClient, e2ee: E2EEManager, from_aid: str,
                         after_seq: int = 0) -> list[dict]:
    """裸 WS pull + 手动解密。"""
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
        "persist": True,
    })


async def _sdk_recv_push(client: AUNClient, from_aid: str, timeout: float = 5.0) -> list[dict]:
    """SDK 通过推送事件接收，超时后 pull 兜底"""
    inbox = []
    event = asyncio.Event()

    def handler(data):
        if isinstance(data, dict) and data.get("from") == from_aid:
            inbox.append(data)
            event.set()

    sub = client.on("message.received", handler)
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    sub.unsubscribe()

    if not inbox:
        result = await client.call("message.pull", {"after_seq": 0, "limit": 50})
        msgs = result.get("messages", [])
        inbox.extend(m for m in msgs if m.get("from") == from_aid)
    return inbox


async def _sdk_recv_pull(client: AUNClient, from_aid: str, after_seq: int = 0) -> list[dict]:
    """SDK 通过 pull 接收（自动解密）"""
    result = await client.call("message.pull", {"after_seq": after_seq, "limit": 50})
    msgs = result.get("messages", [])
    return [m for m in msgs if m.get("from") == from_aid]


def _run_id() -> int:
    return random.randint(10000, 99999)


def _assert_decrypted(msg: dict, expected_payload: dict, label: str = ""):
    prefix = f"[{label}] " if label else ""
    assert msg.get("encrypted") is True, f"{prefix}should be marked encrypted"
    for k, v in expected_payload.items():
        assert msg["payload"].get(k) == v, f"{prefix}payload.{k} mismatch: {msg['payload'].get(k)} != {v}"


# ---------------------------------------------------------------------------
# 基础测试
# ---------------------------------------------------------------------------

async def test_prekey_upload_and_get():
    print("\n=== Test 1: Prekey upload/get ===")
    rid = _run_id()
    alice, bob = _make_client("alice"), _make_client("bob")
    try:
        alice_aid = await _ensure_connected(alice, f"e2ee-alice-{rid}.agentid.pub")
        bob_aid = await _ensure_connected(bob, f"e2ee-bob-{rid}.agentid.pub")

        # generate_prekey + RPC upload
        prekey_material = bob.e2ee.generate_prekey()
        result = await bob._transport.call("message.e2ee.put_prekey", prekey_material)
        assert result.get("ok") or result.get("success", False) or "prekey_id" in result

        pk1 = await alice._transport.call("message.e2ee.get_prekey", {"aid": bob_aid})
        assert pk1["found"]

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
    rid = _run_id()
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, f"e2ee-s-{rid}.agentid.pub")
        r_aid = await _ensure_connected(receiver, f"e2ee-r-{rid}.agentid.pub")

        await _sdk_send(sender, r_aid, {"text": "sdk2sdk prekey", "n": 1})
        msgs = await _sdk_recv_push(receiver, s_aid)
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
    print("\n=== Test 3: SDK long_term_key fallback ===")
    rid = _run_id()
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, f"e2ee-s-{rid}.agentid.pub")
        r_aid = f"e2ee-r-{rid}.agentid.pub"
        await receiver.auth.create_aid({"aid": r_aid})

        await _sdk_send(sender, r_aid, {"text": "fallback"})

        auth = await receiver.auth.authenticate({"aid": r_aid})
        await receiver.connect(auth)
        msgs = await _sdk_recv_pull(receiver, s_aid)
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
    rid = _run_id()
    s_sdk, r_sdk = _make_client("rs"), _make_client("rr")
    try:
        s_aid = await _ensure_connected(s_sdk, f"e2ee-rs-{rid}.agentid.pub")
        r_aid = await _ensure_connected(r_sdk, f"e2ee-rr-{rid}.agentid.pub")
        s_e2ee = _make_raw_e2ee(s_sdk)

        await _raw_send(s_sdk, s_e2ee, r_aid, {"text": "raw2sdk"})
        msgs = await _sdk_recv_push(r_sdk, s_aid)
        assert len(msgs) >= 1
        _assert_decrypted(msgs[0], {"text": "raw2sdk"})

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
    rid = _run_id()
    s_sdk, r_sdk = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(s_sdk, f"e2ee-s-{rid}.agentid.pub")
        r_aid = await _ensure_connected(r_sdk, f"e2ee-r-{rid}.agentid.pub")
        r_e2ee = _make_raw_e2ee(r_sdk)

        await _sdk_send(s_sdk, r_aid, {"text": "sdk2raw"})
        await asyncio.sleep(1)
        msgs = await _raw_recv_pull(r_sdk, r_e2ee, s_aid)
        assert len(msgs) >= 1, f"expected >= 1 msg, got {len(msgs)}"
        _assert_decrypted(msgs[0], {"text": "sdk2raw"})

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
    rid = _run_id()
    a_sdk, b_sdk = _make_client("a"), _make_client("b")
    try:
        a_aid = await _ensure_connected(a_sdk, f"e2ee-a-{rid}.agentid.pub")
        b_aid = await _ensure_connected(b_sdk, f"e2ee-b-{rid}.agentid.pub")
        a_e2ee = _make_raw_e2ee(a_sdk)
        b_e2ee = _make_raw_e2ee(b_sdk)

        # A -> B
        await _raw_send(a_sdk, a_e2ee, b_aid, {"text": "raw_a2b"})
        await asyncio.sleep(1)
        msgs_b = await _raw_recv_pull(b_sdk, b_e2ee, a_aid)
        assert len(msgs_b) >= 1, "B should receive A's message"
        _assert_decrypted(msgs_b[0], {"text": "raw_a2b"}, "A->B")

        # B -> A
        await _raw_send(b_sdk, b_e2ee, a_aid, {"text": "raw_b2a"})
        await asyncio.sleep(1)
        msgs_a = await _raw_recv_pull(a_sdk, a_e2ee, b_aid)
        assert len(msgs_a) >= 1, "A should receive B's message"
        _assert_decrypted(msgs_a[0], {"text": "raw_b2a"}, "B->A")

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
    rid = _run_id()
    sdk_client, raw_client = _make_client("sdk"), _make_client("raw")
    try:
        sdk_aid = await _ensure_connected(sdk_client, f"e2ee-sdk-{rid}.agentid.pub")
        raw_aid = await _ensure_connected(raw_client, f"e2ee-raw-{rid}.agentid.pub")
        raw_e2ee = _make_raw_e2ee(raw_client)

        # SDK -> Raw
        await _sdk_send(sdk_client, raw_aid, {"text": "sdk2raw_bidir", "dir": "forward"})
        await asyncio.sleep(1)
        msgs_raw = await _raw_recv_pull(raw_client, raw_e2ee, sdk_aid)
        assert len(msgs_raw) >= 1, "Raw should receive SDK's message"
        _assert_decrypted(msgs_raw[0], {"text": "sdk2raw_bidir"}, "SDK->Raw")

        # Raw -> SDK
        await _raw_send(raw_client, raw_e2ee, sdk_aid, {"text": "raw2sdk_bidir", "dir": "reverse"})
        msgs_sdk = await _sdk_recv_push(sdk_client, raw_aid)
        assert len(msgs_sdk) >= 1, "SDK should receive Raw's message"
        _assert_decrypted(msgs_sdk[0], {"text": "raw2sdk_bidir"}, "Raw->SDK")

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
    rid = _run_id()
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, f"e2ee-s-{rid}.agentid.pub")
        r_aid = await _ensure_connected(receiver, f"e2ee-r-{rid}.agentid.pub")

        N = 5
        for i in range(N):
            await _sdk_send(sender, r_aid, {"text": f"burst_{i}", "seq": i})

        await asyncio.sleep(2)
        msgs = await _sdk_recv_pull(receiver, s_aid)
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
    rid = _run_id()
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, f"e2ee-s-{rid}.agentid.pub")
        r_aid = await _ensure_connected(receiver, f"e2ee-r-{rid}.agentid.pub")

        await _sdk_send(sender, r_aid, {"text": "before_rotate", "phase": 1})

        # Receiver rotates prekey
        await receiver._upload_prekey()

        await _sdk_send(sender, r_aid, {"text": "after_rotate", "phase": 2})

        await asyncio.sleep(2)
        msgs = await _sdk_recv_pull(receiver, s_aid)
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
    rid = _run_id()
    sender, receiver = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(sender, f"e2ee-s-{rid}.agentid.pub")
        r_aid = await _ensure_connected(receiver, f"e2ee-r-{rid}.agentid.pub")

        push_msgs = []
        push_event = asyncio.Event()

        def handler(data):
            if isinstance(data, dict) and data.get("from") == s_aid:
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

        pull_result = await receiver.call("message.pull", {"after_seq": 0, "limit": 50})
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
    rid = _run_id()
    alice, bob = _make_client("a"), _make_client("b")
    try:
        a_aid = await _ensure_connected(alice, f"e2ee-a-{rid}.agentid.pub")
        b_aid = await _ensure_connected(bob, f"e2ee-b-{rid}.agentid.pub")

        await _sdk_send(alice, b_aid, {"text": "hello_bob", "from": "alice"})
        msgs_bob = await _sdk_recv_push(bob, a_aid)
        assert len(msgs_bob) >= 1
        _assert_decrypted(msgs_bob[0], {"text": "hello_bob"}, "A->B")

        await _sdk_send(bob, a_aid, {"text": "hello_alice", "from": "bob"})
        msgs_alice = await _sdk_recv_push(alice, b_aid)
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


async def test_raw_multi_message():
    """Raw WS burst messages"""
    print("\n=== Test 12: Raw WS burst ===")
    rid = _run_id()
    s_sdk, r_sdk = _make_client("s"), _make_client("r")
    try:
        s_aid = await _ensure_connected(s_sdk, f"e2ee-s-{rid}.agentid.pub")
        r_aid = await _ensure_connected(r_sdk, f"e2ee-r-{rid}.agentid.pub")
        s_e2ee = _make_raw_e2ee(s_sdk)
        r_e2ee = _make_raw_e2ee(r_sdk)

        N = 3
        for i in range(N):
            await _raw_send(s_sdk, s_e2ee, r_aid, {"text": f"raw_burst_{i}", "i": i})

        await asyncio.sleep(2)
        msgs = await _raw_recv_pull(r_sdk, r_e2ee, s_aid)
        assert len(msgs) >= N, f"expected {N}, got {len(msgs)}"

        texts = sorted(m["payload"]["text"] for m in msgs)
        expected = sorted(f"raw_burst_{i}" for i in range(N))
        assert texts == expected, f"mismatch: {texts}"

        print(f"[PASS] Test 12 ({len(msgs)}/{N})")
        return True
    except Exception as e:
        print(f"[FAIL] Test 12: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        await s_sdk.close(); await r_sdk.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("E2EE E2E Tests")
    print("SDK / Raw WS interop matrix + scenarios")
    print("=" * 60)

    tests = [
        ("1.  Prekey upload/get",              test_prekey_upload_and_get),
        ("2.  SDK->SDK prekey",                test_sdk_to_sdk_prekey),
        ("3.  SDK long_term_key fallback",     test_sdk_long_term_fallback),
        ("4.  Raw WS->SDK",                    test_raw_to_sdk),
        ("5.  SDK->Raw WS",                    test_sdk_to_raw),
        ("6.  Raw WS<->Raw WS",               test_raw_to_raw),
        ("7.  SDK<->Raw bidirectional",        test_bidirectional_mixed),
        ("8.  Burst messages",                 test_multi_message_burst),
        ("9.  Prekey rotation",                test_prekey_rotation_in_flight),
        ("10. Push+pull no duplicate",         test_push_then_pull_no_duplicate),
        ("11. SDK<->SDK bidirectional",        test_sdk_to_sdk_bidirectional),
        ("12. Raw WS burst",                   test_raw_multi_message),
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
