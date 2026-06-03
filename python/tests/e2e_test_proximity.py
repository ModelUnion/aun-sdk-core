#!/usr/bin/env python3
"""消息 proximity E2E 测试。"""
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

from aun_core import AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/proximity"
    return "./.aun_test_proximity"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()


def _rid() -> str:
    return uuid.uuid4().hex[:10]


def _make_aun_path(tag: str) -> str:
    root = Path(_TEST_AUN_PATH).parent / f"proximity_{tag}_{_rid()}"
    root.mkdir(parents=True, exist_ok=True)
    return str(root)


def _make_client(tag: str) -> AUNClient:
    return make_client_for_path(
        _make_aun_path(tag),
        debug=False,
        require_forward_secrecy=False,
    )


async def _connect(client: AUNClient, aid: str, slot_id: str) -> None:
    await ensure_connected_identity(
        client,
        aid,
        connect_options={"slot_id": slot_id, "auto_reconnect": False},
    )


async def _safe_close(*clients: AUNClient) -> None:
    await asyncio.sleep(0.5)
    for client in clients:
        try:
            await client.close()
        except Exception:
            pass


def _assert_proximity_payload(
    label: str,
    msg: dict,
    *,
    sender_aid: str,
    text: str,
    encrypted: bool | None = None,
) -> None:
    payload = msg.get("payload") or {}
    if not isinstance(payload, dict) or payload.get("text") != text:
        raise AssertionError(f"{label}: payload 不匹配: {msg}")

    proximity = msg.get("proximity")
    if not isinstance(proximity, dict):
        raise AssertionError(f"{label}: 缺少 proximity: {msg}")
    if proximity.get("asserted_by") != "gateway":
        raise AssertionError(f"{label}: proximity.asserted_by 异常: {proximity}")
    if msg.get("same_egress_ip") is not True or proximity.get("same_egress_ip") is not True:
        raise AssertionError(f"{label}: same_egress_ip 未注入为 true: {msg}")
    if msg.get("same_network") is not True or proximity.get("same_network") is not True:
        raise AssertionError(f"{label}: same_network 未注入为 true: {msg}")
    if "same_device" not in msg or "same_device" not in proximity:
        raise AssertionError(f"{label}: 缺少 same_device 字段: {msg}")
    if encrypted is not None and bool(msg.get("encrypted")) is not encrypted:
        raise AssertionError(f"{label}: encrypted 字段异常 actual={msg.get('encrypted')!r} expected={encrypted!r}: {msg}")
    if encrypted is True:
        e2ee = msg.get("e2ee")
        if not isinstance(e2ee, dict) or e2ee.get("version") != "v2":
            raise AssertionError(f"{label}: 缺少 V2 e2ee 元数据: {msg}")

    for key in ("sender_device_id", "_sender_device_id", "from_device_id", "from_device"):
        if key in msg:
            raise AssertionError(f"{label}: 内部字段泄露到顶层 {key}: {msg}")
        if key in payload:
            raise AssertionError(f"{label}: 内部字段泄露到 payload {key}: {payload}")

    actual_sender = str(msg.get("from") or msg.get("from_aid") or msg.get("sender_aid") or "")
    if actual_sender != sender_aid:
        raise AssertionError(f"{label}: sender 异常 actual={actual_sender!r} expected={sender_aid!r}")


async def _wait_for(event: asyncio.Event, label: str, timeout: float = 15.0) -> None:
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise AssertionError(f"{label}: 应用层 publish 超时 {timeout}s") from exc


async def test_p2p_plaintext_proximity() -> None:
    rid = _rid()
    alice_aid = f"prox-pa-{rid}.{_ISSUER}"
    bob_aid = f"prox-pb-{rid}.{_ISSUER}"
    alice = _make_client("p2p-alice")
    bob = _make_client("p2p-bob")
    received: list[dict] = []
    delivered = asyncio.Event()
    text = f"p2p-proximity-{rid}"

    def _on_message(data):
        if not isinstance(data, dict):
            return
        payload = data.get("payload") or {}
        if isinstance(payload, dict) and payload.get("text") == text:
            received.append(data)
            delivered.set()

    try:
        await _connect(alice, alice_aid, "main")
        await _connect(bob, bob_aid, "main")
        bob.on("message.received", _on_message)

        await alice.call("message.send", {
            "to": bob_aid,
            "payload": {
                "type": "text",
                "text": text,
                "sender_device_id": "payload-must-strip",
                "from_device_id": "payload-must-strip",
            },
            "encrypt": False,
        })

        await _wait_for(delivered, "P2P 明文 message.received")
        _assert_proximity_payload("P2P 明文", received[0], sender_aid=alice_aid, text=text, encrypted=False)
        print(f"[PASS] P2P 明文 proximity: same_device={received[0].get('same_device')}")
    finally:
        await _safe_close(alice, bob)


async def test_p2p_encrypted_proximity() -> None:
    rid = _rid()
    alice_aid = f"prox-ea-{rid}.{_ISSUER}"
    bob_aid = f"prox-eb-{rid}.{_ISSUER}"
    alice = _make_client("p2p-enc-alice")
    bob = _make_client("p2p-enc-bob")
    received: list[dict] = []
    delivered = asyncio.Event()
    text = f"p2p-encrypted-proximity-{rid}"

    def _on_message(data):
        if not isinstance(data, dict):
            return
        payload = data.get("payload") or {}
        if isinstance(payload, dict) and payload.get("text") == text:
            received.append(data)
            delivered.set()

    try:
        await _connect(alice, alice_aid, "main")
        await _connect(bob, bob_aid, "main")
        bob.on("message.received", _on_message)

        await alice.call("message.send", {
            "to": bob_aid,
            "payload": {"type": "text", "text": text},
        })

        await _wait_for(delivered, "P2P 密文 message.received", timeout=20.0)
        _assert_proximity_payload("P2P 密文", received[0], sender_aid=alice_aid, text=text, encrypted=True)
        print(f"[PASS] P2P 密文 proximity: same_device={received[0].get('same_device')}")
    finally:
        await _safe_close(alice, bob)


async def _wait_group_committed(client: AUNClient, group_id: str, member_aid: str, timeout: float = 30.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    last_bootstrap = None
    while asyncio.get_running_loop().time() < deadline:
        try:
            bootstrap = await client.call("group.v2.bootstrap", {"group_id": group_id})
            last_bootstrap = bootstrap
            committed = list(bootstrap.get("committed_member_aids") or bootstrap.get("member_aids") or [])
            devices = bootstrap.get("devices", []) or []
            has_device = any(isinstance(d, dict) and str(d.get("aid") or "") == member_aid for d in devices)
            pending = bool(bootstrap.get("pending_adds")) or bool(bootstrap.get("pending_removes"))
            if member_aid in committed and has_device and not pending:
                return
        except Exception:
            pass
        await asyncio.sleep(0.5)
    raise AssertionError(f"group committed 等待超时: group={group_id} member={member_aid} last={last_bootstrap}")


async def test_group_plaintext_proximity() -> None:
    rid = _rid()
    alice_aid = f"prox-ga-{rid}.{_ISSUER}"
    bob_aid = f"prox-gb-{rid}.{_ISSUER}"
    alice = _make_client("group-alice")
    bob = _make_client("group-bob")
    group_id = ""
    received: list[dict] = []
    delivered = asyncio.Event()
    text = f"group-proximity-{rid}"

    def _on_group_message(data):
        if not isinstance(data, dict):
            return
        payload = data.get("payload") or {}
        if data.get("group_id") == group_id and isinstance(payload, dict) and payload.get("text") == text:
            received.append(data)
            delivered.set()

    try:
        await _connect(alice, alice_aid, "main")
        await _connect(bob, bob_aid, "main")
        bob.on("group.message_created", _on_group_message)

        created = await alice.call("group.create", {"name": f"prox-{rid}", "visibility": "private"})
        group_id = str((created.get("group") or {}).get("group_id") or "")
        if not group_id:
            raise AssertionError(f"group.create 未返回 group_id: {created}")
        await alice.call("group.add_member", {"group_id": group_id, "aid": bob_aid})
        await asyncio.sleep(1.0)

        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {
                "type": "text",
                "text": text,
                "sender_device_id": "payload-must-strip",
                "from_device_id": "payload-must-strip",
            },
            "encrypt": False,
        })

        await _wait_for(delivered, "Group 明文 group.message_created")
        _assert_proximity_payload("Group 明文", received[0], sender_aid=alice_aid, text=text, encrypted=False)
        print(f"[PASS] Group 明文 proximity: same_device={received[0].get('same_device')}")
    finally:
        if group_id:
            await _safe_close(bob)
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
            await _safe_close(alice)
        else:
            await _safe_close(alice, bob)


async def test_group_encrypted_proximity() -> None:
    rid = _rid()
    alice_aid = f"prox-gea-{rid}.{_ISSUER}"
    bob_aid = f"prox-geb-{rid}.{_ISSUER}"
    alice = _make_client("group-enc-alice")
    bob = _make_client("group-enc-bob")
    group_id = ""
    received: list[dict] = []
    delivered = asyncio.Event()
    text = f"group-encrypted-proximity-{rid}"

    def _on_group_message(data):
        if not isinstance(data, dict):
            return
        payload = data.get("payload") or {}
        if data.get("group_id") == group_id and isinstance(payload, dict) and payload.get("text") == text:
            received.append(data)
            delivered.set()

    try:
        await _connect(alice, alice_aid, "main")
        await _connect(bob, bob_aid, "main")
        bob.on("group.message_created", _on_group_message)

        created = await alice.call("group.create", {"name": f"prox-enc-{rid}", "visibility": "private"})
        group_id = str((created.get("group") or {}).get("group_id") or "")
        if not group_id:
            raise AssertionError(f"group.create 未返回 group_id: {created}")
        await alice.call("group.add_member", {"group_id": group_id, "aid": bob_aid})
        await _wait_group_committed(alice, group_id, bob_aid)

        await alice.call("group.send", {
            "group_id": group_id,
            "payload": {"type": "text", "text": text},
        })

        await _wait_for(delivered, "Group 密文 group.message_created", timeout=30.0)
        _assert_proximity_payload("Group 密文", received[0], sender_aid=alice_aid, text=text, encrypted=True)
        print(f"[PASS] Group 密文 proximity: same_device={received[0].get('same_device')}")
    finally:
        if group_id:
            await _safe_close(bob)
            try:
                await alice.call("group.dissolve", {"group_id": group_id})
            except Exception:
                pass
            await _safe_close(alice)
        else:
            await _safe_close(alice, bob)


async def main() -> None:
    print("=" * 60)
    print("proximity 应用层 publish E2E")
    print(f"AUN_PATH={_TEST_AUN_PATH}")
    print(f"ISSUER={_ISSUER}")
    print("=" * 60)
    await test_p2p_plaintext_proximity()
    await test_p2p_encrypted_proximity()
    await test_group_plaintext_proximity()
    await test_group_encrypted_proximity()
    print("[PASS] proximity E2E 全部通过")


if __name__ == "__main__":
    asyncio.run(main())
