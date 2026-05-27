#!/usr/bin/env python3
"""AUN E2EE V2 1DH/per-AID wrap focused E2E test."""
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

from aun_core import AUNClient  # noqa: E402
from aun_core.client import _v2_wrap_capabilities  # noqa: E402
from aun_core.errors import AuthError, RateLimitError  # noqa: E402


os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", "").strip()
if not _TEST_AUN_PATH:
    _TEST_AUN_PATH = (
        f"{_AUN_DATA_ROOT}/single-domain/persistent"
        if _AUN_DATA_ROOT
        else "/data/aun/single-domain/persistent"
    )

_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip()
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()


def _make_client() -> AUNClient:
    return AUNClient({"aun_path": _TEST_AUN_PATH}, debug=True)


async def _connect_client(client: AUNClient, aid: str) -> None:
    if client._auth._keystore.load_identity(aid) is None:
        try:
            await client.auth.register_aid({"aid": aid})
        except Exception as exc:
            print(f"  [connect] register_aid skipped: {aid} ({exc.__class__.__name__})")

    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            params = dict(auth)
            params["auto_reconnect"] = False
            await client.connect(params)
            return
        except (AuthError, RateLimitError, Exception) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


async def _disconnect(*clients: AUNClient) -> None:
    for client in clients:
        try:
            await client.disconnect()
        except Exception:
            pass


async def _ack_old_p2p(client: AUNClient) -> None:
    try:
        result = await client.call("message.v2.pull", {"after_seq": 0, "limit": 200})
        messages = result.get("messages", []) if isinstance(result, dict) else []
        if messages:
            await client.call("message.v2.ack", {"up_to_seq": max(int(m.get("seq") or 0) for m in messages)})
    except Exception as exc:
        print(f"  [cleanup] p2p skipped: {exc}")


def _assert_policy(result: dict, protocol: str, scope: str) -> None:
    policy = result.get("e2ee_wrap_policy")
    assert isinstance(policy, dict), f"missing e2ee_wrap_policy: {result}"
    assert policy.get("protocol") == protocol, policy
    assert policy.get("scope") == scope, policy


def _assert_no_wrap_fields_in_aad(envelope: dict) -> None:
    aad = envelope.get("aad")
    assert isinstance(aad, dict), envelope
    assert "wrap_scope" not in aad, aad
    assert "wrap_policy_version" not in aad, aad
    assert "e2ee_wrap_policy" not in aad, aad


def _find_row(envelope: dict, aid: str, role: str | None = None) -> list:
    for row in envelope.get("recipients", []):
        if not isinstance(row, list) or len(row) < 8:
            continue
        if row[0] != aid:
            continue
        if role is not None and row[2] != role:
            continue
        return row
    raise AssertionError(f"recipient row not found: aid={aid} role={role} rows={envelope.get('recipients')}")


async def _wait_p2p_text(client: AUNClient, inbox: list[dict], text: str) -> dict:
    for _ in range(25):
        for msg in inbox:
            if isinstance(msg.get("payload"), dict) and msg["payload"].get("text") == text:
                return msg
        await asyncio.sleep(0.2)
    result = await client.call("message.pull", {"limit": 50, "max_pages": 5})
    messages = result.get("messages", []) if isinstance(result, dict) else []
    for msg in inbox + messages:
        if isinstance(msg.get("payload"), dict) and msg["payload"].get("text") == text:
            return msg
    raise AssertionError(f"p2p message not decrypted: text={text} got={len(inbox) + len(messages)}")


async def _wait_group_text(client: AUNClient, group_id: str, inbox: list[dict], text: str) -> dict:
    for _ in range(25):
        for msg in inbox:
            if isinstance(msg.get("payload"), dict) and msg["payload"].get("text") == text:
                return msg
        await asyncio.sleep(0.2)
    result = await client.call("group.pull", {"group_id": group_id, "limit": 50, "max_pages": 5})
    messages = result.get("messages", []) if isinstance(result, dict) else []
    for msg in inbox + messages:
        if isinstance(msg.get("payload"), dict) and msg["payload"].get("text") == text:
            return msg
    raise AssertionError(f"group message not decrypted: group={group_id} text={text} got={len(inbox) + len(messages)}")


async def test_p2p_1dh_per_aid(alice: AUNClient, bob: AUNClient) -> None:
    print("\n[p2p] bootstrap legacy/new policy")
    legacy = await alice.call("message.v2.bootstrap", {"peer_aid": _BOB_AID})
    _assert_policy(legacy, "3DH", "device")
    assert any(str(d.get("device_id") or "") for d in legacy.get("peer_devices", [])), legacy

    modern = await alice.call("message.v2.bootstrap", {
        "peer_aid": _BOB_AID,
        "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
    })
    _assert_policy(modern, "1DH", "aid")

    text = f"p2p-1dh-{uuid.uuid4().hex[:10]}"
    envelope = await alice._build_v2_p2p_envelope(
        to=_BOB_AID,
        payload={"text": text},
        message_id=f"m-{uuid.uuid4().hex}",
        timestamp=int(time.time() * 1000),
        use_cache=False,
    )
    row = _find_row(envelope, _BOB_AID, "peer")
    assert row[1] == "", row
    assert row[3] == "aid_master", row
    assert row[5] == "", row
    _assert_no_wrap_fields_in_aad(envelope)

    inbox: list[dict] = []
    bob.on("message.received", lambda data: inbox.append(data) if isinstance(data, dict) else None)
    await alice.call("message.send", {"to": _BOB_AID, "payload": envelope, "encrypt": False})
    msg = await _wait_p2p_text(bob, inbox, text)
    assert msg.get("encrypted") is True, msg
    assert msg.get("e2ee", {}).get("version") == "v2", msg
    print(f"  ok: row_device=<aid> key_source=aid_master text={text}")


async def _create_committed_group(alice: AUNClient) -> str:
    result = await alice.call("group.create", {
        "name": f"v2-1dh-{uuid.uuid4().hex[:8]}",
        "visibility": "private",
    })
    group_id = result["group"]["group_id"]
    await alice.call("group.add_member", {"group_id": group_id, "aid": _BOB_AID})
    committed = []
    for _ in range(40):
        await asyncio.sleep(0.5)
        bs = await alice.call("group.v2.bootstrap", {
            "group_id": group_id,
            "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
        })
        committed = list(bs.get("committed_member_aids") or [])
        if _BOB_AID in committed:
            return group_id
    raise AssertionError(f"Bob not committed: group={group_id} committed={committed}")


async def test_group_1dh_per_aid(alice: AUNClient, bob: AUNClient) -> None:
    print("\n[group] create group and bootstrap legacy/new policy")
    group_id = await _create_committed_group(alice)

    legacy = await alice.call("group.v2.bootstrap", {"group_id": group_id})
    _assert_policy(legacy, "3DH", "device")
    assert any(str(d.get("device_id") or "") for d in legacy.get("devices", [])), legacy

    modern = await alice.call("group.v2.bootstrap", {
        "group_id": group_id,
        "e2ee_wrap_capabilities": _v2_wrap_capabilities(),
    })
    _assert_policy(modern, "1DH", "aid")

    text = f"group-1dh-{uuid.uuid4().hex[:10]}"
    envelope = await alice._build_v2_group_envelope(
        group_id=group_id,
        payload={"text": text},
        message_id=f"gm-{uuid.uuid4().hex}",
        timestamp=int(time.time() * 1000),
        use_cache=False,
    )
    row = _find_row(envelope, _BOB_AID, "member")
    assert row[1] == "", row
    assert row[3] == "aid_master", row
    assert row[5] == "", row
    _assert_no_wrap_fields_in_aad(envelope)

    inbox: list[dict] = []
    bob.on("group.message_created", lambda data: inbox.append(data) if isinstance(data, dict) else None)
    await alice.call("group.v2.send", {"group_id": group_id, "envelope": envelope})
    msg = await _wait_group_text(bob, group_id, inbox, text)
    assert msg.get("encrypted") is True, msg
    assert msg.get("e2ee", {}).get("version") == "v2", msg
    print(f"  ok: group={group_id} row_device=<aid> key_source=aid_master text={text}")


async def main() -> None:
    print("=" * 72)
    print("AUN E2EE V2 1DH/per-AID wrap E2E")
    print("=" * 72)
    print(f"  Alice: {_ALICE_AID}")
    print(f"  Bob:   {_BOB_AID}")
    print(f"  Data:  {_TEST_AUN_PATH}")

    alice = _make_client()
    bob = _make_client()
    try:
        await _connect_client(alice, _ALICE_AID)
        await _connect_client(bob, _BOB_AID)
        await _ack_old_p2p(alice)
        await _ack_old_p2p(bob)
        await test_p2p_1dh_per_aid(alice, bob)
        await test_group_1dh_per_aid(alice, bob)
    finally:
        await _disconnect(alice, bob)


if __name__ == "__main__":
    asyncio.run(main())
