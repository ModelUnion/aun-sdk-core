#!/usr/bin/env python3
"""P2P 消息失败路径集成测试。

覆盖重点：
  1. 显式明文发送不走发送端加密/prekey 路径。
  2. 坏密文（签名篡改）不会投递给业务层，并会推进/确认游标，避免反复 backlog。
"""
from __future__ import annotations

import asyncio
import base64
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

from aun_core import AUNClient, AuthError, RateLimitError

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_p2p_failure_paths"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str):
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str):
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} - {reason}")


def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.register_aid({"aid": aid})
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            await client.connect(auth)
            return aid
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


async def _current_max_seq(client: AUNClient, *, limit: int = 200) -> int:
    after_seq = 0
    max_seq = 0
    for _ in range(100):
        result = await client.call("message.pull", {"after_seq": after_seq, "limit": limit})
        latest_seq = int(result.get("latest_seq") or 0)
        server_ack_seq = int(result.get("server_ack_seq") or 0)
        raw_count = int(result.get("raw_count") or 0)
        max_seq = max(max_seq, server_ack_seq, latest_seq)
        messages = result.get("messages", [])
        for message in messages:
            max_seq = max(max_seq, int(message.get("seq") or 0))
        next_after = max(max_seq, after_seq)
        if raw_count <= 0 or next_after <= after_seq:
            return max_seq
        after_seq = next_after
    return max_seq


async def _raw_bad_encrypted_send(alice: AUNClient, to_aid: str, text: str) -> dict:
    message_id = f"bad-{uuid.uuid4().hex}"
    envelope = await alice._build_v2_p2p_envelope(
        to=to_aid,
        payload={"type": "text", "text": text},
        message_id=message_id,
        timestamp=int(time.time() * 1000),
        use_cache=False,
    )
    sig = bytearray(base64.b64decode(str(envelope.get("sender_signature") or "")))
    if not sig:
        raise AssertionError("构造坏密文失败: sender_signature 为空")
    sig[0] ^= 0x01
    envelope["sender_signature"] = base64.b64encode(bytes(sig)).decode("ascii")
    return await alice._transport.call("message.send", {
        "to": to_aid,
        "payload": envelope,
    })


async def test_plaintext_send_does_not_require_recipient_prekey():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    target = _make_client()
    target_aid = f"plain-{rid}.{_ISSUER}"
    try:
        await _ensure_connected(alice, _ALICE_AID)
        # multi-device 持久消息需要接收方至少注册过设备；本用例验证 sender 的 encrypt=false
        # 明文路径不依赖发送端拉取或使用对端 prekey。
        await _ensure_connected(target, target_aid)

        sent = await alice.call("message.send", {
            "to": target_aid,
            "payload": {"type": "text", "text": f"plain-no-prekey-{rid}"},
            "encrypt": False,
        })
        if not sent.get("message_id"):
            raise AssertionError(f"明文发送未返回 message_id: {sent}")
        _ok("显式明文发送不要求对端 prekey")
    finally:
        await alice.close()
        await target.close()


async def test_bad_encrypted_message_advances_cursor_without_backlog():
    rid = uuid.uuid4().hex[:10]
    alice = _make_client()
    bobb = _make_client()
    delivered: list[dict] = []
    undecryptable: list[dict] = []

    def on_message(data):
        if isinstance(data, dict):
            delivered.append(dict(data))

    def on_undecryptable(data):
        if isinstance(data, dict):
            undecryptable.append(dict(data))

    try:
        await _ensure_connected(alice, _ALICE_AID)
        await _ensure_connected(bobb, _BOBB_AID)
        baseline = await _current_max_seq(bobb)
        sub = bobb.on("message.received", on_message)
        bad_sub = bobb.on("message.undecryptable", on_undecryptable)
        try:
            sent = await _raw_bad_encrypted_send(alice, _BOBB_AID, f"bad-signature-{rid}")
            if not sent.get("message_id"):
                raise AssertionError(f"坏密文发送未返回 message_id: {sent}")

            first_pull: dict | None = None
            for _ in range(20):
                await asyncio.sleep(0.25)
                first_pull = await bobb.call("message.pull", {"after_seq": baseline, "limit": 20})
                observed_seq = max(
                    [int(item.get("seq") or 0) for item in undecryptable]
                    + [
                        int(first_pull.get("latest_seq") or 0),
                        int(first_pull.get("server_ack_seq") or 0),
                    ]
                )
                if observed_seq > baseline:
                    break
            if first_pull is None:
                first_pull = await bobb.call("message.pull", {"after_seq": baseline, "limit": 20})

            bad_seq = max(
                [int(item.get("seq") or 0) for item in undecryptable]
                + [
                    int(first_pull.get("latest_seq") or 0),
                    int(first_pull.get("server_ack_seq") or 0),
                ]
            )
            if bad_seq <= baseline:
                raise AssertionError(f"坏密文发送 seq 异常: baseline={baseline}, sent={sent}, first={first_pull}")

            if any(item.get("seq") == bad_seq for item in delivered):
                raise AssertionError(f"坏密文不应投递 message.received: {delivered}")

            if any(int(item.get("seq") or 0) == bad_seq for item in first_pull.get("messages", [])):
                raise AssertionError(f"坏密文不应出现在 SDK pull 结果: {first_pull}")

            second_pull = await bobb.call("message.pull", {"after_seq": baseline, "limit": 20})
            if any(int(item.get("seq") or 0) == bad_seq for item in second_pull.get("messages", [])):
                raise AssertionError(f"坏密文不应反复 backlog: {second_pull}")

            server_ack = max(
                int(first_pull.get("server_ack_seq") or 0),
                int(second_pull.get("server_ack_seq") or 0),
            )
            if server_ack < bad_seq:
                raise AssertionError(
                    f"坏密文应推进服务端 ack 游标: bad_seq={bad_seq}, "
                    f"first={first_pull}, second={second_pull}"
                )
            _ok("坏密文不投递且不会反复 backlog")
        finally:
            bad_sub.unsubscribe()
            sub.unsubscribe()
    finally:
        await alice.close()
        await bobb.close()


async def _run_test(name: str, func):
    print(f"\n=== {name} ===")
    try:
        await func()
    except Exception as exc:
        _fail(name, str(exc))
        import traceback
        traceback.print_exc()


async def main():
    print("=== P2P failure-path 集成测试 ===\n")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ISSUER   = {_ISSUER}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOBB_AID}")
    print()

    await _run_test("明文发送不依赖 prekey", test_plaintext_send_does_not_require_recipient_prekey)
    await _run_test("坏密文推进游标", test_bad_encrypted_message_advances_cursor_without_backlog)

    print(f"\n{'=' * 50}")
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        print("失败详情:")
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())
