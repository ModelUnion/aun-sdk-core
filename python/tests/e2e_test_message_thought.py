#!/usr/bin/env python3
"""message.thought.get 真实链路 E2E 回归测试。

覆盖用户反馈的场景：服务端存在 9 条 mt-* thought，SDK 解密成功后
返回给应用层的 thoughts[] 不能变成空数组。
"""
import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any

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
    return "./.aun_test_message_thought"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"

_passed = 0
_failed = 0
_errors: list[str] = []


def _ok(name: str) -> None:
    global _passed
    _passed += 1
    print(f"  [PASS] {name}")


def _fail(name: str, reason: str) -> None:
    global _failed
    _failed += 1
    _errors.append(f"{name}: {reason}")
    print(f"  [FAIL] {name} - {reason}")


def _run_id() -> str:
    return uuid.uuid4().hex[:12]


def _make_client(tag: str) -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    client._test_slot_id = f"thought-{tag}-{uuid.uuid4().hex[:12]}"
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.register_aid({"aid": aid})
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
            return
        except (AuthError, RateLimitError) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


def _payload_texts(result: dict[str, Any]) -> list[str]:
    thoughts = result.get("thoughts") if isinstance(result, dict) else None
    if not isinstance(thoughts, list):
        return []
    texts: list[str] = []
    for item in thoughts:
        if not isinstance(item, dict):
            continue
        payload = item.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("text"), str):
            texts.append(payload["text"])
    return texts


async def test_message_thought_get_keeps_decrypted_items() -> None:
    name = "message_thought_get_keeps_decrypted_items"
    rid = _run_id()
    alice_aid = f"thought-a-{rid}.{_ISSUER}"
    bob_aid = f"thought-b-{rid}.{_ISSUER}"
    context = {"type": "run", "id": f"thought-run-{rid}"}
    expected_texts = [f"thought-{idx}-{rid}" for idx in range(9)]

    alice = _make_client(f"alice-{rid}")
    bob = _make_client(f"bob-{rid}")
    try:
        await _ensure_connected(alice, alice_aid)
        await _ensure_connected(bob, bob_aid)

        for idx, text in enumerate(expected_texts):
            put = await alice.call("message.thought.put", {
                "to": bob_aid,
                "context": context,
                "thought_id": f"mt-{rid}-{idx}",
                "payload": {"type": "thought", "text": text, "index": idx},
                "encrypt": True,
            })
            if int(put.get("stored_count") or 0) < idx + 1:
                _fail(name, f"put stored_count 异常 idx={idx}: {put}")
                return

        raw = await bob._transport.call("message.thought.get", {
            "sender_aid": alice_aid,
            "context": context,
        })
        raw_items = raw.get("thoughts") if isinstance(raw, dict) else None
        if not isinstance(raw_items, list) or len(raw_items) != len(expected_texts):
            _fail(name, f"服务端原始返回 thoughts 条数异常: raw={raw}")
            return
        if not raw.get("found"):
            _fail(name, f"服务端原始返回 found=false: raw={raw}")
            return

        result = await bob.call("message.thought.get", {
            "sender_aid": alice_aid,
            "context": context,
        })
        texts = _payload_texts(result)
        if texts != expected_texts:
            _fail(name, f"SDK 返回明文 thoughts 不匹配: texts={texts}, result={result}, raw_count={len(raw_items)}")
            return

        repeat = await bob.call("message.thought.get", {
            "sender_aid": alice_aid,
            "context": context,
        })
        repeat_texts = _payload_texts(repeat)
        if repeat_texts != expected_texts:
            _fail(name, f"重复读取不应被 replay guard 消耗: texts={repeat_texts}, result={repeat}")
            return

        _ok(name)
    finally:
        await alice.close()
        await bob.close()


async def main() -> int:
    print("=" * 60)
    print("message.thought.get 真实链路 E2E 测试")
    print("=" * 60)

    await test_message_thought_get_keeps_decrypted_items()

    print()
    print(f"通过: {_passed}, 失败: {_failed}")
    if _errors:
        print("\n失败详情:")
        for err in _errors:
            print(f"  - {err}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
