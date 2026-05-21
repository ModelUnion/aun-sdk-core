#!/usr/bin/env python3
"""
AUN E2EE V2: thought.put / thought.get 端到端测试

覆盖：
- message.thought.put / message.thought.get（P2P thought，per-device wrap）
- group.thought.put / group.thought.get（Group thought，per-device wrap）

V2 thought 协议约定：
- 服务端依旧仅做内存级 KV，不持久化、不分配 seq、不 ack
- SDK 在 V2 ready 时多设备 wrap 出 e2ee.p2p_encrypted / e2ee.group_encrypted envelope
  作为 payload 上传，服务端对 envelope 透传，客户端读取后再单设备解密
- 单条 thought 服务端只存一份 envelope，envelope 内含多个 device wrap

使用方法（容器内）：
  python /tests/e2e_test_v2_thought.py
"""
import asyncio
import os
import sys
import time
import traceback
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient
from aun_core.errors import AuthError, RateLimitError

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", "").strip()
if not _TEST_AUN_PATH:
    if _AUN_DATA_ROOT:
        _TEST_AUN_PATH = f"{_AUN_DATA_ROOT}/single-domain/persistent"
    else:
        _TEST_AUN_PATH = "/data/aun/single-domain/persistent"

_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip()
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()


async def _make_client() -> AUNClient:
    return AUNClient({"aun_path": _TEST_AUN_PATH}, debug=True)


async def _ensure_connected(client: AUNClient, aid: str) -> None:
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            auth = await client.auth.authenticate({"aid": aid})
            connect_params = dict(auth)
            connect_params["auto_reconnect"] = False
            await client.connect(connect_params)
            return
        except (AuthError, RateLimitError, Exception) as exc:
            last_error = exc
            if attempt >= 3:
                break
            await asyncio.sleep(1.5 * (attempt + 1))
    raise last_error or RuntimeError(f"{aid} connect failed")


def _payload_texts(result):
    if not isinstance(result, dict):
        return []
    items = result.get("thoughts")
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        payload = item.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("text"), str):
            out.append(payload["text"])
    return out


class V2ThoughtTestRunner:
    def __init__(self):
        self.alice: AUNClient | None = None
        self.bob: AUNClient | None = None
        self.group_id: str = ""
        self.passed = 0
        self.failed = 0
        self.errors = []

    async def setup(self):
        print("\n[setup] 连接 Alice 和 Bob...")
        self.alice = await _make_client()
        self.bob = await _make_client()
        await _ensure_connected(self.alice, _ALICE_AID)
        await _ensure_connected(self.bob, _BOB_AID)
        print(f"[setup] Alice V2={self.alice._v2_session is not None}, Bob V2={self.bob._v2_session is not None}")

        # 创建 V2 测试群（V2 默认能力声明会让服务端创建 V2 群）
        result = await self.alice.call("group.create", {
            "name": f"v2-thought-{int(time.time())}",
            "visibility": "private",
        })
        self.group_id = result["group"]["group_id"]
        print(f"[setup] 创建群: {self.group_id}")

        await self.alice.call("group.add_member", {
            "group_id": self.group_id,
            "aid": _BOB_AID,
        })
        # 等待 Bob 端 epoch / 成员状态同步
        await asyncio.sleep(0.5)
        print(f"[setup] Bob 已加入群")

    async def teardown(self):
        for c in [self.alice, self.bob]:
            if c:
                try:
                    await c.disconnect()
                except Exception:
                    pass
        print("[teardown] 已断开")

    async def run_test(self, name, test_func):
        print(f"\n  [{name}] ...", end=" ")
        try:
            await test_func()
            print("✅ PASSED")
            self.passed += 1
        except Exception as e:
            print(f"❌ FAILED: {e}")
            self.errors.append((name, str(e), traceback.format_exc()))
            self.failed += 1

    # ── 场景 1：P2P thought.put 走 V2 加密 ───────────────────────

    async def test_p2p_thought_put_v2_envelope(self):
        rid = uuid.uuid4().hex[:8]
        ctx = {"type": "v2-run", "id": f"v2-thought-run-{rid}"}
        self._p2p_ctx = ctx
        self._p2p_text = f"v2-thought-p2p-{rid}-{int(time.time())}"
        put = await self.alice.call("message.thought.put", {
            "to": _BOB_AID,
            "context": ctx,
            "thought_id": f"mt-v2-{rid}",
            "payload": {"type": "thought", "text": self._p2p_text},
        })
        assert int(put.get("stored_count") or 0) >= 1, f"unexpected put result: {put}"

        # 直接读服务端原始返回，验证 envelope.type 为 V2 P2P 加密格式
        raw = await self.bob._transport.call("message.thought.get", {
            "sender_aid": _ALICE_AID,
            "context": ctx,
        })
        items = raw.get("thoughts") if isinstance(raw, dict) else None
        assert isinstance(items, list) and items, f"server raw thoughts empty: {raw}"
        first_payload = items[0].get("payload") or {}
        env_type = first_payload.get("type")
        assert env_type == "e2ee.p2p_encrypted", (
            f"V2 P2P thought payload.type 必须为 e2ee.p2p_encrypted，实际={env_type}"
        )
        # envelope 内应该有多个 wrap（per-device），即使 Bob 只有一个设备至少要有 1 个 recipient wrap
        recipients = first_payload.get("recipients")
        assert isinstance(recipients, list) and recipients, (
            f"V2 P2P thought envelope 必须包含 recipients[]，实际={first_payload}"
        )
        print(f"(envelope.type={env_type}, recipients={len(recipients)})", end=" ")

    # ── 场景 2：P2P thought.get 解密回明文 ──────────────────────

    async def test_p2p_thought_get_decrypted(self):
        result = await self.bob.call("message.thought.get", {
            "sender_aid": _ALICE_AID,
            "context": self._p2p_ctx,
        })
        texts = _payload_texts(result)
        assert self._p2p_text in texts, (
            f"V2 P2P thought 解密返回不含期望文本: texts={texts}, result={result}"
        )

    # ── 场景 3：P2P thought 重复读取不消耗（无 replay guard） ──

    async def test_p2p_thought_repeat_read(self):
        result = await self.bob.call("message.thought.get", {
            "sender_aid": _ALICE_AID,
            "context": self._p2p_ctx,
        })
        texts = _payload_texts(result)
        assert self._p2p_text in texts, f"重复读 V2 thought 失败: texts={texts}"

    # ── 场景 4：Group thought.put 走 V2 加密 ───────────────────

    async def test_group_thought_put_v2_envelope(self):
        rid = uuid.uuid4().hex[:8]
        ctx = {"type": "v2-group-run", "id": f"v2-group-thought-{rid}"}
        self._g_ctx = ctx
        self._g_text = f"v2-group-thought-{rid}-{int(time.time())}"
        put = await self.alice.call("group.thought.put", {
            "group_id": self.group_id,
            "context": ctx,
            "payload": {"type": "thought", "text": self._g_text},
        })
        assert isinstance(put, dict), f"group.thought.put 失败: {put}"

        raw = await self.bob._transport.call("group.thought.get", {
            "group_id": self.group_id,
            "sender_aid": _ALICE_AID,
            "context": ctx,
        })
        items = raw.get("thoughts") if isinstance(raw, dict) else None
        assert isinstance(items, list) and items, f"server raw group thoughts empty: {raw}"
        first_payload = items[0].get("payload") or {}
        env_type = first_payload.get("type")
        assert env_type == "e2ee.group_encrypted", (
            f"V2 group thought payload.type 必须为 e2ee.group_encrypted，实际={env_type}"
        )
        recipients = first_payload.get("recipients")
        assert isinstance(recipients, list) and recipients, (
            f"V2 group thought envelope 必须含 recipients[]，实际={first_payload}"
        )
        print(f"(envelope.type={env_type}, recipients={len(recipients)})", end=" ")

    # ── 场景 5：Group thought.get 解密回明文 ───────────────────

    async def test_group_thought_get_decrypted(self):
        result = await self.bob.call("group.thought.get", {
            "group_id": self.group_id,
            "sender_aid": _ALICE_AID,
            "context": self._g_ctx,
        })
        texts = _payload_texts(result)
        assert self._g_text in texts, (
            f"V2 group thought 解密失败: texts={texts}, result={result}"
        )

    async def run_all(self):
        print("=" * 60)
        print("AUN E2EE V2: thought.put / thought.get 端到端测试")
        print("=" * 60)
        print(f"  Alice: {_ALICE_AID}")
        print(f"  Bob:   {_BOB_AID}")
        print(f"  Data:  {_TEST_AUN_PATH}")

        await self.setup()
        try:
            await self.run_test("1. P2P thought.put 写 V2 envelope", self.test_p2p_thought_put_v2_envelope)
            await self.run_test("2. P2P thought.get 解密", self.test_p2p_thought_get_decrypted)
            await self.run_test("3. P2P thought 重复读取", self.test_p2p_thought_repeat_read)
            await self.run_test("4. Group thought.put 写 V2 envelope", self.test_group_thought_put_v2_envelope)
            await self.run_test("5. Group thought.get 解密", self.test_group_thought_get_decrypted)
        finally:
            await self.teardown()

        print("\n" + "=" * 60)
        print(f"结果: {self.passed} passed, {self.failed} failed")
        if self.errors:
            print("\n失败详情:")
            for name, err, tb in self.errors:
                print(f"\n  [{name}] {err}")
                print(f"    {tb.strip().split(chr(10))[-1]}")
        print("=" * 60)
        return self.failed == 0


async def main():
    runner = V2ThoughtTestRunner()
    success = await runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
