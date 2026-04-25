#!/usr/bin/env python3
"""Mail 服务集成测试 — 需要运行中的 AUN Gateway + Mail 服务。

覆盖（单域）：
  T2.1  本域投递 — 收件方 inbox 出现邮件
  T2.2  发件方 sent 记录
  T2.3  收件人 AID 不存在 — 返回错误
  T2.4  发送给自己 — inbox + sent 都有记录
  T2.5  多收件人（均本域）
  T2.17 mail.move inbox→archive
  T2.18 mail.mark 已读
  T2.19 mail.mark 星标
  T2.20 mail.search 关键词命中
  T2.21 mail.search 无结果
  T2.22 创建应用专用密码
  T2.23 列出应用专用密码
  T2.24 撤销应用专用密码
  T2.25 超过密码上限（跳过，上限 20 太大）
  T7.1  mail.get_quota 配额查询
  T7.2  mail.status 包含新特性

使用方法：
  docker exec kite-sdk-tester python /tests/integration_test_mail.py

前置条件：
  - Docker 单域环境运行中（docker compose up -d）
  - Mail 模块已部署，PostgreSQL 可达
"""
import asyncio
import os
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aun_core import AUNClient, AuthError, RateLimitError

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_mail"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_BOBB_AID = os.environ.get("AUN_TEST_BOB_AID", f"bobb.{_ISSUER}").strip()

# ---------------------------------------------------------------------------
# 计数
# ---------------------------------------------------------------------------

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
    print(f"  [FAIL] {name} — {reason}")


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _make_client() -> AUNClient:
    client = AUNClient({"aun_path": _TEST_AUN_PATH})
    client._config_model.require_forward_secrecy = False
    return client


async def _ensure_connected(client: AUNClient, aid: str) -> str:
    local = client._auth._keystore.load_identity(aid)
    if local is None:
        await client.auth.create_aid({"aid": aid})
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


async def _wait_mail_subject(
    client: AUNClient,
    mailbox: str,
    subject: str,
    *,
    timeout: float = 8.0,
    limit: int = 200,
) -> dict | None:
    deadline = time.monotonic() + timeout
    while True:
        result = await client.call("mail.list", {"mailbox": mailbox, "limit": limit})
        for msg in result.get("messages", []):
            if msg.get("subject") == subject:
                return msg
        if time.monotonic() >= deadline:
            return None
        await asyncio.sleep(0.3)


# ---------------------------------------------------------------------------
# 测试用例
# ---------------------------------------------------------------------------

async def test_send_and_list(alice: AUNClient, bob: AUNClient):
    """T2.1 + T2.2: 本域发送，收件方 inbox 有邮件，发件方 sent 有记录"""
    name = "T2.1+T2.2 本域投递 + sent 记录"
    ts = str(int(time.time() * 1000))
    subject = f"test-mail-{ts}"

    try:
        result = await alice.call("mail.send", {
            "to": [_BOBB_AID],
            "subject": subject,
            "body": f"Hello from alice at {ts}",
        })
        if not result.get("ok"):
            _fail(name, f"发送失败: {result}")
            return

        # 收件方 inbox
        if not await _wait_mail_subject(bob, "inbox", subject):
            _fail(name, f"收件方 inbox 未找到邮件 (subject={subject})")
            return

        # 发件方 sent
        if not await _wait_mail_subject(alice, "sent", subject):
            _fail(name, "发件方 sent 未找到记录")
            return

        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_get_message(bob: AUNClient):
    """T2.1 补充: mail.get 获取具体邮件"""
    name = "T2.1b mail.get 获取邮件"
    try:
        inbox = await bob.call("mail.list", {"mailbox": "inbox", "limit": 1})
        msgs = inbox.get("messages", [])
        if not msgs:
            _fail(name, "inbox 为空，无法测试 mail.get")
            return

        msg_id = msgs[0]["id"]
        msg = await bob.call("mail.get", {"message_id": msg_id})
        if msg.get("id") != msg_id:
            _fail(name, f"返回的 id 不匹配: {msg.get('id')} != {msg_id}")
            return
        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_nonexistent_recipient(alice: AUNClient):
    """T2.3: 发送到不存在的 AID"""
    name = "T2.3 收件人不存在"
    try:
        result = await alice.call("mail.send", {
            "to": [f"nonexistent_user_xyz.{_ISSUER}"],
            "subject": "should fail",
            "body": "test",
        })
        # 应该返回 ok=true 但 results 中该收件人 status=failed
        results = result.get("results", [])
        if results and results[0].get("status") == "failed":
            _ok(name)
        else:
            _fail(name, f"预期 failed 但得到: {results}")
    except Exception as e:
        # RPC 层面报错也算通过（取决于实现）
        if "不存在" in str(e) or "not found" in str(e).lower():
            _ok(name)
        else:
            _fail(name, str(e))


async def test_send_to_self(alice: AUNClient):
    """T2.4: 发送给自己"""
    name = "T2.4 发送给自己"
    ts = str(int(time.time() * 1000))
    subject = f"self-mail-{ts}"

    try:
        result = await alice.call("mail.send", {
            "to": [_ALICE_AID],
            "subject": subject,
            "body": "Self mail",
        })
        if not result.get("ok"):
            _fail(name, f"发送失败: {result}")
            return

        # inbox 应有
        found_inbox = bool(await _wait_mail_subject(alice, "inbox", subject))

        # sent 应有
        found_sent = bool(await _wait_mail_subject(alice, "sent", subject))

        if found_inbox and found_sent:
            _ok(name)
        else:
            _fail(name, f"inbox={found_inbox}, sent={found_sent}")
    except Exception as e:
        _fail(name, str(e))


async def test_multiple_recipients(alice: AUNClient, bob: AUNClient):
    """T2.5: 多收件人（均本域）"""
    name = "T2.5 多收件人"
    ts = str(int(time.time() * 1000))
    subject = f"multi-rcpt-{ts}"

    try:
        # alice + bob 都收
        result = await alice.call("mail.send", {
            "to": [_ALICE_AID, _BOBB_AID],
            "subject": subject,
            "body": "Multi recipient test",
        })
        if not result.get("ok"):
            _fail(name, f"发送失败: {result}")
            return

        results = result.get("results", [])
        delivered = [r for r in results if r.get("status") == "delivered"]
        if len(delivered) != 2:
            _fail(name, f"预期 2 个 delivered，得到 {len(delivered)}: {results}")
            return

        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_move(bob: AUNClient):
    """T2.17: mail.move inbox→archive"""
    name = "T2.17 mail.move"
    try:
        inbox = await bob.call("mail.list", {"mailbox": "inbox", "limit": 1})
        msgs = inbox.get("messages", [])
        if not msgs:
            _fail(name, "inbox 为空，无法测试 move")
            return

        msg_id = msgs[0]["id"]
        result = await bob.call("mail.move", {"message_id": msg_id, "to_mailbox": "archive"})
        if not result.get("ok"):
            _fail(name, f"move 失败: {result}")
            return

        # 验证 inbox 不再包含该邮件
        inbox2 = await bob.call("mail.list", {"mailbox": "inbox", "limit": 200})
        still_in_inbox = any(m["id"] == msg_id for m in inbox2.get("messages", []))
        if still_in_inbox:
            _fail(name, "move 后邮件仍在 inbox")
            return

        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_mark_seen(bob: AUNClient):
    """T2.18: mail.mark 已读"""
    name = "T2.18 mail.mark seen"
    try:
        inbox = await bob.call("mail.list", {"mailbox": "inbox", "limit": 1})
        msgs = inbox.get("messages", [])
        if not msgs:
            _fail(name, "inbox 为空，无法测试 mark")
            return

        msg_id = msgs[0]["id"]
        result = await bob.call("mail.mark", {
            "message_id": msg_id,
            "flags": {"seen": True},
        })
        if not result.get("ok"):
            _fail(name, f"mark 失败: {result}")
            return

        flags = result.get("flags", [])
        if "\\Seen" in flags:
            _ok(name)
        else:
            _fail(name, f"flags 中缺少 \\Seen: {flags}")
    except Exception as e:
        _fail(name, str(e))


async def test_mark_flagged(bob: AUNClient):
    """T2.19: mail.mark 星标"""
    name = "T2.19 mail.mark flagged"
    try:
        inbox = await bob.call("mail.list", {"mailbox": "inbox", "limit": 1})
        msgs = inbox.get("messages", [])
        if not msgs:
            _fail(name, "inbox 为空，无法测试 mark")
            return

        msg_id = msgs[0]["id"]
        result = await bob.call("mail.mark", {
            "message_id": msg_id,
            "flags": {"flagged": True},
        })
        if not result.get("ok"):
            _fail(name, f"mark 失败: {result}")
            return

        flags = result.get("flags", [])
        if "\\Flagged" in flags:
            _ok(name)
        else:
            _fail(name, f"flags 中缺少 \\Flagged: {flags}")
    except Exception as e:
        _fail(name, str(e))


async def test_search_hit(alice: AUNClient):
    """T2.20: mail.search 命中"""
    name = "T2.20 mail.search 命中"
    ts = str(int(time.time() * 1000))
    keyword = f"searchable{ts}"

    try:
        # 先发一封包含关键词的邮件
        await alice.call("mail.send", {
            "to": [_ALICE_AID],
            "subject": f"Subject with {keyword}",
            "body": "body content",
        })
        await asyncio.sleep(0.5)

        result = await alice.call("mail.search", {"query": keyword, "limit": 10})
        msgs = result.get("messages", [])
        if msgs and any(keyword in m.get("subject", "") for m in msgs):
            _ok(name)
        else:
            _fail(name, f"搜索 '{keyword}' 未命中: {result}")
    except Exception as e:
        _fail(name, str(e))


async def test_search_miss(alice: AUNClient):
    """T2.21: mail.search 无结果"""
    name = "T2.21 mail.search 无结果"
    try:
        result = await alice.call("mail.search", {
            "query": "xyznonexistent99999",
            "limit": 10,
        })
        msgs = result.get("messages", [])
        if msgs is None or len(msgs) == 0:
            _ok(name)
        else:
            _fail(name, f"预期空列表但得到 {len(msgs)} 条")
    except Exception as e:
        _fail(name, str(e))


def _is_test_app_password(item: dict) -> bool:
    name = str(item.get("name") or "")
    return name in {"TestClient", "test-imap"} or name.startswith("AUN_TEST_")


async def _cleanup_test_app_passwords(client: AUNClient):
    try:
        list_result = await client.call("mail.list_app_passwords", {})
        for item in list_result.get("passwords", []):
            if _is_test_app_password(item) and item.get("id"):
                await client.call("mail.revoke_app_password", {"id": item["id"]})
    except Exception:
        pass


async def test_app_password_lifecycle(alice: AUNClient):
    """T2.22+T2.23+T2.24: 创建/列出/撤销应用专用密码"""
    name_create = "T2.22 创建应用专用密码"
    name_list = "T2.23 列出应用专用密码"
    name_revoke = "T2.24 撤销应用专用密码"

    try:
        await _cleanup_test_app_passwords(alice)

        # 创建
        result = await alice.call("mail.create_app_password", {
            "name": f"AUN_TEST_TestClient_{int(time.time() * 1000)}",
        })
        if not result.get("ok"):
            _fail(name_create, f"创建失败: {result}")
            return
        pwd = result.get("password", "")
        pwd_id = result.get("id")
        # 验证格式 XXXX-XXXX-XXXX-XXXX
        parts = pwd.split("-")
        if len(parts) >= 3 and all(len(p) >= 4 for p in parts):
            _ok(name_create)
        else:
            _fail(name_create, f"密码格式不符: {pwd}")
            return

        # 列出
        list_result = await alice.call("mail.list_app_passwords", {})
        passwords = list_result.get("passwords", [])
        found = any(p.get("id") == pwd_id for p in passwords)
        # 确保不含密码哈希
        has_hash = any("password_hash" in p for p in passwords)
        if found and not has_hash:
            _ok(name_list)
        else:
            _fail(name_list, f"found={found}, has_hash={has_hash}")

        # 撤销
        revoke_result = await alice.call("mail.revoke_app_password", {"id": pwd_id})
        if revoke_result.get("ok"):
            # 验证列表中不再包含
            list_result2 = await alice.call("mail.list_app_passwords", {})
            passwords2 = list_result2.get("passwords", [])
            still_exists = any(p.get("id") == pwd_id for p in passwords2)
            if not still_exists:
                _ok(name_revoke)
            else:
                _fail(name_revoke, "撤销后仍在列表中")
        else:
            _fail(name_revoke, f"撤销失败: {revoke_result}")

    except Exception as e:
        _fail(name_create, str(e))


async def test_delete(alice: AUNClient):
    """mail.delete 删除邮件"""
    name = "mail.delete 删除"
    ts = str(int(time.time() * 1000))
    subject = f"to-delete-{ts}"

    try:
        await alice.call("mail.send", {
            "to": [_ALICE_AID],
            "subject": subject,
            "body": "delete me",
        })
        await asyncio.sleep(0.3)

        inbox = await alice.call("mail.list", {"mailbox": "inbox", "limit": 50})
        target = None
        for m in inbox.get("messages", []):
            if m.get("subject") == subject:
                target = m["id"]
                break

        if not target:
            _fail(name, "未找到要删除的邮件")
            return

        result = await alice.call("mail.delete", {"message_id": target})
        if result.get("ok"):
            _ok(name)
        else:
            _fail(name, f"删除失败: {result}")
    except Exception as e:
        _fail(name, str(e))


async def test_health_and_status(alice: AUNClient):
    """mail.health + mail.status"""
    name_h = "mail.health"
    name_s = "mail.status"

    try:
        h = await alice.call("mail.health", {})
        if h.get("status") == "healthy":
            _ok(name_h)
        else:
            _fail(name_h, f"{h}")
    except Exception as e:
        _fail(name_h, str(e))

    try:
        s = await alice.call("mail.status", {})
        if s.get("module") == "mail" and "e2ee" in (s.get("features") or []):
            _ok(name_s)
        else:
            _fail(name_s, f"{s}")
    except Exception as e:
        _fail(name_s, str(e))


async def test_e2ee_send_and_get(alice: AUNClient, bob: AUNClient):
    """T6A.1: E2EE 加密邮件发送 — 服务端存储密文 + 信封"""
    name = "T6A.1 E2EE 加密发送"
    ts = str(int(time.time() * 1000))
    subject = f"e2ee-mail-{ts}"
    # 模拟客户端加密后的密文和信封
    fake_ciphertext = f"ENCRYPTED_BODY_{ts}"
    fake_envelope = '{"algorithm":"ECDH-ES+A256GCM","sender_kid":"alice-key-1","recipient_kid":"bob-key-1","epk":"base64...","iv":"base64...","tag":"base64..."}'

    try:
        result = await alice.call("mail.send", {
            "to": [_BOBB_AID],
            "subject": subject,
            "body": fake_ciphertext,
            "encrypted": 1,
            "e2ee_envelope": fake_envelope,
        })
        if not result.get("ok"):
            _fail(name, f"发送失败: {result}")
            return

        msg_id = result.get("message_id", "")

        # 检查发件方 sent 中 encrypted 字段
        sent_msg = await _wait_mail_subject(alice, "sent", subject)
        if not sent_msg:
            _fail(name, "sent 中未找到加密邮件")
            return
        if sent_msg.get("encrypted") != 1:
            _fail(name, f"sent 邮件 encrypted 字段不正确: {sent_msg.get('encrypted')}")
            return
        if not sent_msg.get("e2ee_envelope"):
            _fail(name, "sent 邮件缺少 e2ee_envelope")
            return

        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_e2ee_recipient_gets_envelope(alice: AUNClient, bob: AUNClient):
    """T6A.2: 收件人获取邮件时包含 E2EE 信封和密文"""
    name = "T6A.2 收件人获取 E2EE 邮件"
    ts = str(int(time.time() * 1000))
    subject = f"e2ee-recv-{ts}"
    fake_ciphertext = f"ENCRYPTED_{ts}"
    fake_envelope = '{"algorithm":"ECDH-ES+A256GCM","recipient_kid":"bob-key-1"}'

    try:
        await alice.call("mail.send", {
            "to": [_BOBB_AID],
            "subject": subject,
            "body": fake_ciphertext,
            "encrypted": 1,
            "e2ee_envelope": fake_envelope,
        })
        # bob 列出 inbox
        target = await _wait_mail_subject(bob, "inbox", subject)

        if not target:
            _fail(name, "收件人 inbox 未找到 E2EE 邮件")
            return

        # 验证 encrypted 标志和 e2ee_envelope
        if target.get("encrypted") != 1:
            _fail(name, f"encrypted 字段不正确: {target.get('encrypted')}")
            return
        if not target.get("e2ee_envelope"):
            _fail(name, "缺少 e2ee_envelope")
            return

        # 验证 body 是密文（不是明文）
        body = target.get("body_text", "")
        if "ENCRYPTED_" in body:
            _ok(name)
        else:
            _fail(name, f"body 不像密文: {body[:50]}")
    except Exception as e:
        _fail(name, str(e))


async def test_e2ee_plaintext_still_works(alice: AUNClient, bob: AUNClient):
    """T6A.3: 不传 encrypted 参数时，行为与之前一致（明文）"""
    name = "T6A.3 明文兼容"
    ts = str(int(time.time() * 1000))
    subject = f"plain-after-e2ee-{ts}"

    try:
        result = await alice.call("mail.send", {
            "to": [_BOBB_AID],
            "subject": subject,
            "body": "Hello plaintext",
        })
        if not result.get("ok"):
            _fail(name, f"发送失败: {result}")
            return

        target = await _wait_mail_subject(bob, "inbox", subject)
        if not target:
            _fail(name, "未找到明文邮件")
            return
        if target.get("encrypted", 0) != 0:
            _fail(name, f"明文邮件 encrypted 应为 0，实际: {target.get('encrypted')}")
            return
        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_get_quota(alice: AUNClient):
    """T7.1: mail.get_quota 配额查询"""
    name = "T7.1 mail.get_quota"
    try:
        result = await alice.call("mail.get_quota", {})
        used = result.get("used_bytes")
        quota = result.get("quota_bytes")
        pct = result.get("usage_pct")

        if used is None or quota is None or pct is None:
            _fail(name, f"返回字段不完整: {result}")
            return

        if quota <= 0:
            _fail(name, f"配额应 > 0，实际: {quota}")
            return

        if not isinstance(pct, (int, float)):
            _fail(name, f"usage_pct 类型不正确: {type(pct)}")
            return

        _ok(name)
    except Exception as e:
        _fail(name, str(e))


async def test_status_new_features(alice: AUNClient):
    """T7.2: mail.status 包含新增特性"""
    name = "T7.2 mail.status 新特性"
    try:
        s = await alice.call("mail.status", {})
        features = s.get("features", [])
        expected = ["tls", "spf", "dkim_verify", "dmarc", "quota", "spam_filter"]
        missing = [f for f in expected if f not in features]
        if missing:
            _fail(name, f"缺少特性: {missing}")
            return
        if "mail.get_quota" not in features:
            _fail(name, "缺少 mail.get_quota 特性")
            return
        _ok(name)
    except Exception as e:
        _fail(name, str(e))


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

async def main():
    print(f"=== Mail 集成测试 ===")
    print(f"AUN_PATH: {_TEST_AUN_PATH}")
    print(f"ISSUER:   {_ISSUER}")
    print(f"ALICE:    {_ALICE_AID}")
    print(f"BOB:      {_BOBB_AID}")
    print()

    alice = _make_client()
    bob = _make_client()

    try:
        print("[1/2] 连接 Alice ...")
        await _ensure_connected(alice, _ALICE_AID)
        print(f"  Alice 已连接: {_ALICE_AID}")

        print("[2/2] 连接 Bob ...")
        await _ensure_connected(bob, _BOBB_AID)
        print(f"  Bob 已连接: {_BOBB_AID}")
    except Exception as e:
        print(f"\n连接失败: {e}")
        sys.exit(1)

    print()
    print("--- 运维 RPC ---")
    await test_health_and_status(alice)

    print()
    print("--- 本域投递 ---")
    await test_send_and_list(alice, bob)
    await test_get_message(bob)
    await test_nonexistent_recipient(alice)
    await test_send_to_self(alice)
    await test_multiple_recipients(alice, bob)

    print()
    print("--- 邮箱操作 ---")
    await test_mark_seen(bob)
    await test_mark_flagged(bob)
    await test_move(bob)
    await test_search_hit(alice)
    await test_search_miss(alice)
    await test_delete(alice)

    print()
    print("--- 应用专用密码 ---")
    await test_app_password_lifecycle(alice)

    print()
    print("--- E2EE 加密邮件 ---")
    await test_e2ee_send_and_get(alice, bob)
    await test_e2ee_recipient_gets_envelope(alice, bob)
    await test_e2ee_plaintext_still_works(alice, bob)

    print()
    print("--- 配额与新特性 ---")
    await test_get_quota(alice)
    await test_status_new_features(alice)

    # 清理
    try:
        await alice.disconnect()
    except Exception:
        pass
    try:
        await bob.disconnect()
    except Exception:
        pass

    # 报告
    print()
    print(f"{'='*50}")
    total = _passed + _failed
    print(f"完成: {total} 项, 通过: {_passed}, 失败: {_failed}")
    if _errors:
        print()
        print("失败详情:")
        for e in _errors:
            print(f"  - {e}")
    print(f"{'='*50}")
    sys.exit(1 if _failed > 0 else 0)


if __name__ == "__main__":
    asyncio.run(main())
