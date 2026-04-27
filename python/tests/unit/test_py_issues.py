"""PY-002 ~ PY-007 修复验证测试。

按 TDD RED→GREEN 流程，每个 ISSUE 一个测试类。
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone


# ── 辅助函数 ──────────────────────────────────────────────


def _gen_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _make_cert(private_key, cn="test"):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


# ── PY-002: P2P 解密路径验证 sender_signature ─────────────


class TestPY002SenderSignatureVerification:
    """PY-002: decrypt_message 必须验证 sender_signature，缺失时拒绝解密。"""

    def _make_pair(self):
        """创建 sender/receiver E2EEManager 对。"""
        from aun_core.e2ee import E2EEManager, MODE_LONG_TERM_KEY

        sender_key = _gen_ec_key()
        receiver_key = _gen_ec_key()
        sender_cert = _make_cert(sender_key, "sender.test")
        receiver_cert = _make_cert(receiver_key, "receiver.test")

        class FakeKS:
            def __init__(self):
                self._key_pairs = {}
                self._certs = {}
                self._prekeys = {}
            def load_key_pair(self, aid):
                return self._key_pairs.get(aid)
            def load_cert(self, aid, cert_fingerprint=None):
                if cert_fingerprint:
                    c = self._certs.get((aid, cert_fingerprint))
                    if c:
                        return c
                    active = self._certs.get(aid)
                    if active:
                        obj = x509.load_pem_x509_certificate(
                            active.encode() if isinstance(active, str) else active)
                        fp = "sha256:" + obj.fingerprint(hashes.SHA256()).hex()
                        if fp == cert_fingerprint:
                            return active
                    return None
                return self._certs.get(aid)
            def save_e2ee_prekey(self, aid, pk_id, data, device_id=""):
                self._prekeys.setdefault(aid, {})[pk_id] = data
            def load_e2ee_prekeys(self, aid, device_id=""):
                return self._prekeys.get(aid, {})
            def cleanup_e2ee_prekeys(self, aid, cutoff_ms, keep_latest=7, device_id=""):
                return []
            def list_group_secret_ids(self, *a, **kw): return []
            def load_group_secret_epoch(self, *a, **kw): return None
            def cleanup_group_old_epochs_state(self, *a, **kw): return 0

        sender_priv_pem = sender_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        sender_pub_der = sender_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        receiver_priv_pem = receiver_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        receiver_pub_der = receiver_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

        sender_ks = FakeKS()
        receiver_ks = FakeKS()
        sender_ks._key_pairs["sender.test"] = {
            "private_key_pem": sender_priv_pem,
            "public_key_der_b64": base64.b64encode(sender_pub_der).decode(),
        }
        receiver_ks._key_pairs["receiver.test"] = {
            "private_key_pem": receiver_priv_pem,
            "public_key_der_b64": base64.b64encode(receiver_pub_der).decode(),
        }
        sender_ks._certs["receiver.test"] = receiver_cert.decode()
        receiver_ks._certs["sender.test"] = sender_cert.decode()

        sender_identity = {
            "aid": "sender.test",
            "private_key_pem": sender_priv_pem,
            "public_key_der_b64": base64.b64encode(sender_pub_der).decode(),
            "cert": sender_cert.decode(),
        }
        receiver_identity = {
            "aid": "receiver.test",
            "private_key_pem": receiver_priv_pem,
            "public_key_der_b64": base64.b64encode(receiver_pub_der).decode(),
            "cert": receiver_cert.decode(),
        }

        sender_mgr = E2EEManager(identity_fn=lambda: sender_identity, keystore=sender_ks)
        receiver_mgr = E2EEManager(identity_fn=lambda: receiver_identity, keystore=receiver_ks)
        return sender_mgr, receiver_mgr, receiver_cert

    def test_missing_sender_signature_rejected(self):
        """缺少 sender_signature 的加密消息应被拒绝（返回 None）。"""
        sender_mgr, receiver_mgr, receiver_cert = self._make_pair()
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, _ = sender_mgr._encrypt_with_long_term_key(
            "receiver.test", {"type": "text", "text": "hello"}, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        # 移除 sender_signature
        envelope.pop("sender_signature", None)
        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }
        result = receiver_mgr.decrypt_message(message)
        assert result is None, "缺少 sender_signature 的消息应被拒绝"

    def test_tampered_signature_rejected(self):
        """篡改 sender_signature 的消息应被拒绝。"""
        sender_mgr, receiver_mgr, receiver_cert = self._make_pair()
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, _ = sender_mgr._encrypt_with_long_term_key(
            "receiver.test", {"type": "text", "text": "hello"}, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        # 篡改签名
        import os
        envelope["sender_signature"] = base64.b64encode(os.urandom(64)).decode()
        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }
        result = receiver_mgr.decrypt_message(message)
        assert result is None, "篡改签名的消息应被拒绝"

    def test_valid_signature_accepted(self):
        """正确签名的消息应成功解密。"""
        sender_mgr, receiver_mgr, receiver_cert = self._make_pair()
        mid = str(uuid.uuid4())
        ts = int(time.time() * 1000)
        envelope, _ = sender_mgr._encrypt_with_long_term_key(
            "receiver.test", {"type": "text", "text": "hello"}, receiver_cert,
            message_id=mid, timestamp=ts,
        )
        message = {
            "message_id": mid, "from": "sender.test", "to": "receiver.test",
            "timestamp": ts, "seq": 1, "payload": envelope, "encrypted": True,
        }
        result = receiver_mgr.decrypt_message(message)
        assert result is not None
        assert result["payload"]["text"] == "hello"


# ── PY-003 / PY-005: 断线时保存 SeqTracker ────────────────


class TestPY003PY005DisconnectSavesSeqTracker:
    """PY-003/PY-005: _handle_transport_disconnect 必须保存 SeqTracker 状态。"""

    def _make_client(self):
        from aun_core import AUNClient
        client = AUNClient({"aun_path": "/tmp/test_py003"})
        client._session_options = {
            "auto_reconnect": False,
            "heartbeat_interval": 0,
            "token_refresh_before": 60.0,
            "retry": {"initial_delay": 0.01, "max_delay": 0.05},
            "timeouts": {"connect": 5.0, "call": 10.0, "http": 30.0},
        }
        client._state = "connected"
        client._gateway_url = "wss://gateway.test/aun"
        client._transport = MagicMock()
        client._transport.close = AsyncMock()
        client._discovery = MagicMock()
        client._discovery.check_health = AsyncMock(return_value=True)
        return client

    @pytest.mark.asyncio
    async def test_disconnect_saves_seq_tracker(self):
        """断线处理应调用 _save_seq_tracker_state。"""
        client = self._make_client()
        # 模拟有 seq 数据
        client._seq_tracker.on_message_seq("group:g1", 1)
        client._seq_tracker.on_message_seq("group:g1", 2)

        with patch.object(client, "_save_seq_tracker_state") as mock_save:
            await client._handle_transport_disconnect(Exception("网络断开"))
            mock_save.assert_called_once()


# ── PY-004: _prekey_refresh_loop 实现 ─────────────────────


class TestPY004PrekeyRefreshLoop:
    """PY-004: _prekey_refresh_loop 不应为空实现，应定期上传 prekey。"""

    def test_prekey_refresh_loop_not_empty(self):
        """_prekey_refresh_loop 不应直接 return（空实现）。"""
        import inspect
        from aun_core import AUNClient
        source = inspect.getsource(AUNClient._prekey_refresh_loop)
        # 空实现只有 return 语句
        lines = [l.strip() for l in source.splitlines() if l.strip() and not l.strip().startswith(("#", "\"\"\"", "async"))]
        assert len(lines) > 1, "_prekey_refresh_loop 不应为空实现（仅 return）"

    def test_start_prekey_refresh_task_not_empty(self):
        """_start_prekey_refresh_task 不应直接 return（空实现）。"""
        import inspect
        from aun_core import AUNClient
        source = inspect.getsource(AUNClient._start_prekey_refresh_task)
        lines = [l.strip() for l in source.splitlines() if l.strip() and not l.strip().startswith(("#", "\"\"\"", "def"))]
        assert len(lines) > 1, "_start_prekey_refresh_task 不应为空实现（仅 return）"


# ── PY-006: discovery check_health 异常日志 ───────────────


class TestPY006DiscoveryCheckHealthLogging:
    """PY-006: check_health 异常不应被静默吞掉，应记录日志。"""

    @pytest.mark.asyncio
    async def test_check_health_exception_logged(self, caplog):
        """check_health 网络异常时应记录 warning 日志。"""
        from aun_core.discovery import GatewayDiscovery
        discovery = GatewayDiscovery(verify_ssl=False)

        with caplog.at_level(logging.WARNING, logger="aun_core.discovery"):
            # 使用不可达地址触发异常
            result = await discovery.check_health("http://127.0.0.1:1/aun", timeout=0.1)
            assert result is False
            # 应该有 warning 日志记录异常
            assert any("check_health" in r.message or "健康检查" in r.message for r in caplog.records), \
                f"check_health 异常应记录 warning 日志，实际日志: {[r.message for r in caplog.records]}"


# ── PY-007: EventDispatcher 处理器异常含 traceback ────────


class TestPY007EventDispatcherTraceback:
    """PY-007: 事件处理器异常时日志应包含 traceback 信息。"""

    @pytest.mark.asyncio
    async def test_handler_exception_includes_traceback(self):
        """处理器抛异常时，warning 日志应包含 exc_info。"""
        from aun_core.events import EventDispatcher

        dispatcher = EventDispatcher()

        def bad_handler(data):
            raise ValueError("测试异常")

        dispatcher.subscribe("test.event", bad_handler)

        with patch("aun_core.events._events_log") as mock_log:
            await dispatcher.publish("test.event", {"key": "value"})
            # 应该调用了 warning，且包含 exc_info=True
            mock_log.warning.assert_called()
            # 检查 exc_info 参数
            call_kwargs = mock_log.warning.call_args
            assert call_kwargs is not None
            # exc_info 可以在 args 或 kwargs 中
            has_exc_info = (
                call_kwargs.kwargs.get("exc_info") is True
                or (len(call_kwargs.args) > 0 and "exc_info" in str(call_kwargs))
            )
            assert has_exc_info, "warning 日志应包含 exc_info=True 以输出 traceback"


# ── ISSUE-SDK-PY-001: disconnect() 与 close() 并发竞态 ──


class TestSDKPY001DisconnectCloseRace:
    """ISSUE-SDK-PY-001: disconnect() 应检查 _closing 标志，避免与 close() 竞态。"""

    def _make_client(self):
        from aun_core import AUNClient
        client = AUNClient({"aun_path": "/tmp/test_sdkpy001"})
        client._session_options = {
            "auto_reconnect": False,
            "heartbeat_interval": 0,
            "token_refresh_before": 60.0,
            "retry": {"initial_delay": 0.01, "max_delay": 0.05},
            "timeouts": {"connect": 5.0, "call": 10.0, "http": 30.0},
        }
        client._state = "connected"
        client._gateway_url = "wss://gateway.test/aun"
        client._transport = MagicMock()
        client._transport.close = AsyncMock()
        return client

    @pytest.mark.asyncio
    async def test_disconnect_noop_when_closing(self):
        """当 _closing=True 时，disconnect() 应直接返回，不执行任何清理操作。"""
        client = self._make_client()
        # 模拟 close() 已设置 _closing 标志
        client._closing = True
        original_state = client._state

        await client.disconnect()

        # disconnect() 应直接返回，不应调用 _transport.close()
        client._transport.close.assert_not_called()
        # 状态不应被 disconnect() 修改（close() 正在负责状态转换）
        assert client._state == original_state

    @pytest.mark.asyncio
    async def test_disconnect_works_when_not_closing(self):
        """当 _closing=False 时，disconnect() 应正常工作。"""
        client = self._make_client()
        client._closing = False

        await client.disconnect()

        # disconnect() 应正常执行清理
        client._transport.close.assert_called_once()
        assert client._state == "disconnected"

    @pytest.mark.asyncio
    async def test_concurrent_close_and_disconnect(self):
        """并发调用 close() 和 disconnect() 时不应产生竞态异常。"""
        client = self._make_client()
        client._closing = False

        # 让 transport.close 有一点延迟以模拟真实场景
        async def slow_close():
            await asyncio.sleep(0.01)

        client._transport.close = AsyncMock(side_effect=slow_close)

        # 并发执行 close() 和 disconnect()
        results = await asyncio.gather(
            client.close(),
            client.disconnect(),
            return_exceptions=True,
        )

        # 不应有异常
        for r in results:
            assert not isinstance(r, Exception), f"并发调用产生异常: {r}"

        # 最终状态应为 closed（close() 的最终状态优先）
        assert client._state in {"closed", "disconnected"}


# ── ISSUE-SDK-PY-002: discover() 异步 Task 引用 ────────────


class TestSDKPY002DiscoverTaskReference:
    """ISSUE-SDK-PY-002: discover() 创建的后台 Task 必须被持有引用，防止 GC 回收。"""

    @pytest.mark.asyncio
    async def test_background_tasks_set_exists(self):
        """GatewayDiscovery 应有 _background_tasks 集合来持有 Task 引用。"""
        from aun_core.discovery import GatewayDiscovery
        discovery = GatewayDiscovery(verify_ssl=False)
        assert hasattr(discovery, "_background_tasks"), \
            "GatewayDiscovery 应有 _background_tasks 属性"
        assert isinstance(discovery._background_tasks, set), \
            "_background_tasks 应为 set 类型"

    @pytest.mark.asyncio
    async def test_discover_saves_task_reference(self):
        """discover() 创建的 health check Task 应被保存到 _background_tasks 中。"""
        from aun_core.discovery import GatewayDiscovery
        discovery = GatewayDiscovery(verify_ssl=False)

        # mock aiohttp 返回 well-known 数据
        mock_response = AsyncMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={
            "gateways": [{"url": "ws://gw.test/aun", "priority": 1}]
        })
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        # mock check_health 使其阻塞，这样我们能捕获到 Task 存在于集合中
        health_started = asyncio.Event()
        health_release = asyncio.Event()

        original_check_health = discovery.check_health

        async def slow_check_health(*args, **kwargs):
            health_started.set()
            await health_release.wait()
            return True

        with patch("aiohttp.ClientSession", return_value=mock_session):
            with patch.object(discovery, "check_health", side_effect=slow_check_health):
                url = await discovery.discover("http://example.com/.well-known/aun")
                assert url == "ws://gw.test/aun"

                # 等待 Task 启动
                await asyncio.wait_for(health_started.wait(), timeout=1.0)

                # 此时 _background_tasks 应包含至少一个 Task
                assert len(discovery._background_tasks) > 0, \
                    "discover() 应将 health check Task 保存到 _background_tasks 中"

                # 释放 health check
                health_release.set()
                # 等待 Task 完成
                await asyncio.sleep(0.05)

        # Task 完成后应自动从集合中移除
        assert len(discovery._background_tasks) == 0, \
            "Task 完成后应自动从 _background_tasks 中移除"
