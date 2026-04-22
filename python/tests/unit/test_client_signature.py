"""群操作签名/验签/审计 单元测试。

测试范围：
- _SIGNED_METHODS 覆盖所有群关键修改操作
- _sign_client_operation 输出包含 cert_fingerprint
- _verify_event_signature 验签逻辑（通过/失败/pending）
"""
import asyncio
import base64
import hashlib
import json
import time

import pytest

from aun_core import AUNClient


# ── ECDSA 密钥对生成工具 ──────────────────────────────────


def _generate_ecdsa_keypair():
    """生成 ECDSA P-256 密钥对和自签名证书，返回 (private_key_pem, cert_pem, cert_fingerprint)。"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_fingerprint = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()

    return private_key_pem, cert_pem, cert_fingerprint


def _make_client_with_identity(tmp_path):
    """创建带有完整 identity（含私钥和证书）的 client。"""
    private_key_pem, cert_pem, cert_fingerprint = _generate_ecdsa_keypair()
    client = AUNClient({"aun_path": str(tmp_path / "aun")})
    client._identity = {
        "aid": "test.example.com",
        "private_key_pem": private_key_pem,
        "cert": cert_pem,
    }
    client._state = "connected"
    return client, cert_fingerprint


# ── SIGNED_METHODS 覆盖测试 ──────────────────────────────


class TestSignedMethodsCoverage:
    """验证 _SIGNED_METHODS 包含所有群关键修改操作。"""

    EXPECTED_METHODS = [
        # 群管理
        "group.send", "group.kick", "group.add_member",
        "group.leave", "group.remove_member", "group.update_rules",
        "group.update", "group.update_announcement",
        "group.update_join_requirements", "group.set_role",
        "group.transfer_owner", "group.review_join_request",
        "group.batch_review_join_request",
        "group.request_join", "group.use_invite_code",
        # 群资源
        "group.resources.put", "group.resources.update",
        "group.resources.delete", "group.resources.request_add",
        "group.resources.direct_add", "group.resources.approve_request",
        "group.resources.reject_request",
    ]

    # 服务端通过 _require_actor_aid_verified 强制要求签名的方法
    # 如果服务端新增了签名要求，必须同步加入 SDK _SIGNED_METHODS
    SERVER_VERIFIED_METHODS = [
        "group.add_member",
        "group.leave",
        "group.kick",
        "group.update_rules",
        "group.send",
        "group.request_join",
        "group.use_invite_code",
        "group.update",
        "group.update_announcement",
        "group.update_join_requirements",
        "group.set_role",
        "group.transfer_owner",
        "group.review_join_request",
        "group.batch_review_join_request",
    ]

    @pytest.mark.parametrize("method", EXPECTED_METHODS)
    def test_method_in_signed_set(self, method):
        assert method in AUNClient._SIGNED_METHODS, (
            f"{method} 应在 _SIGNED_METHODS 中"
        )

    def test_no_unexpected_methods(self):
        for m in AUNClient._SIGNED_METHODS:
            assert m in self.EXPECTED_METHODS, (
                f"_SIGNED_METHODS 中包含未预期的方法: {m}"
            )

    @pytest.mark.parametrize("method", SERVER_VERIFIED_METHODS)
    def test_server_verified_method_in_sdk_signed(self, method):
        """服务端 _require_actor_aid_verified 的方法必须在 SDK _SIGNED_METHODS 中，
        否则 SDK 调用时不会签名，服务端会拒绝请求。"""
        assert method in AUNClient._SIGNED_METHODS, (
            f"服务端要求签名的 {method} 未在 SDK _SIGNED_METHODS 中，"
            f"调用将失败 (client signature verification failed)"
        )


# ── 签名输出测试 ──────────────────────────────────────────


class TestSignClientOperation:
    """验证 _sign_client_operation 输出格式正确。"""

    def test_signature_contains_cert_fingerprint(self, tmp_path):
        client, expected_fp = _make_client_with_identity(tmp_path)
        params = {"group_id": "g-test", "content": "hello"}
        client._sign_client_operation("group.update_announcement", params)

        cs = params.get("client_signature")
        assert cs is not None, "应生成 client_signature"
        assert cs["aid"] == "test.example.com"
        assert cs["cert_fingerprint"] == expected_fp
        assert cs["cert_fingerprint"].startswith("sha256:")
        assert len(cs["cert_fingerprint"]) == 7 + 64  # sha256: + 64 hex chars
        assert cs["params_hash"]
        assert cs["signature"]
        assert cs["timestamp"]

    def test_signature_excludes_internal_fields(self, tmp_path):
        client, _ = _make_client_with_identity(tmp_path)
        params = {"group_id": "g-test", "_auth": {"aid": "x"}, "client_signature": "old"}
        client._sign_client_operation("group.update", params)

        cs = params["client_signature"]
        # params_hash 应排除 _auth 和旧 client_signature
        expected_hash_input = {"group_id": "g-test"}
        expected_json = json.dumps(expected_hash_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected_hash = hashlib.sha256(expected_json.encode("utf-8")).hexdigest()
        assert cs["params_hash"] == expected_hash

    def test_no_identity_no_signature(self, tmp_path):
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = None
        params = {"group_id": "g-test"}
        client._sign_client_operation("group.update", params)
        assert "client_signature" not in params

    def test_no_private_key_no_signature(self, tmp_path):
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = {"aid": "test.example.com"}
        params = {"group_id": "g-test"}
        client._sign_client_operation("group.update", params)
        assert "client_signature" not in params

    def test_sign_failure_raises_instead_of_silent_downgrade(self, tmp_path):
        """签名失败时应抛出异常，而非静默降级到无签名请求（PY-012）。"""
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = {
            "aid": "test.example.com",
            "private_key_pem": "INVALID-NOT-A-PEM-KEY",  # 故意给无效私钥
            "cert": "also-invalid",
        }
        params = {"group_id": "g-test"}
        with pytest.raises(Exception):
            client._sign_client_operation("group.update", params)
        # 签名失败后 params 中不应有 client_signature
        assert "client_signature" not in params

    def test_no_cert_empty_fingerprint(self, tmp_path):
        """没有证书时 cert_fingerprint 为空字符串。"""
        private_key_pem, _, _ = _generate_ecdsa_keypair()
        client = AUNClient({"aun_path": str(tmp_path / "aun")})
        client._identity = {
            "aid": "test.example.com",
            "private_key_pem": private_key_pem,
            # 不设 cert
        }
        params = {"group_id": "g-test"}
        client._sign_client_operation("group.update", params)
        cs = params["client_signature"]
        assert cs["cert_fingerprint"] == ""


# ── 验签测试 ──────────────────────────────────────────────


class TestVerifyEventSignature:
    """验证 _verify_event_signature 逻辑。"""

    def _sign_and_build_event(self, client, method, params):
        """模拟签名并构建事件 payload。"""
        client._sign_client_operation(method, params)
        cs = dict(params["client_signature"])
        cs["_method"] = method
        return {
            "action": "test",
            "group_id": "g-test",
            "actor_aid": "test.example.com",
            "client_signature": cs,
        }

    def test_valid_signature_returns_true(self, tmp_path):
        client, cert_fp = _make_client_with_identity(tmp_path)
        # 缓存证书
        from aun_core.client import _CachedPeerCert
        client._cert_cache[client._cert_cache_key("test.example.com", cert_fp)] = _CachedPeerCert(
            cert_bytes=client._identity["cert"].encode("utf-8"),
            validated_at=time.time(),
            refresh_after=time.time() + 600,
        )
        params = {"group_id": "g-test", "content": "hello"}
        event = self._sign_and_build_event(client, "group.update_announcement", params)

        result = asyncio.run(client._verify_event_signature(event, event["client_signature"]))
        assert result is True

    def test_tampered_params_hash_returns_false(self, tmp_path):
        client, cert_fp = _make_client_with_identity(tmp_path)
        from aun_core.client import _CachedPeerCert
        client._cert_cache[client._cert_cache_key("test.example.com", cert_fp)] = _CachedPeerCert(
            cert_bytes=client._identity["cert"].encode("utf-8"),
            validated_at=time.time(),
            refresh_after=time.time() + 600,
        )
        params = {"group_id": "g-test", "content": "hello"}
        event = self._sign_and_build_event(client, "group.update_announcement", params)
        # 篡改 params_hash
        event["client_signature"]["params_hash"] = "0" * 64

        result = asyncio.run(client._verify_event_signature(event, event["client_signature"]))
        assert result is False

    def test_wrong_cert_fingerprint_returns_false(self, tmp_path):
        client, _ = _make_client_with_identity(tmp_path)
        from aun_core.client import _CachedPeerCert
        wrong_fp = "sha256:" + "ff" * 32
        client._cert_cache[client._cert_cache_key("test.example.com", wrong_fp)] = _CachedPeerCert(
            cert_bytes=client._identity["cert"].encode("utf-8"),
            validated_at=time.time(),
            refresh_after=time.time() + 600,
        )
        params = {"group_id": "g-test"}
        event = self._sign_and_build_event(client, "group.update", params)
        event["client_signature"]["cert_fingerprint"] = wrong_fp

        result = asyncio.run(client._verify_event_signature(event, event["client_signature"]))
        assert result is False

    def test_no_cached_cert_returns_pending(self, tmp_path):
        client, _ = _make_client_with_identity(tmp_path)
        # 不缓存证书
        params = {"group_id": "g-test"}
        event = self._sign_and_build_event(client, "group.update", params)
        # mock _fetch_peer_cert 不阻塞
        async def _noop_fetch(aid):
            pass
        client._fetch_peer_cert = _noop_fetch

        result = asyncio.run(client._verify_event_signature(event, event["client_signature"]))
        assert result == "pending"

    def test_no_method_returns_pending(self, tmp_path):
        client, _ = _make_client_with_identity(tmp_path)
        from aun_core.client import _CachedPeerCert
        client._cert_cache["test.example.com"] = _CachedPeerCert(
            cert_bytes=client._identity["cert"].encode("utf-8"),
            validated_at=time.time(),
            refresh_after=time.time() + 600,
        )
        cs = {"aid": "test.example.com", "timestamp": "123", "params_hash": "abc", "signature": "xxx"}
        # 没有 _method
        result = asyncio.run(client._verify_event_signature({}, cs))
        assert result == "pending"

    def test_empty_aid_returns_pending(self, tmp_path):
        client, _ = _make_client_with_identity(tmp_path)
        cs = {"aid": "", "_method": "group.update"}
        result = asyncio.run(client._verify_event_signature({}, cs))
        assert result == "pending"


# ── 服务端签名验证覆盖度源码扫描 ─────────────────────────

import re
from pathlib import Path


class TestServerSideSignatureVerification:
    """扫描服务端 group/service.py 源码，验证所有需要签名的方法确实调用了 _require_actor_aid_verified。

    这是 TDD 的核心测试：确保服务端对 SDK _SIGNED_METHODS 中列出的方法执行签名验证，
    防止 request_join 等方法遗漏签名验证的安全漏洞。
    """

    # 服务端 RPC 方法名 → service.py 中的方法名映射
    # entry.py 路由: "update" → _rpc_update → _service.update_group(params)
    _RPC_TO_SERVICE_METHOD = {
        "group.add_member": "add_member",
        "group.leave": "leave_group",
        "group.kick": "kick_member",
        "group.update_rules": "update_rules",
        "group.send": "send_message",
        "group.request_join": "request_join",
        "group.use_invite_code": "use_invite_code",
        "group.update": "update_group",
        "group.update_announcement": "update_announcement",
        "group.update_join_requirements": "update_join_requirements",
        "group.set_role": "set_role",
        "group.transfer_owner": "transfer_owner",
        "group.review_join_request": "review_join_request",
        "group.batch_review_join_request": "batch_review_join_request",
    }

    @staticmethod
    def _find_service_py() -> str:
        """查找 group/service.py 的路径。"""
        # 从测试文件位置向上回溯到项目根目录
        candidates = [
            Path(__file__).resolve().parents[4] / "extensions" / "services" / "group" / "service.py",
            Path(__file__).resolve().parents[3] / "extensions" / "services" / "group" / "service.py",
            Path(__file__).resolve().parents[5] / "extensions" / "services" / "group" / "service.py",
        ]
        for p in candidates:
            if p.exists():
                return str(p)
        # 尝试从环境变量
        import os
        kite_root = os.environ.get("KITE_ROOT", "")
        if kite_root:
            p = Path(kite_root) / "extensions" / "services" / "group" / "service.py"
            if p.exists():
                return str(p)
        pytest.skip("group/service.py not found, cannot perform source scan")

    @staticmethod
    def _extract_method_body(source: str, method_name: str) -> str:
        """从源码中提取指定方法的函数体（到下一个同级 def/async def 为止）。"""
        # 匹配 async def method_name(self, params
        pattern = rf"(?:async\s+)?def\s+{re.escape(method_name)}\s*\(\s*self\s*,\s*params"
        match = re.search(pattern, source)
        if not match:
            return ""
        start = match.start()
        # 找到下一个同级 def（通过缩进判断）
        lines = source[start:].split("\n")
        body_lines = [lines[0]]
        for line in lines[1:]:
            # 同级或更高级的 def/class/async def 标志方法结束
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if stripped and indent <= 4 and (stripped.startswith("def ") or stripped.startswith("async def ") or stripped.startswith("class ")):
                break
            body_lines.append(line)
        return "\n".join(body_lines)

    @pytest.mark.parametrize(
        "rpc_method",
        list(_RPC_TO_SERVICE_METHOD.keys()),
    )
    def test_service_method_uses_verified(self, rpc_method):
        """验证服务端方法对 SDK 签名方法确实调用了 _require_actor_aid_verified。"""
        service_method = self._RPC_TO_SERVICE_METHOD[rpc_method]
        service_path = self._find_service_py()
        source = Path(service_path).read_text(encoding="utf-8")

        body = self._extract_method_body(source, service_method)
        assert body, f"未找到 service.py 中的方法 {service_method}"

        assert "_require_actor_aid_verified" in body, (
            f"服务端 {service_method}() 未调用 _require_actor_aid_verified，"
            f"但 SDK 对 {rpc_method} 会签名。"
            f"这是安全漏洞：SDK 签名被服务端忽略，任何人可伪造请求。"
        )
