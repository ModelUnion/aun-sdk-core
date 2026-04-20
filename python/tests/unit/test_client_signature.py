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
