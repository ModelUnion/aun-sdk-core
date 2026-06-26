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
from aun_core.client import _NON_IDEMPOTENT_METHODS, _PEER_CERT_CACHE_TTL


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
    import dataclasses
    from aun_core.aid import AID
    from cryptography import x509 as _x509
    private_key_pem, cert_pem, cert_fingerprint = _generate_ecdsa_keypair()
    cert_obj = _x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    from cryptography.hazmat.primitives import serialization
    private_key_obj = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    aid_obj = AID._create(
        aid="test.example.com",
        aun_path=str(tmp_path),
        cert_pem=cert_pem,
        cert_obj=cert_obj,
        private_key_obj=private_key_obj,
        cert_valid=True,
        private_key_valid=True,
        private_key_pem=private_key_pem,
    )
    client = AUNClient(aid_obj)
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

    STORAGE_MUTATION_METHODS = [
        "storage.put_object", "storage.delete_object", "storage.get_by_share",
        "storage.create_share_link", "storage.revoke_share_link",
        "storage.create_upload_session", "storage.complete_upload",
        "storage.create_folder", "storage.rename_folder", "storage.move_folder",
        "storage.delete_folder", "storage.move_object", "storage.copy_object",
        "storage.batch_delete", "storage.set_object_meta", "storage.append_object",
        "storage.set_acl", "storage.remove_acl", "storage.set_visibility",
        "storage.issue_token", "storage.revoke_token",
        "storage.create_symlink", "storage.atomic_repoint",
        "storage.rename_symlink", "storage.delete_symlink",
        "storage.fs.mkdir", "storage.fs.remove", "storage.fs.rename", "storage.fs.copy",
        "storage.fs.mount", "storage.fs.approve", "storage.fs.reject", "storage.fs.unmount",
        "storage.fs.invalidate_membership",
        "storage.volume.create", "storage.volume.renew", "storage.volume.expire_due",
    ]

    STORAGE_SIGNED_PROBE_METHODS = [
        "storage.check_access",
    ]

    GROUP_FS_SIGNED_METHODS = [
        "group.fs.mkdir", "group.fs.rm", "group.fs.cp", "group.fs.mv",
        "group.fs.set_acl", "group.fs.remove_acl",
        "group.fs.mount", "group.fs.umount",
        "group.fs.check_upload", "group.fs.create_upload_session",
        "group.fs.complete_upload", "group.fs.create_download_ticket",
    ]

    GROUP_FS_NON_IDEMPOTENT_METHODS = list(GROUP_FS_SIGNED_METHODS)

    COLLAB_MUTATION_METHODS = [
        "collab.create", "collab.commit", "collab.clone",
        "collab.prune", "collab.revert", "collab.gc", "collab.unregister",
        "collab.tag.create", "collab.tag.restore",
        "collab.tag.rm", "collab.tag.prune",
    ]

    EXPECTED_METHODS = [
        # P2P / V2 入口
        "message.send",
        "message.v2.put_peer_pk", "message.v2.bootstrap",
        "message.v2.group_bootstrap", "message.v2.pull",
        "message.v2.ack",
        # V2 群入口
        "group.v2.put_group_pk", "group.v2.bootstrap",
        "group.v2.send", "group.v2.pull", "group.v2.ack",
        "group.v2.propose_state", "group.v2.confirm_state",
        "group.v2.get_proposal",
        # 群管理
        "group.send", "group.kick", "group.add_member",
        "group.leave", "group.remove_member", "group.recall", "group.update_rules",
        "group.update", "group.update_announcement",
        "group.update_join_requirements", "group.set_role",
        "group.transfer_owner", "group.complete_transfer", "group.bind_group_aid",
        "group.renew_group_aid",
        "group.review_join_request",
        "group.batch_review_join_request",
        "group.request_join", "group.use_invite_code",
        "group.thought.put",
        "message.thought.put",
        "group.set_settings",
        "group.commit_state",
        # E2EE epoch 轮换
        "group.e2ee.begin_rotation", "group.e2ee.commit_rotation",
        "group.e2ee.abort_rotation",
        # 群生命周期
        "group.ban", "group.unban",
        "group.dissolve", "group.suspend", "group.resume",
        # 群文件系统
    ] + GROUP_FS_SIGNED_METHODS + COLLAB_MUTATION_METHODS + STORAGE_SIGNED_PROBE_METHODS + STORAGE_MUTATION_METHODS

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
        "group.thought.put",
        "group.update",
        "group.update_announcement",
        "group.update_join_requirements",
        "group.set_role",
        "group.transfer_owner",
        "group.review_join_request",
        "group.batch_review_join_request",
        "group.bind_group_aid",
        "group.complete_transfer",
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

    def test_collab_tag_read_methods_are_not_signed(self):
        for method in ("collab.tag.list", "collab.tag.show", "collab.tag.diff"):
            assert method not in AUNClient._SIGNED_METHODS

    @pytest.mark.parametrize("method", STORAGE_MUTATION_METHODS)
    def test_storage_mutation_method_is_non_idempotent(self, method):
        assert method in _NON_IDEMPOTENT_METHODS, (
            f"{method} 应进入 _NON_IDEMPOTENT_METHODS，避免写操作沿用短超时"
        )

    @pytest.mark.parametrize("method", GROUP_FS_NON_IDEMPOTENT_METHODS)
    def test_group_fs_method_is_non_idempotent(self, method):
        assert method in _NON_IDEMPOTENT_METHODS, (
            f"{method} 应进入 _NON_IDEMPOTENT_METHODS，避免群文件系统写入或票据/session 控制面沿用短超时"
        )

    @pytest.mark.parametrize("method", COLLAB_MUTATION_METHODS)
    def test_collab_mutation_method_is_non_idempotent(self, method):
        assert method in _NON_IDEMPOTENT_METHODS, (
            f"{method} 应进入 _NON_IDEMPOTENT_METHODS，避免 collab 写操作沿用短超时"
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
        client = AUNClient()
        params = {"group_id": "g-test"}
        client._sign_client_operation("group.update", params)
        assert "client_signature" not in params

    def test_no_private_key_no_signature(self, tmp_path):
        # 无 AID（无私钥）时不应生成签名
        client = AUNClient()
        params = {"group_id": "g-test"}
        client._sign_client_operation("group.update", params)
        assert "client_signature" not in params

    def test_sign_failure_raises_instead_of_silent_downgrade(self, tmp_path):
        """签名失败时应抛出异常，而非静默降级到无签名请求（PY-012）。"""
        import dataclasses
        client, _ = _make_client_with_identity(tmp_path)
        # 注入无效私钥到 _current_aid，触发签名失败
        client._current_aid = dataclasses.replace(client._current_aid, private_key_pem="INVALID-NOT-A-PEM-KEY")
        params = {"group_id": "g-test"}
        with pytest.raises(Exception):
            client._sign_client_operation("group.update", params)
        # 签名失败后 params 中不应有 client_signature
        assert "client_signature" not in params

    def test_no_cert_empty_fingerprint(self, tmp_path):
        """没有证书时 cert_fingerprint 为空字符串。"""
        import dataclasses
        client, _ = _make_client_with_identity(tmp_path)
        # 清空证书，保留私钥
        client._current_aid = dataclasses.replace(client._current_aid, cert_pem="")
        params = {"group_id": "g-test"}
        client._sign_client_operation("group.update", params)
        cs = params["client_signature"]
        assert cs["cert_fingerprint"] == ""

    @pytest.mark.asyncio
    async def test_call_strips_client_signature_identity_before_transport(self, tmp_path):
        client, _ = _make_client_with_identity(tmp_path)
        client._state = "ready"

        class _Transport:
            def __init__(self):
                self.calls = []

            async def call(self, method, params, **kwargs):
                json.dumps(params, ensure_ascii=False)
                self.calls.append((method, dict(params), dict(kwargs)))
                return {"ok": True}

        transport = _Transport()
        client._transport = transport

        await client.call(
            "group.fs.mkdir",
            {
                "path": "g-team.example.test:/docs",
                "_client_signature_identity": client._current_aid,
            },
        )

        payload = transport.calls[0][1]
        assert "_client_signature_identity" not in payload
        assert payload["client_signature"]["aid"] == "test.example.com"


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
            refresh_after=time.time() + _PEER_CERT_CACHE_TTL,
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
            refresh_after=time.time() + _PEER_CERT_CACHE_TTL,
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
            refresh_after=time.time() + _PEER_CERT_CACHE_TTL,
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
            refresh_after=time.time() + _PEER_CERT_CACHE_TTL,
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
