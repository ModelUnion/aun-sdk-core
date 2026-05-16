"""Token 复用 + gateway 持久化单元测试。

验证：
1. authenticate() 优先复用 keystore 里的 cached access_token，跳过两阶段重登
2. authenticate() 在 cached_token 过期时仍走 _login
3. _resolve_gateway 在 keystore metadata 命中时跳过 well-known discovery
4. _resolve_gateway 在 discovery 成功后持久化 gateway_url
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from aun_core import AUNClient


def _setup_client(tmp_path):
    """创建一个 client 并 mock 掉真实网络/login，方便测试。"""
    client = AUNClient({"aun_path": str(tmp_path)})
    return client


# ── 改进 A: authenticate() 复用 cached_token ─────────────────────────

@pytest.mark.asyncio
async def test_authenticate_reuses_cached_token(tmp_path):
    """keystore 里有有效 cached_token 时 authenticate 直接返回，不走 _login。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    auth_flow = client._auth

    # 注入一个有效的 identity（含未过期 access_token + refresh_token）
    future_expiry = int(time.time()) + 3600  # 1h 后过期
    identity = {
        "aid": aid,
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
        "public_key_der_b64": "AAAA",
        "cert": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        "access_token": "cached-access-tok",
        "refresh_token": "cached-refresh-tok",
        "access_token_expires_at": future_expiry,
    }

    # mock load_identity_or_raise / _login
    auth_flow._load_identity_or_raise = MagicMock(return_value=identity)
    auth_flow._login = AsyncMock()  # 不应被调用

    result = await auth_flow.authenticate("ws://gateway/aun", aid=aid)

    # 验证 _login 没被调用
    auth_flow._login.assert_not_called()
    # 验证返回的 token 是 cached 值
    assert result["access_token"] == "cached-access-tok"
    assert result["refresh_token"] == "cached-refresh-tok"
    assert result["aid"] == aid


@pytest.mark.asyncio
async def test_authenticate_falls_back_to_login_when_no_cached_token(tmp_path):
    """没有 cached_token 时 authenticate 走 _login。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    auth_flow = client._auth

    identity = {
        "aid": aid,
        "private_key_pem": "fake",
        "public_key_der_b64": "AAAA",
        "cert": "fake-cert",
        # 没有 access_token / refresh_token
    }

    auth_flow._load_identity_or_raise = MagicMock(return_value=identity)
    auth_flow._login = AsyncMock(return_value={
        "access_token": "new-tok",
        "refresh_token": "new-refresh",
        "expires_in": 3600,
    })
    auth_flow._validate_new_cert = AsyncMock()
    auth_flow._persist_identity = MagicMock()

    result = await auth_flow.authenticate("ws://gateway/aun", aid=aid)

    auth_flow._login.assert_called_once()
    assert result["access_token"] == "new-tok"


@pytest.mark.asyncio
async def test_authenticate_login_when_cached_token_expired(tmp_path):
    """cached_token 已过期时 authenticate 走 _login（_get_cached_access_token 会返回空）。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    auth_flow = client._auth

    past_expiry = int(time.time()) - 100  # 已过期
    identity = {
        "aid": aid,
        "private_key_pem": "fake",
        "public_key_der_b64": "AAAA",
        "cert": "fake-cert",
        "access_token": "expired-tok",
        "refresh_token": "old-refresh",
        "access_token_expires_at": past_expiry,
    }

    auth_flow._load_identity_or_raise = MagicMock(return_value=identity)
    auth_flow._login = AsyncMock(return_value={
        "access_token": "fresh-tok",
        "refresh_token": "fresh-refresh",
        "expires_in": 3600,
    })
    auth_flow._validate_new_cert = AsyncMock()
    auth_flow._persist_identity = MagicMock()

    result = await auth_flow.authenticate("ws://gateway/aun", aid=aid)

    auth_flow._login.assert_called_once()
    assert result["access_token"] == "fresh-tok"


# ── 改进 B: gateway_url 持久化 ───────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_gateway_uses_keystore_cache(tmp_path):
    """_resolve_gateway 在 keystore metadata 命中时跳过 discovery。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    client._aid = aid

    # 直接写入 keystore metadata
    client.auth._persist_gateway_url(aid, "wss://cached-gateway.test/aun")

    # mock discovery —— 不应被调用
    client._discovery = MagicMock()
    client._discovery.discover = AsyncMock()

    result = await client.auth._resolve_gateway(aid)

    assert result == "wss://cached-gateway.test/aun"
    client._discovery.discover.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_gateway_persists_after_discovery(tmp_path):
    """discovery 成功后 gateway_url 应被写入 keystore metadata。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    client._aid = aid
    client._gateway_url = ""  # 内存缓存清空

    client._discovery = MagicMock()
    client._discovery.discover = AsyncMock(return_value="wss://discovered.test/aun")

    result = await client.auth._resolve_gateway(aid)
    assert result == "wss://discovered.test/aun"

    # 验证已持久化
    cached = client.auth._load_cached_gateway_url(aid)
    assert cached == "wss://discovered.test/aun"


@pytest.mark.asyncio
async def test_resolve_gateway_preset_in_memory_takes_priority(tmp_path):
    """内存里的 _gateway_url 优先级最高（即使 keystore 有值）。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    client._aid = aid

    client.auth._persist_gateway_url(aid, "wss://stale.test/aun")
    client._gateway_url = "wss://memory-fresh.test/aun"  # 内存优先

    client._discovery = MagicMock()
    client._discovery.discover = AsyncMock()

    result = await client.auth._resolve_gateway(aid)
    assert result == "wss://memory-fresh.test/aun"


def test_persist_gateway_url_handles_empty(tmp_path):
    """空字符串不应写入 keystore（避免污染）。"""
    aid = "alice.test.com"
    client = _setup_client(tmp_path)
    client._aid = aid
    # 不应抛异常
    client.auth._persist_gateway_url(aid, "")


def test_load_cached_gateway_url_returns_empty_when_missing(tmp_path):
    """keystore 没有记录时返回空字符串。"""
    aid = "alice-no-record.test.com"
    client = _setup_client(tmp_path)
    # 应返回空字符串而非异常
    result = client.auth._load_cached_gateway_url(aid)
    assert result == ""
