#!/usr/bin/env python3
"""验证 CA 指纹兼容性 — 通过 Gateway PKI 端点验证
证书 DER SHA-256 和公钥 SPKI SHA-256 两种指纹都能下载到证书。

使用方法（Docker 单域环境内）：
  python /tests/verify_fingerprint_compat.py
"""
import asyncio
import hashlib
import os
import ssl
import sys
from pathlib import Path
from urllib.parse import quote, urlencode

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from aun_core import AUNClient

# ── 配置 ──
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
os.environ.setdefault("AUN_ENV", "development")


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"alice.{_ISSUER}").strip()
_GATEWAY_HOST = f"gateway.{_ISSUER}"


def _compute_fingerprints(cert_pem: bytes) -> tuple[str, str]:
    """计算证书的两种 SHA-256 指纹，返回 (cert_der_hex, pubkey_spki_hex)"""
    cert = x509.load_pem_x509_certificate(cert_pem)
    cert_der_hex = cert.fingerprint(hashes.SHA256()).hex()
    pubkey_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pubkey_spki_hex = hashlib.sha256(pubkey_der).hexdigest()
    return cert_der_hex, pubkey_spki_hex


async def _fetch_cert_by_fingerprint(session: aiohttp.ClientSession, aid: str, fingerprint: str) -> str | None:
    """通过 Gateway PKI 端点下载证书"""
    url = f"https://{_GATEWAY_HOST}:20001/pki/cert/{quote(aid, safe='')}?{urlencode({'cert_fingerprint': fingerprint})}"
    try:
        async with session.get(url, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text()
            else:
                body = await resp.text()
                print(f"    HTTP {resp.status}: {body[:200]}")
                return None
    except Exception as e:
        print(f"    请求失败: {e}")
        return None


async def _fetch_cert_no_fingerprint(session: aiohttp.ClientSession, aid: str) -> str | None:
    """通过 Gateway PKI 端点下载证书（不带指纹 = active_signing）"""
    url = f"https://{_GATEWAY_HOST}:20001/pki/cert/{quote(aid, safe='')}"
    try:
        async with session.get(url, ssl=False) as resp:
            if resp.status == 200:
                return await resp.text()
            else:
                body = await resp.text()
                print(f"    HTTP {resp.status}: {body[:200]}")
                return None
    except Exception as e:
        print(f"    请求失败: {e}")
        return None


async def main():
    passed = 0
    failed = 0

    print(f"\n{'='*60}")
    print(f"验证 CA 指纹兼容性（Gateway PKI 端点）")
    print(f"AID:      {_ALICE_AID}")
    print(f"Gateway:  {_GATEWAY_HOST}:20001")
    print(f"aun_path: {_TEST_AUN_PATH}")
    print(f"{'='*60}\n")

    # 1. 读取本地证书计算两种指纹
    cert_path = Path(_TEST_AUN_PATH) / "AIDs" / _ALICE_AID / "public" / "cert.pem"
    if not cert_path.exists():
        # 如果固定身份不存在，先创建
        print(f"[INFO] 本地证书不存在，尝试用 SDK 创建身份...")
        client = AUNClient({"aun_path": _TEST_AUN_PATH}, debug=False)
        client._config_model.require_forward_secrecy = False
        try:
            await client.auth.create_aid({"aid": _ALICE_AID})
            auth = await client.auth.authenticate({"aid": _ALICE_AID})
            connect_params = dict(auth)
            connect_params["verify_ssl"] = False
            await client.connect(connect_params)
            await asyncio.sleep(1)
            await client.close()
        except Exception as e:
            print(f"[FAIL] 创建身份失败: {e}")
            return

    cert_pem = cert_path.read_bytes()
    cert_der_hex, pubkey_spki_hex = _compute_fingerprints(cert_pem)

    print(f"  证书 DER SHA-256:  {cert_der_hex}")
    print(f"  公钥 SPKI SHA-256: {pubkey_spki_hex}")
    assert cert_der_hex != pubkey_spki_hex, "两种指纹应该不同"
    print(f"  [OK] 两种指纹确实不同\n")

    async with aiohttp.ClientSession() as session:
        # ── 测试 0: 无指纹 → 取 active_signing 证书 ──
        print("[TEST 0] 无指纹参数 → 取 active_signing 证书 ...")
        cert0 = await _fetch_cert_no_fingerprint(session, _ALICE_AID)
        if cert0 and "BEGIN CERTIFICATE" in cert0:
            print(f"  [PASS] 成功获取 active_signing 证书")
            passed += 1
        else:
            print(f"  [FAIL] 未能获取证书")
            failed += 1

        # ── 测试 1: 证书 DER SHA-256 指纹 ──
        print(f"[TEST 1] 证书 DER SHA-256 指纹查询 ...")
        fp1 = f"sha256:{cert_der_hex}"
        cert1 = await _fetch_cert_by_fingerprint(session, _ALICE_AID, fp1)
        if cert1 and "BEGIN CERTIFICATE" in cert1:
            print(f"  [PASS] 成功获取证书（证书 DER 指纹）")
            passed += 1
        else:
            print(f"  [FAIL] 未能获取证书")
            failed += 1

        # ── 测试 2: 公钥 SPKI SHA-256 指纹 ──
        print(f"[TEST 2] 公钥 SPKI SHA-256 指纹查询 ...")
        fp2 = f"sha256:{pubkey_spki_hex}"
        cert2 = await _fetch_cert_by_fingerprint(session, _ALICE_AID, fp2)
        if cert2 and "BEGIN CERTIFICATE" in cert2:
            print(f"  [PASS] 成功获取证书（公钥 SPKI 指纹）")
            passed += 1
        else:
            print(f"  [FAIL] 未能获取证书")
            failed += 1

        # ── 测试 3: 两种指纹返回同一证书 ──
        print("[TEST 3] 两种指纹返回的是同一个证书 ...")
        if cert1 and cert2:
            if cert1.strip() == cert2.strip():
                print(f"  [PASS] 两种指纹返回同一证书")
                passed += 1
            else:
                print(f"  [FAIL] 返回了不同的证书!")
                failed += 1
        else:
            print(f"  [SKIP] 前置测试未通过")
            failed += 1

        # ── 测试 4: 不存在的指纹 → fallback 到 active_signing ──
        print("[TEST 4] 不存在的指纹查询 → 预期 fallback 到 active_signing ...")
        fake_fp = "sha256:" + "0" * 64
        cert4 = await _fetch_cert_by_fingerprint(session, _ALICE_AID, fake_fp)
        if cert4 and "BEGIN CERTIFICATE" in cert4:
            # CA 设计：fingerprint 不匹配时 fallback 到 active_signing（兼容旧客户端）
            print(f"  [PASS] 不存在的指纹 fallback 到 active_signing 证书（设计如此）")
            passed += 1
        else:
            print(f"  [FAIL] 应返回 fallback 证书")
            failed += 1

    # ── 汇总 ──
    print(f"\n{'='*60}")
    if failed == 0:
        print(f"ALL PASSED: {passed}/{passed + failed}")
    else:
        print(f"RESULT: {passed} passed, {failed} failed")
    print(f"{'='*60}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
