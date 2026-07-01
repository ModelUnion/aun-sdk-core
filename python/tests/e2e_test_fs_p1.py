#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

_ROOT = Path(__file__).parent.parent


def _resolve_src_root() -> Path:
    for item in os.environ.get("PYTHONPATH", "").split(os.pathsep):
        if not item:
            continue
        candidate = Path(item)
        if (candidate / "aun_cli").exists():
            return candidate
    return _ROOT / "src"


_SRC_ROOT = _resolve_src_root()
sys.path.insert(0, str(_SRC_ROOT))

from aun_cli.config import load_config, save_config
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path


os.environ.setdefault("AUN_ENV", "development")
_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()


def _default_test_aun_path() -> str:
    if _AUN_DATA_ROOT:
        return f"{_AUN_DATA_ROOT}/single-domain/persistent"
    return "./.aun_test_fs_p1_e2e"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p1-e2e-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()

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


def _prepare_cli_env(tag: str) -> dict[str, str]:
    cli_root = Path(_TEST_AUN_PATH).parent / f"cli-fs-p1-{tag}"
    cli_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC_ROOT)
    env["AUN_CLI_CONFIG"] = str(cli_root / "cli.toml")
    env["AUN_CLI_STATE_DIR"] = str(cli_root / "sessions")
    env["AUN_CLI_SESSION_ID"] = f"fs-p1-{tag}"
    env["AUN_DATA_ROOT"] = _TEST_AUN_PATH
    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {
        "default": {
            "aid": _ALICE_AID,
            "aun_path": _TEST_AUN_PATH,
            "timeout": 60,
        }
    }
    old_config = os.environ.get("AUN_CLI_CONFIG")
    os.environ["AUN_CLI_CONFIG"] = env["AUN_CLI_CONFIG"]
    try:
        save_config(cfg)
    finally:
        if old_config is None:
            os.environ.pop("AUN_CLI_CONFIG", None)
        else:
            os.environ["AUN_CLI_CONFIG"] = old_config
    return env


def _cmd(env: dict[str, str], *args: str) -> dict:
    proc = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "aun_cli", "--json", *args],
        cwd=str(_SRC_ROOT.parent),
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cmd failed rc={proc.returncode}: {' '.join(args)}\nstdout={proc.stdout}\nstderr={proc.stderr}")
    text = proc.stdout.strip()
    return json.loads(text) if text else {}


async def _ensure_identity() -> None:
    client = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    try:
        await ensure_connected_identity(client, _ALICE_AID)
    finally:
        await client.close()


async def main() -> None:
    print("=== AUN fs P1 E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    tag = uuid.uuid4().hex[:10]
    root = f"fs-p1-e2e-{tag}"
    env = _prepare_cli_env(tag)
    work = (Path(os.environ.get("AUN_TEST_TMP_DIR", tempfile.gettempdir())) / ".tmp_fs_p1_e2e" / tag).resolve()
    work.mkdir(parents=True, exist_ok=True)
    local = work / "hello.txt"
    got = work / "got.txt"
    local.write_bytes(b"FS-P1-E2E-" + tag.encode("ascii"))
    remote = f"{_ALICE_AID}:/{root}/hello.txt"

    await _ensure_identity()
    try:
        try:
            _cmd(env, "fs", "mkdir", "-p", f"{_ALICE_AID}:/{root}")
            _cmd(env, "fs", "cp", str(local), remote)
            _cmd(env, "fs", "cp", remote, str(got))
            if hashlib.sha256(local.read_bytes()).hexdigest() != hashlib.sha256(got.read_bytes()).hexdigest():
                raise AssertionError("CLI round-trip sha256 mismatch")
            _ok("fs_cp_upload_download")
        except Exception as exc:
            _fail("fs_cp_upload_download", str(exc))

        try:
            listed = _cmd(env, "fs", "ls", f"{_ALICE_AID}:/{root}")
            stat = _cmd(env, "fs", "stat", remote)
            if not any(item.get("name") == "hello.txt" for item in listed):
                raise AssertionError(f"ls 未返回 hello.txt: {listed}")
            if stat.get("type") != "file":
                raise AssertionError(f"stat type 异常: {stat}")
            _ok("fs_ls_stat")
        except Exception as exc:
            _fail("fs_ls_stat", str(exc))

        try:
            usage = _cmd(env, "fs", "df", f"{_ALICE_AID}:")
            if usage.get("owner") != _ALICE_AID:
                raise AssertionError(f"df owner 异常: {usage}")
            _ok("fs_df")
        except Exception as exc:
            _fail("fs_df", str(exc))

        try:
            removed = _cmd(env, "fs", "rm", "-r", f"{_ALICE_AID}:/{root}")
            if int(removed.get("removed_count") or 0) <= 0:
                raise AssertionError(f"rm -r 返回异常: {removed}")
            _ok("fs_rm_recursive")
        except Exception as exc:
            _fail("fs_rm_recursive", str(exc))
    finally:
        try:
            _cmd(env, "fs", "rm", "-r", f"{_ALICE_AID}:/{root}")
        except Exception:
            pass

    print("=" * 50)
    print(f"结果: {_passed} passed, {_failed} failed")
    if _errors:
        for item in _errors:
            print(f"  - {item}")
    if _failed:
        sys.exit(1)
    print("全部通过")


if __name__ == "__main__":
    asyncio.run(main())


def test_cli_fs_p1_e2e() -> None:
    asyncio.run(main())
