#!/usr/bin/env python3
from __future__ import annotations

import asyncio
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
    return "./.aun_test_fs_p2_e2e"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p2-e2e-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()

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
    cli_root = Path(_TEST_AUN_PATH).parent / f"cli-fs-p2-{tag}"
    cli_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC_ROOT)
    env["AUN_CLI_CONFIG"] = str(cli_root / "cli.toml")
    env["AUN_CLI_STATE_DIR"] = str(cli_root / "sessions")
    env["AUN_CLI_SESSION_ID"] = f"fs-p2-{tag}"
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
    print("=== AUN fs P2 E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    tag = uuid.uuid4().hex[:10]
    root = f"fs-p2-e2e-{tag}"
    env = _prepare_cli_env(tag)
    work = (Path(os.environ.get("AUN_TEST_TMP_DIR", tempfile.gettempdir())) / ".tmp_fs_p2_e2e" / tag).resolve()
    work.mkdir(parents=True, exist_ok=True)
    v1 = work / "v1.txt"
    v2 = work / "v2.txt"
    v1.write_text("P2-V1", encoding="utf-8")
    v2.write_text("P2-V2", encoding="utf-8")

    await _ensure_identity()
    try:
        try:
            _cmd(env, "fs", "mkdir", "-p", f"{_ALICE_AID}:/{root}/private")
            _cmd(env, "fs", "mkdir", "-p", f"{_ALICE_AID}:/{root}/public")
            _cmd(env, "fs", "cp", str(v1), f"{_ALICE_AID}:/{root}/private/v1.txt")
            _cmd(env, "fs", "ln", "-s", f"{_ALICE_AID}:/{root}/private/v1.txt", f"{_ALICE_AID}:/{root}/public/current.txt")
            stat = _cmd(env, "fs", "stat", f"{_ALICE_AID}:/{root}/public/current.txt")
            if stat.get("type") != "symlink" or stat.get("target") != f"/{root}/private/v1.txt":
                raise AssertionError(f"stat 软链异常: {stat}")
            cat = _cmd(env, "fs", "cat", f"{_ALICE_AID}:/{root}/public/current.txt")
            if cat.get("content") != "P2-V1":
                raise AssertionError(f"cat 未跟随软链: {cat}")
            _ok("ln_create_stat_cat")
        except Exception as exc:
            _fail("ln_create_stat_cat", str(exc))

        try:
            _cmd(env, "fs", "cp", str(v2), f"{_ALICE_AID}:/{root}/private/v2.txt")
            updated = _cmd(env, "fs", "ln", "-s", "-f", f"{_ALICE_AID}:/{root}/private/v2.txt", f"{_ALICE_AID}:/{root}/public/current.txt")
            if int(updated.get("version") or 0) < 2:
                raise AssertionError(f"ln -sf version 异常: {updated}")
            cat = _cmd(env, "fs", "cat", f"{_ALICE_AID}:/{root}/public/current.txt")
            if cat.get("content") != "P2-V2":
                raise AssertionError(f"重指后 cat 内容异常: {cat}")
            _ok("ln_force_repoint")
        except Exception as exc:
            _fail("ln_force_repoint", str(exc))

        try:
            removed = _cmd(env, "fs", "rm", f"{_ALICE_AID}:/{root}/public/current.txt")
            if int(removed.get("removed_count") or 0) != 1:
                raise AssertionError(f"rm 软链返回异常: {removed}")
            target = _cmd(env, "fs", "stat", f"{_ALICE_AID}:/{root}/private/v2.txt")
            if target.get("type") != "file":
                raise AssertionError(f"target 被误删: {target}")
            _ok("rm_deletes_link_not_target")
        except Exception as exc:
            _fail("rm_deletes_link_not_target", str(exc))
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


def test_cli_fs_p2_e2e() -> None:
    asyncio.run(main())
