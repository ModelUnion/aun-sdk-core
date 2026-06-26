#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
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
    return "./.aun_test_fs_p4_e2e"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p4-e2e-alice-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
_BOB_AID = os.environ.get("AUN_TEST_BOB_AID", f"fs-p4-e2e-bob-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()

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
    cli_root = Path(_TEST_AUN_PATH).parent / f"cli-fs-p4-{tag}"
    cli_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC_ROOT)
    env["AUN_CLI_CONFIG"] = str(cli_root / "cli.toml")
    env["AUN_CLI_STATE_DIR"] = str(cli_root / "sessions")
    env["AUN_CLI_SESSION_ID"] = f"fs-p4-{tag}"
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


def _cmd(env: dict[str, str], *args: str, expect_ok: bool = True) -> dict:
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
    if expect_ok and proc.returncode != 0:
        raise RuntimeError(f"cmd failed rc={proc.returncode}: {' '.join(args)}\nstdout={proc.stdout}\nstderr={proc.stderr}")
    if not expect_ok:
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    text = proc.stdout.strip()
    return json.loads(text) if text else {}


def _text_cmd(env: dict[str, str], *args: str, expect_ok: bool = True) -> str:
    proc = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "aun_cli", *args],
        cwd=str(_SRC_ROOT.parent),
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if expect_ok and proc.returncode != 0:
        raise RuntimeError(f"cmd failed rc={proc.returncode}: {' '.join(args)}\nstdout={proc.stdout}\nstderr={proc.stderr}")
    if not expect_ok:
        return f"rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
    return proc.stdout


async def _ensure_identities() -> None:
    alice = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    bob = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        await ensure_connected_identity(bob, _BOB_AID)
    finally:
        await alice.close()
        await bob.close()


async def main() -> None:
    print("=== AUN fs P4 E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"BOB      = {_BOB_AID}")
    tag = uuid.uuid4().hex[:10]
    root = f"fs-p4-e2e-{tag}"
    env = _prepare_cli_env(tag)
    work = (Path(os.environ.get("AUN_TEST_TMP_DIR", ".")) / ".tmp_fs_p4_e2e" / tag).resolve()
    work.mkdir(parents=True, exist_ok=True)
    src = work / "secret.txt"
    src.write_text("P4-CLI", encoding="utf-8")
    writer_src = work / "writer.txt"
    writer_src.write_text("BOB-WRITE", encoding="utf-8")

    await _ensure_identities()
    try:
        try:
            _cmd(env, "fs", "mkdir", "-p", f"{_ALICE_AID}:/{root}/docs")
            _cmd(env, "fs", "cp", str(src), f"{_ALICE_AID}:/{root}/docs/a.txt")
            denied = _text_cmd(env, "fs", "cat", "--as", _BOB_AID, f"{_ALICE_AID}:/{root}/docs/a.txt", expect_ok=False)
            if "rc=0" in denied:
                raise AssertionError("bob 未授权时不应能读取")
            denied_write = _cmd(
                env,
                "fs",
                "cp",
                "--as",
                _BOB_AID,
                str(writer_src),
                f"{_ALICE_AID}:/{root}/docs/bob.txt",
                expect_ok=False,
            )
            if int(denied_write.get("returncode") or 0) == 0:
                raise AssertionError("bob 未授权时不应能写入")
            _cmd(env, "fs", "setfacl", "-m", f"aid:{_BOB_AID}:w", f"{_ALICE_AID}:/{root}/docs")
            _cmd(env, "fs", "cp", "--as", _BOB_AID, str(writer_src), f"{_ALICE_AID}:/{root}/docs/bob.txt")
            got = _text_cmd(env, "fs", "cat", f"{_ALICE_AID}:/{root}/docs/bob.txt")
            if got.strip().splitlines()[-1] != "BOB-WRITE":
                raise AssertionError(f"owner 读取 bob 写入内容异常: {got!r}")
            _cmd(env, "fs", "setfacl", "-x", f"aid:{_BOB_AID}", f"{_ALICE_AID}:/{root}/docs")
            denied_after_revoke = _cmd(
                env,
                "fs",
                "cp",
                "--as",
                _BOB_AID,
                "--force",
                str(writer_src),
                f"{_ALICE_AID}:/{root}/docs/bob.txt",
                expect_ok=False,
            )
            if int(denied_after_revoke.get("returncode") or 0) == 0:
                raise AssertionError("bob ACL 撤销后不应能继续写入")
            _ok("cli_setfacl_bob_write_revoke")
        except Exception as exc:
            _fail("cli_setfacl_bob_write_revoke", str(exc))

        try:
            issued = _cmd(env, "fs", "token", "issue", "--max-reads", "1", f"{_ALICE_AID}:/{root}/docs/a.txt")
            token = str(issued.get("token") or "")
            if not token:
                raise AssertionError(f"token issue 未返回 token: {issued}")
            got = _text_cmd(env, "fs", "cat", "--as", _BOB_AID, "--token", token, f"{_ALICE_AID}:/{root}/docs/a.txt")
            if got.strip().splitlines()[-1] != "P4-CLI":
                raise AssertionError(f"token cat 异常: {got!r}")
            denied = _text_cmd(env, "fs", "cat", "--as", _BOB_AID, "--token", token, f"{_ALICE_AID}:/{root}/docs/a.txt", expect_ok=False)
            if "rc=0" in denied:
                raise AssertionError("max_reads=1 token 第二次读取不应成功")
            issued2 = _cmd(env, "fs", "token", "issue", f"{_ALICE_AID}:/{root}/docs/a.txt")
            _cmd(env, "fs", "token", "revoke", "--token", issued2["token"], f"{_ALICE_AID}:/{root}/docs/a.txt")
            denied2 = _text_cmd(env, "fs", "cat", "--as", _BOB_AID, "--token", issued2["token"], f"{_ALICE_AID}:/{root}/docs/a.txt", expect_ok=False)
            if "rc=0" in denied2:
                raise AssertionError("revoked token 不应成功")
            _ok("cli_token_issue_cat_revoke")
        except Exception as exc:
            _fail("cli_token_issue_cat_revoke", str(exc))
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


def test_cli_fs_p4_e2e() -> None:
    asyncio.run(main())
