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
    if Path("/sdk/src/aun_cli").exists():
        return Path("/sdk/src")
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
    return "./.aun_test_fs_p6_e2e"


_TEST_AUN_PATH = os.environ.get("AUN_TEST_AUN_PATH", _default_test_aun_path()).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_ALICE_AID = os.environ.get("AUN_TEST_ALICE_AID", f"fs-p6-e2e-alice-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()
_GROUP_AID = os.environ.get("AUN_TEST_GROUP_AID", f"fs-p6-e2e-group-{uuid.uuid4().hex[:8]}.{_ISSUER}").strip()

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
    cli_root = Path(_TEST_AUN_PATH).parent / f"cli-fs-p6-{tag}"
    cli_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC_ROOT)
    env["AUN_CLI_CONFIG"] = str(cli_root / "cli.toml")
    env["AUN_CLI_STATE_DIR"] = str(cli_root / "sessions")
    env["AUN_CLI_SESSION_ID"] = f"fs-p6-{tag}"
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
    group = make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)
    try:
        await ensure_connected_identity(alice, _ALICE_AID)
        await ensure_connected_identity(group, _GROUP_AID)
    finally:
        await alice.close()
        await group.close()


async def main() -> None:
    print("=== AUN fs P6 E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    print(f"ALICE    = {_ALICE_AID}")
    print(f"GROUP    = {_GROUP_AID}")
    tag = uuid.uuid4().hex[:10]
    root = f"fs-p6-e2e-{tag}"
    env = _prepare_cli_env(tag)
    work = Path(os.environ.get("AUN_TEST_TMP_DIR", "/tmp")) / "aun-fs-p6-e2e" / tag
    work.mkdir(parents=True, exist_ok=True)
    source_file = work / "source.txt"
    source_file.write_text("P6-CLI-SOURCE", encoding="utf-8")
    write_file = work / "write.txt"
    write_file.write_text("P6-CLI-WRITE", encoding="utf-8")

    await _ensure_identities()
    try:
        try:
            source_dir = f"{_ALICE_AID}:/{root}/source"
            mount_dir = f"{_GROUP_AID}:/{root}/memberdata/alice"
            _cmd(env, "fs", "mkdir", "-p", source_dir)
            _cmd(env, "fs", "cp", str(source_file), f"{source_dir}/a.txt")
            _cmd(env, "fs", "setfacl", "-m", f"aid:{_GROUP_AID}:rwd", source_dir)

            mounted = _cmd(env, "fs", "mount", "--as", _GROUP_AID, "--readwrite", mount_dir, "--source", source_dir)
            if mounted.get("type") != "mount" or mounted.get("mount_source") != f"{_ALICE_AID}:{root}/source":
                raise AssertionError(f"mount 返回异常: {mounted}")
            listing = _cmd(env, "fs", "ls", "--as", _GROUP_AID, mount_dir)
            if not any(item.get("name") == "a.txt" for item in listing):
                raise AssertionError(f"ls 未看到 source 文件: {listing}")
            got = _text_cmd(env, "fs", "cat", "--as", _GROUP_AID, f"{mount_dir}/a.txt")
            if got.strip().splitlines()[-1] != "P6-CLI-SOURCE":
                raise AssertionError(f"cat 挂载源文件异常: {got!r}")

            _cmd(env, "fs", "cp", "--as", _GROUP_AID, str(write_file), f"{mount_dir}/b.txt")
            source_got = _text_cmd(env, "fs", "cat", f"{source_dir}/b.txt")
            if source_got.strip().splitlines()[-1] != "P6-CLI-WRITE":
                raise AssertionError(f"挂载点写入未落 source: {source_got!r}")
            _cmd(env, "fs", "cp", "--as", _GROUP_AID, f"{mount_dir}/b.txt", f"{mount_dir}/copy.txt")
            moved = _cmd(env, "fs", "mv", "--as", _GROUP_AID, f"{mount_dir}/copy.txt", f"{mount_dir}/moved.txt")
            removed = _cmd(env, "fs", "rm", "--as", _GROUP_AID, f"{mount_dir}/moved.txt")
            if moved.get("path") != f"/{root}/source/moved.txt" or removed.get("removed_count") != 1:
                raise AssertionError(f"mv/rm 挂载路径返回异常: moved={moved} removed={removed}")

            unmounted = _cmd(env, "fs", "umount", "--as", _GROUP_AID, mount_dir)
            if unmounted.get("removed_count") != 1:
                raise AssertionError(f"umount 返回异常: {unmounted}")
            missing = _cmd(env, "fs", "stat", "--as", _GROUP_AID, mount_dir, expect_ok=False)
            if missing["returncode"] == 0:
                raise AssertionError("umount 后 group 挂载路径不应可 stat")
            still = _text_cmd(env, "fs", "cat", f"{source_dir}/a.txt")
            if still.strip().splitlines()[-1] != "P6-CLI-SOURCE":
                raise AssertionError("umount 后 source 数据丢失")
            _ok("cli_mount_read_write_umount")
        except Exception as exc:
            _fail("cli_mount_read_write_umount", str(exc))
    finally:
        try:
            _cmd(env, "fs", "rm", "-r", f"{_ALICE_AID}:/{root}")
        except Exception:
            pass
        try:
            _cmd(env, "fs", "rm", "-r", f"{_GROUP_AID}:/{root}")
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


def test_cli_fs_p6_e2e() -> None:
    asyncio.run(main())
