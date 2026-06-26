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
from aun_core import AIDStore, AUNClient
from aun_refactor_helpers import ensure_connected_identity, make_client_for_path

os.environ.setdefault("AUN_ENV", "development")

_AUN_DATA_ROOT = os.environ.get("AUN_DATA_ROOT", "").strip()
_TEST_AUN_PATH = os.environ.get(
    "AUN_TEST_AUN_PATH",
    f"{_AUN_DATA_ROOT}/single-domain/persistent" if _AUN_DATA_ROOT else "./.aun_test_group_fs_cli_e2e",
).strip()
_ISSUER = os.environ.get("AUN_TEST_ISSUER", "agentid.pub").strip() or "agentid.pub"
_SEED = os.environ.get("AUN_TEST_ENCRYPTION_SEED", "")

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
    if os.environ.get("PYTEST_CURRENT_TEST"):
        raise AssertionError(reason)


def _make_client() -> AUNClient:
    return make_client_for_path(_TEST_AUN_PATH, require_forward_secrecy=False)


def _make_store() -> AIDStore:
    return AIDStore(_TEST_AUN_PATH, encryption_seed=_SEED, verify_ssl=False)


def _prepare_cli_env(tag: str, *, owner_aid: str, active_group: str) -> dict[str, str]:
    cli_root = Path(_TEST_AUN_PATH).parent / f"cli-group-fs-{tag}"
    cli_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SRC_ROOT)
    env["AUN_CLI_CONFIG"] = str(cli_root / "cli.toml")
    env["AUN_CLI_STATE_DIR"] = str(cli_root / "sessions")
    env["AUN_CLI_SESSION_ID"] = f"group-fs-{tag}"
    env["AUN_DATA_ROOT"] = _TEST_AUN_PATH
    env["AUN_TEST_AUN_PATH"] = _TEST_AUN_PATH
    if _SEED:
        env["AUN_TEST_ENCRYPTION_SEED"] = _SEED
        env["AUN_ENCRYPTION_SEED"] = _SEED

    old_config = os.environ.get("AUN_CLI_CONFIG")
    os.environ["AUN_CLI_CONFIG"] = env["AUN_CLI_CONFIG"]
    try:
        cfg = load_config()
        cfg["default"]["profile"] = "default"
        cfg["profiles"] = {
            "default": {
                "aid": owner_aid,
                "aun_path": _TEST_AUN_PATH,
                "active_group": active_group,
                "timeout": 90,
                "encryption_seed": _SEED,
            }
        }
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
        timeout=150,
    )
    if expect_ok and proc.returncode != 0:
        raise RuntimeError(
            f"cmd failed rc={proc.returncode}: {' '.join(args)}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    if not expect_ok:
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    text = proc.stdout.strip()
    return json.loads(text) if text else {}


async def _create_group(owner_aid: str, group_name: str) -> tuple[str, str]:
    owner = _make_client()
    store = _make_store()
    try:
        await ensure_connected_identity(owner, owner_aid)
        created = await owner.create_group(
            {
                "name": f"group-fs-cli-{group_name}",
                "group_name": group_name,
                "visibility": "private",
            },
            aid_store=store,
        )
        group = created.get("group") if isinstance(created, dict) else {}
        group_id = str((group or {}).get("group_id") or "").strip()
        group_aid = str((group or {}).get("group_aid") or "").strip()
        if not group_id or not group_aid:
            raise AssertionError(f"create_group 未返回 group_id/group_aid: {created}")
        return group_id, group_aid
    finally:
        await owner.close()


async def main() -> None:
    print("=== AUN group fs CLI E2E ===")
    print(f"AUN_PATH = {_TEST_AUN_PATH}")
    tag = uuid.uuid4().hex[:8]
    owner_aid = f"gfs-cli-owner-{tag}.{_ISSUER}"
    group_name = f"gfscli{tag}"
    remote_dir = f"cli-e2e-{tag}"
    remote_file = f"{remote_dir}/note.txt"
    body = f"GROUP-FS-CLI-E2E-{tag}"

    group_id, group_aid = await _create_group(owner_aid, group_name)
    print(f"OWNER    = {owner_aid}")
    print(f"GROUP_ID = {group_id}")
    print(f"GROUP_AID= {group_aid}")

    env = _prepare_cli_env(tag, owner_aid=owner_aid, active_group=group_id)
    work = Path(os.environ.get("AUN_TEST_TMP_DIR", "/tmp")) / "aun-group-fs-cli-e2e" / tag
    work.mkdir(parents=True, exist_ok=True)
    source_file = work / "source.txt"
    download_file = work / "download.txt"
    source_file.write_text(body, encoding="utf-8")
    remote_dir_ref = f"{group_aid}:/{remote_dir}"
    remote_file_ref = f"{group_aid}:/{remote_file}"

    try:
        try:
            _cmd(env, "group", "fs", "mkdir", "--parents", remote_dir_ref, "--as", group_aid)
            uploaded = _cmd(env, "group", "fs", "cp", str(source_file), remote_file_ref, "--force", "--as", group_aid)
            if str(uploaded.get("type") or "") != "file":
                raise AssertionError(f"cp 上传返回异常: {uploaded}")

            listed = _cmd(env, "group", "fs", "ls", remote_dir_ref)
            items = listed.get("items") if isinstance(listed, dict) else listed
            if not isinstance(items, list) or not any(item.get("name") == "note.txt" for item in items if isinstance(item, dict)):
                raise AssertionError(f"ls 未看到上传文件: {listed}")

            stat = _cmd(env, "group", "fs", "stat", remote_file_ref)
            if stat.get("type") != "file" or stat.get("name") != "note.txt":
                raise AssertionError(f"stat 返回异常: {stat}")

            _cmd(env, "group", "fs", "cp", remote_file_ref, f"local:{download_file}", "--force")
            if download_file.read_text(encoding="utf-8") != body:
                raise AssertionError("下载文件内容不一致")

            blocked = _cmd(env, "group", "fs", "cp", remote_file_ref, f"local:{download_file}", expect_ok=False)
            if int(blocked["returncode"]) == 0:
                raise AssertionError("本地目标已存在时未加 --force 不应成功")

            removed = _cmd(env, "group", "fs", "rm", remote_file_ref, "--as", group_aid)
            if int(removed.get("removed_count") or 0) < 1:
                raise AssertionError(f"rm 返回异常: {removed}")

            missing = _cmd(env, "group", "fs", "stat", remote_file_ref, expect_ok=False)
            if int(missing["returncode"]) == 0:
                raise AssertionError("rm 后 stat 不应成功")

            _ok("cli_group_fs_mkdir_cp_ls_stat_download_rm")
        except Exception as exc:
            _fail("cli_group_fs_mkdir_cp_ls_stat_download_rm", str(exc))

        try:
            acl_dir = f"{group_aid}:/archive/cli-acl-{tag}"
            _cmd(env, "group", "fs", "mkdir", "--parents", acl_dir, "--as", group_aid)
            grant = _cmd(env, "group", "fs", "setfacl", "-m", "role:admin:rwx", acl_dir)
            listed = _cmd(env, "group", "fs", "getfacl", acl_dir)
            revoke = _cmd(env, "group", "fs", "setfacl", "-x", "role:admin", acl_dir)
            acls = listed.get("acls") if isinstance(listed, dict) else []
            if grant.get("acl_action") != "set_acl" or revoke.get("acl_action") != "remove_acl":
                raise AssertionError(f"setfacl 返回异常: grant={grant} revoke={revoke}")
            if not any(isinstance(item, dict) and item.get("grantee_aid") == "role:admin" and item.get("perms") == "rwx" for item in acls):
                raise AssertionError(f"getfacl 未返回 role:admin:rwx: {listed}")
            _ok("cli_group_fs_setfacl_getfacl")
        except Exception as exc:
            _fail("cli_group_fs_setfacl_getfacl", str(exc))
    finally:
        try:
            _cmd(env, "group", "fs", "rm", "--recursive", "--force", remote_dir_ref, "--as", group_aid)
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


def test_cli_group_fs_e2e() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    asyncio.run(main())
