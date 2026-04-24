"""三端 SDK SQLite 本地存储互操作测试。

目标：同一 AID、同一 aun.db，由 Python / TypeScript / Go 轮流写入敏感字段，
再由各端交叉读取，验证 schema、字段级加密、明文兼容读取完全一致。
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import uuid
from pathlib import Path

import pytest

from aun_core.keystore.file import FileKeyStore

AID = "interop.aid.test"
SEED = "interop-seed"
EXPECTED = {
    "python-prekey": "PY-PREKEY-SECRET",
    "ts-prekey": "TS-PREKEY-SECRET",
    "go-prekey": "GO-PREKEY-SECRET",
}
EXPECTED_GROUPS = {
    "python-group": "PY-GROUP-SECRET",
    "ts-group": "TS-GROUP-SECRET",
    "go-group": "GO-GROUP-SECRET",
}
EXPECTED_SESSIONS = {
    "python-session": "PY-SESSION-SECRET",
    "ts-session": "TS-SESSION-SECRET",
    "go-session": "GO-SESSION-SECRET",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    resolved = shutil.which(cmd[0])
    if resolved:
        cmd = [resolved, *cmd[1:]]
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        env={**os.environ, **(env or {})},
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result.stdout


def _write_python(root: Path) -> None:
    ks = FileKeyStore(root, encryption_seed=SEED)
    ks.save_e2ee_prekey(AID, "python-prekey", {"private_key_pem": EXPECTED["python-prekey"], "created_at": 1})
    ks.save_group_secret_state(AID, "python-group", {"epoch": 1, "secret": EXPECTED_GROUPS["python-group"]})
    db = ks._get_db(AID)
    db.save_session("python-session", {"secret": EXPECTED_SESSIONS["python-session"]})
    for aid_db in list(ks._aid_dbs.values()):
        aid_db.close()


def _read_python(root: Path) -> dict:
    ks = FileKeyStore(root, encryption_seed=SEED)
    db = ks._get_db(AID)
    payload = {
        "prekeys": ks.load_e2ee_prekeys(AID),
        "groups": ks.load_all_group_secret_states(AID),
        "sessions": db.load_all_sessions(),
    }
    for aid_db in list(ks._aid_dbs.values()):
        aid_db.close()
    return payload


def _ts_script(root: Path, action: str) -> str:
    repo = _repo_root()
    import_path = (repo / "ts" / "dist" / "index.js").resolve().as_uri()
    root_js = root.as_posix()
    return f"""
import {{ FileKeyStore }} from '{import_path}';
const root = {json.dumps(root_js)};
const aid = {json.dumps(AID)};
const ks = new FileKeyStore(root, {{ encryptionSeed: {json.dumps(SEED)} }});
if ({json.dumps(action)} === 'write') {{
  await ks.saveE2EEPrekey(aid, 'ts-prekey', {{ private_key_pem: 'TS-PREKEY-SECRET', created_at: 1 }});
  await ks.saveGroupSecretState(aid, 'ts-group', {{ epoch: 1, secret: 'TS-GROUP-SECRET' }});
  await ks.saveE2EESession(aid, 'ts-session', {{ secret: 'TS-SESSION-SECRET' }});
  ks.close?.();
}} else {{
  const payload = {{
    prekeys: await ks.loadE2EEPrekeys(aid),
    groups: await ks.loadAllGroupSecretStates(aid),
    sessions: await ks.loadE2EESessions(aid),
  }};
  ks.close?.();
  console.log(JSON.stringify(payload));
}}
"""


def _run_ts_driver(root: Path, action: str) -> dict | None:
    repo = _repo_root()
    root.mkdir(parents=True, exist_ok=True)
    script = root / f"interop-ts-{action}.mjs"
    script.write_text(_ts_script(root, action), encoding="utf-8")
    out = _run(["node", str(script)], cwd=repo)
    return json.loads(out) if action == "read" else None


def _run_go_driver(root: Path, action: str) -> dict | None:
    repo = _repo_root()
    go_cache = repo / ".codex-tmp" / "go-build-cache"
    go_tmp = repo / "python" / "tests" / ".tmp_sqlite_storage_interop" / f"go-tmp-{action}"
    go_bin = repo / "python" / "tests" / ".tmp_sqlite_storage_interop" / "go-keystore-interop.test.exe"
    go_cache.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(go_tmp, ignore_errors=True)
    go_tmp.mkdir(parents=True, exist_ok=True)
    compile_env = {
        **os.environ,
        "GOTELEMETRY": "off",
        "GOCACHE": str(go_cache),
        "GOTMPDIR": str(go_tmp),
    }
    compile_result = subprocess.run(
        [shutil.which("go") or "go", "test", "-c", "./keystore", "-o", str(go_bin)],
        cwd=str(repo / "go"),
        env=compile_env,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if compile_result.returncode != 0:
        cleanup_error = "Access is denied" in compile_result.stderr and go_bin.exists()
        if not cleanup_error:
            raise AssertionError(
                "command failed: go test -c ./keystore\n"
                f"STDOUT:\n{compile_result.stdout}\nSTDERR:\n{compile_result.stderr}"
            )
    out = _run(
        [str(go_bin), "-test.run", "TestSQLiteInteropDriver", "-test.count=1", "-test.v"],
        cwd=repo / "go",
        env={
            "AUN_SQLITE_INTEROP_DRIVER": "1",
            "AUN_SQLITE_INTEROP_ROOT": str(root),
            "AUN_SQLITE_INTEROP_AID": AID,
            "AUN_SQLITE_INTEROP_ACTION": "write-go" if action == "write" else "read-all",
            "GOTELEMETRY": "off",
            "GOCACHE": str(go_cache),
            "GOTMPDIR": str(go_tmp),
        },
    )
    if action != "read":
        return None
    start = out.find("{")
    end = out.rfind("}")
    if start < 0 or end < start:
        raise AssertionError(f"go driver did not emit JSON:\n{out}")
    return json.loads(out[start : end + 1])


def _assert_payload(payload: dict) -> None:
    prekeys = payload["prekeys"]
    groups = payload["groups"]
    sessions = {item["session_id"]: item for item in payload["sessions"]}
    for prekey_id, secret in EXPECTED.items():
        assert prekeys[prekey_id]["private_key_pem"] == secret
    for group_id, secret in EXPECTED_GROUPS.items():
        assert groups[group_id]["secret"] == secret
    for session_id, secret in EXPECTED_SESSIONS.items():
        assert sessions[session_id]["secret"] == secret


def _assert_db_sensitive_fields_encrypted(root: Path) -> None:
    db_path = root / "AIDs" / AID / "aun.db"
    conn = sqlite3.connect(db_path)
    values = []
    values += [row[0] for row in conn.execute("SELECT private_key_enc FROM prekeys")]
    values += [row[0] for row in conn.execute("SELECT secret_enc FROM group_current")]
    values += [row[0] for row in conn.execute("SELECT data_enc FROM e2ee_sessions")]
    joined = "\n".join(values)
    for secret in list(EXPECTED.values()) + list(EXPECTED_GROUPS.values()) + list(EXPECTED_SESSIONS.values()):
        assert secret not in joined
    for value in values:
        record = json.loads(value)
        assert record["scheme"] == "file_aes"
        assert record.get("nonce") and record.get("ciphertext") and record.get("tag")


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required")
@pytest.mark.skipif(shutil.which("go") is None, reason="go is required")
def test_sqlite_storage_interop_python_ts_go() -> None:
    repo = _repo_root()
    _run(["npm", "run", "-s", "build"], cwd=repo / "ts")

    root = repo / "python" / "tests" / ".tmp_sqlite_storage_interop" / f"aun-store-{uuid.uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)

    _write_python(root)
    _run_ts_driver(root, "write")
    _run_go_driver(root, "write")

    for payload in (
        _read_python(root),
        _run_ts_driver(root, "read"),
        _run_go_driver(root, "read"),
    ):
        assert payload is not None
        _assert_payload(payload)

    _assert_db_sensitive_fields_encrypted(root)
