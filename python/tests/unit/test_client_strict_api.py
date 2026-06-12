from __future__ import annotations

import asyncio
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from aun_core import AIDStore, AUNClient, ConnectionState
from aun_core.errors import ValidationError

from test_client_state_machine import _load_local_aid


def _federation_tests_dir() -> Path | None:
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "docker-deploy" / "federation-test" / "tests"
        if candidate.exists():
            return candidate
        candidate = parent.parent / "docker-deploy" / "federation-test" / "tests"
        if candidate.exists():
            return candidate
    return None


def _existing(paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.exists()]


def test_client_rejects_legacy_config_constructor():
    with pytest.raises(TypeError, match="AID"):
        AUNClient({"aun_path": "/tmp/aun"})


def test_aid_store_rejects_external_gateway_constructor(tmp_path):
    with pytest.raises(TypeError, match="gateway_url"):
        AIDStore(tmp_path / "aun", "", gateway_url="ws://gateway.example/aun")


@pytest.mark.asyncio
async def test_client_authenticate_rejects_external_gateway_option(tmp_path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)

    with pytest.raises(ValidationError, match="gateway.*discovery"):
        await client.authenticate({"gateway": "ws://gateway.example/aun"})

    store.close()


@pytest.mark.asyncio
async def test_client_connect_rejects_external_gateway_option(tmp_path):
    store, aid = _load_local_aid(tmp_path)
    client = AUNClient(aid)

    with pytest.raises(ValidationError, match=r"unsupported field\(s\): gateway"):
        await client.connect({"gateway": "ws://gateway.example/aun"})

    store.close()


def test_cli_profile_config_ignores_external_gateway_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-no-gateway")
    monkeypatch.setenv("AUN_GATEWAY", "wss://env-gateway.example/aun")

    from aun_cli.adapter import resolve_profile_config
    from aun_cli.config import load_config, save_config

    cfg = load_config()
    cfg["default"]["profile"] = "work"
    cfg["profiles"] = {
        "work": {
            "aid": "work.agentid.pub",
            "gateway": "wss://profile-gateway.example/aun",
        },
    }
    save_config(cfg)

    ctx = SimpleNamespace(
        obj={
            "profile": None,
            "gateway": "wss://cli-gateway.example/aun",
            "timeout": None,
            "debug": False,
        }
    )

    resolved = resolve_profile_config(ctx)

    assert resolved["gateway"] is None


def test_cli_does_not_define_external_gateway_options():
    root = Path(__file__).resolve().parents[2] / "src" / "aun_cli"

    violations: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute) or node.func.attr != "Option":
                continue
            labels = [
                arg.value
                for arg in node.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            ]
            if "--gateway" in labels or "-g" in labels:
                violations.append(f"{path}:{node.lineno}: gateway option")

    assert violations == []


def test_migrated_code_does_not_touch_private_gateway_state():
    root = Path(__file__).resolve().parents[2]
    federation_tests = _federation_tests_dir()
    checked = [
        root / "tests" / "aun_refactor_helpers.py",
        root / "tests" / "test_integration_auth_flow.py",
        root / "tests" / "unit" / "test_client.py",
        root / "tests" / "unit" / "test_client_state_machine.py",
        root / "tests" / "unit" / "test_reconnect.py",
        root / "tests" / "unit" / "test_py_issues.py",
        root / "tests" / "unit" / "test_p0_common_gaps.py",
        root / "tests" / "integration_test_v2_push_seq.py",
        root / "src" / "aun_cli" / "adapter.py",
        root / "src" / "aun_cli" / "commands" / "diag.py",
    ]
    if federation_tests is not None:
        checked.append(federation_tests / "sdk_client_helper.py")
    checked = _existing(checked)

    violations: list[str] = []
    for path in checked:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "_gateway_url":
                violations.append(f"{path}:{node.lineno}")

    assert violations == []


def test_federation_tests_use_discovery_only_gateway_flow():
    root = _federation_tests_dir()
    if root is None:
        return

    violations: list[str] = []
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "AUNClient"
                and node.args
                and isinstance(node.args[0], ast.Dict)
            ):
                violations.append(f"{path}:{node.lineno}: legacy AUNClient(config)")
            if isinstance(node, ast.Attribute) and node.attr in {"_gateway_url", "_device_id", "_v2_session"}:
                violations.append(f"{path}:{node.lineno}: private {node.attr}")

    assert violations == []


def test_migrated_helpers_do_not_pass_legacy_auth_dict():
    root = Path(__file__).resolve().parents[2]
    federation_tests = _federation_tests_dir()
    checked = [
        root / "tests" / "aun_refactor_helpers.py",
    ]
    if federation_tests is not None:
        checked.append(federation_tests / "sdk_client_helper.py")
    checked = _existing(checked)

    violations: list[str] = []
    for path in checked:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "authenticate"
                and node.args
                and isinstance(node.args[0], ast.Dict)
            ):
                violations.append(f"{path}:{node.lineno}: legacy authenticate(dict)")

    assert violations == []


def test_client_does_not_expose_test_or_diagnostic_helpers():
    client = AUNClient()

    for name in (
        "get_current_v2_group_spk_id",
        "build_v2_p2p_envelope_for_diagnostics",
        "build_v2_group_envelope_for_diagnostics",
        "build_v2_target_from_device",
        "clear_v2_bootstrap_cache",
        "set_v2_bootstrap_cache_epoch",
        "get_v2_bootstrap_cache_epoch",
        "export_sequence_state",
        "reset_sequence_state",
        "set_v2_auto_state_management_enabled",
        "rotate_v2_spk",
        "get_v2_sender_identity",
        "get_group_secret_epochs",
        "handle_group_key_distribution",
        "has_v2_session",
        "v2_session_info",
        "get_remote_agent_md_etag",
        "publish_agent_md",
        "create_named_group",
        "_set_agent_md_path",
    ):
        assert not hasattr(client, name)


def test_migrated_tests_do_not_attach_private_test_fields_to_clients():
    root = Path(__file__).resolve().parents[2] / "tests"
    checked = [
        path
        for pattern in ("integration_test_*.py", "e2e_test_*.py", "test_integration_*.py")
        for path in root.glob(pattern)
    ]

    violations: list[str] = []
    for path in sorted(checked):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr.startswith("_test_")
                and not (isinstance(node.value, ast.Name) and node.value.id == "self")
            ):
                violations.append(f"{path}:{node.lineno}: private test field {node.attr}")

    assert violations == []


def test_migrated_integration_tests_do_not_call_removed_client_methods():
    python_tests = Path(__file__).resolve().parents[2] / "tests"
    federation_tests = _federation_tests_dir()
    checked = [
        *[
            path
            for pattern in ("integration_test_*.py", "e2e_test_*.py", "test_integration_*.py")
            for path in python_tests.glob(pattern)
        ],
    ]
    if federation_tests is not None:
        checked.extend(sorted(federation_tests.glob("*.py")))
    removed_methods = {
        "check_gateway_health",
        "list_identities",
        "publish_agent_md",
        "fetch_agent_md",
        "check_agent_md",
        "ping",
        "status",
        "trust_roots",
        "call_raw",
        "get_current_v2_group_spk_id",
        "build_v2_p2p_envelope_for_diagnostics",
        "build_v2_group_envelope_for_diagnostics",
        "build_v2_target_from_device",
        "clear_v2_bootstrap_cache",
        "set_v2_bootstrap_cache_epoch",
        "get_v2_bootstrap_cache_epoch",
        "export_sequence_state",
        "reset_sequence_state",
        "set_v2_auto_state_management_enabled",
        "rotate_v2_spk",
        "get_v2_sender_identity",
        "get_group_secret_epochs",
        "handle_group_key_distribution",
        "has_v2_session",
        "v2_session_info",
        "get_remote_agent_md_etag",
        "create_named_group",
    }

    violations: list[str] = []
    for path in sorted(checked):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in removed_methods:
                    violations.append(f"{path}:{node.lineno}: removed client method {node.func.attr}")

    assert violations == []


def test_migrated_integration_tests_do_not_touch_client_private_members():
    python_tests = Path(__file__).resolve().parents[2] / "tests"
    federation_tests = _federation_tests_dir()
    checked = [
        *[
            path
            for pattern in ("integration_test_*.py", "e2e_test_*.py", "test_integration_*.py")
            for path in python_tests.glob(pattern)
        ],
    ]
    if federation_tests is not None:
        checked.extend(sorted(federation_tests.glob("*.py")))
    client_like_names = {
        "client",
        "client1",
        "client2",
        "client_for_edit",
        "alice",
        "bob",
        "bobb",
        "carol",
        "target",
        "short",
        "short_client",
        "long_client",
    }

    violations: list[str] = []
    for path in sorted(checked):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute) or not node.attr.startswith("_"):
                continue
            if isinstance(node.value, ast.Name) and node.value.id in client_like_names:
                violations.append(f"{path}:{node.lineno}: private client member {node.value.id}.{node.attr}")

    assert violations == []


def test_client_does_not_expose_removed_namespaces():
    client = AUNClient()

    assert not hasattr(client, "auth")
    assert not hasattr(client, "meta")
    assert not hasattr(client, "custody")


def test_client_does_not_expose_proxy_control_surface_by_default():
    client = AUNClient()

    for name in (
        "proxy",
        "proxy_client",
        "start_proxy",
        "stop_proxy",
        "connect_proxy",
        "register_proxy_service",
        "unregister_proxy_service",
        "list_proxy_services",
    ):
        assert not hasattr(client, name)


@pytest.mark.asyncio
async def test_client_constructor_does_not_start_proxy_background_tasks():
    before = set()
    current = asyncio.current_task()
    for task in asyncio.all_tasks():
        if task is not current:
            before.add(task)

    client = AUNClient()
    assert client.state == ConnectionState.NO_IDENTITY

    after = {task for task in asyncio.all_tasks() if task is not current}
    assert after - before == set()


@pytest.mark.asyncio
async def test_client_connect_rejects_legacy_auth_options_signature():
    client = AUNClient()

    with pytest.raises(TypeError):
        await client.connect({"access_token": "token"}, {"gateway": "wss://gateway.example/aun"})


def test_client_does_not_expose_removed_convenience_methods():
    client = AUNClient()

    for name in (
        "list_identities",
        "set_agent_md_path",
        "SetAgentMDPath",
        "publish_agent_md",
        "fetch_agent_md",
        "check_agent_md",
        "check_gateway_health",
        "ping",
        "status",
        "trust_roots",
        "public_state",
        "configure_runtime",
        "call_raw",
        "get_remote_agent_md_etag",
        "create_named_group",
    ):
        assert not hasattr(client, name)


def test_aid_store_does_not_expose_internal_trust_roots_or_test_helpers(tmp_path):
    store = AIDStore(tmp_path / "aun", "")

    for name in (
        "download_trust_roots",
        "verify_trust_roots",
        "import_trust_roots",
        "refresh_trust_roots",
        "download_issuer_root_cert",
        "update_issuer_root_cert",
        "get_auth_cache_info",
        "expire_cached_access_token",
        "head_agent_md",
    ):
        assert not hasattr(store, name)

    store.close()
