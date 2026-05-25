import pytest
from pathlib import Path
from types import SimpleNamespace
import json


def test_load_config_creates_default(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    from aun_cli.config import get_tab_profile_name, load_config
    cfg = load_config()
    assert cfg["default"]["profile"] == "default"
    assert cfg["default"]["timeout"] == 30


def test_get_set_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    from aun_cli.config import get_profile, set_profile
    set_profile("work", {"aid": "bot@corp.com", "gateway": "wss://gw.corp.com/ws"})
    p = get_profile("work")
    assert p["aid"] == "bot@corp.com"
    assert p["gateway"] == "wss://gw.corp.com/ws"


def test_get_profile_not_found(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    from aun_cli.config import get_profile
    with pytest.raises(KeyError):
        get_profile("nonexistent")


def test_effective_profile_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-a")

    from aun_cli.config import get_effective_profile_name, load_config, save_config, set_tab_profile_name

    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {
        "default": {"aid": "alice@aid.com"},
        "work": {"aid": "work@aid.com"},
    }
    save_config(cfg)

    assert get_effective_profile_name() == ("default", "default")

    set_tab_profile_name("work")
    assert get_effective_profile_name() == ("work", "tab")

    monkeypatch.setenv("AUN_PROFILE", "env")
    assert get_effective_profile_name() == ("env", "env")
    assert get_effective_profile_name("cli") == ("cli", "command")


def test_resolve_profile_initializes_current_tab(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-b")

    from aun_cli.adapter import resolve_profile_config
    from aun_cli.config import get_tab_profile_name, load_config, save_config

    cfg = load_config()
    cfg["default"]["profile"] = "work"
    cfg["profiles"] = {
        "work": {
            "aid": "work@aid.com",
            "gateway": "wss://gw.example/ws",
            "active_group": "g-work.agentid.pub",
        },
    }
    save_config(cfg)

    ctx = SimpleNamespace(obj={"profile": None, "gateway": None, "timeout": None, "debug": False})
    resolved = resolve_profile_config(ctx)

    assert resolved["profile_name"] == "work"
    assert resolved["profile_source"] == "default"
    assert resolved["aid"] == "work@aid.com"
    assert resolved["active_group"] == "g-work.agentid.pub"
    assert get_tab_profile_name() == "work"


def test_doctor_private_key_check_uses_keystore_split_format(tmp_path):
    from aun_cli.commands.diag import _check_private_key
    from aun_core.crypto import CryptoProvider
    from aun_core.keystore.file import FileKeyStore

    aid = "alice.agentid.pub"
    keystore = FileKeyStore(tmp_path)
    try:
        keystore.save_key_pair(aid, CryptoProvider().generate_identity())
    finally:
        keystore.close()

    ok, detail = _check_private_key(tmp_path, aid)

    assert ok is True
    assert detail == "P-256"
    assert (tmp_path / "AIDs" / aid / "private" / "key.json").exists()
    assert not (tmp_path / "AIDs" / aid / "private" / f"{aid}.key").exists()


def test_profile_command_registered_at_top_level(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-cli")

    from typer.testing import CliRunner
    from aun_cli.config import load_config, save_config
    from aun_cli.main import app

    cfg = load_config()
    cfg["default"]["profile"] = "default"
    cfg["profiles"] = {
        "default": {"aid": "alice.agentid.pub", "gateway": "wss://gateway.example/aun"},
    }
    save_config(cfg)

    result = CliRunner().invoke(app, ["--json", "profile", "list"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["current"] == "default"
    assert "default" in data["profiles"]


def test_help_supports_nested_command_path(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-help-nested")

    from typer.testing import CliRunner
    from aun_cli.main import app

    result = CliRunner().invoke(app, ["--json", "help", "group", "create"])

    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output
    assert "aun group create" in result.output
    assert "NAME" in result.output


def test_profile_current_banner_includes_active_group(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-banner")

    from typer.testing import CliRunner
    from aun_cli.config import load_config, save_config
    from aun_cli.main import app

    cfg = load_config()
    cfg["default"]["profile"] = "work"
    cfg["profiles"] = {
        "work": {
            "aid": "work.agentid.pub",
            "gateway": "wss://gateway.example/aun",
            "active_group": "g-work.agentid.pub",
        },
    }
    save_config(cfg)

    result = CliRunner().invoke(app, ["profile", "current"])

    assert result.exit_code == 0, result.output
    first_line = result.output.splitlines()[0]
    assert "active_group=g-work.agentid.pub" in first_line


def test_identity_check_command_registered(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-identity-check")

    async def fake_check_aid(self, params):
        return {
            "aid": params["aid"],
            "status": "available",
            "can_register": True,
            "local": {
                "exists": False,
                "complete": False,
                "private_key": False,
                "public_key": False,
                "certificate": {"present": False, "valid": False, "expired": False},
                "issues": ["local identity not found"],
            },
            "remote": {"status": "available", "source": "agent.md"},
        }

    from typer.testing import CliRunner
    from aun_core.namespaces.auth_namespace import AuthNamespace
    from aun_cli.main import app

    monkeypatch.setattr(AuthNamespace, "check_aid", fake_check_aid)

    result = CliRunner().invoke(app, ["--json", "identity", "check", "free.agentid.pub"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output[result.output.find("{"):])
    assert data["aid"] == "free.agentid.pub"
    assert data["status"] == "available"
    assert data["can_register"] is True


def test_profile_create_command(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-create")

    from typer.testing import CliRunner
    from aun_cli.config import get_tab_profile_name, load_config
    from aun_cli.main import app

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "profile",
            "create",
            "work",
            "--aid",
            "work.agentid.pub",
            "--gateway",
            "wss://gateway.example/aun",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["created"] == "work"
    assert data["switched"] is True
    cfg = load_config()
    assert cfg["profiles"]["work"]["aid"] == "work.agentid.pub"
    assert cfg["profiles"]["work"]["gateway"] == "wss://gateway.example/aun"
    assert cfg["default"]["profile"] == "work"
    assert get_tab_profile_name() == "work"


def test_profile_create_can_skip_switch(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-create-no-switch")

    from typer.testing import CliRunner
    from aun_cli.config import get_tab_profile_name, load_config
    from aun_cli.main import app

    result = CliRunner().invoke(app, ["--json", "profile", "create", "work", "--no-switch"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["created"] == "work"
    assert data["switched"] is False
    cfg = load_config()
    assert "work" in cfg["profiles"]
    assert cfg["default"]["profile"] == "default"
    assert get_tab_profile_name() is None


def test_profile_switch_can_create(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-switch-create")

    from typer.testing import CliRunner
    from aun_cli.config import get_tab_profile_name, load_config
    from aun_cli.main import app

    result = CliRunner().invoke(
        app,
        [
            "--json",
            "profile",
            "switch",
            "work",
            "--create",
            "--aid",
            "work.agentid.pub",
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["switched_to"] == "work"
    assert data["created"] is True
    cfg = load_config()
    assert cfg["default"]["profile"] == "work"
    assert cfg["profiles"]["work"]["aid"] == "work.agentid.pub"
    assert get_tab_profile_name() == "work"
