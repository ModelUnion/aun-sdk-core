import pytest
from pathlib import Path


def test_load_config_creates_default(tmp_path, monkeypatch):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    from aun_cli.config import load_config
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
