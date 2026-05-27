import json
from pathlib import Path


def _write_profile_config(
    tmp_path,
    monkeypatch,
    *,
    profile_name="default",
    aid="alice.agentid.pub",
    gateway="wss://gateway.example/aun",
    agentmd_path=None,
):
    monkeypatch.setenv("AUN_CLI_CONFIG", str(tmp_path / ".aun" / "cli.toml"))
    monkeypatch.setenv("AUN_CLI_STATE_DIR", str(tmp_path / ".aun" / "cli-sessions"))
    monkeypatch.setenv("AUN_CLI_SESSION_ID", "tab-agentmd")

    from aun_cli.config import load_config, save_config

    aun_path = str(tmp_path / "aun-profile")
    cfg = load_config()
    cfg["default"]["profile"] = profile_name
    cfg["profiles"] = {
        profile_name: {
            "aid": aid,
            "gateway": gateway,
            "aun_path": aun_path,
        },
    }
    if agentmd_path is not None:
        cfg["profiles"][profile_name]["agentmd_path"] = str(agentmd_path)
    save_config(cfg)
    return cfg["profiles"][profile_name]


def test_agentmd_path_sets_profile(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.config import load_config
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)

    class FakeClient:
        def __init__(self):
            self._agent_md_path = ""

        def set_agent_md_path(self, path):
            self._agent_md_path = str(Path(path))
            return self._agent_md_path

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(agentmd_commands, "CLISession", FakeSession)
    new_path = tmp_path / "AgentMDs"

    result = CliRunner().invoke(app, ["--json", "agentmd", "path", str(new_path)])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["profile"] == "default"
    assert data["agentmd_path"] == str(new_path)
    cfg = load_config()
    assert cfg["profiles"]["default"]["agentmd_path"] == str(new_path)


def test_agentmd_publish_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeClient:
        async def publish_agent_md(self):
            calls.append("publish_agent_md")
            return {"aid": "alice.agentid.pub", "etag": '"v1"', "agent_md_url": "https://alice.agentid.pub/agent.md"}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(agentmd_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "agentmd", "publish_agent_md"])

    assert result.exit_code == 0, result.output
    assert calls == ["publish_agent_md"]
    assert json.loads(result.output)["etag"] == '"v1"'


def test_agentmd_fetch_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeClient:
        async def fetch_agent_md(self, aid=None):
            calls.append(aid)
            return {
                "aid": aid,
                "content": "# Bob\n",
                "signature": {"status": "verified"},
                "saved_to": "AgentMDs/bob.agentid.pub/agent.md",
            }

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(agentmd_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "agentmd", "fetch", "bob.agentid.pub"])

    assert result.exit_code == 0, result.output
    assert calls == ["bob.agentid.pub"]
    data = json.loads(result.output)
    assert data["aid"] == "bob.agentid.pub"
    assert data["content"] == "# Bob\n"


def test_agentmd_check_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeClient:
        async def check_agent_md(self, aid=None, max_unsynced_days=0):
            calls.append((aid, max_unsynced_days))
            return {"aid": aid, "local_found": True, "remote_found": True, "in_sync": True}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(agentmd_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(
        app,
        ["--json", "agentmd", "check_agent_md", "bob.agentid.pub", "--max-unsynced-days", "3"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [("bob.agentid.pub", 3.0)]
    assert json.loads(result.output)["in_sync"] is True


def test_agentmd_check_defaults_to_one_day_cache_window(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeClient:
        async def check_agent_md(self, aid=None, max_unsynced_days=0):
            calls.append((aid, max_unsynced_days))
            return {"aid": aid or "alice.agentid.pub", "local_found": False, "remote_found": False, "cached": True}

    class FakeSession:
        def __init__(self, ctx, **kwargs):
            pass

        async def __aenter__(self):
            return FakeClient()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(agentmd_commands, "CLISession", FakeSession)

    result = CliRunner().invoke(app, ["--json", "agentmd", "check"])

    assert result.exit_code == 0, result.output
    assert calls == [(None, 1.0)]
