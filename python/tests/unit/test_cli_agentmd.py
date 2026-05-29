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

    class FakeStore:
        async def fetch_agent_md(self, aid):
            calls.append(aid)
            from aun_core import result_ok
            return result_ok({
                "aid": aid,
                "content": "# Bob\n",
                "verification": {"status": "verified"},
                "cert_pem": "cert",
            })

        def close(self):
            pass

    monkeypatch.setattr(agentmd_commands, "make_aid_store", lambda resolved: FakeStore())

    result = CliRunner().invoke(app, ["--json", "agentmd", "fetch", "bobb.agentid.pub"])

    assert result.exit_code == 0, result.output
    assert calls == ["bobb.agentid.pub"]
    data = json.loads(result.output)
    assert data["aid"] == "bobb.agentid.pub"
    assert data["content"] == "# Bob\n"


def test_agentmd_check_calls_sdk_method(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeStore:
        async def check_agent_md(self, aid, ttl_days=1):
            calls.append((aid, ttl_days))
            from aun_core import result_ok
            return result_ok({"aid": aid, "local_found": True, "remote_found": True, "needs_update": False})

        def close(self):
            pass

    monkeypatch.setattr(agentmd_commands, "make_aid_store", lambda resolved: FakeStore())

    result = CliRunner().invoke(
        app,
        ["--json", "agentmd", "check_agent_md", "bobb.agentid.pub", "--max-unsynced-days", "3"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [("bobb.agentid.pub", 3)]
    assert json.loads(result.output)["needs_update"] is False


def test_agentmd_check_defaults_to_one_day_cache_window(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from aun_cli.commands import agentmd as agentmd_commands
    from aun_cli.main import app

    _write_profile_config(tmp_path, monkeypatch)
    calls = []

    class FakeStore:
        async def check_agent_md(self, aid, ttl_days=1):
            calls.append((aid, ttl_days))
            from aun_core import result_ok
            return result_ok({"aid": aid, "local_found": False, "remote_found": False, "ttl_days": ttl_days})

        def close(self):
            pass

    monkeypatch.setattr(agentmd_commands, "make_aid_store", lambda resolved: FakeStore())

    result = CliRunner().invoke(app, ["--json", "agentmd", "check"])

    assert result.exit_code == 0, result.output
    assert calls == [("alice.agentid.pub", 1)]
